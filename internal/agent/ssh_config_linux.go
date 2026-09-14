//go:build linux

package agent

import (
	"path/filepath"
	"strings"
)

const sshEndpointEnvironment = "PORTICO_SSH_ENDPOINT"
const sshHelperEnvironment = "PORTICO_SSH_HELPER"

func (s SSH) application(helper string) (Application, []string, error) {
	// OpenSSH expands tokens in identity and known-host paths. Reject those
	// spellings so the supplied path cannot resolve to a different trust file.
	path := func(v string) bool {
		return len(v) > 1 && len(v) <= 4096 && filepath.IsAbs(v) && filepath.Clean(v) == v && !strings.ContainsAny(v, "\x00\r\n\"\\$%")
	}
	name := func(v string, limit int) bool {
		if len(v) == 0 || len(v) > limit || v[0] == '-' || v[0] == '.' {
			return false
		}
		for _, c := range v {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				return false
			}
		}
		return true
	}
	if !path(s.KnownHosts) || !path(s.Identity) || !filepath.IsAbs(helper) || filepath.Clean(helper) != helper || strings.ContainsRune(helper, 0) || !name(s.Host, 253) || !name(s.User, 64) {
		return Application{}, nil, ErrRejected
	}
	a := Application{AgentSocket: s.AgentSocket, Endpoint: s.Endpoint, ResourceID: s.ResourceID, Revision: s.Revision, Stdin: s.Stdin, Stdout: s.Stdout, Stderr: s.Stderr}
	// The fixed command excludes configuration hooks, multiplexing, alternate
	// proxies and trust-file fallback. OpenSSH's shell expands only quoted
	// environment values, never caller text as shell syntax or percent tokens.
	a.Argv = []string{"/usr/bin/ssh", "-F", "none", "-o", `ProxyCommand="$PORTICO_SSH_HELPER" agent fdpass`,
		"-o", "ProxyUseFdpass=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no",
		"-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile="` + s.KnownHosts + `"`, "-o", "GlobalKnownHostsFile=none",
		"-o", "CanonicalizeHostname=no", "-o", "VerifyHostKeyDNS=no", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
		"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "AddKeysToAgent=no", "-o", "CertificateFile=none",
		"-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
		"-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
		// Unlike -i, IdentityFile retains a missing explicit path in OpenSSH's
		// identity list. It cannot silently enable the default private keys.
		"-o", `IdentityFile="` + s.Identity + `"`, "-l", s.User, "--", s.Host}
	a.Argv = append(a.Argv, s.Command...)
	args, err := a.commandArguments(false)
	if err != nil {
		return Application{}, nil, err
	}
	return a, args, nil
}

func sshEnvironment(inherited []string, endpoint, helper string) []string {
	env := make([]string, 0, len(inherited)+4)
	for _, entry := range inherited {
		key, _, _ := strings.Cut(entry, "=")
		if key != sshEndpointEnvironment && key != sshHelperEnvironment && key != "SHELL" && key != "SSH_ASKPASS_REQUIRE" {
			env = append(env, entry)
		}
	}
	return append(env, sshEndpointEnvironment+"="+endpoint, sshHelperEnvironment+"="+helper, "SHELL=/bin/sh", "SSH_ASKPASS_REQUIRE=never")
}
