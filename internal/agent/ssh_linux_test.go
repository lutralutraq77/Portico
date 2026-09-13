//go:build linux

package agent

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSSHInvocation(t *testing.T) {
	s := SSH{AgentSocket: "/private/agent", Endpoint: "/private/app with % $() ; spaces", ResourceID: "59d73719-4dc0-4d8c-898e-aa2f9466a89e", Revision: 3,
		Host: "ssh.private.test", User: "alice", Identity: "/private/user key", KnownHosts: "/private/known hosts", Command: []string{"printf", "{socket}"}}
	helper := "/private/helper % $() ; with spaces"
	a, argv, err := s.application(helper)
	if err != nil {
		t.Fatal(err)
	}
	if a.Endpoint != s.Endpoint || argv[0] != "/usr/bin/ssh" || argv[len(argv)-1] != "{socket}" || s.Command[1] != "{socket}" {
		t.Fatal("SSH command mutated or placeholder expanded in remote command")
	}
	if !slices.Equal(argv[len(argv)-8:], []string{"-i", s.Identity, "-l", s.User, "--", s.Host, "printf", "{socket}"}) {
		t.Fatal("host or command entered the SSH option list")
	}
	for _, option := range []string{"none", "ProxyUseFdpass=yes", "ControlPath=none", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none", "IdentityAgent=none", "CertificateFile=none", "CanonicalizeHostname=no", "VerifyHostKeyDNS=no", "UpdateHostKeys=no"} {
		if !slices.Contains(argv, option) {
			t.Fatal("missing SSH boundary option")
		}
	}
	for _, arg := range argv {
		if strings.HasPrefix(arg, "ProxyCommand=") && (strings.Contains(arg, s.Host) || strings.Contains(arg, s.Endpoint) || strings.Contains(arg, helper)) {
			t.Fatal("caller input entered shell command")
		}
	}
	for name, change := range map[string]func(*SSH){
		"option_host":       func(s *SSH) { s.Host = "-oProxyCommand=bad" },
		"shell_host":        func(s *SSH) { s.Host = "a$(bad)" },
		"token_host":        func(s *SSH) { s.Host = "%h" },
		"embedded_user":     func(s *SSH) { s.Host = "bob@host" },
		"invalid_user":      func(s *SSH) { s.User = "alice\nbob" },
		"relative_identity": func(s *SSH) { s.Identity = "key" },
		"token_identity":    func(s *SSH) { s.Identity = "/private/%h" },
		"environment_trust": func(s *SSH) { s.KnownHosts = "/private/${HOME}" },
		"quoted_trust":      func(s *SSH) { s.KnownHosts = "/private/\" trust" },
		"nul_command":       func(s *SSH) { s.Command = []string{"a\x00b"} },
		"oversized_command": func(s *SSH) { s.Command = []string{strings.Repeat("a", 32768)} },
		"missing_resource":  func(s *SSH) { s.ResourceID = "" },
		"stale_revision":    func(s *SSH) { s.Revision = 0 },
		"same_socket":       func(s *SSH) { s.Endpoint = s.AgentSocket },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := s
			change(&candidate)
			if _, _, err := candidate.application(helper); err == nil {
				t.Fatal("ambiguous SSH invocation accepted")
			}
		})
	}
}

func TestSSHEnvironmentReplacesInheritedTransport(t *testing.T) {
	inherited := []string{"HOME=/home/alice", "PORTICO_SSH_ENDPOINT=/wrong", "PORTICO_SSH_ENDPOINT=/also-wrong", "PORTICO_SSH_HELPER=/wrong", "SHELL=/wrong", "SSH_ASKPASS_REQUIRE=force"}
	original := append([]string(nil), inherited...)
	want := []string{"HOME=/home/alice", "PORTICO_SSH_ENDPOINT=/right/socket", "PORTICO_SSH_HELPER=/right/helper", "SHELL=/bin/sh", "SSH_ASKPASS_REQUIRE=never"}
	if got := sshEnvironment(inherited, "/right/socket", "/right/helper"); !reflect.DeepEqual(got, want) || !reflect.DeepEqual(inherited, original) {
		t.Fatal("transport environment can be shadowed or parent mutated")
	}
}
