package agent

import "os"

// SSH selects one resource and explicit OpenSSH trust and user identity files.
// Host is the SSH host-key name, not an address supplied to the connector.
// Command follows OpenSSH remote command semantics (the remote user's shell).
type SSH struct {
	AgentSocket, Endpoint, ResourceID string
	Revision                          int64
	Host, User, KnownHosts, Identity  string
	Command                           []string
	Stdin, Stdout, Stderr             *os.File
}
