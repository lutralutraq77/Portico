// Package workload composes inner TLS, online policy and exact TCP forwarding.
package workload

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

var ErrDenied = errors.New("workload connection rejected")

const version = 1
const maxMessage = 1024
const chunkSize = 32 * 1024

// An open names a stored resource revision, never a destination address.
type openRequest struct {
	Version    int
	ResourceID string
	Revision   int64
}
type ready struct {
	Version               int
	SessionID, ResourceID string
	Revision              int64
}

// Destination is trusted local configuration, independent of controller
// permission. Changing a tuple requires an explicit new configuration.
type Destination struct {
	ResourceID string
	Revision   int64
	Address    string
	Port       int
	Protocol   string
}

func (d Destination) matches(r control.ResourceAccess) bool {
	return d.ResourceID == r.ID && d.Revision == r.Revision && d.Address == r.Address && d.Port == r.Port && d.Protocol == r.Protocol
}
func (d Destination) valid(blocks []netip.Prefix) bool {
	a, e := netip.ParseAddr(d.Address)
	if !pki.ValidID(d.ResourceID) || d.Revision < 1 || e != nil || a.String() != d.Address || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() || d.Protocol != "tcp" || d.Port < 1 || d.Port > 65535 {
		return false
	}
	for _, block := range blocks {
		if block.Contains(a) {
			return false
		}
	}
	return true
}
func readMessage(r io.Reader, v any) error {
	var head [4]byte
	if _, e := io.ReadFull(r, head[:]); e != nil {
		return ErrDenied
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > maxMessage {
		return ErrDenied
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil || wire.Decode(b, v) != nil {
		return ErrDenied
	}
	return nil
}
func writeMessage(w io.Writer, v any) error {
	b, e := json.Marshal(v)
	if e != nil || len(b) == 0 || len(b) > maxMessage {
		return ErrDenied
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(b)))
	for _, part := range [][]byte{head[:], b} {
		for len(part) > 0 {
			n, e := w.Write(part)
			if e != nil || n <= 0 {
				return ErrDenied
			}
			part = part[n:]
		}
	}
	return nil
}
