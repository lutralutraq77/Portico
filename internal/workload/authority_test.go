package workload

import (
	"context"
	"net"
	"testing"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

func authorityFixture(t *testing.T) (*session, sample, control.Authorization) {
	t.Helper()
	wall := time.Now().UTC()
	boot := time.Hour
	c := &clock{health: func() (time.Duration, error) { return 0, nil }, readBoot: func() (time.Duration, error) { return boot, nil }, readWall: func() time.Time { return wall }}
	start, e := c.now()
	if e != nil {
		t.Fatal(e)
	}
	device := "00000000-0000-4000-8000-000000000001"
	connector := "00000000-0000-4000-8000-000000000002"
	resource := "00000000-0000-4000-8000-000000000003"
	certificate := "00000000-0000-4000-8000-000000000004"
	connectorCertificate := "00000000-0000-4000-8000-000000000005"
	id := "00000000-0000-4000-8000-000000000006"
	a := control.Authorization{Version: 1, SessionID: id, DeviceID: device, ConnectorID: connector, CertificateID: certificate, ConnectorCertificateID: connectorCertificate, Sequence: 1, PolicyRevision: 2, IssuedAt: wall, LeaseUntil: wall.Add(10 * time.Second), ActivateUntil: wall.Add(5 * time.Second), SessionUntil: wall.Add(30 * time.Minute)}
	a.Resource = control.ResourceAccess{ID: resource, Revision: 1, ConnectorID: connector, Address: "192.0.2.10", Protocol: "tcp", Port: 1234, Until: a.SessionUntil}
	ctx, cancel := context.WithCancel(context.Background())
	raw, peer := net.Pipe()
	t.Cleanup(func() { cancel(); _ = raw.Close(); _ = peer.Close() })
	s := &Server{clock: c, identity: pki.Credential{PrincipalID: connector, NotAfter: wall.Add(time.Hour)}, config: ServerConfig{CertificateID: connectorCertificate, IdleTimeout: time.Minute}}
	x := &session{server: s, raw: raw, ctx: ctx, cancel: cancel, peer: pki.Credential{PrincipalID: device, NotAfter: wall.Add(time.Hour)}, id: id, destination: Destination{resource, 1, "192.0.2.10", 1234, "tcp"}, lease: boot + 5*time.Second, absolute: wall.Add(5 * time.Second), hostUntil: wall.Add(time.Hour)}
	if e := x.accept(start, a, true); e != nil {
		t.Fatal(e)
	}
	return x, start, a
}

func TestAuthorizationTransitionPinsOriginalAuthority(t *testing.T) {
	for _, name := range []string{"valid", "session", "device", "connector", "certificate", "connector_certificate", "resource", "revision", "address", "port", "protocol", "sequence_repeat", "sequence_skip", "policy_rollback", "absolute_extension", "certificate_expiry", "host_expiry", "expired_old_lease", "stopped"} {
		t.Run(name, func(t *testing.T) {
			x, start, a := authorityFixture(t)
			a.Sequence++
			other := "00000000-0000-4000-8000-000000000099"
			switch name {
			case "session":
				a.SessionID = other
			case "device":
				a.DeviceID = other
			case "connector":
				a.ConnectorID = other
				a.Resource.ConnectorID = other
			case "certificate":
				a.CertificateID = other
			case "connector_certificate":
				a.ConnectorCertificateID = other
			case "resource":
				a.Resource.ID = other
			case "revision":
				a.Resource.Revision++
			case "address":
				a.Resource.Address = "192.0.2.11"
			case "port":
				a.Resource.Port++
			case "protocol":
				a.Resource.Protocol = "udp"
			case "sequence_repeat":
				a.Sequence--
			case "sequence_skip":
				a.Sequence++
			case "policy_rollback":
				a.PolicyRevision--
			case "absolute_extension":
				a.SessionUntil = a.SessionUntil.Add(time.Second)
				a.Resource.Until = a.SessionUntil
			case "certificate_expiry":
				x.peer.NotAfter = a.SessionUntil.Add(-time.Second)
			case "host_expiry":
				x.hostUntil = a.SessionUntil.Add(-time.Second)
			case "expired_old_lease":
				x.lease = start.boot
			case "stopped":
				x.stop()
			}
			e := x.accept(start, a, false)
			if name == "valid" {
				if e != nil || !x.active || x.auth.Sequence != 2 {
					t.Fatal("valid activation rejected", e)
				}
			} else if e == nil {
				t.Fatal("changed or expired authority accepted")
			}
		})
	}
}

func TestSuspendExpiryDoesNotReviveOnRenewal(t *testing.T) {
	x, start, a := authorityFixture(t)
	// CLOCK_BOOTTIME advances across sleep even while no supervisor runs.
	x.server.clock.readBoot = func() (time.Duration, error) { return start.boot + 20*time.Second, nil }
	x.server.clock.readWall = func() time.Time { return start.wall.Add(20 * time.Second) }
	if x.allowed() {
		t.Fatal("expired permit survived simulated suspend")
	}
	a.Sequence++
	a.IssuedAt = start.wall.Add(20 * time.Second)
	a.LeaseUntil = a.IssuedAt.Add(10 * time.Second)
	a.ActivateUntil = a.IssuedAt.Add(5 * time.Second)
	now, e := x.server.clock.now()
	if e != nil {
		t.Fatal(e)
	}
	if x.accept(now, a, false) == nil {
		t.Fatal("fresh response revived a terminated session")
	}
}
