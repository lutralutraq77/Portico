package controller

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

type fixture struct {
	s             *Store
	dir, actor    string
	user          User
	device        Device
	connector     Connector
	issuer        Issuer
	cert, service Certificate
	resource      Resource
	grant         Grant
	host          HostBinding
	session       Session
}

func seed(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	s, e := Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	f := fixture{s: s, dir: dir, actor: NewID()}
	f.user = User{NewID(), "Alice", true}
	f.device = Device{NewID(), f.user.ID, "Laptop", "linux", true, now.Add(2 * time.Hour)}
	f.connector = Connector{NewID(), "Home", "0.2.0-dev", true}
	f.issuer = Issuer{NewID(), true, now.Add(3 * time.Hour)}
	f.cert = Certificate{NewID(), f.issuer.ID, "1", f.device.ID, "device", strings.Repeat("a", 64), strings.Repeat("c", 64), now.Add(-time.Hour), now.Add(time.Hour), false}
	f.service = Certificate{NewID(), f.issuer.ID, "2", f.connector.ID, "connector", strings.Repeat("b", 64), strings.Repeat("d", 64), now.Add(-time.Hour), now.Add(time.Hour), false}
	f.resource = Resource{NewID(), 1, "Media", f.connector.ID, "application", "192.168.50.10", "tcp", 8096, true}
	f.grant = Grant{NewID(), f.user.ID, f.device.ID, f.resource.ID, NewID(), 1, true, now.Add(-time.Minute), now.Add(30 * time.Minute)}
	f.host = HostBinding{NewID(), f.connector.ID, f.resource.ID, 1, true, now.Add(-time.Minute), now.Add(30 * time.Minute)}
	f.session = Session{NewID(), f.device.ID, f.cert.ID, f.service.ID, f.resource.ID, f.grant.ID, f.host.ID, 1, now.Add(15 * time.Second)}
	must(t, s.Update(ctx, f.actor, func(tx *Tx) error {
		for _, op := range []func() error{func() error { return tx.AddUser(f.user) }, func() error { return tx.AddDevice(f.device) }, func() error { return tx.AddConnector(f.connector) }, func() error { return tx.AddIssuer(f.issuer) }, func() error { return tx.RegisterCertificate(f.cert) }, func() error { return tx.RegisterCertificate(f.service) }, func() error { return tx.AddResource(f.resource) }, func() error { return tx.AddGrant(f.grant) }, func() error { return tx.AddHostBinding(f.host) }} {
			if e := op(); e != nil {
				return e
			}
		}
		return nil
	}))
	return f
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func summary(t *testing.T, s *Store) Summary {
	t.Helper()
	v, e := s.Summary(ctx)
	must(t, e)
	return v
}

func TestDomainDefaultDeny(t *testing.T) {
	for _, kind := range []string{"user", "device", "connector", "issuer", "resource", "grant", "host_binding", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			f := seed(t)
			ids := map[string]string{"user": f.user.ID, "device": f.device.ID, "connector": f.connector.ID, "issuer": f.issuer.ID, "resource": f.resource.ID, "grant": f.grant.ID, "host_binding": f.host.ID, "certificate": f.cert.ID}
			must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
			must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable(kind, ids[kind]) }))
			before := summary(t, f.s)
			if before.OpenSessions != 0 {
				t.Fatal("disable left an open record")
			}
			f.session.ID = NewID()
			e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) })
			if !errors.Is(e, ErrDenied) {
				t.Fatalf("wanted deny, got %v", e)
			}
			if summary(t, f.s) != before {
				t.Fatal("denied mutation changed state or audit")
			}
		})
	}
	for _, field := range []string{"device", "certificate", "connector_certificate", "grant", "host", "resource", "revision", "deadline"} {
		t.Run("wrong_"+field, func(t *testing.T) {
			f := seed(t)
			v := f.session
			switch field {
			case "device":
				v.DeviceID = NewID()
			case "certificate":
				v.CertificateID = NewID()
			case "connector_certificate":
				v.ConnectorCertificateID = f.cert.ID
			case "grant":
				v.GrantID = NewID()
			case "host":
				v.HostBindingID = NewID()
			case "resource":
				v.ResourceID = NewID()
			case "revision":
				v.Revision++
			case "deadline":
				v.Until = f.grant.Until.Add(time.Second)
			}
			if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(v) }); e == nil {
				t.Fatal("mismatched references accepted")
			}
			if summary(t, f.s).Sessions != 0 {
				t.Fatal("failed request persisted")
			}
		})
	}
}

func TestResourceRevisionAndIndependentHostPermission(t *testing.T) {
	f := seed(t)
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RenameResource(f.resource.ID, 1, "New name") }))
	if summary(t, f.s).OpenSessions != 1 {
		t.Fatal("display rename invalidated endpoint")
	}
	next := f.resource
	next.Revision = 2
	next.Port++
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.ReviseResource(1, next) }))
	if summary(t, f.s).OpenSessions != 0 {
		t.Fatal("revision left old session")
	}
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.ReviseResource(1, next) }); !errors.Is(e, ErrConflict) {
		t.Fatalf("stale edit: %v", e)
	}
	f.session.ID = NewID()
	f.session.Revision = 2
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }); e == nil {
		t.Fatal("old grants inherited new endpoint")
	}
	f.grant.ID = NewID()
	f.grant.Revision = 2
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddGrant(f.grant) }))
	f.session.GrantID = f.grant.ID
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }); e == nil {
		t.Fatal("dial grant implied host permission")
	}
	f.host.ID = NewID()
	f.host.Revision = 2
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddHostBinding(f.host) }))
	f.session.HostBindingID = f.host.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
}

func TestOwnershipForeignKeysAndNoFutureDeviceInheritance(t *testing.T) {
	f := seed(t)
	bob := User{NewID(), "Bob", true}
	other := f.device
	other.ID = NewID()
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if e := tx.AddUser(bob); e != nil {
			return e
		}
		return tx.AddDevice(other)
	}))
	g := f.grant
	g.ID = NewID()
	g.UserID = bob.ID
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddGrant(g) }); !errors.Is(e, ErrConflict) {
		t.Fatalf("owner mismatch: %v", e)
	}
	f.session.DeviceID = other.ID
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }); e == nil {
		t.Fatal("future device inherited permission")
	}
	h := f.host
	h.ID = NewID()
	h.ConnectorID = NewID()
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddHostBinding(h) }); e == nil {
		t.Fatal("wrong connector can host")
	}
}

func TestCertificateProfilesExpiryAndNoImplicitReplacement(t *testing.T) {
	f := seed(t)
	replacement := f.cert
	replacement.ID = NewID()
	replacement.Serial = "3"
	replacement.LeafSHA256 = strings.Repeat("e", 64)
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RegisterCertificate(replacement) }))
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
	// Recording another certificate does not revoke the old one.
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("certificate", f.cert.ID) }))
	f.session.ID = NewID()
	f.session.CertificateID = replacement.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
	f.s.now = func() time.Time { return f.grant.Until }
	f.session.ID = NewID()
	f.session.Until = f.grant.Until.Add(time.Second)
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }); !errors.Is(e, ErrDenied) {
		t.Fatalf("expiry boundary: %v", e)
	}
}

func TestTerminalSessionAndRestart(t *testing.T) {
	f := seed(t)
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.EndSession(f.session.ID, "active") }); !errors.Is(e, ErrInvalid) {
		t.Fatal("Phase 2 activated access")
	}
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.EndSession(f.session.ID, "closed") }))
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.EndSession(f.session.ID, "expired") }); !errors.Is(e, ErrConflict) {
		t.Fatal("terminal record changed")
	}
	f.session.ID = NewID()
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
	must(t, f.s.Close())
	reopened, e := Open(ctx, f.dir)
	must(t, e)
	defer func() { _ = reopened.Close() }()
	if summary(t, reopened).OpenSessions != 0 {
		t.Fatal("restart revived a lease")
	}
}

func TestAtomicRollbackAndIgnoredError(t *testing.T) {
	f := seed(t)
	before := summary(t, f.s)
	e := f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if e := tx.AddUser(User{NewID(), "must rollback", true}); e != nil {
			return e
		}
		_ = tx.AddDevice(Device{ID: NewID(), UserID: NewID(), Name: "orphan", Platform: "linux", Enabled: true, NotAfter: time.Now().Add(time.Hour)})
		return nil
	})
	if e == nil || summary(t, f.s) != before {
		t.Fatal("ignored error allowed partial transaction")
	}
	var retained *Tx
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { retained = tx; return nil }))
	if e = retained.AddUser(User{NewID(), "late", true}); e == nil {
		t.Fatal("escaped transaction stayed usable")
	}
}

func TestConcurrentDuplicateAndOptimisticEdits(t *testing.T) {
	f := seed(t)
	id := NewID()
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			results <- f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddUser(User{id, "once", true}) })
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatalf("success count %d", success)
	}
}

func TestAuditCheckpointTamperAndRedaction(t *testing.T) {
	f := seed(t)
	canary := "secret-display-name"
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), canary, true}) }))
	events, e := f.s.AuditBatch(ctx, Checkpoint{}, 256)
	must(t, e)
	end, e := VerifyBatch(Checkpoint{}, events)
	must(t, e)
	body, e := json.Marshal(events)
	must(t, e)
	if strings.Contains(string(body), canary) {
		t.Fatal("display value entered audit")
	}
	copyEvents := append([]Event(nil), events...)
	copyEvents[1].Action = "tampered"
	if _, e = VerifyBatch(Checkpoint{}, copyEvents); !errors.Is(e, ErrIntegrity) {
		t.Fatal("tamper undetected")
	}
	if _, e = VerifyBatch(Checkpoint{}, events[1:]); !errors.Is(e, ErrIntegrity) {
		t.Fatal("gap undetected")
	}
	must(t, f.s.Acknowledge(ctx, Checkpoint{}, end))
	if e = f.s.Acknowledge(ctx, Checkpoint{}, end); !errors.Is(e, ErrConflict) {
		t.Fatal("stale export acknowledgment accepted")
	}
	if _, e = f.s.db.Exec("UPDATE audit_events SET action='tamper'"); e == nil {
		t.Fatal("normal audit mutation accepted")
	}
	// Simulate host-root tampering, outside normal application capabilities.
	_, e = f.s.db.Exec("DROP TRIGGER audit_no_delete; DELETE FROM audit_events WHERE sequence=?", end.Sequence)
	must(t, e)
	if _, e = f.s.AuditBatch(ctx, Checkpoint{}, 256); !errors.Is(e, ErrIntegrity) {
		t.Fatal("tail deletion undetected")
	}
}

func TestAuditFailureStorageFailureAndEmergencyStop(t *testing.T) {
	f := seed(t)
	before := summary(t, f.s)
	_, e := f.s.db.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit storage failure'); END")
	must(t, e)
	e = f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "must not persist", true}) })
	if e == nil || summary(t, f.s) != before {
		t.Fatal("audit failure allowed state change")
	}
	f.s.EmergencyDeny()
	if !f.s.Stopped() {
		t.Fatal("emergency stop not latched")
	}
	if e = f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }); !errors.Is(e, ErrDenied) {
		t.Fatalf("stopped update: %v", e)
	}
}

func TestDiskFullAtomicFailure(t *testing.T) {
	f := seed(t)
	before := summary(t, f.s)
	var pages int
	must(t, f.s.db.QueryRow("PRAGMA page_count").Scan(&pages))
	var ceiling int
	must(t, f.s.db.QueryRow("PRAGMA max_page_count="+fmtInt(pages)).Scan(&ceiling))
	e := f.s.Update(ctx, f.actor, func(tx *Tx) error {
		for i := 0; i < 500; i++ {
			if e := tx.AddUser(User{NewID(), strings.Repeat("x", 128), true}); e != nil {
				return e
			}
		}
		return nil
	})
	if !errors.Is(e, ErrStorage) || summary(t, f.s) != before {
		t.Fatalf("full database did not roll back: %v", e)
	}
	f.s.EmergencyDeny()
	if !f.s.Stopped() {
		t.Fatal("full disk prevented containment latch")
	}
}

func TestAUDIT01ProcessCrashAtomicity(t *testing.T) {
	if stage := os.Getenv("PORTICO_CRASH_STAGE"); stage != "" {
		s, e := Open(ctx, os.Getenv("PORTICO_CRASH_DIR"))
		if e != nil {
			os.Exit(71)
		}
		actor := NewID()
		e = s.Update(ctx, actor, func(tx *Tx) error {
			if stage == "state" {
				if e := tx.exec("INSERT INTO users VALUES(?,?,?,?)", NewID(), "crash", true, tx.now.UnixNano()); e != nil {
					return e
				}
				os.Exit(73)
			}
			if e := tx.AddUser(User{NewID(), "crash", true}); e != nil {
				return e
			}
			if stage == "audit" {
				os.Exit(73)
			}
			return nil
		})
		if e != nil {
			os.Exit(72)
		}
		os.Exit(73)
	}
	for _, stage := range []string{"state", "audit", "committed"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			child := exec.Command(os.Args[0], "-test.run=^TestAUDIT01ProcessCrashAtomicity$")
			child.Env = append(os.Environ(), "PORTICO_CRASH_STAGE="+stage, "PORTICO_CRASH_DIR="+dir)
			out, e := child.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(e, &ee) || ee.ExitCode() != 73 {
				t.Fatalf("crash control failed: %v %s", e, out)
			}
			s, e := Open(ctx, dir)
			must(t, e)
			defer func() { _ = s.Close() }()
			v := summary(t, s)
			want := 0
			if stage == "committed" {
				want = 1
			}
			if v.Users != want || v.AuditSequence != int64(want) {
				t.Fatalf("partial commit after %s: %+v", stage, v)
			}
		})
	}
}

func TestRejectUnknownSchemaCorruptionAndClockRollback(t *testing.T) {
	f := seed(t)
	f.s.now = func() time.Time { return time.Unix(1, 0) }
	if e := f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "backward clock", true}) }); !errors.Is(e, ErrDenied) {
		t.Fatal("backward clock extended authority")
	}
	_, e := f.s.db.Exec("PRAGMA user_version=99")
	must(t, e)
	must(t, f.s.Close())
	if _, e = Open(ctx, f.dir); !errors.Is(e, ErrIntegrity) {
		t.Fatal("unknown migration accepted")
	}
	broken := t.TempDir()
	must(t, os.WriteFile(filepath.Join(broken, "controller.sqlite"), []byte("not a SQLite database"), 0600))
	if _, e = Open(ctx, broken); e == nil {
		t.Fatal("corrupt database reset silently")
	}
}

func TestSnapshotIsConsistentAndQuarantined(t *testing.T) {
	f := seed(t)
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
	dir := t.TempDir()
	destination := filepath.Join(dir, "controller.sqlite")
	before := summary(t, f.s)
	must(t, f.s.Snapshot(ctx, destination))
	if summary(t, f.s) != before {
		t.Fatal("snapshot changed live state")
	}
	if _, e := Open(ctx, dir); !errors.Is(e, ErrQuarantine) {
		t.Fatalf("snapshot resumed as live controller: %v", e)
	}
	bytesBefore, e := os.ReadFile(destination)
	must(t, e)
	if e = f.s.Snapshot(ctx, destination); e == nil {
		t.Fatal("snapshot overwrote existing file")
	}
	bytesAfter, e := os.ReadFile(destination)
	must(t, e)
	if string(bytesBefore) != string(bytesAfter) {
		t.Fatal("existing snapshot was modified")
	}
}
