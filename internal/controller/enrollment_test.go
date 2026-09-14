package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

type issueFunc func(context.Context, IssuanceRequest) ([]byte, error)

func (f issueFunc) Issue(c context.Context, r IssuanceRequest) ([]byte, error) { return f(c, r) }
func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, e)
	return k
}
func cert(t *testing.T, template, parent *x509.Certificate, pub any, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, e := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	must(t, e)
	return b
}
func parseCert(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	c, e := x509.ParseCertificate(b)
	must(t, e)
	return c
}
func csrFor(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	must(t, e)
	return b
}

type enrollmentFixture struct {
	f      fixture
	trust  *pki.Trust
	config pki.Config
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	calls  atomic.Int32
}

func enrollmentSeed(t *testing.T) *enrollmentFixture {
	t.Helper()
	f := seed(t)
	rk, ik := newKey(t), newKey(t)
	now := f.s.now()
	r := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(8 * time.Hour), KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	rder := cert(t, r, r, &rk.PublicKey, rk)
	r = parseCert(t, rder)
	i := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated test issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(4 * time.Hour), KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true}
	ider := cert(t, i, r, &ik.PublicKey, rk)
	i = parseCert(t, ider)
	config := pki.Config{DeploymentID: NewID(), IssuerID: NewID(), Profile: pki.Device, RootDER: rder, IssuerDER: ider}
	tr, e := pki.NewTrust(config)
	must(t, e)
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.BindIssuer(tr) }))
	return &enrollmentFixture{f: f, trust: tr, config: config, ca: i, caKey: ik}
}
func (f *enrollmentFixture) sign(t *testing.T, r IssuanceRequest) []byte {
	t.Helper()
	f.calls.Add(1)
	csr, e := pki.ParseCSR(r.CSR)
	must(t, e)
	u, e := pki.IdentityURI(r.DeploymentID, r.Profile, r.PrincipalID)
	must(t, e)
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 158))
	must(t, e)
	n.Add(n, big.NewInt(1))
	tmpl := &x509.Certificate{SerialNumber: n, NotBefore: r.NotBefore, NotAfter: r.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{u}}
	if r.Profile == pki.Connector {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		name, e := pki.ConnectorName(r.DeploymentID, r.PrincipalID)
		must(t, e)
		tmpl.DNSNames = []string{name}
	}
	return cert(t, tmpl, f.ca, csr.PublicKey, f.caKey)
}
func (f *enrollmentFixture) provider(t *testing.T) issueFunc {
	return func(_ context.Context, r IssuanceRequest) ([]byte, error) { return f.sign(t, r), nil }
}

type invited struct {
	id, secret, attempt string
	key                 *ecdsa.PrivateKey
	csr, der            []byte
}

func (f *enrollmentFixture) invite(t *testing.T) invited {
	t.Helper()
	now := f.f.s.now()
	v := InvitationSpec{NewID(), f.trust.IssuerID(), f.f.device.ID, pki.Device, now.Add(10 * time.Minute), now.Add(time.Hour)}
	secret, e := f.f.s.Invite(ctx, f.f.actor, v)
	must(t, e)
	k := newKey(t)
	return invited{id: v.ID, secret: secret, attempt: NewID(), key: k, csr: csrFor(t, k)}
}
func (f *enrollmentFixture) issue(t *testing.T) vIssued {
	t.Helper()
	v := f.invite(t)
	must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
	must(t, f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, f.provider(t)))
	der, e := f.f.s.EnrollmentCertificate(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr)
	must(t, e)
	v.der = der
	return vIssued{v}
}

type vIssued struct{ invited }

// Real TLS over net.Pipe uses no host listening port, DNS or external network.
// Both ends verify certificates; failed client authentication is read on the
// server too because TLS 1.3 clients may finish before receiving the rejection.
func tlsHandshake(t *testing.T, s *Store, trust *pki.Trust, client tls.Certificate, pending bool) (*tls.Conn, error) {
	t.Helper()
	k := newKey(t)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"enrollment.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der := cert(t, tmpl, tmpl, &k.PublicKey, k)
	serverConfig, e := s.ClientTLSConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, trust, pending)
	if trust.Profile() == pki.Administrator {
		serverConfig, e = s.AdminTLSConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, trust)
	}
	must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(parseCert(t, der))
	cc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "enrollment.test"}
	if len(client.Certificate) > 0 {
		cc.Certificates = []tls.Certificate{client}
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))
	server, remote := tls.Server(a, serverConfig), tls.Client(b, cc)
	done := make(chan error, 1)
	go func() {
		err := server.HandshakeContext(ctx)
		if err != nil {
			_ = a.Close()
		}
		done <- err
	}()
	ce := remote.HandshakeContext(ctx)
	if ce != nil {
		_ = b.Close()
	} else {
		// Drain a possible TLS 1.3 rejection alert after the client Finished.
		go func() { var one [1]byte; _, _ = remote.Read(one[:]) }()
	}
	se := <-done
	if ce != nil {
		return nil, ce
	}
	if se != nil {
		return nil, se
	}
	return server, nil
}
func tlsIdentity(v invited) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{v.der}, PrivateKey: v.key}
}

func TestEnrollmentTLSActivationAndLiveRevocation(t *testing.T) {
	f := enrollmentSeed(t)
	v := f.issue(t)
	if _, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v.invited), false); e == nil {
		t.Fatal("unactivated credential authenticated")
	}
	if _, e := tlsHandshake(t, f.f.s, f.trust, tls.Certificate{}, true); e == nil {
		t.Fatal("no certificate authenticated")
	}
	wrong := tlsIdentity(v.invited)
	wrong.PrivateKey = newKey(t)
	if _, e := tlsHandshake(t, f.f.s, f.trust, wrong, true); e == nil {
		t.Fatal("wrong private key authenticated")
	}
	if e := f.f.s.ActivateEnrollment(ctx, v.id, nil, f.trust); e == nil {
		t.Fatal("activation without TLS proof")
	}
	conn, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v.invited), true)
	must(t, e)
	if e = f.f.s.ActivateEnrollment(ctx, NewID(), conn, f.trust); e == nil {
		t.Fatal("wrong enrollment activated")
	}
	must(t, f.f.s.ActivateEnrollment(ctx, v.id, conn, f.trust))
	must(t, f.f.s.ActivateEnrollment(ctx, v.id, conn, f.trust))
	conn, e = tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v.invited), false)
	must(t, e)
	identity, e := f.f.s.Authenticate(ctx, conn, f.trust)
	must(t, e)
	if identity.PrincipalID != f.f.device.ID {
		t.Fatal("wrong principal")
	}
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.Disable("device", f.f.device.ID) }))
	if _, e = f.f.s.Authenticate(ctx, conn, f.trust); e == nil {
		t.Fatal("cached connection bypassed disable")
	}
	if _, e = tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v.invited), false); e == nil {
		t.Fatal("revoked device handshook")
	}
}

func TestEnrollmentConcurrentSingleUse(t *testing.T) {
	f := enrollmentSeed(t)
	v := f.invite(t)
	otherKey := newKey(t)
	otherCSR := csrFor(t, otherKey)
	otherAttempt := NewID()
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for i, candidate := range []struct {
		attempt string
		csr     []byte
	}{{v.attempt, v.csr}, {otherAttempt, otherCSR}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, candidate.attempt, candidate.csr) == nil {
				results <- i
			}
		}()
	}
	wg.Wait()
	close(results)
	winners := []int{}
	for i := range results {
		winners = append(winners, i)
	}
	if len(winners) != 1 {
		t.Fatalf("winners %v", winners)
	}
	if winners[0] == 1 {
		v.attempt = otherAttempt
		v.csr = otherCSR
		v.key = otherKey
	}
	must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
	if e := f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, NewID(), v.csr); e == nil {
		t.Fatal("attempt rebound")
	}
	var success atomic.Int32
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, f.provider(t)) == nil {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if f.calls.Load() != 1 || success.Load() != 1 {
		t.Fatalf("signing calls %d successes %d", f.calls.Load(), success.Load())
	}
	der, e := f.f.s.EnrollmentCertificate(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr)
	must(t, e)
	if len(der) == 0 {
		t.Fatal("missing public certificate")
	}
	if _, e = f.f.s.EnrollmentCertificate(ctx, f.f.actor, v.id, v.secret, NewID(), v.csr); e == nil {
		t.Fatal("result delivered to wrong attempt")
	}
}

func TestEnrollmentAmbiguousIssuanceAndReconciliation(t *testing.T) {
	f := enrollmentSeed(t)
	v := f.invite(t)
	must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
	var signedDER []byte
	provider := issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
		signedDER = f.sign(t, r)
		return nil, errors.New("sensitive provider response must be redacted")
	})
	if e := f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, provider); e != ErrDenied {
		t.Fatalf("provider error leaked: %v", e)
	}
	must(t, f.f.s.Close())
	s, e := Open(ctx, f.f.dir)
	must(t, e)
	f.f.s = s
	t.Cleanup(func() { _ = s.Close() })
	if e = f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, provider); e == nil {
		t.Fatal("uncertain issuance retried")
	}
	if f.calls.Load() != 1 {
		t.Fatal("unlimited signing after restart")
	}
	v.der = signedDER
	if _, e = tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v), true); e == nil {
		t.Fatal("unregistered signed leaf authenticated")
	}
	must(t, f.f.s.ReconcileEnrollment(ctx, f.f.actor, v.id, f.trust, signedDER))
	must(t, f.f.s.ReconcileEnrollment(ctx, f.f.actor, v.id, f.trust, signedDER))
	conn, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v), true)
	must(t, e)
	must(t, f.f.s.ActivateEnrollment(ctx, v.id, conn, f.trust))
	if _, e = f.f.s.Authenticate(ctx, conn, f.trust); e != nil {
		t.Fatal(e)
	}
}

func TestEnrollmentRejectsProviderConstraintChanges(t *testing.T) {
	for _, field := range []string{"principal", "deployment", "profile", "key", "lifetime", "start"} {
		t.Run(field, func(t *testing.T) {
			f := enrollmentSeed(t)
			v := f.invite(t)
			must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
			provider := issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
				switch field {
				case "principal":
					r.PrincipalID = NewID()
				case "deployment":
					r.DeploymentID = NewID()
				case "profile":
					r.Profile = pki.Connector
				case "key":
					r.CSR = csrFor(t, newKey(t))
				case "lifetime":
					r.NotAfter = r.NotAfter.Add(time.Second)
				case "start":
					r.NotBefore = r.NotBefore.Add(-time.Second)
				}
				return f.sign(t, r), nil
			})
			before := summary(t, f.f.s).Certificates
			if e := f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, provider); e == nil {
				t.Fatal("issuer changed approved constraints")
			}
			if summary(t, f.f.s).Certificates != before {
				t.Fatal("invalid certificate registered")
			}
			if e := f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, f.provider(t)); e == nil {
				t.Fatal("invalid response allowed re-signing")
			}
		})
	}
}

func TestInvitationExpiryAuthorityAndSecrets(t *testing.T) {
	f := enrollmentSeed(t)
	v := f.invite(t)
	if e := f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, strings.Repeat("A", 43), v.attempt, v.csr); e == nil {
		t.Fatal("wrong token accepted")
	}
	var hash string
	must(t, f.f.s.db.QueryRow("SELECT token_hash FROM enrollments WHERE id=?", v.id).Scan(&hash))
	if hash == v.secret || len(hash) != 64 {
		t.Fatal("plaintext token stored")
	}
	body, e := os.ReadFile(filepath.Join(f.f.dir, "controller.sqlite"))
	must(t, e)
	if bytes.Contains(body, []byte(v.secret)) {
		t.Fatal("token present in database")
	}
	events, e := f.f.s.AuditBatch(ctx, Checkpoint{}, 256)
	must(t, e)
	for _, event := range events {
		if strings.Contains(event.Action, v.secret) || strings.Contains(event.TargetID, v.secret) {
			t.Fatal("secret in audit")
		}
	}
	now := f.f.s.now()
	f.f.s.now = func() time.Time { return now.Add(10 * time.Minute) }
	if e = f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr); e == nil {
		t.Fatal("exact token expiry accepted")
	}
	f.f.s.now = func() time.Time { return now }
	for _, profile := range []pki.Profile{"admin", "service", ""} {
		if secret, e := f.f.s.Invite(ctx, f.f.actor, InvitationSpec{NewID(), f.trust.IssuerID(), f.f.device.ID, profile, now.Add(time.Minute), now.Add(time.Hour)}); e == nil || secret != "" {
			t.Fatal("unsupported invitation profile")
		}
	}
	if secret, e := f.f.s.Invite(ctx, f.f.actor, InvitationSpec{NewID(), f.trust.IssuerID(), f.f.device.ID, pki.Device, now.Add(time.Minute), now.Add(3 * time.Hour)}); e == nil || secret != "" {
		t.Fatal("extended device authority")
	}
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(v.id) }))
	if e = f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr); e == nil {
		t.Fatal("revoked token accepted")
	}
}

func TestEnrollmentAuditFailureAndMidflightRevocation(t *testing.T) {
	t.Run("invite", func(t *testing.T) {
		f := enrollmentSeed(t)
		_, e := f.f.s.db.Exec("CREATE TRIGGER fail_enrollment_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test audit failure'); END;")
		must(t, e)
		now := f.f.s.now()
		secret, e := f.f.s.Invite(ctx, f.f.actor, InvitationSpec{NewID(), f.trust.IssuerID(), f.f.device.ID, pki.Device, now.Add(time.Minute), now.Add(time.Hour)})
		if e == nil || secret != "" {
			t.Fatal("uncommitted invitation revealed")
		}
		var n int
		must(t, f.f.s.db.QueryRow("SELECT count(*) FROM enrollments").Scan(&n))
		if n != 0 {
			t.Fatal("invitation escaped audit transaction")
		}
	})
	for _, kind := range []string{"device", "issuer", "invitation"} {
		t.Run(kind, func(t *testing.T) {
			f := enrollmentSeed(t)
			v := f.invite(t)
			must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
			before := summary(t, f.f.s).Certificates
			provider := issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
				der := f.sign(t, r)
				must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error {
					switch kind {
					case "device":
						return tx.Disable("device", f.f.device.ID)
					case "issuer":
						return tx.Disable("issuer", f.trust.IssuerID())
					default:
						return tx.RevokeEnrollment(v.id)
					}
				}))
				return der, nil
			})
			if e := f.f.s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, provider); e == nil {
				t.Fatal("midflight revocation bypassed")
			}
			if summary(t, f.f.s).Certificates != before {
				t.Fatal("revoked issuance registered")
			}
		})
	}
}

func TestSchemaOneMigrationAndQuarantine(t *testing.T) {
	for _, quarantine := range []bool{false, true} {
		t.Run(map[bool]string{false: "migrate", true: "quarantine"}[quarantine], func(t *testing.T) {
			dir := t.TempDir()
			db, e := sql.Open("sqlite", databaseURI(filepath.Join(dir, "controller.sqlite")))
			must(t, e)
			_, e = db.Exec(schema)
			must(t, e)
			h := sha256.Sum256([]byte(schema))
			_, e = db.Exec("INSERT INTO meta(singleton,schema_digest,quarantined) VALUES(1,?,?)", hex.EncodeToString(h[:]), quarantine)
			must(t, e)
			_, e = db.Exec("PRAGMA user_version=1; PRAGMA application_id=1347572803")
			must(t, e)
			must(t, db.Close())
			s, e := Open(ctx, dir)
			if quarantine {
				if e != ErrQuarantine {
					t.Fatalf("restore gate %v", e)
				}
				return
			}
			must(t, e)
			defer func() { _ = s.Close() }()
			var version int
			must(t, s.db.QueryRow("PRAGMA user_version").Scan(&version))
			if version != schemaVersion {
				t.Fatal("migration missing")
			}
			events, e := s.AuditBatch(ctx, Checkpoint{}, 10)
			must(t, e)
			if len(events) != 1 || events[0].Action != "schema.security" {
				t.Fatal("migration not audited")
			}
		})
	}
}

// The subprocess exits immediately after the durable pre-sign transition. Its
// parent checks SQLite after process death; this is not a mocked rollback.
func TestEnrollmentProcessCrash(t *testing.T) {
	if os.Getenv("PORTICO_ENROLL_CRASH") == "1" {
		s, e := Open(ctx, os.Getenv("PORTICO_ENROLL_DIR"))
		if e != nil {
			os.Exit(2)
		}
		data, e := os.ReadFile(filepath.Join(os.Getenv("PORTICO_ENROLL_DIR"), "public-trust.json"))
		if e != nil {
			os.Exit(4)
		}
		var config pki.Config
		if json.Unmarshal(data, &config) != nil {
			os.Exit(5)
		}
		trust, e := pki.NewTrust(config)
		if e != nil {
			os.Exit(6)
		}
		e = s.IssueEnrollment(ctx, os.Getenv("PORTICO_ENROLL_ACTOR"), os.Getenv("PORTICO_ENROLL_ID"), trust, issueFunc(func(context.Context, IssuanceRequest) ([]byte, error) { os.Exit(73); return nil, nil }))
		if e != nil {
			os.Exit(3)
		}
		os.Exit(7)
	}
	f := enrollmentSeed(t)
	v := f.invite(t)
	must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
	must(t, f.f.s.Close())
	data, e := json.Marshal(f.config)
	must(t, e)
	must(t, os.WriteFile(filepath.Join(f.f.dir, "public-trust.json"), data, 0600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollmentProcessCrash$")
	cmd.Env = append(os.Environ(), "PORTICO_ENROLL_CRASH=1", "PORTICO_ENROLL_DIR="+f.f.dir, "PORTICO_ENROLL_ACTOR="+f.f.actor, "PORTICO_ENROLL_ID="+v.id)
	e = cmd.Run()
	var ee *exec.ExitError
	if !errors.As(e, &ee) || ee.ExitCode() != 73 {
		t.Fatalf("crash helper %v", e)
	}
	s, e := Open(ctx, f.f.dir)
	must(t, e)
	defer func() { _ = s.Close() }()
	if e = s.IssueEnrollment(ctx, f.f.actor, v.id, f.trust, f.provider(t)); e == nil || f.calls.Load() != 0 {
		t.Fatal("crash allowed duplicate signing")
	}
	if e = s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, NewID(), csrFor(t, newKey(t))); e == nil {
		t.Fatal("crash released key binding")
	}
}

func TestEnrollmentSnapshotRevokesInvitations(t *testing.T) {
	f := enrollmentSeed(t)
	v := f.invite(t)
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	must(t, f.f.s.Snapshot(ctx, snapshot))
	db, e := sql.Open("sqlite", databaseURI(snapshot))
	must(t, e)
	defer func() { _ = db.Close() }()
	var state string
	must(t, db.QueryRow("SELECT state FROM enrollments WHERE id=?", v.id).Scan(&state))
	if state != "revoked" {
		t.Fatal("snapshot retained invitation authority")
	}
	var quarantine int
	must(t, db.QueryRow("SELECT quarantined FROM meta WHERE singleton=1").Scan(&quarantine))
	if quarantine != 1 {
		t.Fatal("snapshot not quarantined")
	}
	// The source remains usable; the backup cannot consume its tokens.
	must(t, f.f.s.ReserveEnrollment(ctx, f.f.actor, v.id, v.secret, v.attempt, v.csr))
}
