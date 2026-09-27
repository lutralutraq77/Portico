package adminapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
	"portico.local/portico/internal/wire"
)

// Portable orchestration tests use an explicit memory persistence fixture and
// virtual approval responses. Separate Linux tests exercise actual file barriers;
// controller and issuer integration tests exercise real WebAuthn verification.
type memoryCredentials struct {
	mu           sync.Mutex
	data         []byte
	commits      int
	failAt       int
	afterPublish bool
}

func (m *memoryCredentials) Read() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return bytes.Clone(m.data), nil
}
func (m *memoryCredentials) Commit(previous, next []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !bytes.Equal(previous, m.data) {
		return ErrRejected
	}
	m.commits++
	fail := m.commits == m.failAt
	if !fail || m.afterPublish {
		m.data = bytes.Clone(next)
	}
	if fail {
		return ErrRejected
	}
	return nil
}
func (m *memoryCredentials) Close() {}
func (m *memoryCredentials) record(t *testing.T) credentialRecord {
	t.Helper()
	data, err := m.Read()
	testfixture.Must(t, err)
	var r credentialRecord
	testfixture.Must(t, wire.Decode(data, &r))
	return r
}

type nativeTestKey struct {
	key       *ecdsa.PrivateKey
	trust     *pki.Trust
	principal string
	csrs      atomic.Int32
}

func (k *nativeTestKey) Identity(der []byte) (tls.Certificate, error) {
	if _, err := k.trust.Verify(der, k.principal, time.Now()); err != nil {
		return tls.Certificate{}, err
	}
	return k.trust.TLSIdentity(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k.key})
}
func (k *nativeTestKey) CSR() ([]byte, error) {
	k.csrs.Add(1)
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}, k.key)
}
func (k *nativeTestKey) Close() {}

type nativeRenewalFixture struct {
	config      *Configuration
	key         *nativeTestKey
	storage     *memoryCredentials
	disk        credentialStorage
	native      *nativeRenewal
	candidate   []byte
	active      atomic.Value
	prepares    atomic.Int32
	confirms    atomic.Int32
	retrieves   atomic.Int32
	activations atomic.Int32
	lostConfirm bool
	lostActive  atomic.Bool
	sign        func([]byte, time.Time, time.Time) []byte
}

func nativeRenewalSeed(t *testing.T) *nativeRenewalFixture {
	t.Helper()
	f := &nativeRenewalFixture{storage: &memoryCredentials{}}
	root, rootKey := testfixture.Root(t)
	issuerKey := testfixture.Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, issuerKey.Public(), rootKey)
	trust, err := pki.NewTrust(pki.Config{DeploymentID: uuid.NewString(), IssuerID: uuid.NewString(), Profile: pki.Administrator, RootDER: root.Raw, IssuerDER: issuer.Raw})
	testfixture.Must(t, err)
	f.key = &nativeTestKey{key: testfixture.Key(t), trust: trust, principal: uuid.NewString()}
	uri, err := pki.IdentityURI(trust.DeploymentID(), pki.Administrator, f.key.principal)
	testfixture.Must(t, err)
	issue := func(serial, hours int64) []byte {
		return testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Duration(hours) * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, issuer, f.key.key.Public(), issuerKey).Raw
	}
	old := issue(3, 1)
	f.candidate = issue(4, 2)
	f.sign = func(csrDER []byte, before, after time.Time) []byte {
		csr, err := pki.ParseCSR(csrDER)
		testfixture.Must(t, err)
		return testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: before, NotAfter: after, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, issuer, csr.PublicKey, issuerKey).Raw
	}
	f.active.Store(pki.Hash(old))
	serverRoot, serverKey := testfixture.Root(t)
	identity := testfixture.TLSIdentity(t, serverRoot, serverKey, true)
	serve := func(activation bool) adminbridge.Config {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			if !activation {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path != "/admin" || r.Method != http.MethodGet {
					t.Error("candidate probe escaped its read-only path")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				_, _ = io.WriteString(w, "<p>Current administrator</p>")
				return
			}
			f.activations.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			var request adminrenewal.ActivateRequest
			body, err := io.ReadAll(io.LimitReader(r.Body, adminrenewal.MaxActivationBody+1))
			retained := f.stored(t).Pending
			if err != nil || wire.Decode(body, &request) != nil || request.Version != 1 || r.URL.Path != adminrenewal.ActivatePath || r.Method != http.MethodPost || r.Header.Get("Origin") != "https://"+r.Host || retained == nil || retained.Phase != "issued" || request.RenewalID != retained.Request.RenewalID || !bytes.Equal(retained.Certificate, f.candidate) {
				t.Error("activation preceded exact candidate persistence or changed its scope")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			f.active.Store(pki.Hash(f.candidate))
			if f.lostActive.Load() {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			_ = json.NewEncoder(w).Encode(adminrenewal.Activated{Version: 1, RenewalID: request.RenewalID, CertificateSHA256: pki.Hash(f.candidate)})
		}))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAnyClientCert, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) < 1 {
				return ErrRejected
			}
			credential, err := trust.VerifyPeer(state.PeerCertificates[0].Raw, time.Now())
			want := f.active.Load().(string)
			if activation {
				want = pki.Hash(f.candidate)
			}
			if err != nil || credential.LeafSHA256 != want {
				return ErrRejected
			}
			return nil
		}}
		server.StartTLS()
		t.Cleanup(server.Close)
		_, port, err := net.SplitHostPort(server.Listener.Addr().String())
		testfixture.Must(t, err)
		// The same fixture runs under the NIC-less emulated Linux kernel. Use
		// the existing supported maximum rather than a one-second test budget.
		return adminbridge.Config{Origin: "https://localhost:" + port, ServerSPKI: pki.Hash(identity.Leaf.RawSubjectPublicKeyInfo), ServerRootDER: serverRoot.Raw, AdministratorTrust: trust, BootstrapAddress: server.Listener.Addr().String(), Timeout: 5 * time.Second, Lifetime: time.Minute, ClockHealth: func() (time.Duration, error) { return 0, nil }}
	}
	management, activation := serve(false), serve(true)
	f.config = &Configuration{bridge: management, renewal: &activation, binding: pki.Hash([]byte("isolated native renewal authority")), principal: f.key.principal, leaf: old}
	f.native, err = newNativeRenewal(f.config, f.key, f.storage)
	testfixture.Must(t, err)
	return f
}

func (f *nativeRenewalFixture) send(t *testing.T) adminbridge.RenewalExchange {
	t.Helper()
	return func(path string, body []byte) (adminbridge.Response, error) {
		p := f.stored(t).Pending
		switch path {
		case adminrenewal.PreparePath:
			f.prepares.Add(1)
			var request adminrenewal.PrepareRequest
			testfixture.Must(t, wire.Decode(body, &request))
			if p == nil || p.Phase != "preparing" || request.RenewalID != p.Request.RenewalID || !bytes.Equal(request.CSR, p.Request.CSR) {
				t.Fatal("CSR request was not retained before sending")
			}
			challenge, err := json.Marshal(renewalChallenge{ID: uuid.NewString(), Approval: &protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{Challenge: bytes.Repeat([]byte{1}, 32), RelyingPartyID: "localhost", UserVerification: protocol.VerificationRequired, AllowedCredentials: []protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("isolated virtual hardware fixture")}}}}})
			testfixture.Must(t, err)
			data, err := json.Marshal(adminrenewal.Prepared{Version: 1, RenewalID: request.RenewalID, CSRHash: pki.Hash(request.CSR), CurrentCertificateHash: pki.Hash(f.native.journal.record.Certificate), NotAfter: request.NotAfter, ExpiresAt: time.Now().Add(2 * time.Minute), PolicyRevision: request.PolicyRevision, Challenge: challenge})
			testfixture.Must(t, err)
			return adminbridge.Response{Status: 200, Body: data}, nil
		case adminrenewal.ConfirmPath:
			f.confirms.Add(1)
			if p == nil || p.Phase != "confirming" {
				t.Fatal("confirmation intent was not retained before sending")
			}
			if f.lostConfirm {
				return adminbridge.Response{}, ErrRejected
			}
		case adminrenewal.CertificatePath:
			f.retrieves.Add(1)
			if p == nil || p.Phase != "confirming" || f.confirms.Load() != 1 {
				t.Fatal("result retrieval changed an unapproved attempt")
			}
		default:
			t.Fatal("native sender selected another endpoint")
		}
		data, err := json.Marshal(adminrenewal.Certificate{Version: 1, RenewalID: p.Request.RenewalID, CertificateDER: f.candidate})
		testfixture.Must(t, err)
		return adminbridge.Response{Status: 200, Body: data}, nil
	}
}

func (f *nativeRenewalFixture) request(t *testing.T, path string, value any) (adminrenewal.Status, error) {
	t.Helper()
	body, err := json.Marshal(value)
	testfixture.Must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := f.native.Handle(ctx, adminbridge.Request{Method: http.MethodPost, Path: path, Origin: f.config.bridge.Origin, Body: body}, f.send(t))
	var status adminrenewal.Status
	if err == nil {
		testfixture.Must(t, wire.Decode(response.Body, &status))
	}
	return status, err
}

func (f *nativeRenewalFixture) start(t *testing.T) adminrenewal.Status {
	t.Helper()
	candidate, err := x509.ParseCertificate(f.candidate)
	testfixture.Must(t, err)
	status, err := f.request(t, adminrenewal.StartPath, adminrenewal.StartRequest{Version: 1, NotAfter: candidate.NotAfter, PolicyRevision: 2})
	testfixture.Must(t, err)
	if status.State != "prepared" || status.Prepared == nil || status.CurrentCertificateHash != pki.Hash(f.config.leaf) {
		t.Fatal("native review did not retain the exact current identity")
	}
	return status
}

func (f *nativeRenewalFixture) confirmation(t *testing.T) adminrenewal.ConfirmRequest {
	t.Helper()
	_, challenge, err := f.native.journal.prepared(f.native.journal.record.Certificate, f.native.journal.record.Pending)
	testfixture.Must(t, err)
	return adminrenewal.ConfirmRequest{Version: 1, ChallengeID: challenge.ID, Response: json.RawMessage(`{"isolated_fixture":true}`)}
}

func (f *nativeRenewalFixture) reopen(t *testing.T) {
	t.Helper()
	var err error
	f.native, err = newNativeRenewal(f.config, f.key, f.storage)
	testfixture.Must(t, err)
}

func (f *nativeRenewalFixture) stored(t *testing.T) credentialRecord {
	t.Helper()
	if f.disk == nil {
		return f.storage.record(t)
	}
	data, err := f.disk.Read()
	testfixture.Must(t, err)
	var record credentialRecord
	testfixture.Must(t, wire.Decode(data, &record))
	return record
}

func TestNativeRenewalRetainsCandidateBeforeTLSActivationAndReopensCurrentIdentity(t *testing.T) {
	f := nativeRenewalSeed(t)
	f.start(t)
	status, err := f.request(t, adminrenewal.ApprovePath, f.confirmation(t))
	testfixture.Must(t, err)
	if status.State != "complete" || status.CurrentCertificateHash != pki.Hash(f.candidate) || f.confirms.Load() != 1 || f.activations.Load() != 1 || f.key.csrs.Load() != 1 || f.storage.record(t).Pending != nil {
		t.Fatal("renewal did not complete one retained identity transition")
	}
	f.reopen(t)
	identity, err := f.key.Identity(f.native.journal.record.Certificate)
	testfixture.Must(t, err)
	config := f.config.bridge
	config.Identity = identity
	client, err := adminbridge.New(context.Background(), config)
	testfixture.Must(t, err)
	t.Cleanup(client.Close)
	response, err := client.Exchange(context.Background(), adminbridge.Request{Method: http.MethodGet, Path: "/admin"})
	testfixture.Must(t, err)
	if response.Status != http.StatusOK {
		t.Fatal("reopened application did not use the activated certificate")
	}
	config.Identity, err = f.key.Identity(f.config.leaf)
	testfixture.Must(t, err)
	old, err := adminbridge.New(context.Background(), config)
	testfixture.Must(t, err)
	t.Cleanup(old.Close)
	if _, err := old.Exchange(context.Background(), adminbridge.Request{Method: http.MethodGet, Path: "/admin"}); err == nil {
		t.Fatal("old application certificate retained authority")
	}
}

func TestNativeRenewalReconcilesLostConfirmationWithoutResubmission(t *testing.T) {
	f := nativeRenewalSeed(t)
	f.lostConfirm = true
	f.start(t)
	proof := f.confirmation(t)
	if _, err := f.request(t, adminrenewal.ApprovePath, proof); err == nil {
		t.Fatal("lost confirmation was reported successful")
	}
	f.reopen(t)
	if _, err := f.request(t, adminrenewal.ApprovePath, proof); err == nil {
		t.Fatal("uncertain approval was submitted again")
	}
	if _, err := f.request(t, adminrenewal.CancelPath, adminrenewal.NativeRequest{Version: 1}); err == nil {
		t.Fatal("uncertain signing intent was forgotten")
	}
	status, err := f.request(t, adminrenewal.ResumePath, adminrenewal.NativeRequest{Version: 1})
	testfixture.Must(t, err)
	if status.State != "complete" || f.confirms.Load() != 1 || f.retrieves.Load() != 1 || f.activations.Load() != 1 || f.key.csrs.Load() != 1 {
		t.Fatal("resumption repeated signing or lost the original identity")
	}
}

func TestNativeRenewalReconcilesLostActivationWithReadOnlyCurrentTLS(t *testing.T) {
	f := nativeRenewalSeed(t)
	f.lostActive.Store(true)
	f.start(t)
	if _, err := f.request(t, adminrenewal.ApprovePath, f.confirmation(t)); err == nil {
		t.Fatal("lost activation response was reported successful")
	}
	if f.storage.record(t).Pending.Phase != "issued" {
		t.Fatal("lost activation response discarded the candidate")
	}
	f.reopen(t)
	status, err := f.request(t, adminrenewal.ResumePath, adminrenewal.NativeRequest{Version: 1})
	testfixture.Must(t, err)
	if status.State != "complete" || f.activations.Load() != 1 || f.confirms.Load() != 1 || f.retrieves.Load() != 0 {
		t.Fatal("current TLS reconciliation repeated activation or signing")
	}
}

func TestNativeRenewalDurabilityFailuresStopDependentNetworkActions(t *testing.T) {
	for _, after := range []bool{false, true} {
		for _, stage := range []int{2, 3, 4, 5, 6} {
			t.Run(strings.Join([]string{map[bool]string{false: "before", true: "after"}[after], []string{"", "", "request", "review", "confirmation", "candidate", "current"}[stage]}, "-"), func(t *testing.T) {
				f := nativeRenewalSeed(t)
				f.storage.failAt, f.storage.afterPublish = stage, after
				if stage > 3 {
					f.start(t)
					if _, err := f.request(t, adminrenewal.ApprovePath, f.confirmation(t)); err == nil {
						t.Fatal("failed commit was reported successful")
					}
				} else {
					candidate, err := x509.ParseCertificate(f.candidate)
					testfixture.Must(t, err)
					if _, err := f.request(t, adminrenewal.StartPath, adminrenewal.StartRequest{Version: 1, NotAfter: candidate.NotAfter, PolicyRevision: 2}); err == nil {
						t.Fatal("failed preparation commit was reported successful")
					}
				}
				if !f.native.journal.failed || (stage == 2 && f.prepares.Load() != 0) || (stage <= 4 && f.confirms.Load() != 0) || (stage <= 5 && f.activations.Load() != 0) {
					t.Fatal("network action ran before its durability prerequisite")
				}
				if _, err := f.request(t, adminrenewal.ResumePath, adminrenewal.NativeRequest{Version: 1}); err == nil {
					t.Fatal("uncertain journal was reused without reopening")
				}
				f.storage.failAt = 0
				f.reopen(t)
				if stage == 6 {
					status, err := f.request(t, adminrenewal.ResumePath, adminrenewal.NativeRequest{Version: 1})
					testfixture.Must(t, err)
					if status.CurrentCertificateHash != pki.Hash(f.candidate) || f.activations.Load() != 1 || f.confirms.Load() != 1 {
						t.Fatal("final commit reconciliation lost the active identity")
					}
				}
			})
		}
	}
}

func TestNativeRenewalRejectsUnboundReviewStateAndRendererAuthority(t *testing.T) {
	f := nativeRenewalSeed(t)
	candidate, err := x509.ParseCertificate(f.candidate)
	testfixture.Must(t, err)
	for _, extra := range []string{`"CSR":"AA=="`, `"key":"private"`, `"Origin":"https://other.test"`, `"RenewalID":"` + uuid.NewString() + `"`, `"Path":"/elsewhere"`, `"Version":1`} {
		body, err := json.Marshal(adminrenewal.StartRequest{Version: 1, NotAfter: candidate.NotAfter, PolicyRevision: 2})
		testfixture.Must(t, err)
		body = append(bytes.TrimSuffix(body, []byte("}")), []byte(","+extra+"}")...)
		if _, err := f.native.Handle(context.Background(), adminbridge.Request{Method: http.MethodPost, Origin: f.config.bridge.Origin, Path: adminrenewal.StartPath, Body: body}, f.send(t)); err == nil {
			t.Fatal("renderer supplied additional authority")
		}
	}
	if f.key.csrs.Load() != 0 || f.prepares.Load() != 0 {
		t.Fatal("invalid renderer request caused signing or network I/O")
	}
	f.start(t)
	original, err := f.storage.Read()
	testfixture.Must(t, err)
	for _, scenario := range []string{"binding", "certificate", "phase", "csr", "revision", "review-hash", "issued-without-certificate", "candidate-before-issuance"} {
		t.Run(scenario, func(t *testing.T) {
			var record credentialRecord
			testfixture.Must(t, wire.Decode(original, &record))
			switch scenario {
			case "binding":
				record.Binding = strings.Repeat("0", 64)
			case "certificate":
				record.Certificate = []byte("untrusted identity")
			case "phase":
				record.Pending.Phase = "active"
			case "csr":
				record.Pending.Request.CSR = []byte("unsigned CSR")
			case "revision":
				record.Pending.Request.PolicyRevision++
			case "review-hash":
				var review adminrenewal.Prepared
				testfixture.Must(t, wire.Decode(record.Pending.Prepared, &review))
				review.CurrentCertificateHash = pki.Hash(f.candidate)
				record.Pending.Prepared, err = json.Marshal(review)
				testfixture.Must(t, err)
			case "issued-without-certificate":
				record.Pending.Phase = "issued"
			case "candidate-before-issuance":
				record.Pending.Certificate = f.candidate
			}
			data, err := json.Marshal(record)
			testfixture.Must(t, err)
			if _, err := newNativeRenewal(f.config, f.key, &memoryCredentials{data: data}); err == nil {
				t.Fatal("unbound or inconsistent public state was promoted into authority")
			}
		})
	}
}

func TestNativeRenewalClockFaultStopsActivationAndRetainsCandidate(t *testing.T) {
	f := nativeRenewalSeed(t)
	f.start(t)
	f.config.bridge.ClockHealth = func() (time.Duration, error) { return 0, ErrRejected }
	if _, err := f.request(t, adminrenewal.ApprovePath, f.confirmation(t)); err == nil {
		t.Fatal("clock failure admitted candidate activation")
	}
	if f.activations.Load() != 0 || f.storage.record(t).Pending.Phase != "issued" {
		t.Fatal("clock fault made a network transition or discarded durable state")
	}
}

func TestNativeRenewalExpiredReviewStaysCancellableWithoutSubmittingProof(t *testing.T) {
	f := nativeRenewalSeed(t)
	f.start(t)
	proof := f.confirmation(t)
	next := f.native.journal.next()
	var prepared adminrenewal.Prepared
	testfixture.Must(t, wire.Decode(next.Pending.Prepared, &prepared))
	prepared.ExpiresAt = next.Pending.CreatedAt.Add(time.Nanosecond)
	var err error
	next.Pending.Prepared, err = json.Marshal(prepared)
	testfixture.Must(t, err)
	testfixture.Must(t, f.native.journal.commit(next))
	f.reopen(t)
	if _, err := f.request(t, adminrenewal.ApprovePath, proof); err == nil || f.confirms.Load() != 0 || f.storage.record(t).Pending.Phase != "prepared" {
		t.Fatal("expired review entered uncertain confirmation instead of remaining cancellable")
	}
	status, err := f.request(t, adminrenewal.CancelPath, adminrenewal.NativeRequest{Version: 1})
	testfixture.Must(t, err)
	if status.State != "ready" || f.confirms.Load() != 0 || f.activations.Load() != 0 {
		t.Fatal("expired review could not be cancelled without signing")
	}
}
