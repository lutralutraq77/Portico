package adminauth

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestPackedAttestationAndBoundApproval(t *testing.T) {
	k := testfixture.Virtual(t)
	v, e := New(Config{Origin: "https://admin.portico.test", ValidUntil: time.Now().Add(time.Hour), Models: []Model{{AAGUID: k.AAGUID.String(), RootsDER: [][]byte{k.Root.Raw}}}})
	testfixture.Must(t, e)
	u := User{ID: uuid.NewString()}
	binding := Binding{u.ID, pki.Hash([]byte("device")), pki.Hash([]byte("exact operation")), 1}
	_, session, e := v.BeginRegistration(u, binding)
	testfixture.Must(t, e)
	response := k.Register(t, session.Data.Challenge, v.origin, v.wa.Config.RPID, 5)
	c, e := v.VerifyRegistration(u, session, binding, response)
	testfixture.Must(t, e)
	u.Credentials = []webauthn.Credential{*c}
	_, approval, e := v.BeginApproval(u, binding)
	testfixture.Must(t, e)
	assertion := k.Assert(t, approval.Data.Challenge, v.origin, v.wa.Config.RPID, 5)
	updated, e := v.VerifyApproval(u, approval, binding, assertion)
	testfixture.Must(t, e)
	if updated.Authenticator.SignCount != 1 {
		t.Fatal("counter not updated")
	}
	for _, name := range []string{"operation", "device", "administrator", "revision", "expiry", "wrong_origin", "wrong_rp", "touch_only", "no_presence", "backup", "signature", "counter", "attestation_signature", "configuration"} {
		t.Run(name, func(t *testing.T) {
			b, s, r, user := binding, approval, assertion, u
			verifier := v
			switch name {
			case "operation":
				b.OperationHash = pki.Hash([]byte("different"))
			case "device":
				b.DeviceCertificateHash = pki.Hash([]byte("different"))
			case "administrator":
				b.AdministratorID = uuid.NewString()
			case "revision":
				b.Revision++
			case "expiry":
				s.ExpiresAt = time.Now().Add(-time.Minute)
			case "wrong_origin":
				r = k.Assert(t, s.Data.Challenge, "https://evil.portico.test", v.wa.Config.RPID, 5)
			case "wrong_rp":
				r = k.Assert(t, s.Data.Challenge, v.origin, "evil.portico.test", 5)
			case "touch_only":
				r = k.Assert(t, s.Data.Challenge, v.origin, v.wa.Config.RPID, 1)
			case "no_presence":
				r = k.Assert(t, s.Data.Challenge, v.origin, v.wa.Config.RPID, 4)
			case "backup":
				r = k.Assert(t, s.Data.Challenge, v.origin, v.wa.Config.RPID, 29)
			case "signature":
				old := k.Private
				k.Private = testfixture.Key(t)
				r = k.Assert(t, s.Data.Challenge, v.origin, v.wa.Config.RPID, 5)
				k.Private = old
			case "counter":
				user.Credentials = []webauthn.Credential{*updated}
			case "attestation_signature":
				corrupted := *c
				var att protocol.AttestationObject
				testfixture.Must(t, decodeAttestation(c.Attestation.Object, &att))
				sig := att.AttStatement["sig"].([]byte)
				sig[len(sig)-1] ^= 1
				corrupted.Attestation.Object, e = webauthncbor.Marshal(map[string]any{"fmt": att.Format, "authData": att.RawAuthData, "attStmt": att.AttStatement})
				testfixture.Must(t, e)
				user.Credentials = []webauthn.Credential{corrupted}
			case "configuration":
				verifier, e = New(Config{Origin: "https://admin.portico.test:8443", ValidUntil: v.validUntil, Models: []Model{{AAGUID: k.AAGUID.String(), RootsDER: [][]byte{k.Root.Raw}}}})
				testfixture.Must(t, e)
				r = k.Assert(t, s.Data.Challenge, verifier.origin, verifier.wa.Config.RPID, 5)
			}
			if _, e := verifier.VerifyApproval(user, s, b, r); e == nil {
				t.Fatal("accepted changed or invalid assertion")
			}
		})
	}
	for _, name := range []string{"unknown_model", "zero_model", "wrong_root", "synced", "touch_only", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			key := *k
			flags := byte(5)
			user := User{ID: u.ID}
			switch name {
			case "unknown_model":
				key.AAGUID = uuid.New()
			case "zero_model":
				key.AAGUID = uuid.Nil
			case "wrong_root":
				other := testfixture.Virtual(t)
				key.Attestation = other.Attestation
				key.AttestationKey = other.AttestationKey
			case "synced":
				flags = 29
			case "touch_only":
				flags = 1
			case "duplicate":
				user = u
			}
			r := key.Register(t, session.Data.Challenge, v.origin, v.wa.Config.RPID, flags)
			if _, e := v.VerifyRegistration(user, session, binding, r); e == nil {
				t.Fatal("unqualified factor accepted")
			}
		})
	}
}

func FuzzWebAuthnResponses(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte{0xff, 0x00})
	k := testfixture.Virtual(f)
	v, e := New(Config{Origin: "https://admin.portico.test", ValidUntil: time.Now().Add(time.Hour), Models: []Model{{AAGUID: k.AAGUID.String(), RootsDER: [][]byte{k.Root.Raw}}}})
	testfixture.Must(f, e)
	u := User{ID: uuid.NewString()}
	b := Binding{u.ID, pki.Hash([]byte("d")), pki.Hash([]byte("o")), 1}
	_, s, e := v.BeginRegistration(u, b)
	testfixture.Must(f, e)
	registration := k.Register(f, s.Data.Challenge, v.origin, v.wa.Config.RPID, 5)
	f.Add(registration)
	c, e := v.VerifyRegistration(u, s, b, registration)
	testfixture.Must(f, e)
	registered := User{ID: u.ID, Credentials: []webauthn.Credential{*c}}
	_, assertionSession, e := v.BeginApproval(registered, b)
	testfixture.Must(f, e)
	f.Add(k.Assert(f, assertionSession.Data.Challenge, v.origin, v.wa.Config.RPID, 5))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = v.VerifyRegistration(u, s, b, data)
		_, _ = v.VerifyApproval(registered, assertionSession, b, data)
	})
}
