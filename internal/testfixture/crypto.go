// Package testfixture creates ephemeral cryptographic fixtures for tests only.
// Virtual authenticators exercise signed WebAuthn messages, not hardware claims.
package testfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
)

func Must(t testing.TB, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Must(t, e)
	return k
}
func Certificate(t testing.TB, template, parent *x509.Certificate, pub any, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, e := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	Must(t, e)
	c, e := x509.ParseCertificate(der)
	Must(t, e)
	return c
}
func Root(t testing.TB) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := Key(t)
	now := time.Now()
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	return Certificate(t, c, c, &k.PublicKey, k), k
}
func TLSIdentity(t testing.TB, root *x509.Certificate, key *ecdsa.PrivateKey, server bool) tls.Certificate {
	t.Helper()
	k := Key(t)
	eku := x509.ExtKeyUsageClientAuth
	if server {
		eku = x509.ExtKeyUsageServerAuth
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	Must(t, e)
	serial.Add(serial, big.NewInt(1))
	c := Certificate(t, &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "isolated TLS fixture"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}, root, &k.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}
}

type VirtualKey struct {
	ID                      []byte
	AAGUID                  uuid.UUID
	Root, Attestation       *x509.Certificate
	AttestationKey, Private *ecdsa.PrivateKey
	Counter                 uint32
}

func Virtual(t testing.TB) *VirtualKey {
	t.Helper()
	root, rk := Root(t)
	ak := Key(t)
	aaguid := uuid.New()
	att := Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Country: []string{"GB"}, Organization: []string{"Portico isolated test fixture"}, OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Virtual key, not hardware qualification"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}, root, &ak.PublicKey, rk)
	id := make([]byte, 32)
	_, e := rand.Read(id)
	Must(t, e)
	return &VirtualKey{ID: id, AAGUID: aaguid, Root: root, Attestation: att, AttestationKey: ak, Private: Key(t)}
}
func b64(b []byte) string                { return base64.RawURLEncoding.EncodeToString(b) }
func marshal(t testing.TB, v any) []byte { b, e := json.Marshal(v); Must(t, e); return b }
func signature(t testing.TB, key *ecdsa.PrivateKey, auth, client []byte) []byte {
	h := sha256.Sum256(client)
	signed := append(append([]byte{}, auth...), h[:]...)
	hash := sha256.Sum256(signed)
	sig, e := ecdsa.SignASN1(rand.Reader, key, hash[:])
	Must(t, e)
	return sig
}
func (k *VirtualKey) auth(rp string, flags byte) []byte {
	h := sha256.Sum256([]byte(rp))
	b := append([]byte{}, h[:]...)
	b = append(b, flags)
	return binary.BigEndian.AppendUint32(b, k.Counter)
}
func (k *VirtualKey) Register(t testing.TB, challenge, origin, rp string, flags byte) []byte {
	t.Helper()
	auth := k.auth(rp, flags|0x40)
	auth = append(auth, k.AAGUID[:]...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(k.ID)))
	auth = append(auth, k.ID...)
	pub, e := k.Private.PublicKey.Bytes()
	Must(t, e)
	cose, e := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pub[1:33], -3: pub[33:]})
	Must(t, e)
	auth = append(auth, cose...)
	client := marshal(t, map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	att, e := webauthncbor.Marshal(map[string]any{"fmt": "packed", "authData": auth, "attStmt": map[string]any{"alg": -7, "sig": signature(t, k.AttestationKey, auth, client), "x5c": []any{k.Attestation.Raw}}})
	Must(t, e)
	return marshal(t, map[string]any{"id": b64(k.ID), "rawId": b64(k.ID), "type": "public-key", "authenticatorAttachment": "cross-platform", "response": map[string]any{"attestationObject": b64(att), "clientDataJSON": b64(client), "transports": []string{"usb"}}})
}
func (k *VirtualKey) Assert(t testing.TB, challenge, origin, rp string, flags byte) []byte {
	t.Helper()
	k.Counter++
	auth := k.auth(rp, flags)
	client := marshal(t, map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	return marshal(t, map[string]any{"id": b64(k.ID), "rawId": b64(k.ID), "type": "public-key", "authenticatorAttachment": "cross-platform", "response": map[string]any{"authenticatorData": b64(auth), "clientDataJSON": b64(client), "signature": b64(signature(t, k.Private, auth, client))}})
}
