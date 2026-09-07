package pki

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

// VerifyPeer extracts a candidate immutable principal and then verifies its
// complete pinned profile. Public certificate bytes do not prove key possession
// or current registry status; callers must check both at their own boundary.
func (t *Trust) VerifyPeer(der []byte, now time.Time) (Credential, error) {
	if t == nil || len(der) == 0 || len(der) > MaxDER {
		return Credential{}, ErrDenied
	}
	c, e := x509.ParseCertificate(der)
	if e != nil || len(c.URIs) != 1 {
		return Credential{}, ErrDenied
	}
	principal := strings.TrimPrefix(c.URIs[0].Path, "/"+string(t.profile)+"/")
	return t.Verify(der, principal, now)
}

// TLSIdentity constructs the exact leaf/intermediate chain from pinned trust.
// The private key may be an OS-backed crypto.Signer and is never exported.
func (t *Trust) TLSIdentity(c tls.Certificate) (tls.Certificate, error) {
	if t == nil || len(c.Certificate) == 0 || len(c.Certificate) > 3 {
		return tls.Certificate{}, ErrDenied
	}
	if _, e := t.VerifyPeer(c.Certificate[0], time.Now()); e != nil {
		return tls.Certificate{}, ErrDenied
	}
	key, ok := c.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, ErrDenied
	}
	public, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		return tls.Certificate{}, ErrDenied
	}
	leaf, e := x509.ParseCertificate(c.Certificate[0])
	if e != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, public) {
		return tls.Certificate{}, ErrDenied
	}
	return tls.Certificate{Certificate: [][]byte{bytes.Clone(leaf.Raw), bytes.Clone(t.issuer.Raw)}, PrivateKey: key}, nil
}

// ConnectorClientTLS preserves the standard chain, serverAuth and DNS name
// checks, then verifies the exact typed identity and issuing-certificate pin.
// The client must check this actual peer leaf against the online controller
// before requesting a resource or sending any application bytes.
func (t *Trust) ConnectorClientTLS(identity tls.Certificate, connector string) (*tls.Config, error) {
	if t == nil || t.profile != Connector || len(identity.Certificate) == 0 || len(identity.Certificate) > 3 || identity.PrivateKey == nil {
		return nil, ErrDenied
	}
	name, e := ConnectorName(t.deployment, connector)
	if e != nil {
		return nil, ErrDenied
	}
	// Copy public buffers so a caller cannot mutate the configured identity.
	local := tls.Certificate{PrivateKey: identity.PrivateKey}
	for _, der := range identity.Certificate {
		local.Certificate = append(local.Certificate, bytes.Clone(der))
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: t.roots.Clone(), ServerName: name, Certificates: []tls.Certificate{local}, SessionTicketsDisabled: true}
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 {
			return ErrDenied
		}
		_, e := t.Verify(state.PeerCertificates[0].Raw, connector, time.Now())
		return e
	}
	return c, nil
}

// ConnectorServerTLS accepts only the pinned ordinary-device profile. Live
// registry, grant and hosting checks still occur online for every resource open.
func (t *Trust) ConnectorServerTLS(identity tls.Certificate, devices *Trust) (*tls.Config, error) {
	if t == nil || t.profile != Connector || devices == nil || devices.profile != Device || devices.deployment != t.deployment || devices.issuerID == t.issuerID || devices.IssuerFingerprint() == t.IssuerFingerprint() {
		return nil, ErrDenied
	}
	local, e := t.TLSIdentity(identity)
	if e != nil {
		return nil, e
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{local}, ClientCAs: devices.roots.Clone(), ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 {
			return ErrDenied
		}
		_, e := devices.VerifyPeer(state.PeerCertificates[0].Raw, time.Now())
		return e
	}
	return c, nil
}
