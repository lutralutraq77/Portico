// Package pki validates Portico's narrow certificate profiles with Go's X.509
// implementation. It holds public trust only and provides no signing endpoint.
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid PKI input")
var ErrDenied = errors.New("certificate rejected")

const MaxDER = 16 * 1024
const MaxCSR = 4 * 1024

type Profile string

// IssuanceRequest contains only approved public inputs for an isolated issuer.
type IssuanceRequest struct {
	AttemptID, DeploymentID, IssuerID, PrincipalID string
	Profile                                        Profile
	CSR                                            []byte
	NotBefore, NotAfter                            time.Time
}

const (
	Device        Profile = "device"
	Connector     Profile = "connector"
	Administrator Profile = "administrator"
)

// Administrator credentials use a separate pinned issuer and registry. They
// cannot enter the ordinary enrollment or resource-authentication registry.
func ValidProfile(p Profile) bool { return p == Device || p == Connector || p == Administrator }
func ValidID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func IdentityURI(deployment string, profile Profile, principal string) (*url.URL, error) {
	if !ValidID(deployment) || !ValidID(principal) || !ValidProfile(profile) {
		return nil, ErrInvalid
	}
	return &url.URL{Scheme: "portico", Host: deployment, Path: "/" + string(profile) + "/" + principal}, nil
}

// ConnectorName is a certificate name, never a DNS lookup or public endpoint.
// It enables ordinary TLS hostname verification on an already paired stream.
const ConnectorProfileVersion = "connector-dns-v1"

func ConnectorName(deployment, principal string) (string, error) {
	if !ValidID(deployment) || !ValidID(principal) {
		return "", ErrInvalid
	}
	return principal + "." + deployment + ".connector.portico.invalid", nil
}

// IdentitySANs derives every signed name from server-approved immutable IDs.
// Enrolling clients still submit an empty, proof-only CSR.
func IdentitySANs(deployment string, profile Profile, principal string) ([]string, error) {
	u, e := IdentityURI(deployment, profile, principal)
	if e != nil {
		return nil, e
	}
	names := []string{u.String()}
	if profile == Connector {
		name, e := ConnectorName(deployment, principal)
		if e != nil {
			return nil, e
		}
		names = append(names, name)
	}
	return names, nil
}

func p256(key any) bool {
	k, ok := key.(*ecdsa.PublicKey)
	if !ok || k == nil || k.Curve != elliptic.P256() {
		return false
	}
	_, e := k.Bytes()
	return e == nil
}

// ParseCSR accepts DER proof of possession only. All identity, extension and
// lifetime claims must be absent; the approved server-side record supplies them.
func ParseCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > MaxCSR {
		return nil, ErrInvalid
	}
	r, e := x509.ParseCertificateRequest(bytes.Clone(der))
	if e != nil || !bytes.Equal(r.RawSubject, []byte{0x30, 0}) || len(r.Extensions) != 0 || !p256(r.PublicKey) || r.SignatureAlgorithm != x509.ECDSAWithSHA256 || r.CheckSignature() != nil {
		return nil, ErrInvalid
	}
	// x509 intentionally drops attributes such as challengePassword from its
	// parsed Attributes field. Reject raw attributes too, rather than silently
	// ignoring a signed caller claim. This is PKCS#10 structure checking only.
	var info struct {
		Version            int
		Subject, PublicKey asn1.RawValue
		Attributes         []asn1.RawValue `asn1:"tag:0"`
	}
	rest, e := asn1.Unmarshal(r.RawTBSCertificateRequest, &info)
	if e != nil || len(rest) != 0 || info.Version != 0 || len(info.Attributes) != 0 {
		return nil, ErrInvalid
	}
	canonical, e := asn1.Marshal(info)
	if e != nil || !bytes.Equal(canonical, r.RawTBSCertificateRequest) {
		return nil, ErrInvalid
	}
	return r, nil
}

type Config struct {
	DeploymentID, IssuerID string
	Profile                Profile
	RootDER, IssuerDER     []byte
}

// Trust is immutable, pinned to one issuing certificate and one profile. Caller
// buffers are copied; OS roots, AIA downloads and caller-supplied chains are unused.
type Trust struct {
	deployment, issuerID string
	profile              Profile
	root, issuer         *x509.Certificate
	roots                *x509.CertPool
}

func NewTrust(c Config) (*Trust, error) {
	if !ValidID(c.DeploymentID) || !ValidID(c.IssuerID) || !ValidProfile(c.Profile) || len(c.RootDER) == 0 || len(c.RootDER) > MaxDER || len(c.IssuerDER) == 0 || len(c.IssuerDER) > MaxDER {
		return nil, ErrInvalid
	}
	r, e := x509.ParseCertificate(bytes.Clone(c.RootDER))
	if e != nil {
		return nil, ErrInvalid
	}
	i, e := x509.ParseCertificate(bytes.Clone(c.IssuerDER))
	if e != nil {
		return nil, ErrInvalid
	}
	if !r.IsCA || !r.BasicConstraintsValid || !i.IsCA || !i.BasicConstraintsValid || !i.MaxPathLenZero || i.MaxPathLen != 0 || bytes.Equal(r.Raw, i.Raw) || r.CheckSignatureFrom(r) != nil || i.CheckSignatureFrom(r) != nil || r.KeyUsage&x509.KeyUsageCertSign == 0 || i.KeyUsage&x509.KeyUsageCertSign == 0 || len(r.UnhandledCriticalExtensions) != 0 || len(i.UnhandledCriticalExtensions) != 0 {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(r)
	return &Trust{c.DeploymentID, c.IssuerID, c.Profile, r, i, roots}, nil
}

func (t *Trust) DeploymentID() string      { return t.deployment }
func (t *Trust) IssuerID() string          { return t.issuerID }
func (t *Trust) Profile() Profile          { return t.profile }
func (t *Trust) RootFingerprint() string   { return Hash(t.root.Raw) }
func (t *Trust) IssuerFingerprint() string { return Hash(t.issuer.Raw) }
func (t *Trust) NotAfter() time.Time {
	if t.root.NotAfter.Before(t.issuer.NotAfter) {
		return t.root.NotAfter
	}
	return t.issuer.NotAfter
}

type Credential struct {
	DeploymentID, IssuerID, PrincipalID string
	Profile                             Profile
	Serial, LeafSHA256, SPKISHA256      string
	NotBefore, NotAfter                 time.Time
}

// Verify checks public certificate validity, not possession of its private key.
// Authentication additionally requires a real TLS handshake and live registry.
func (t *Trust) Verify(der []byte, principal string, now time.Time) (Credential, error) {
	var zero Credential
	if t == nil || !ValidID(principal) || now.IsZero() || len(der) == 0 || len(der) > MaxDER {
		return zero, ErrDenied
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		return zero, ErrDenied
	}
	u, _ := IdentityURI(t.deployment, t.profile, principal)
	dns := ""
	if t.profile == Connector {
		dns, _ = ConnectorName(t.deployment, principal)
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || !p256(c.PublicKey) || c.SignatureAlgorithm != x509.ECDSAWithSHA256 || c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 159 || !bytes.Equal(c.RawSubject, []byte{0x30, 0}) || len(c.UnhandledCriticalExtensions) != 0 || len(c.UnknownExtKeyUsage) != 0 || !c.NotAfter.After(now) || now.Before(c.NotBefore) || c.NotBefore.Before(t.issuer.NotBefore) || c.NotAfter.After(t.NotAfter()) || !exactSAN(c, u.String(), dns) {
		return zero, ErrDenied
	}
	want := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if t.profile == Connector {
		want = append(want, x509.ExtKeyUsageServerAuth)
	}
	if len(c.ExtKeyUsage) != len(want) {
		return zero, ErrDenied
	}
	for _, usage := range want {
		count := 0
		for _, got := range c.ExtKeyUsage {
			if got == usage {
				count++
			}
		}
		if count != 1 {
			return zero, ErrDenied
		}
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(t.issuer)
	// Verify treats KeyUsages as alternatives. Check each required usage separately.
	for _, usage := range want {
		options := x509.VerifyOptions{Roots: t.roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			options.DNSName = dns
		}
		chains, err := c.Verify(options)
		if err != nil {
			return zero, ErrDenied
		}
		pinned := false
		for _, chain := range chains {
			if len(chain) == 3 && bytes.Equal(chain[1].Raw, t.issuer.Raw) && bytes.Equal(chain[2].Raw, t.root.Raw) {
				pinned = true
			}
		}
		if !pinned {
			return zero, ErrDenied
		}
	}
	return Credential{t.deployment, t.issuerID, principal, t.profile, c.SerialNumber.Text(16), Hash(c.Raw), Hash(c.RawSubjectPublicKeyInfo), c.NotBefore, c.NotAfter}, nil
}

func exactSAN(c *x509.Certificate, want, dns string) bool {
	if len(c.URIs) != 1 || c.URIs[0].String() != want || len(c.EmailAddresses)+len(c.IPAddresses) != 0 {
		return false
	}
	nameCount := 1
	if dns != "" {
		if len(c.DNSNames) != 1 || c.DNSNames[0] != dns {
			return false
		}
		nameCount++
	} else if len(c.DNSNames) != 0 {
		return false
	}
	found := false
	for _, ext := range c.Extensions {
		switch ext.Id.String() {
		case "2.5.29.17":
			if found || !ext.Critical {
				return false
			}
			found = true
			var names []asn1.RawValue
			rest, e := asn1.Unmarshal(ext.Value, &names)
			if e != nil || len(rest) != 0 || len(names) != nameCount {
				return false
			}
			seenURI, seenDNS := false, false
			for _, n := range names {
				if n.Class != 2 || n.IsCompound {
					return false
				}
				switch n.Tag {
				case 6:
					if seenURI || string(n.Bytes) != want {
						return false
					}
					seenURI = true
				case 2:
					if seenDNS || dns == "" || string(n.Bytes) != dns {
						return false
					}
					seenDNS = true
				default:
					return false
				}
			}
			if !seenURI || (dns != "" && !seenDNS) {
				return false
			}
		case "2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.14", "2.5.29.35":
		default:
			return false
		}
	}
	return found
}
