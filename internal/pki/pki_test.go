package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func signed(t testing.TB, c, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, e := x509.CreateCertificate(rand.Reader, c, parent, pub, signer)
	if e != nil {
		t.Fatal(e)
	}
	return der
}
func parsed(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

type fixture struct {
	trust                *Trust
	leaf                 *x509.Certificate
	issuer               *x509.Certificate
	issuerKey, deviceKey *ecdsa.PrivateKey
	now                  time.Time
	principal            string
}

func setup(t testing.TB, profile Profile) fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rk, ik, dk := key(t), key(t), key(t)
	r := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder := signed(t, r, r, &rk.PublicKey, rk)
	r = parsed(t, rder)
	i := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	ider := signed(t, i, r, &ik.PublicKey, rk)
	i = parsed(t, ider)
	tr, e := NewTrust(Config{uuid.NewString(), uuid.NewString(), profile, rder, ider})
	if e != nil {
		t.Fatal(e)
	}
	id := uuid.NewString()
	uri, _ := IdentityURI(tr.DeploymentID(), profile, id)
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if profile == Connector {
		usages = append(usages, x509.ExtKeyUsageServerAuth)
	}
	l := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, URIs: []*url.URL{uri}}
	return fixture{tr, l, i, ik, dk, now, id}
}

func TestCSRClaimsRejected(t *testing.T) {
	k := key(t)
	for _, tc := range []struct {
		name   string
		mutate func(*x509.CertificateRequest)
	}{
		{"subject", func(c *x509.CertificateRequest) { c.Subject.CommonName = "administrator" }},
		{"dns", func(c *x509.CertificateRequest) { c.DNSNames = []string{"admin.example"} }},
		{"uri", func(c *x509.CertificateRequest) {
			u, _ := url.Parse("portico://foreign/admin/claim")
			c.URIs = []*url.URL{u}
		}},
		{"lifetime_extension", func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}},
		{"basic_constraints", func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &x509.CertificateRequest{}
			tc.mutate(c)
			der, e := x509.CreateCertificateRequest(rand.Reader, c, k)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = ParseCSR(der); e == nil {
				t.Fatal("CSR claims accepted")
			}
		})
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseCSR(der); e != nil {
		t.Fatal(e)
	}
	der[len(der)-1] ^= 1
	if _, e = ParseCSR(der); e == nil {
		t.Fatal("invalid signature accepted")
	}
	k384, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k384)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseCSR(der); e == nil {
		t.Fatal("unsupported key accepted")
	}
}

func TestCertificateProfiles(t *testing.T) {
	for _, profile := range []Profile{Device, Connector} {
		t.Run(string(profile), func(t *testing.T) {
			f := setup(t, profile)
			der := signed(t, f.leaf, f.issuer, &f.deviceKey.PublicKey, f.issuerKey)
			c, e := f.trust.Verify(der, f.principal, f.now)
			if e != nil {
				t.Fatal(e)
			}
			if c.PrincipalID != f.principal || c.Profile != profile || c.LeafSHA256 != Hash(der) {
				t.Fatal("identity mismatch")
			}
			if _, e = f.trust.Verify(der, uuid.NewString(), f.now); e == nil {
				t.Fatal("foreign principal accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"ca_leaf", func(c *x509.Certificate) { c.IsCA = true }},
		{"no_constraints", func(c *x509.Certificate) { c.BasicConstraintsValid = false }},
		{"wrong_eku", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }},
		{"any_eku", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{"extra_eku", func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) }},
		{"extra_key_usage", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }},
		{"cn", func(c *x509.Certificate) { c.Subject.CommonName = "Alice" }},
		{"dns", func(c *x509.Certificate) { c.DNSNames = []string{"example.test"} }},
		{"ip", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }},
		{"email", func(c *x509.Certificate) { c.EmailAddresses = []string{"a@example.test"} }},
		{"extra_uri", func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) }},
		{"foreign_deployment", func(c *x509.Certificate) { c.URIs[0].Host = uuid.NewString() }},
		{"admin_profile", func(c *x509.Certificate) { c.URIs[0].Path = "/admin/" + uuid.NewString() }},
		{"unknown_extension", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}},
		{"unknown_critical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
		{"expired", func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(time.Second) }},
		{"future", func(c *x509.Certificate) { c.NotBefore = c.NotAfter.Add(-time.Second) }},
		{"outlives_issuer", func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(48 * time.Hour) }},
		{"weak_signature", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA384 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, Device)
			tc.change(f.leaf)
			der := signed(t, f.leaf, f.issuer, &f.deviceKey.PublicKey, f.issuerKey)
			if _, e := f.trust.Verify(der, f.principal, f.now); e == nil {
				t.Fatal("hostile certificate accepted")
			}
		})
	}
}

func TestTrustPinningAndExpiryBoundary(t *testing.T) {
	f := setup(t, Device)
	der := signed(t, f.leaf, f.issuer, &f.deviceKey.PublicKey, f.issuerKey)
	if _, e := f.trust.Verify(der, f.principal, f.leaf.NotAfter); e == nil {
		t.Fatal("accepted exact expiry")
	}
	other := setup(t, Device)
	if _, e := other.trust.Verify(der, f.principal, f.now); e == nil {
		t.Fatal("unrelated issuer accepted")
	}
	if _, e := NewTrust(Config{f.trust.deployment, f.trust.issuerID, "admin", f.trust.root.Raw, f.trust.issuer.Raw}); e == nil {
		t.Fatal("admin trust enabled")
	}
	if _, e := NewTrust(Config{f.trust.deployment, f.trust.issuerID, Device, f.trust.root.Raw, f.trust.root.Raw}); e == nil {
		t.Fatal("root accepted as online issuer")
	}
}

func FuzzPKIInputs(f *testing.F) {
	fixture := setup(f, Device)
	validCSR, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, fixture.deviceKey)
	if e != nil {
		f.Fatal(e)
	}
	f.Add(validCSR)
	f.Add(signed(f, fixture.leaf, fixture.issuer, &fixture.deviceKey.PublicKey, fixture.issuerKey))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0})
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseCSR(b)
		_, _ = fixture.trust.Verify(b, fixture.principal, fixture.now)
		_, _ = NewTrust(Config{fixture.trust.deployment, fixture.trust.issuerID, Device, b, b})
	})
}

func TestCSRRejectsAttributesDiscardedByX509(t *testing.T) {
	k := key(t)
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if e != nil {
		t.Fatal(e)
	}
	var outer struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, e = asn1.Unmarshal(der, &outer); e != nil {
		t.Fatal(e)
	}
	var info struct {
		Version            int
		Subject, PublicKey asn1.RawValue
		Attributes         []asn1.RawValue `asn1:"tag:0"`
	}
	if _, e = asn1.Unmarshal(outer.Info.FullBytes, &info); e != nil {
		t.Fatal(e)
	}
	attribute, e := asn1.Marshal(struct {
		ID     asn1.ObjectIdentifier
		Values []string `asn1:"set"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, []string{"unexpected-password-claim"}})
	if e != nil {
		t.Fatal(e)
	}
	info.Attributes = []asn1.RawValue{{FullBytes: attribute}}
	body, e := asn1.Marshal(info)
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(body)
	signature, e := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	outer.Info = asn1.RawValue{FullBytes: body}
	outer.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, e = asn1.Marshal(outer)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificateRequest(der)
	if e != nil || parsed.CheckSignature() != nil || len(parsed.Extensions) != 0 {
		t.Fatal("positive control did not reproduce X.509 attribute omission")
	}
	if _, e = ParseCSR(der); e == nil {
		t.Fatal("raw signed attribute silently ignored")
	}
}

func TestHiddenSANAndNoncriticalSANRejected(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		t.Run(map[bool]string{false: "noncritical", true: "ignored_registered_id"}[hidden], func(t *testing.T) {
			f := setup(t, Device)
			names := []asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte(f.leaf.URIs[0].String())}}
			if hidden {
				names = append(names, asn1.RawValue{Class: 2, Tag: 8, Bytes: []byte{42, 3}})
			}
			value, e := asn1.Marshal(names)
			if e != nil {
				t.Fatal(e)
			}
			f.leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: hidden, Value: value}}
			der := signed(t, f.leaf, f.issuer, &f.deviceKey.PublicKey, f.issuerKey)
			c := parsed(t, der)
			if len(c.URIs) != 1 {
				t.Fatal("positive control URI missing")
			}
			if _, e = f.trust.Verify(der, f.principal, f.now); e == nil {
				t.Fatal("ambiguous SAN accepted")
			}
		})
	}
}
