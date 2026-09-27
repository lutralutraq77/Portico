//go:build dashboardbrowser

package testfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// ChromiumAttestation is ONLY a native-browser software test fixture. Chromium's
// virtual CTAP2 device uses the publicly documented FIDO U2F example signing key:
// https://chromium.googlesource.com/chromium/src/+/HEAD/device/fido/virtual_fido_device.cc
// (source blob 9b98eb85ccb28b02d0d6e5ed459d43f18b6f93ba, kAttestationKey).
// Its non-CA attestation certificate is self-issued. This ephemeral CA uses the
// same published test signer and issuer name, so the ordinary production chain
// verifier can validate the browser's real packed attestation. Production roots,
// model admission, certificate verification and WebAuthn validation are unchanged.
// This publicly known test identity must NEVER be trusted in a deployment.
func ChromiumAttestation(t *testing.T) (string, [][]byte) {
	t.Helper()
	d, err := hex.DecodeString("f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664")
	Must(t, err)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	Must(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"Chromium"}, OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Batch Certificate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	// Match Chromium AddName's encoding: country is PrintableString; the other
	// attributes are UTF8String. Go's default printable encoding has the same
	// display text but different issuer bytes and correctly fails chain building.
	// https://raw.githubusercontent.com/chromium/chromium/main/net/cert/x509_util.cc
	name := template.Subject.ToRDNSequence()
	for i := range name {
		for j := range name[i] {
			attribute := &name[i][j]
			if !attribute.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}) {
				attribute.Value = asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(attribute.Value.(string))}
			}
		}
	}
	template.RawSubject, err = asn1.Marshal(name)
	Must(t, err)
	// Distinguish the fixture CA from Chromium's same-subject/same-key leaf in
	// X.509 cycle detection. This SAN is only an identity on the disposable CA;
	// it creates no host mapping and does not change certificate verification.
	template.DNSNames = []string{"chromium-attestation-root.portico.test"}
	root := Certificate(t, template, template, &key.PublicKey, key)
	Must(t, root.CheckSignatureFrom(root))
	return "01020304-0506-0708-0102-030405060708", [][]byte{root.Raw}
}
