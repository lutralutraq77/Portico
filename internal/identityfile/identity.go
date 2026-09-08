// Package identityfile composes bounded protected files into typed TLS identities.
package identityfile

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/netip"
	"net/url"

	"portico.local/portico/internal/pki"
)

var ErrRejected = errors.New("identity configuration rejected")

type TrustFiles struct {
	IssuerID              string `json:"issuer_id"`
	RootCertificateFile   string `json:"root_certificate_file"`
	IssuerCertificateFile string `json:"issuer_certificate_file"`
}
type EndpointFiles struct {
	URL                 string `json:"url"`
	RootCertificateFile string `json:"root_certificate_file"`
	SPKI                string `json:"spki_sha256"`
}

// Reader must enforce the local path/owner/mode rules, size cap and secret bit.
// Production configurations always supply localfile.Read.
type Reader func(path string, maximum int64, secret bool) ([]byte, error)

func (read Reader) Certificate(path string) ([]byte, error) {
	data, err := read(path, 2*pki.MaxDER, false)
	block, rest := pem.Decode(data)
	if err != nil || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > pki.MaxDER || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrRejected
	}
	return block.Bytes, nil
}

func (read Reader) Trust(deployment string, files TrustFiles, profile pki.Profile) (*pki.Trust, error) {
	root, err := read.Certificate(files.RootCertificateFile)
	if err != nil {
		return nil, ErrRejected
	}
	issuer, err := read.Certificate(files.IssuerCertificateFile)
	if err != nil {
		return nil, ErrRejected
	}
	return pki.NewTrust(pki.Config{DeploymentID: deployment, IssuerID: files.IssuerID, Profile: profile, RootDER: root, IssuerDER: issuer})
}

func (read Reader) Identity(trust *pki.Trust, certificatePath, keyPath string) (tls.Certificate, error) {
	leaf, err := read.Certificate(certificatePath)
	if err != nil || trust == nil {
		return tls.Certificate{}, ErrRejected
	}
	key, err := read(keyPath, pki.MaxDER, true)
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	defer clear(key)
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return tls.Certificate{}, ErrRejected
	}
	defer clear(block.Bytes)
	identity, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), key)
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	identity, err = trust.TLSIdentity(identity)
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	return identity, nil
}

// LoopbackEndpoint is the development deployment boundary shared by both
// commands. Broader endpoints require the independent deployment/network gate.
func LoopbackEndpoint(text string) bool {
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "https" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.IsLoopback() && !a.Is4In6() && a.Zone() == "" && a.String() == u.Hostname()
}
