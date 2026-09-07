package service

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.step.sm/crypto/pemutil"
	"portico.local/portico/internal/issuer"
	"portico.local/portico/internal/pki"
)

// FileConfig contains paths and public identifiers, never inline private keys.
// The command currently accepts loopback listeners only; deployment network
// isolation and physical issuer-key custody are separate qualification gates.
type FileConfig struct {
	ListenAddress, Endpoint, Provisioner, KeyID, DatabasePath                                          string
	DeploymentID, IssuerID                                                                             string
	Profile                                                                                            pki.Profile
	RootCertificateFile, IssuerCertificateFile, IssuerKeyFile, IssuerPasswordFile                      string
	ProvisionerPublicKeyFile, ServerCertificateFile, ServerKeyFile, ControllerRootFile, ControllerSPKI string
}

func readFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, "\\\\") {
		return nil, issuer.ErrRejected
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, issuer.ErrRejected
	}
	defer func() { _ = f.Close() }()
	stat, e := f.Stat()
	if e != nil || !stat.Mode().IsRegular() || stat.Size() > max {
		return nil, issuer.ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, issuer.ErrRejected
	}
	return b, nil
}
func readCert(path string) ([]byte, error) {
	b, e := readFile(path, pki.MaxDER*2)
	if e != nil {
		return nil, e
	}
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" || len(p.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, issuer.ErrRejected
	}
	return p.Bytes, nil
}
func LoadConfig(path string) (Config, string, error) {
	var c Config
	var f FileConfig
	b, e := readFile(path, issuer.MaxBody)
	if e != nil || issuer.Decode(b, &f) != nil {
		return c, "", issuer.ErrRejected
	}
	address, e := netip.ParseAddrPort(f.ListenAddress)
	if e != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return c, "", issuer.ErrRejected
	}
	u, e := url.Parse(f.Endpoint)
	if e != nil || u.Hostname() != "localhost" || u.Port() != strconv.Itoa(int(address.Port())) {
		return c, "", issuer.ErrRejected
	}
	c = Config{Endpoint: f.Endpoint, Provisioner: f.Provisioner, KeyID: f.KeyID, DatabasePath: f.DatabasePath, ControllerSPKI: f.ControllerSPKI, TrustConfig: pki.Config{DeploymentID: f.DeploymentID, IssuerID: f.IssuerID, Profile: f.Profile}}
	c.TrustConfig.RootDER, e = readCert(f.RootCertificateFile)
	if e != nil {
		return Config{}, "", e
	}
	c.TrustConfig.IssuerDER, e = readCert(f.IssuerCertificateFile)
	if e != nil {
		return Config{}, "", e
	}
	c.ControllerRootDER, e = readCert(f.ControllerRootFile)
	if e != nil {
		return Config{}, "", e
	}
	public, e := readFile(f.ProvisionerPublicKeyFile, 8192)
	if e != nil || json.Unmarshal(public, &c.ProvisionerPublicKey) != nil {
		return Config{}, "", issuer.ErrRejected
	}
	cert, e := readFile(f.ServerCertificateFile, pki.MaxDER*2)
	if e != nil {
		return Config{}, "", e
	}
	key, e := readFile(f.ServerKeyFile, pki.MaxDER)
	if e != nil {
		return Config{}, "", e
	}
	c.ServerIdentity, e = tls.X509KeyPair(cert, key)
	if e != nil {
		return Config{}, "", issuer.ErrRejected
	}
	// Noninteractive password handling prevents an unattended process from
	// opening a prompt or reading unbounded/arbitrary key provider locations.
	issuerKey, e := readFile(f.IssuerKeyFile, pki.MaxDER)
	if e != nil {
		return Config{}, "", e
	}
	password, e := readFile(f.IssuerPasswordFile, 1024)
	password = bytes.TrimSpace(password)
	if e != nil || len(password) < 16 {
		return Config{}, "", issuer.ErrRejected
	}
	block, rest := pem.Decode(issuerKey)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return Config{}, "", issuer.ErrRejected
	}
	parsed, e := pemutil.Parse(issuerKey, pemutil.WithPassword(password))
	if e != nil {
		return Config{}, "", issuer.ErrRejected
	}
	var ok bool
	c.IssuerSigner, ok = parsed.(crypto.Signer)
	if !ok {
		return Config{}, "", issuer.ErrRejected
	}
	return c, f.ListenAddress, nil
}
