//go:build dashboardbrowser

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestDashboardNativeBrowser(t *testing.T) {
	runDashboardNativeBrowser(t, "")
}

func TestDashboardNativeBrowserFailure(t *testing.T) {
	runDashboardNativeBrowser(t, "intentional-failure")
}

func TestDashboardNativeBrowserClockFault(t *testing.T) {
	runDashboardNativeBrowser(t, "clock-fault")
}

func runDashboardNativeBrowser(t *testing.T, mode string) {
	t.Helper()
	executable, report := filepath.Clean(os.Getenv("PORTICO_NATIVE_EXECUTABLE")), filepath.Clean(os.Getenv("PORTICO_BROWSER_REPORT"))
	if !filepath.IsAbs(executable) || !filepath.IsAbs(report) {
		t.Fatal("native browser requires absolute runtime and report paths")
	}
	if mode != "" {
		report += "-" + mode
	}
	a := adminSeed(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	host := net.JoinHostPort("admin.portico.test", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	origin := "https://" + host
	verifier, err := adminauth.New(adminauth.Config{Origin: origin, ValidUntil: time.Now().Add(time.Hour), Models: []adminauth.Model{chromiumBrowserModel(t)}})
	must(t, err)
	root, rootKey := testfixture.Root(t)
	serverKey := newKey(t)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"admin.portico.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, &serverKey.PublicKey, rootKey)
	policy := policyFixtureFor(t, a.f)
	server, err := policy.engine.NewHTTPServer(PolicyHTTPConfig{Profile: pki.Administrator, Host: host, ServerIdentity: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: serverKey}, AdministratorTrust: a.trust, AdministratorVerifier: verifier})
	must(t, err)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, server.Close(stop))
		if err := <-done; err != http.ErrServerClosed {
			t.Errorf("native browser server shutdown: %v", err)
		}
	})
	testContext, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var clockFault atomic.Bool
	// Only the health estimate is synthetic. The actual boot/UTC readers remain
	// active; this fixture never changes the host clock or time service.
	health := func() (time.Duration, error) {
		if clockFault.Load() {
			return 0, errors.New("isolated clock health fault")
		}
		return time.Millisecond, nil
	}
	client, err := adminbridge.New(testContext, adminbridge.Config{Origin: origin, ServerRootDER: root.Raw, ServerSPKI: pki.Hash(leaf.RawSubjectPublicKeyInfo), AdministratorTrust: a.trust, Identity: a.identity, BootstrapAddress: listener.Addr().String(), Timeout: 5 * time.Second, Lifetime: 2 * time.Minute, ClockHealth: health})
	must(t, err)
	defer client.Close()
	entry, err := filepath.Abs(filepath.Join("..", "..", "scripts", "test-dashboard-native-browser.cjs"))
	must(t, err)
	if mode == "intentional-failure" {
		entry, err = filepath.Abs(filepath.Join("..", "..", "scripts", "test-dashboard-native-failure.cjs"))
		must(t, err)
	}
	watchContext, stopWatch := context.WithCancel(testContext)
	defer stopWatch()
	watchDone := make(chan struct{})
	if mode == "clock-fault" {
		entry, err = filepath.Abs(filepath.Join("..", "..", "scripts", "test-dashboard-native-clock.cjs"))
		must(t, err)
		go func() {
			defer close(watchDone)
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-watchContext.Done():
					return
				case <-ticker.C:
					marker, err := os.ReadFile(filepath.Join(report, "clock-ready.txt"))
					if err == nil && string(marker) == "native clock fixture ready\n" {
						clockFault.Store(true)
						return
					}
				}
			}
		}()
	} else {
		close(watchDone)
	}
	started := time.Now()
	err = adminbridge.Run(testContext, client, adminbridge.Launch{Executable: executable, EntryPoint: entry, StateDirectory: report})
	stopWatch()
	<-watchDone
	if mode == "clock-fault" {
		if !clockFault.Load() || !errors.Is(err, adminbridge.ErrRejected) || time.Since(started) > 12*time.Second {
			t.Fatal("loaded native window did not terminate promptly after clock health loss")
		}
		t.Log("loaded native window rejected clock health loss and joined the child and pipes; physical suspend remains unqualified")
		return
	}
	if mode == "intentional-failure" {
		if !errors.Is(err, adminbridge.ErrRejected) || time.Since(started) > 12*time.Second {
			t.Fatal("native failure did not reject and terminate promptly")
		}
		marker, err := os.ReadFile(filepath.Join(report, "intentional-failure.txt"))
		must(t, err)
		if string(marker) != "intentional native failure\n" {
			t.Fatal("native test did not reach intentional failure")
		}
		t.Log("actual native failure closed inherited pipes and joined the child promptly")
		return
	}
	must(t, err)
	var total, enabled, tested, registered, retired, tests int
	for query, value := range map[string]*int{
		"SELECT count(*) FROM admin_factors":                                     &total,
		"SELECT count(*) FROM admin_factors WHERE enabled=1":                     &enabled,
		"SELECT count(*) FROM admin_factors WHERE enabled=1 AND tested=1":        &tested,
		"SELECT count(*) FROM audit_events WHERE action='admin.factor.register'": &registered,
		"SELECT count(*) FROM audit_events WHERE action='admin.factor.disable'":  &retired,
		"SELECT count(*) FROM audit_events WHERE action='admin.factor.test'":     &tests,
	} {
		must(t, a.f.f.s.db.QueryRow(query).Scan(value))
	}
	if total != 2 || enabled != 1 || tested != 1 || registered != 2 || retired != 1 || tests != 2 {
		t.Fatal("native browser did not commit exact factor lifecycle")
	}
	must(t, verifyAudit(ctx, a.f.f.s.db))
	t.Log("actual native shell, private anonymous pipes, Go-owned administrator TLS signer, stable origin, native registration/assertions and committed audit verified")
}
