package adminbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestNativeRenewalCallbackRestrictsRendererAndRemoteDestinations(t *testing.T) {
	var callbacks atomic.Int32
	f := bridgeSeed(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminrenewal.PreparePath || r.Method != http.MethodPost || r.Header.Get("Origin") != "https://"+r.Host {
			t.Error("native sender escaped its fixed remote route")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"fixture":true}`))
	})
	plain := f.client(t)
	request := Request{Method: http.MethodPost, Origin: f.config.Origin, Path: adminrenewal.StartPath, Body: []byte(`{"Version":1}`)}
	if _, err := plain.Exchange(context.Background(), request); err == nil {
		t.Fatal("ordinary native configuration acquired renewal capability")
	}
	f.config.RenewalHandler = func(_ context.Context, r Request, send RenewalExchange) (Response, error) {
		callbacks.Add(1)
		if r.Path != adminrenewal.StartPath {
			t.Error("unrecognized renderer operation reached native callback")
		}
		for _, path := range []string{"/admin", adminrenewal.ActivatePath, "https://other.test" + adminrenewal.PreparePath, adminrenewal.PreparePath + "?override=1", "/api/v1/admin/policy/confirm"} {
			if _, err := send(path, []byte(`{}`)); err == nil {
				t.Error("callback sender acquired an unrelated endpoint")
			}
		}
		return send(adminrenewal.PreparePath, []byte(`{"fixture":true}`))
	}
	client := f.client(t)
	for _, path := range []string{adminrenewal.PreparePath, adminrenewal.ConfirmPath, adminrenewal.CertificatePath, adminrenewal.ActivatePath, adminrenewal.StartPath + "?override=1"} {
		changed := request
		changed.Path = path
		if _, err := client.Exchange(context.Background(), changed); err == nil {
			t.Fatal("renderer directly invoked a native-owned remote operation")
		}
	}
	for _, change := range []func(*Request){func(r *Request) { r.Origin = "https://other.test" }, func(r *Request) { r.Site = "cross-site" }, func(r *Request) { r.Body = []byte(`{"Version":1,"version":1}`) }, func(r *Request) { r.Method = http.MethodGet }} {
		changed := request
		change(&changed)
		if _, err := client.Exchange(context.Background(), changed); err == nil {
			t.Fatal("unbound native renewal request admitted")
		}
	}
	if callbacks.Load() != 0 || f.hits.Load() != 0 {
		t.Fatal("invalid request reached native code or the network")
	}
	response, err := client.Exchange(context.Background(), request)
	testfixture.Must(t, err)
	if response.Status != http.StatusOK || callbacks.Load() != 1 || f.hits.Load() != 1 {
		t.Fatal("native renewal did not use one fixed authenticated request")
	}
}

func TestNativeActivationValidatesFreshTLSAndExactPublicReceipt(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-id", "wrong-hash", "wrong-version", "duplicate-version", "extra-field", "oversized", "redirect", "wrong-pin", "wrong-key"} {
		t.Run(scenario, func(t *testing.T) {
			id := uuid.NewString()
			f := bridgeSeed(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
				if r.URL.Path != adminrenewal.ActivatePath || r.Method != http.MethodPost || r.Header.Get("Origin") != "https://"+r.Host || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("activation changed its fixed scope")
				}
				result := adminrenewal.Activated{Version: 1, RenewalID: id, CertificateSHA256: pki.Hash(r.TLS.PeerCertificates[0].Raw)}
				switch scenario {
				case "wrong-id":
					result.RenewalID = uuid.NewString()
				case "wrong-hash":
					result.CertificateSHA256 = strings.Repeat("0", 64)
				case "wrong-version":
					result.Version = 2
				case "oversized":
					_, _ = w.Write(bytes.Repeat([]byte(" "), adminrenewal.MaxActivationBody+1))
					return
				case "redirect":
					w.Header().Set("Location", "https://other.test")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				data, err := json.Marshal(result)
				testfixture.Must(t, err)
				if scenario == "duplicate-version" {
					data = append(bytes.TrimSuffix(data, []byte("}")), []byte(`,"version":1}`)...)
				} else if scenario == "extra-field" {
					data = append(bytes.TrimSuffix(data, []byte("}")), []byte(`,"Retry":true}`)...)
				}
				_, _ = w.Write(data)
			})
			if scenario == "wrong-pin" {
				f.config.ServerSPKI = strings.Repeat("0", 64)
			} else if scenario == "wrong-key" {
				f.config.Identity.PrivateKey = testfixture.Key(t)
			}
			f.config.RenewalHandler = func(context.Context, Request, RenewalExchange) (Response, error) {
				t.Error("activation reused the ordinary native callback")
				return Response{}, ErrRejected
			}
			err := Activate(context.Background(), f.config, id)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("activation accepted an invalid receipt or rejected an exact one")
			}
			if scenario == "valid" {
				testfixture.Must(t, Activate(context.Background(), f.config, id))
				if f.signer.signs.Load() != 2 || f.hits.Load() != 2 {
					t.Fatal("explicit confirmation did not prove the key on fresh TLS")
				}
			} else if (scenario == "wrong-pin" || scenario == "wrong-key") && f.hits.Load() != 0 {
				t.Fatal("invalid TLS authority reached the activation handler")
			}
		})
	}
}
