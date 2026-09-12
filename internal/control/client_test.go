package control

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
	"portico.local/portico/internal/wire"
)

func testClient(t *testing.T, handler http.Handler, timeout time.Duration) (*Client, ClientConfig) {
	t.Helper()
	root, key := testfixture.Root(t)
	serverIdentity := testfixture.TLSIdentity(t, root, key, true)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	config := ClientConfig{Endpoint: strings.Replace(server.URL, "127.0.0.1", "localhost", 1), ServerRootDER: root.Raw, ServerSPKI: pki.Hash(serverIdentity.Leaf.RawSubjectPublicKeyInfo), Identity: testfixture.TLSIdentity(t, root, key, false), Profile: pki.Connector, Timeout: timeout, MaxConnections: 2}
	client, e := NewClient(config)
	testfixture.Must(t, e)
	t.Cleanup(client.Close)
	return client, config
}

func hostingFixture() HostingSnapshot {
	now := time.Now().UTC()
	return HostingSnapshot{Version: 1, ConnectorID: uuid.NewString(), ConnectorCertificateID: uuid.NewString(), PolicyRevision: 1, CheckedAt: now, Until: now.Add(time.Second), Resources: []HostingResource{}}
}

func TestDeviceCatalogRejectsAmbiguousInventory(t *testing.T) {
	r := ResourceAccess{ID: uuid.NewString(), Revision: 1, ConnectorID: uuid.NewString(), Name: "service", ConnectorName: "connector", Address: "192.0.2.10", Port: 443, Protocol: "tcp", Until: time.Now().Add(time.Hour)}
	for _, name := range []string{"valid", "empty", "null", "duplicate_resource", "duplicate_field", "case_alias", "unknown_field", "mapped_address", "wrong_protocol", "oversize", "connector_role", "future_version", "bare_array"} {
		t.Run(name, func(t *testing.T) {
			resources := []ResourceAccess{r}
			switch name {
			case "empty":
				resources = []ResourceAccess{}
			case "null":
				resources = nil
			case "duplicate_resource":
				resources = append(resources, r)
			case "mapped_address":
				resources[0].Address = "::ffff:192.0.2.10"
			case "wrong_protocol":
				resources[0].Protocol = "socks"
			}
			b, e := json.Marshal(CatalogSnapshot{Version: 1, Resources: resources})
			testfixture.Must(t, e)
			body := string(b)
			switch name {
			case "future_version":
				body = strings.Replace(body, `"Version":1`, `"Version":2`, 1)
			case "bare_array":
				b, e = json.Marshal(resources)
				testfixture.Must(t, e)
				body = string(b)
			case "duplicate_field":
				body = strings.Replace(body, `"Revision":1`, `"Revision":1,"Revision":1`, 1)
			case "case_alias":
				body = strings.Replace(body, `"Revision":1`, `"Revision":1,"revision":1`, 1)
			case "unknown_field":
				body = strings.Replace(body, `"Revision":1`, `"Revision":1,"Allowed":true`, 1)
			case "oversize":
				body = strings.Repeat(" ", wire.MaxBody) + body
			}
			_, config := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/api/v1/device/catalog" {
					t.Error("wrong catalog route")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}), time.Second)
			if name != "connector_role" {
				config.Profile = pki.Device
			}
			client, e := NewClient(config)
			testfixture.Must(t, e)
			defer client.Close()
			got, e := client.Catalog(context.Background())
			if name == "valid" || name == "empty" {
				if e != nil || len(got) != len(resources) {
					t.Fatal("valid catalog rejected")
				}
			} else if e != ErrRejected || got != nil {
				t.Fatal("ambiguous catalog returned usable inventory")
			}
		})
	}
}

func TestClientRejectsHostileResponsesAndRedirects(t *testing.T) {
	for _, name := range []string{"valid", "redirect", "denied", "unknown_field", "duplicate_field", "case_alias", "trailing", "oversize", "null", "wrong_content_type", "compressed", "future_version", "nil_resources", "long_validity"} {
		t.Run(name, func(t *testing.T) {
			var destination atomic.Int64
			value := hostingFixture()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/unexpected" {
					destination.Add(1)
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if name == "redirect" {
					w.Header().Set("Location", "/unexpected")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				if name == "denied" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if name == "wrong_content_type" {
					w.Header().Set("Content-Type", "text/html")
				}
				if name == "compressed" {
					w.Header().Set("Content-Encoding", "gzip")
				}
				if name == "future_version" {
					value.Version = 2
				}
				if name == "nil_resources" {
					value.Resources = nil
				}
				if name == "long_validity" {
					value.Until = value.CheckedAt.Add(time.Hour)
				}
				b, e := json.Marshal(value)
				if e != nil {
					panic(e)
				}
				body := string(b)
				switch name {
				case "unknown_field":
					body = strings.TrimSuffix(body, "}") + `,"Allowed":true}`
				case "duplicate_field":
					body = strings.TrimSuffix(body, "}") + `,"Version":1}`
				case "case_alias":
					body = strings.TrimSuffix(body, "}") + `,"version":1}`
				case "trailing":
					body += `{}`
				case "oversize":
					body = strings.Repeat(" ", wire.MaxBody) + body
				case "null":
					body = "null"
				}
				_, _ = io.WriteString(w, body)
			})
			client, _ := testClient(t, handler, time.Second)
			got, e := client.Hosting(context.Background())
			if name == "valid" {
				testfixture.Must(t, e)
				if got.ConnectorID != value.ConnectorID {
					t.Fatal("client changed response identity")
				}
			} else if e == nil || got.ConnectorID != "" {
				t.Fatal("hostile response returned usable snapshot")
			}
			if destination.Load() != 0 {
				t.Fatal("control client followed redirect")
			}
		})
	}
}

func TestClientDeadlineAndCloseCancelBlockedRequest(t *testing.T) {
	for _, name := range []string{"timeout", "close"} {
		t.Run(name, func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// net/http can watch for peer disconnect after the finite request
				// body is consumed. The fixture must not itself block that watcher.
				_, _ = io.Copy(io.Discard, r.Body)
				close(started)
				<-r.Context().Done()
				close(stopped)
			}), time.Second)
			result := make(chan error, 1)
			go func() { _, e := client.Hosting(context.Background()); result <- e }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("request did not reach local fixture")
			}
			if name == "close" {
				client.Close()
			}
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("blocked request returned authority")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("blocked request survived cancellation")
			}
			select {
			case <-stopped:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not observe cancellation")
			}
		})
	}
}

func TestClientConfigurationCannotAddAuthorityOrUnboundedIO(t *testing.T) {
	_, config := testClient(t, http.NotFoundHandler(), time.Second)
	for _, name := range []string{"http", "userinfo", "query", "fragment", "path", "no_port", "zero_port", "large_port", "root", "pin", "key", "chain", "leaf_size", "administrator", "timeout", "connections"} {
		t.Run(name, func(t *testing.T) {
			c := config
			switch name {
			case "http":
				c.Endpoint = strings.Replace(c.Endpoint, "https:", "http:", 1)
			case "userinfo":
				c.Endpoint = strings.Replace(c.Endpoint, "https://", "https://fixture@", 1)
			case "query":
				c.Endpoint += "?"
			case "fragment":
				c.Endpoint += "#fixture"
			case "path":
				c.Endpoint += "/api"
			case "no_port":
				c.Endpoint = "https://localhost"
			case "zero_port":
				c.Endpoint = "https://localhost:0"
			case "large_port":
				c.Endpoint = "https://localhost:65536"
			case "root":
				c.ServerRootDER = []byte{1}
			case "pin":
				c.ServerSPKI = "short"
			case "key":
				c.Identity.PrivateKey = nil
			case "chain":
				c.Identity.Certificate = nil
			case "leaf_size":
				c.Identity.Certificate = [][]byte{make([]byte, pki.MaxDER+1)}
			case "administrator":
				c.Profile = pki.Administrator
			case "timeout":
				c.Timeout = 6 * time.Second
			case "connections":
				c.MaxConnections = 0
			}
			client, e := NewClient(c)
			if e == nil {
				client.Close()
				t.Fatal("unsafe client configuration accepted")
			}
		})
	}
}

func TestClientRejectsMismatchedOrExtendedAuthorizations(t *testing.T) {
	for _, name := range []string{"valid", "wrong_session", "wrong_resource_connector", "missing_certificate", "loopback", "future_version", "long_lease", "long_activation", "extended_absolute", "resource_deadline", "skipped_sequence"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			session := uuid.NewString()
			connector := uuid.NewString()
			v := Authorization{Version: 1, SessionID: session, DeviceID: uuid.NewString(), ConnectorID: connector, CertificateID: uuid.NewString(), ConnectorCertificateID: uuid.NewString(), Resource: ResourceAccess{ID: uuid.NewString(), Revision: 1, Name: "Fixture", ConnectorID: connector, ConnectorName: "Fixture connector", Address: "192.0.2.10", Port: 8096, Protocol: "tcp", Until: now.Add(10 * time.Second)}, Sequence: 2, PolicyRevision: 1, IssuedAt: now, LeaseUntil: now.Add(2 * time.Second), ActivateUntil: now.Add(time.Second), SessionUntil: now.Add(10 * time.Second)}
			switch name {
			case "wrong_session":
				v.SessionID = uuid.NewString()
			case "wrong_resource_connector":
				v.Resource.ConnectorID = uuid.NewString()
			case "missing_certificate":
				v.ConnectorCertificateID = ""
			case "loopback":
				v.Resource.Address = "127.0.0.1"
			case "future_version":
				v.Version = 2
			case "long_lease":
				v.LeaseUntil = now.Add(16 * time.Second)
			case "long_activation":
				v.ActivateUntil = now.Add(6 * time.Second)
			case "extended_absolute":
				v.SessionUntil = now.Add(2 * time.Hour)
				v.Resource.Until = v.SessionUntil
			case "resource_deadline":
				v.Resource.Until = v.SessionUntil.Add(time.Second)
			case "skipped_sequence":
				v.Sequence = 3
			}
			client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(v)
			}), time.Second)
			got, e := client.Activate(context.Background(), SessionRequest{1, session, 1})
			if name == "valid" {
				testfixture.Must(t, e)
			} else if e == nil || got.SessionID != "" {
				t.Fatal("malformed permission returned usable authorization")
			}
		})
	}
}
