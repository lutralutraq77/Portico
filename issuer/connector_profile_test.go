package service

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"portico.local/portico/internal/issuer"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestConnectorIssuerRejectsUnapprovedNames(t *testing.T) {
	l := newLab(t, pki.Connector)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: l.request.CSR}))
	for _, kind := range []string{"uri_only", "arbitrary_dns", "wildcard", "duplicate", "wrong_order"} {
		t.Run(kind, func(t *testing.T) {
			token := l.token(t, func(c *issuer.Claims) {
				switch kind {
				case "uri_only":
					c.SANs = c.SANs[:1]
				case "arbitrary_dns":
					c.SANs[1] = "administrator.portico.test"
				case "wildcard":
					c.SANs[1] = "*.connector.portico.invalid"
				case "duplicate":
					c.SANs = append(c.SANs, c.SANs[1])
				case "wrong_order":
					c.SANs[0], c.SANs[1] = c.SANs[1], c.SANs[0]
				}
			})
			if status := l.send(t, issuer.SignPath, issuer.SignRequest{CSR: csr, Token: token}, l.http); status != 403 {
				t.Fatalf("unapproved connector names accepted: %d", status)
			}
		})
	}
}

func TestConnectorIssuerCannotSilentlyReuseLegacyProfile(t *testing.T) {
	l := newLab(t, pki.Connector)
	stored, e := l.s.database.Get(bindingTable, []byte("identity"))
	testfixture.Must(t, e)
	var fields []string
	testfixture.Must(t, json.Unmarshal(stored, &fields))
	if len(fields) != 9 || fields[len(fields)-1] != pki.ConnectorProfileVersion {
		t.Fatal("connector profile not durably versioned")
	}
	legacy, e := json.Marshal(fields[:len(fields)-1])
	testfixture.Must(t, e)
	// Reconstruct the exact earlier binding as a test fixture. A restart must
	// require explicit profile migration instead of silently changing issuance.
	testfixture.Must(t, l.s.database.Set(bindingTable, []byte("identity"), legacy))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	testfixture.Must(t, l.s.Close(ctx))
	reopened, e := New(l.config)
	if e == nil {
		_ = reopened.Close(ctx)
		t.Fatal("legacy connector issuer silently upgraded")
	}
}
