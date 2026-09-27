package controller

import (
	"reflect"
	"testing"

	"portico.local/portico/internal/pki"
)

func TestDashboardInventoryExactCertificateChoices(t *testing.T) {
	f := newAccessFixture(t)
	s := f.a.f.f.s
	before := summary(t, s)
	for _, profile := range []string{"device", "connector"} {
		request := DashboardRequest{Section: "certificates", Profile: profile, Limit: 1}
		seen := map[string]bool{}
		selected := false
		for pages := 0; ; pages++ {
			if pages > 5 {
				t.Fatal("certificate pagination did not terminate")
			}
			page, err := s.DashboardInventory(ctx, f.a.conn, f.a.trust, request)
			must(t, err)
			items := page.Items.([]DashboardCertificate)
			if len(items) != 1 {
				t.Fatal("filtered certificate page was not bounded or omitted a choice")
			}
			item := items[0]
			if item.Profile != profile || seen[item.ID] || item.ID <= request.After {
				t.Fatal("certificate profile filter or ordered continuation failed")
			}
			seen[item.ID] = true
			if item.ID == f.request.DeviceCertificateID {
				selected = true
				if item.PrincipalID != f.device.ID || item.PrincipalName != f.device.Name || item.Fingerprint != pki.Hash(f.leaf) {
					t.Fatal("device choice did not identify the exact registered certificate")
				}
			}
			if item.ID == f.request.ConnectorCertificateID {
				selected = true
				if item.PrincipalID != f.a.f.f.connector.ID || item.PrincipalName != f.a.f.f.connector.Name || item.Fingerprint != pki.Hash(f.v.connectorLeaf) {
					t.Fatal("connector choice did not identify the exact registered certificate")
				}
			}
			if page.Next == "" {
				break
			}
			request.After, request.PolicyRevision = page.Next, page.PolicyRevision
		}
		// seed also retains one historical metadata-only certificate per
		// ordinary profile; inventory must not silently discard those records.
		want, historicalID := 3, f.a.f.f.cert.ID
		if profile == "connector" {
			want, historicalID = 2, f.a.f.f.service.ID
		}
		if !selected || !seen[historicalID] || len(seen) != want {
			t.Fatalf("%s certificate choices: selected=%t historical=%t count=%d want=%d", profile, selected, seen[historicalID], len(seen), want)
		}
	}
	if summary(t, s) != before {
		t.Fatal("certificate choices mutated authority")
	}
}

func TestDashboardInventoryRulesRetainTheirResourceRevision(t *testing.T) {
	f := newAccessFixture(t)
	s := f.a.f.f.s
	resource := f.a.f.f.resource
	oldName := resource.Name
	resource.Revision++
	resource.Name, resource.Port = "Replacement destination", 8443
	grant := f.grant
	grant.ID, grant.Revision = NewID(), resource.Revision
	hosting := HostBinding{NewID(), resource.ConnectorID, resource.ID, resource.Revision, true, grant.From, grant.Until}
	must(t, s.Update(ctx, f.a.f.f.actor, func(tx *Tx) error {
		if err := tx.ReviseResource(1, resource); err != nil {
			return err
		}
		if err := tx.AddGrant(grant); err != nil {
			return err
		}
		if err := tx.AddHostBinding(hosting); err != nil {
			return err
		}
		return tx.Disable("grant", f.grant.ID)
	}))
	before := summary(t, s)
	for _, section := range []string{"grants", "hosting"} {
		request := DashboardRequest{Section: section, Limit: 1}
		seen := map[string]bool{}
		var lastRevision int64
		for pages := 0; ; pages++ {
			if pages > 5 {
				t.Fatal("rule pagination did not terminate")
			}
			page, err := s.DashboardInventory(ctx, f.a.conn, f.a.trust, request)
			must(t, err)
			lastRevision = page.PolicyRevision
			var id, name string
			var revision int64
			if section == "grants" {
				items := page.Items.([]DashboardGrant)
				if len(items) != 1 {
					t.Fatal("unbounded or missing grant page")
				}
				item := items[0]
				id, name, revision = item.ID, item.ResourceName, item.Revision
				if id == f.grant.ID || id == grant.ID {
					if item.UserID != f.user.ID || item.UserName != f.user.Name || item.DeviceID != f.device.ID || item.DeviceName != f.device.Name || item.ResourceID != resource.ID || item.Enabled != (id == grant.ID) || !item.From.Equal(grant.From) || !item.Until.Equal(grant.Until) {
						t.Fatal("grant metadata lost its exact principals, state or interval")
					}
				}
			} else {
				items := page.Items.([]DashboardHosting)
				if len(items) != 1 {
					t.Fatal("unbounded or missing hosting page")
				}
				item := items[0]
				id, name, revision = item.ID, item.ResourceName, item.Revision
				if item.ConnectorID != f.a.f.f.connector.ID || item.ConnectorName != f.a.f.f.connector.Name || item.ResourceID != resource.ID {
					t.Fatal("hosting metadata lost the exact connector or resource")
				}
			}
			if seen[id] || id <= request.After || (revision != 1 && revision != 2) || (revision == 1 && name != oldName) || (revision == 2 && name != resource.Name) {
				t.Fatal("rule continuation repeated an item or joined the wrong resource revision")
			}
			seen[id] = true
			if page.Next == "" {
				break
			}
			request.After, request.PolicyRevision = page.Next, page.PolicyRevision
		}
		if (section == "grants" && (len(seen) != 3 || !seen[f.grant.ID] || !seen[grant.ID])) || (section == "hosting" && (len(seen) != 2 || !seen[hosting.ID])) {
			t.Fatal("historical or replacement rule missing")
		}
		if summary(t, s) != before {
			t.Fatal("rule inventory mutated authority")
		}
		must(t, s.Update(ctx, f.a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Revision change", true}) }))
		request.PolicyRevision = lastRevision
		page, err := s.DashboardInventory(ctx, f.a.conn, f.a.trust, request)
		if err != ErrConflict || !reflect.DeepEqual(page, DashboardPage{}) {
			t.Fatal("stale rule continuation exposed data")
		}
		before = summary(t, s)
	}
}
