package control

import (
	"net/netip"
	"time"

	"portico.local/portico/internal/pki"
)

// Structural checks cannot establish current authority. The connector must also
// compare its locally approved tuple, original session identity and monotonic
// request-start deadline before dialing, activation, renewal or forwarding.
func validResource(v ResourceAccess) bool {
	a, e := netip.ParseAddr(v.Address)
	return pki.ValidID(v.ID) && v.Revision > 0 && pki.ValidID(v.ConnectorID) && len(v.Name) <= 128 && len(v.ConnectorName) <= 128 && e == nil && a.Zone() == "" && !a.Is4In6() && a.String() == v.Address && a.IsGlobalUnicast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && v.Protocol == "tcp" && v.Port > 0 && v.Port <= 65535 && !v.Until.IsZero()
}
func validAuthorization(v Authorization) bool {
	return v.Version == Version && pki.ValidID(v.SessionID) && pki.ValidID(v.DeviceID) && pki.ValidID(v.ConnectorID) && pki.ValidID(v.CertificateID) && pki.ValidID(v.ConnectorCertificateID) && validResource(v.Resource) && v.Resource.ConnectorID == v.ConnectorID && v.Sequence > 0 && v.PolicyRevision > 0 && !v.IssuedAt.IsZero() && v.LeaseUntil.After(v.IssuedAt) && v.LeaseUntil.Sub(v.IssuedAt) <= 15*time.Second && !v.LeaseUntil.After(v.SessionUntil) && v.ActivateUntil.After(v.IssuedAt) && !v.ActivateUntil.After(v.LeaseUntil) && v.ActivateUntil.Sub(v.IssuedAt) <= 5*time.Second && v.SessionUntil.After(v.IssuedAt) && v.SessionUntil.Sub(v.IssuedAt) <= time.Hour && v.Resource.Until.Equal(v.SessionUntil)
}
func validHosting(v HostingSnapshot) bool {
	if v.Version != Version || !pki.ValidID(v.ConnectorID) || !pki.ValidID(v.ConnectorCertificateID) || v.PolicyRevision < 1 || v.CheckedAt.IsZero() || !v.Until.After(v.CheckedAt) || v.Until.Sub(v.CheckedAt) > 15*time.Second || v.Resources == nil || len(v.Resources) > MaxHostingResources {
		return false
	}
	seen := map[string]bool{}
	for _, r := range v.Resources {
		if !validResource(r.Resource) || r.Resource.ConnectorID != v.ConnectorID || seen[r.Resource.ID] || !pki.ValidID(r.HostBindingID) || r.From.IsZero() || r.From.After(v.CheckedAt) || !r.Until.After(v.CheckedAt) || !r.Until.Equal(r.Resource.Until) || v.Until.After(r.Until) {
			return false
		}
		seen[r.Resource.ID] = true
	}
	return true
}
func (r CancellationRequest) Valid() bool {
	if r.Version != Version || r.Limit < 1 || r.Limit > MaxCancellationBatch || r.WaitMillis < 0 || r.WaitMillis > 1000 || len(r.SessionIDs) > r.Limit {
		return false
	}
	seen := map[string]bool{}
	for _, id := range r.SessionIDs {
		if !pki.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validCancellations(v CancellationBatch, r CancellationRequest) bool {
	if !r.Valid() || v.Version != Version || !pki.ValidID(v.ConnectorCertificateID) || v.PolicyRevision < 1 || v.ObservedAt.IsZero() || v.Items == nil || len(v.Items) > r.Limit {
		return false
	}
	wanted := map[string]bool{}
	for _, id := range r.SessionIDs {
		wanted[id] = true
	}
	seen := map[string]bool{}
	for _, c := range v.Items {
		if !pki.ValidID(c.SessionID) || seen[c.SessionID] || (len(wanted) > 0 && !wanted[c.SessionID]) || (c.Reason != "closed" && c.Reason != "denied" && c.Reason != "expired") {
			return false
		}
		seen[c.SessionID] = true
	}
	return true
}
