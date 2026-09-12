package controller

import (
	"context"
	"crypto/tls"
	"database/sql"
	"time"

	"portico.local/portico/internal/pki"
)

const dashboardPageLimit = 50

// DashboardRequest uses keyset pagination. A continuation must name the policy
// revision returned with its first page; changing authority requires a refresh.
type DashboardRequest struct {
	Section        string
	After          string
	Limit          int
	PolicyRevision int64
}

type DashboardPage struct {
	Version        int
	Section        string
	PolicyRevision int64
	ObservedAt     time.Time
	Items          any
	Next           string
}

// These DTOs deliberately have no invitation tokens/hashes, CSR/certificate
// blobs, private keys, factor credentials, or pending ceremony/approval data.
// Enabled is stored configuration, never an effective-access decision.
type DashboardUser struct {
	ID, Name string
	Enabled  bool
}
type DashboardDevice struct {
	ID, UserID, Name, Platform string
	Enabled                    bool
	NotAfter                   time.Time
}
type DashboardConnector struct {
	ID, Name, Version string
	Enabled           bool
}
type DashboardResource struct {
	ID                               string
	Revision                         int64
	Name, ConnectorID, Kind, Address string
	Port                             int
	Protocol                         string
	Enabled                          bool
}
type DashboardEnrollment struct {
	ID, IssuerID, PrincipalID, Profile, State string
	ExpiresAt, NotAfter                       time.Time
}
type DashboardCertificate struct {
	ID, IssuerID, PrincipalID, Profile string
	NotBefore, NotAfter                time.Time
	Revoked                            bool
}

// DashboardInventory is a metadata-only read, authenticated from the real TLS
// peer again on every request, including reused connections. It neither grants
// authority nor supplies a secret-reveal path. Mutations retain their existing
// preview and hardware-approval handlers.
func (s *Store) DashboardInventory(ctx context.Context, conn *tls.Conn, trust *pki.Trust, request DashboardRequest) (DashboardPage, error) {
	if request.Limit < 1 || request.Limit > dashboardPageLimit || request.PolicyRevision < 0 ||
		(request.After != "" && (!validID(request.After) || request.PolicyRevision == 0)) {
		return DashboardPage{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	der, err := adminDER(ctx, conn)
	if err != nil {
		return DashboardPage{}, err
	}
	var result DashboardPage
	err = s.Update(ctx, NewID(), func(tx *Tx) error {
		if _, err := tx.adminPeer(trust, der); err != nil {
			return err
		}
		var revision int64
		if err := tx.tx.QueryRowContext(ctx, "SELECT revision FROM policy_meta WHERE singleton=1").Scan(&revision); err != nil {
			return tx.fail(ErrStorage)
		}
		if request.PolicyRevision != 0 && request.PolicyRevision != revision {
			return tx.fail(ErrConflict)
		}
		result = DashboardPage{Version: 1, Section: request.Section, PolicyRevision: revision, ObservedAt: tx.now}
		var err error
		switch request.Section {
		case "users":
			result.Items, result.Next, err = dashboardRows(tx, request, "SELECT id,name,enabled FROM users WHERE id>? ORDER BY id LIMIT ?", func(rows *sql.Rows) (DashboardUser, string, error) {
				var v DashboardUser
				e := rows.Scan(&v.ID, &v.Name, &v.Enabled)
				return v, v.ID, e
			})
		case "devices":
			result.Items, result.Next, err = dashboardRows(tx, request, "SELECT id,user_id,name,platform,enabled,not_after FROM devices WHERE id>? ORDER BY id LIMIT ?", func(rows *sql.Rows) (DashboardDevice, string, error) {
				var v DashboardDevice
				var expiry int64
				e := rows.Scan(&v.ID, &v.UserID, &v.Name, &v.Platform, &v.Enabled, &expiry)
				v.NotAfter = time.Unix(0, expiry).UTC()
				return v, v.ID, e
			})
		case "connectors":
			result.Items, result.Next, err = dashboardRows(tx, request, "SELECT id,name,version,enabled FROM connectors WHERE id>? ORDER BY id LIMIT ?", func(rows *sql.Rows) (DashboardConnector, string, error) {
				var v DashboardConnector
				e := rows.Scan(&v.ID, &v.Name, &v.Version, &v.Enabled)
				return v, v.ID, e
			})
		case "resources":
			result.Items, result.Next, err = dashboardRows(tx, request, "SELECT r.id,r.revision,r.name,r.connector_id,r.kind,r.address,r.port,r.protocol,r.enabled FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision WHERE r.id>? ORDER BY r.id LIMIT ?", func(rows *sql.Rows) (DashboardResource, string, error) {
				var v DashboardResource
				e := rows.Scan(&v.ID, &v.Revision, &v.Name, &v.ConnectorID, &v.Kind, &v.Address, &v.Port, &v.Protocol, &v.Enabled)
				return v, v.ID, e
			})
		case "enrollments":
			result.Items, result.Next, err = dashboardRows(tx, request, "SELECT e.id,e.issuer_id,COALESCE(e.device_id,e.connector_id),b.profile,e.state,e.expires_at,e.not_after FROM enrollments e JOIN pki_bindings b ON b.issuer_id=e.issuer_id WHERE e.id>? ORDER BY e.id LIMIT ?", func(rows *sql.Rows) (DashboardEnrollment, string, error) {
				var v DashboardEnrollment
				var expiry, notAfter int64
				e := rows.Scan(&v.ID, &v.IssuerID, &v.PrincipalID, &v.Profile, &v.State, &expiry, &notAfter)
				v.ExpiresAt, v.NotAfter = time.Unix(0, expiry).UTC(), time.Unix(0, notAfter).UTC()
				return v, v.ID, e
			})
		case "certificates":
			result.Items, result.Next, err = dashboardRows(tx, request, "SELECT id,issuer_id,COALESCE(device_id,connector_id),profile,not_before,not_after,revoked FROM certificates WHERE id>? ORDER BY id LIMIT ?", func(rows *sql.Rows) (DashboardCertificate, string, error) {
				var v DashboardCertificate
				var before, after int64
				e := rows.Scan(&v.ID, &v.IssuerID, &v.PrincipalID, &v.Profile, &before, &after, &v.Revoked)
				v.NotBefore, v.NotAfter = time.Unix(0, before).UTC(), time.Unix(0, after).UTC()
				return v, v.ID, e
			})
		default:
			return tx.fail(ErrInvalid)
		}
		return err
	})
	if err != nil {
		return DashboardPage{}, err
	}
	return result, nil
}

// Query text is selected only by the fixed switch above. Reading one extra row
// lets the response provide an exact continuation without an unbounded count.
func dashboardRows[T any](tx *Tx, request DashboardRequest, query string, scan func(*sql.Rows) (T, string, error)) ([]T, string, error) {
	rows, err := tx.tx.QueryContext(tx.ctx, query, request.After, request.Limit+1)
	if err != nil {
		return nil, "", tx.fail(ErrStorage)
	}
	defer func() { _ = rows.Close() }()
	items := make([]T, 0, request.Limit)
	last, next := "", ""
	for rows.Next() {
		v, id, err := scan(rows)
		if err != nil || !validID(id) {
			return nil, "", tx.fail(ErrIntegrity)
		}
		if len(items) == request.Limit {
			next = last
			break
		}
		items, last = append(items, v), id
	}
	if rows.Err() != nil {
		return nil, "", tx.fail(ErrStorage)
	}
	return items, next, nil
}
