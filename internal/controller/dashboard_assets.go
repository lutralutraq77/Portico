package controller

import (
	"context"
	"crypto/tls"
	"embed"
	"net/http"
	"time"
)

// No inline code, third-party resources, framing, forms, or persistence is
// required by this inventory view. The private TLS API remains its authority.
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'"

//go:embed dashboard/index.html dashboard/admin.css dashboard/admin.js
var dashboardAssets embed.FS

// Assets are also private: recheck the registered leaf and current principal on
// every request, even when a browser reuses an authenticated TLS connection.
func (s *Store) serveDashboardAsset(w http.ResponseWriter, r *http.Request, conn *tls.Conn, c PolicyHTTPConfig) error {
	var name, contentType string
	switch r.URL.Path {
	case "/admin":
		name, contentType = "index.html", "text/html; charset=utf-8"
	case "/admin.css":
		name, contentType = "admin.css", "text/css; charset=utf-8"
	case "/admin.js":
		name, contentType = "admin.js", "text/javascript; charset=utf-8"
	default:
		return ErrDenied
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Type") != "" || r.Header.Get("Range") != "" {
		return ErrDenied
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != "https://"+c.Host) {
		return ErrDenied
	}
	// Top-level navigation normally has no Origin. Fetch Metadata is an extra
	// browser boundary, never a substitute for actual certificate authentication.
	sites := r.Header.Values("Sec-Fetch-Site")
	if len(sites) > 1 || (len(sites) == 1 && sites[0] != "none" && sites[0] != "same-origin") {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	der, err := adminDER(ctx, conn)
	if err != nil {
		return err
	}
	if err := s.Update(ctx, NewID(), func(tx *Tx) error {
		_, err := tx.adminPeer(c.AdministratorTrust, der)
		return err
	}); err != nil {
		return err
	}
	data, err := dashboardAssets.ReadFile("dashboard/" + name)
	if err != nil {
		return ErrStorage
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return nil
}
