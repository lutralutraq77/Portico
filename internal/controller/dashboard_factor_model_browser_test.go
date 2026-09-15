//go:build dashboardbrowser

package controller

import (
	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/testfixture"
	"testing"
)

func chromiumBrowserModel(t *testing.T) adminauth.Model {
	t.Helper()
	id, roots := testfixture.ChromiumAttestation(t)
	return adminauth.Model{AAGUID: id, RootsDER: roots}
}
