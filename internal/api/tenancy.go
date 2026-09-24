package api

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/Celaris-dev1/Ledger/internal/tenant"
)

type tenantKey struct{}

// tokenTenant resolves "Bearer <token>" to its tenant with a constant-time compare per token.
func (s *Server) tokenTenant(authz string) (string, bool) {
	got, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok || got == "" {
		return "", false
	}
	found, ten := false, ""
	for tok, t := range s.Tenants {
		if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
			found, ten = true, t
		}
	}
	return ten, found
}

// tenantScopedRoute lists the routes whose data is scoped by tenant. Everything else (the
// projection query API, incident review) reads across chains and needs an operator token.
func tenantScopedRoute(pattern string) bool {
	switch pattern {
	case "GET /healthz", "POST /v1/records", "GET /v1/records", "GET /v1/chains/{chain}/verify",
		"GET /v1/chains/{chain}/root", "GET /v1/chains/{chain}/anchors", "GET /v1/goals/{goal_id}/replay", "GET /v1/export":
		return true
	}
	return false
}

// backend returns the store view for this request: the tenant-scoped store when multi-tenancy
// is on (operator tokens get the unscoped store), else Store.
func (s *Server) backend(w http.ResponseWriter, r *http.Request) (Backend, bool) {
	if len(s.Tenants) == 0 {
		return s.Store, true
	}
	t, _ := r.Context().Value(tenantKey{}).(string)
	if t == tenant.Admin {
		return s.Store, true
	}
	if t == "" || s.TenantStore == nil {
		writeErr(w, http.StatusForbidden, "no tenant for this token")
		return nil, false
	}
	be, err := s.TenantStore(t)
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return nil, false
	}
	return be, true
}

// physical maps a logical chain name to the stored name for tenant-scoped backends.
func physical(w http.ResponseWriter, be Backend, chain string) (string, bool) {
	ph, ok := be.(interface{ Physical(string) (string, error) })
	if !ok {
		return chain, true
	}
	p, err := ph.Physical(chain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return p, true
}
