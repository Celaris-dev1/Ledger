package api

import (
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/tenant"
)

// Regression (hardening): any appender could write ledger's own system records through the
// API — e.g. append ledger.hold.released to the "ledger" chain and so lift a legal hold that
// blocks erasure (retention folds that chain), or fake ledger.backup.created evidence.
func TestSystemRecordTypesNotAppendableViaAPI(t *testing.T) {
	h := (&Server{Store: &memBackend{}}).Handler()
	for _, typ := range []string{"ledger.hold.released", "ledger.hold.created", "ledger.retention.policy.set", "ledger.erasure", "ledger.key.rotated", "ledger.backup.created"} {
		body := `{"chain":"ledger","type":"` + typ + `","actor_chain":[{"kind":"human","id":"mallory"}],"payload":{"hold_id":"lit-7"}}`
		if w := do(t, h, "POST", "/v1/records", body, ""); w.Code != 403 {
			t.Errorf("%s on system chain: %d %s", typ, w.Code, w.Body)
		}
		other := `{"chain":"app","type":"` + typ + `","actor_chain":[{"kind":"human","id":"a"}],"payload":{}}`
		if w := do(t, h, "POST", "/v1/records", other, ""); w.Code != 201 {
			t.Errorf("%s on another chain: %d", typ, w.Code)
		}
	}
	// ordinary ledger.* vocabulary records on the ledger chain stay allowed
	ok := `{"chain":"ledger","type":"ledger.goal.created","goal_id":"g","actor_chain":[{"kind":"human","id":"a"}],"payload":{}}`
	if w := do(t, h, "POST", "/v1/records", ok, ""); w.Code != 201 {
		t.Fatalf("vocabulary record: %d", w.Code)
	}
	// the default tenant's bare "ledger" is the system chain too; another tenant's is not
	ts := &Server{Store: &memBackend{}, Tenants: map[string]string{"tokD": "default", "tokA": "acme"},
		TenantStore: func(t string) (Backend, error) { return tenant.New(nil, t) }}
	th := ts.Handler()
	body := `{"chain":"ledger","type":"ledger.hold.released","actor_chain":[{"kind":"human","id":"m"}],"payload":{}}`
	if w := do(t, th, "POST", "/v1/records", body, "tokD"); w.Code != 403 {
		t.Fatalf("default tenant: %d %s", w.Code, w.Body)
	}
}
