package tenant

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

// Defense in depth: the tenant column is derived and not hashed. If it is altered, a scoped
// read must still only return rows whose hashed chain name belongs to the tenant.
func TestScopedReadsIgnoreAlteredTenantColumn(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	acme, _ := New(st, "acme")
	if _, err := acme.Append(ctx, store.AppendRequest{Chain: "x", Type: "t", GoalID: "g",
		ActorChain: []store.Actor{{Kind: "human", ID: "h"}}, Payload: json.RawMessage(`{"secret":1}`)}); err != nil {
		t.Fatal(err)
	}
	tx, _ := st.Pool.Begin(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skip(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE records SET tenant='evil'`); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	evil, _ := New(st, "evil")
	if recs, _ := evil.List(ctx, store.Query{}); len(recs) != 0 {
		t.Fatalf("list leaked %d foreign records", len(recs))
	}
	if recs, _ := evil.Replay(ctx, "g"); len(recs) != 0 {
		t.Fatalf("replay leaked %d foreign records", len(recs))
	}
}
