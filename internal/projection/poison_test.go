package projection

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Regression (hardening): a payload string containing U+0000 is valid JSON and is stored (the
// records table uses json, not jsonb), but Postgres jsonb/text columns reject NUL. The
// projector used to fail on such a record forever, blocking every later record of the chain.
func TestPGProjectorSurvivesNULPayloads(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p := &PG{Pool: s.Pool}
	ac := []store.Actor{{Kind: "human", ID: "alice"}, {Kind: "agent", ID: "a1"}}
	app := func(typ string, pl string) {
		t.Helper()
		if _, err := s.Append(ctx, store.AppendRequest{Chain: "ledger", Type: typ, GoalID: "g1", ActorChain: ac, Payload: json.RawMessage(pl)}); err != nil {
			t.Fatal(err)
		}
	}
	app("ledger.goal.created", `{"title":"a\u0000b"}`)
	app("ledger.memory.written", `{"key":"k\u0000","value":{"x\u0000":"\u0000"}}`)
	app("ledger.action.attempted", `{"attempt_id":"at\u0000","tool":"t","action":{"q":"\u0000"}}`)
	app("ledger.verification.recorded", `{"attempt_id":"at\u0000","verifier":"v","passed":true,"evidence":{"e":"\u0000"}}`)
	app("ledger.identity.asserted", `{"operator_id":"a1","fact":"f\u0000","value":"\u0000"}`)
	app("ledger.step.planned", `{"step_no":1,"description":"\u0000"}`)
	app("ledger.goal.status", `{"status":"done"}`)
	if _, err := p.CatchUp(ctx); err != nil {
		t.Fatalf("projector stuck on NUL payload: %v", err)
	}
	var cur int64
	_ = s.Pool.QueryRow(ctx, `SELECT seq FROM projection_cursors WHERE chain='ledger'`).Scan(&cur)
	if cur != 7 {
		t.Fatalf("cursor %d, want 7", cur)
	}
	if d, err := p.Check(ctx); err != nil || d != "" {
		t.Fatalf("stored != model: %v %s", err, d)
	}
	r, err := p.Rows(ctx, "g1")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Goals) != 1 || r.Goals[0].Status != "done" {
		t.Fatalf("goal: %+v", r.Goals)
	}
}
