package compliance

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

// End to end against Postgres: records, anchors (file backend), a key rotation and a
// retention policy all flow into the pack; anchors are re-verified; the pack is signed.
func TestGatherFromPostgres(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	for _, r := range testfix.MultiProduct().Recs {
		if _, err := st.Append(ctx, testfix.Request(r)); err != nil {
			t.Fatal(err)
		}
	}
	kr, err := anchor.OpenKeyring(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := &anchoring.Service{Store: st, Key: kr.Active, Keyring: kr, Backends: []anchoring.Backend{&anchoring.FileBackend{Dir: t.TempDir()}}}
	if _, _, err := svc.RotateKey(ctx, "security-officer", false); err != nil {
		t.Fatal(err)
	}
	rs := &retention.Service{Store: st}
	for _, c := range []string{"gate", "warrant", "harbour", "proof", "ledger", "bench"} {
		if _, err := svc.AnchorChain(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := rs.SetPolicy(ctx, retention.Policy{Chain: c, Regime: "soc2"}, "compliance-officer"); err != nil {
			t.Fatal(err)
		}
	}
	g := &Gatherer{Store: st, Anchors: svc, Signer: keys.Ed25519Signer{Key: kr.Active}, Now: func() time.Time { return now }}
	ev, err := g.Gather(ctx, Scope{Chains: []string{"gate", "warrant", "harbour"}})
	if err != nil {
		t.Fatal(err)
	}
	soc, _ := Lookup("soc2", "")
	r := Evaluate(soc, ev)
	for id, want := range map[string]string{"SOC2-INT-1": Pass, "SOC2-INT-2": Pass, "SOC2-INT-3": Pass, "CC6.1-KM": Pass, "CC7.2": Pass, "CC8.1": Pass} {
		if c := control(r, id); c.Status != want {
			t.Errorf("%s = %s: %s", id, c.Status, c.Summary)
		}
	}
	if len(r.Integrity.KeyRotations) != 1 || !r.Integrity.AnchorsOK || r.Integrity.Chains[0].Root == nil || !anchor.VerifyRoot(*r.Integrity.Chains[0].Root) {
		t.Fatalf("%+v", r.Integrity)
	}
	if err := Sign(ctx, &r, g.Signer); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	var back Report
	_ = json.Unmarshal(b, &back)
	if err := Verify(back, nil); err != nil {
		t.Fatal(err)
	}
	// time window excludes everything -> the logging controls become gaps, integrity still passes
	ev2, _ := g.Gather(ctx, Scope{Chains: []string{"gate"}, From: time.Now().Add(time.Hour)})
	r2 := Evaluate(soc, ev2)
	if r2.RecordCount != 0 || control(r2, "CC8.1").Status != Gap || control(r2, "SOC2-INT-1").Status != Pass {
		t.Fatalf("%d %s", r2.RecordCount, control(r2, "CC8.1").Status)
	}
	// goal scope
	ev3, _ := g.Gather(ctx, Scope{GoalID: "goal-incident-7"})
	if len(ev3.Scope.Chains) != 4 || len(ev3.Records) == 0 {
		t.Fatalf("%v %d", ev3.Scope.Chains, len(ev3.Records))
	}
}
