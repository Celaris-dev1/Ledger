package incident

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

// reversed lists chains in the opposite order (Build must not depend on it).
type reversed struct{ fake }

func (r reversed) Chains(ctx context.Context) ([]string, error) {
	cs, _ := r.fake.Chains(ctx)
	out := append([]string(nil), cs...)
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

var refKeys = []string{"token_id", "parent_id", "run_id", "gate_run_id", "task_id", "request_id", "attempt_id", "capture_id", "action_hash", "manifest_hash", "other"}

// FuzzIncidentRefs: arbitrary cross-reference graphs (cycles, self references, shared values,
// nested payloads) terminate, never panic, and give the same report whatever the chain order.
func FuzzIncidentRefs(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{1, 1, 1, 1, 17, 17, 33, 33, 49, 49, 65, 65})
	f.Fuzz(func(t *testing.T, data []byte) {
		b := testfix.New()
		chains := []string{"gate", "warrant", "harbour", "proof", "bench"}
		types := []string{"gate.run.started", "warrant.call.allowed", "warrant.call.denied", "harbour.effect.intent", "harbour.effect.result",
			"ledger.action.attempted", "ledger.action.completed", "ledger.verification.recorded", "proof.fetch.captured", "x.y"}
		for i := 0; i+2 < len(data) && i < 300; i += 3 {
			pl := map[string]any{}
			// two refs per record over a tiny value space: cycles and long paths abound
			pl[refKeys[int(data[i])%len(refKeys)]] = string(rune('a' + data[i+1]%5))
			nested := map[string]any{refKeys[int(data[i+1])%len(refKeys)]: string(rune('a' + data[i+2]%5))}
			if data[i+2]%3 == 0 {
				pl["inner"] = []any{nested, nil, 3}
			} else {
				pl["x"] = nested
			}
			goal := ""
			if data[i+2]%7 == 0 {
				goal = "g"
			} else if data[i+2]%7 == 1 {
				goal = string(rune('a' + data[i]%5)) // run id used as goal id
			}
			b.Add(chains[int(data[i+2])%len(chains)], types[int(data[i])%len(types)], goal, testfix.Actors("h", "a"), pl)
		}
		ctx := context.Background()
		r1, err := Build(ctx, fake{b}, "g")
		if err != nil {
			t.Fatal(err)
		}
		r2, err := Build(ctx, reversed{fake{b}}, "g")
		if err != nil {
			t.Fatal(err)
		}
		if (r1 == nil) != (r2 == nil) {
			t.Fatal("presence depends on chain order")
		}
		if r1 == nil {
			return
		}
		r2.GeneratedAt = r1.GeneratedAt
		if !reflect.DeepEqual(r1, r2) {
			t.Fatalf("report depends on chain order / map iteration:\n%+v\n%+v", r1.Narrative, r2.Narrative)
		}
		ids := map[string]bool{}
		for _, e := range r1.Narrative {
			if ids[e.RecordID] {
				t.Fatalf("record %s twice in the narrative", e.RecordID)
			}
			ids[e.RecordID] = true
		}
		_ = store.Record{}
	})
}
