package projection

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

// fuzzTypes is every mapped record type plus a few unknown/near-miss ones.
func fuzzTypes() []string {
	var ts []string
	for _, v := range Vocabulary {
		ts = append(ts, v.Type)
	}
	for _, p := range ProductMappings {
		ts = append(ts, strings.TrimSuffix(p.Type, "*")+map[bool]string{true: "x", false: ""}[strings.HasSuffix(p.Type, "*")])
	}
	return append(ts, "ledger.", "ledger.goal", "unknown.type", "")
}

var fuzzKeys = []string{"title", "status", "reason", "step_no", "description", "tool_id", "name", "version", "attempt_id", "tool",
	"action", "action_hash", "arguments", "tool_version", "outcome", "result", "verifier", "passed", "evidence", "request_id",
	"resource", "amount", "operator_id", "fact", "value", "operator_kind", "key", "run_id", "stage", "decision", "repo", "base",
	"head", "scope", "capture_id", "url", "token_id", "subject", "max_calls", "effect_id", "step", "manifest_hash", "cause", "caused_by",
	"effect", "record_id", "reference", "refs", "policy_version", "rule", "id", "kind"}

var fuzzValues = []any{"", "a", "b", "at1", "r1", "g1", "t1", "usd", "pass", "block", "committed", "failed", "done", "open",
	"\u0000", "�", strings.Repeat("x", 300), 0, 1, -1, 2.5, 1e308, -1e308, json.Number("1e400"), json.Number("-0"),
	json.Number("123456789012345678901234567890"), true, false, nil, []any{}, []any{1, "a"}, map[string]any{},
	map[string]any{"tool": "t", "n": 1}, map[string]any{"a": map[string]any{"b": []any{nil}}}}

// fuzzStream turns fuzz bytes into a record stream over small id spaces (so ops collide).
func fuzzStream(data []byte) []store.Record {
	types := fuzzTypes()
	b := testfix.New()
	next := func() int {
		if len(data) == 0 {
			return 0
		}
		v := int(data[0])
		data = data[1:]
		return v
	}
	for n := 0; len(data) > 0 && n < 200; n++ {
		typ := types[next()%len(types)]
		chain := []string{"ledger", "gate", "warrant", "harbour", "proof"}[next()%5]
		goal := []string{"g1", "g2", "", "g\u0000"}[next()%4]
		pl := map[string]any{}
		for k := next() % 6; k > 0; k-- {
			pl[fuzzKeys[next()%len(fuzzKeys)]] = fuzzValues[next()%len(fuzzValues)]
		}
		b.Add(chain, typ, goal, testfix.Actors([]string{"alice", "bob"}[next()%2], []string{"a1", "svc:s1"}[next()%2]), pl)
	}
	return b.Recs
}

// FuzzProjection: arbitrary record streams never panic the mapper, folds or query builders,
// and incremental projection (random per-chain interleaving with redelivery) always equals
// a rebuild in global order.
func FuzzProjection(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, int64(1))
	f.Add([]byte(strings.Repeat("\x08\x00\x01\x03\x05\x11\x07\x13\x09", 20)), int64(7))
	f.Fuzz(func(t *testing.T, data []byte, seed int64) {
		recs := fuzzStream(data)
		for _, r := range recs {
			ops, _ := Map(r)
			if b, _ := json.Marshal(ops); strings.Contains(string(b), `\u0000`) {
				t.Fatalf("op carries U+0000 (Postgres rejects it): %s", b)
			}
		}
		rebuild := project(recs)
		byChain := map[string][]store.Record{}
		var chains []string
		for _, r := range recs {
			if _, ok := byChain[r.Chain]; !ok {
				chains = append(chains, r.Chain)
			}
			byChain[r.Chain] = append(byChain[r.Chain], r)
		}
		rng := rand.New(rand.NewSource(seed))
		m := NewModel()
		for {
			var open []string
			for _, c := range chains {
				if m.Cursor(c) < int64(len(byChain[c])) {
					open = append(open, c)
				}
			}
			if len(open) == 0 {
				break
			}
			c := open[rng.Intn(len(open))]
			cur := int(m.Cursor(c))
			start := cur
			if cur > 0 && rng.Intn(4) == 0 {
				start = cur - 1
			}
			for i := start; i < cur+1+rng.Intn(4) && i < len(byChain[c]); i++ {
				m.Apply(byChain[c][i])
			}
		}
		incr := m.Rows()
		if d := Diff(rebuild, incr); d != "" {
			t.Fatalf("rebuild != incremental: %s", d)
		}
		// query builders over hostile rows
		for _, g := range []string{"", "g1", "g2", "g\u0000", "missing"} {
			_, _ = BuildTree(incr, g)
			_ = Budgets(incr, g)
		}
		_ = Goals(incr)
		_ = Approvals(incr, "")
		_ = Approvals(incr, "pending")
		if _, err := json.Marshal(incr); err != nil {
			t.Fatalf("rows not serialisable: %v", err)
		}
	})
}
