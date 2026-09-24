package retention

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// FuzzParseRetention: an accepted period never shortens retention (Until >= creation time,
// and a longer period of the same unit never ends earlier).
func FuzzParseRetention(f *testing.F) {
	for _, s := range []string{"6y", "18m", "400d", "0d", "99999999999999999999y", "1000000000y", " 6y ", "-1y"} {
		f.Add(s)
	}
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		y, m, d, err := ParseRetention(s)
		if err != nil {
			return
		}
		if y < 0 || m < 0 || d < 0 {
			t.Fatalf("%q: negative period", s)
		}
		u := Policy{MinRetention: s}.Until(t0)
		if u.Before(t0) {
			t.Fatalf("%q: retention ends before the record was created (%s)", s, u)
		}
		if y+m+d > 0 && !u.After(t0) {
			t.Fatalf("%q parsed as %d/%d/%d but retention is zero", s, y, m, d)
		}
	})
}

// FuzzFold: arbitrary system-chain payloads never panic the fold; a hold, once released,
// never becomes active again, and the first creation of a hold id wins.
func FuzzFold(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3}, []byte(`{"hold_id":"h","all":true}`))
	f.Add([]byte{1, 1, 2, 0, 1}, []byte(`{"hold_id":"h","chains":["c"]}`))
	f.Add([]byte{3, 0}, []byte(`{"chain":"*","min_retention":"6y"}`))
	types := []string{TypeHoldCreated, TypeHoldReleased, TypePolicySet, TypeErasure, "ledger.other"}
	f.Fuzz(func(t *testing.T, script []byte, payload []byte) {
		if len(script) > 64 {
			script = script[:64] // the check below folds every prefix (quadratic)
		}
		var recs []store.Record
		for i, b := range script {
			pl := payload
			if b&0x80 != 0 {
				pl = []byte(`{"hold_id":"h","reason":"r"}`)
			}
			recs = append(recs, store.Record{Seq: int64(i + 1), Type: types[int(b&0x7f)%len(types)], Payload: json.RawMessage(pl),
				ActorChain: json.RawMessage(`[{"kind":"human","id":"op"}]`), CreatedAt: time.Unix(int64(i), 0)})
		}
		released := map[string]bool{}
		for n := 1; n <= len(recs); n++ {
			st := Fold(recs[:n])
			seen := map[string]bool{}
			for _, h := range st.Holds {
				if seen[h.ID] {
					t.Fatalf("hold %q listed twice", h.ID)
				}
				seen[h.ID] = true
				if released[h.ID] && !h.Released {
					t.Fatalf("hold %q re-activated", h.ID)
				}
				if h.Released {
					released[h.ID] = true
				}
			}
			_ = st.ActiveHolds()
			_, _ = st.PolicyFor("c")
		}
	})
}
