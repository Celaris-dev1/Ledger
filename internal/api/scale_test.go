package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

// TestScaleLargeGoalAndPayloads: a 10k-record goal and near-limit payloads through the real
// store: replay, export caps, goal tree, approvals, incident review and verification stay
// correct and bounded in time.
func TestScaleLargeGoalAndPayloads(t *testing.T) {
	st := storetest.Open(t)
	ctx := context.Background()
	const N = 10000
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < N; i += 16 {
				typ, pl := "ledger.action.attempted", fmt.Sprintf(`{"attempt_id":"at%d","tool":"t","action":{"n":%d}}`, i, i)
				switch i % 4 {
				case 1:
					typ, pl = "ledger.approval.requested", fmt.Sprintf(`{"request_id":"r%d","action":{"n":%d}}`, i-1, i-1)
				case 2:
					typ, pl = "ledger.approval.granted", fmt.Sprintf(`{"request_id":"r%d","action":{"n":%d}}`, i-2, i-2)
				case 3:
					typ, pl = "ledger.verification.recorded", fmt.Sprintf(`{"attempt_id":"at%d","verifier":"v","passed":true}`, i-3)
				}
				if _, err := st.Append(ctx, store.AppendRequest{Chain: fmt.Sprintf("big%d", w%4), Type: typ, GoalID: "big-goal",
					ActorChain: []store.Actor{{Kind: "human", ID: "a"}, {Kind: "agent", ID: "x"}}, Payload: json.RawMessage(pl)}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	p := &projection.PG{Pool: st.Pool, Batch: 1000}
	start := time.Now()
	if _, err := p.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("projected %d records in %s", N, time.Since(start))
	s := &Server{Store: st, Projections: p, Limits: Limits{MaxExportRecords: N}}
	h := s.Handler()
	timed := func(path string, want int) *httptest.ResponseRecorder {
		t.Helper()
		t0 := time.Now()
		w := do(t, h, "GET", path, "", "")
		if w.Code != want {
			t.Fatalf("%s: %d %.200s", path, w.Code, w.Body.String())
		}
		if d := time.Since(t0); d > 20*time.Second {
			t.Fatalf("%s took %s", path, d)
		}
		t.Logf("%s: %d bytes in %s", path, w.Body.Len(), time.Since(t0))
		return w
	}
	w := timed("/v1/goals/big-goal/replay", 200)
	var rep struct{ Records []store.Record }
	_ = json.Unmarshal(w.Body.Bytes(), &rep)
	if len(rep.Records) != N {
		t.Fatalf("replay returned %d", len(rep.Records))
	}
	timed("/v1/goals/big-goal", 200)
	timed("/v1/approvals?limit=100", 200)
	timed("/v1/incidents/big-goal", 200)
	timed("/v1/chains/big0/verify", 200)
	s.Limits.MaxExportRecords = N - 1
	h = s.Handler()
	timed("/v1/goals/big-goal/replay", 413)
	// payloads near the body cap
	big := `{"chain":"p","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{"blob":"` + strings.Repeat("x", 4<<20-200) + `"}}`
	if w := do(t, h, "POST", "/v1/records", big, ""); w.Code != 201 {
		t.Fatalf("near-limit payload: %d %.200s", w.Code, w.Body.String())
	}
	if v, err := st.Verify(ctx, "p"); err != nil || !v.OK {
		t.Fatalf("verify big payload chain: %+v %v", v, err)
	}
}
