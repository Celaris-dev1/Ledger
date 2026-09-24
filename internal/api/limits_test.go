package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const okBody = `{"chain":"c","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{"x":1}}`

func TestPostRecordBodyLimits(t *testing.T) {
	h := (&Server{Store: &memBackend{}, Limits: Limits{MaxBodyBytes: 1024}}).Handler()
	big := `{"chain":"c","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{"x":"` + strings.Repeat("a", 2000) + `"}}`
	if w := do(t, h, "POST", "/v1/records", big, ""); w.Code != 413 || !strings.Contains(w.Body.String(), "LEDGER_MAX_BODY_BYTES") {
		t.Fatalf("oversized body: %d %s", w.Code, w.Body)
	}
	for _, b := range []string{okBody + `{"chain":"x"}`, okBody + `x`, okBody + `]`} {
		if w := do(t, h, "POST", "/v1/records", b, ""); w.Code != 400 {
			t.Fatalf("trailing data %q: %d %s", b, w.Code, w.Body)
		}
	}
	if w := do(t, h, "POST", "/v1/records", okBody+"\n  ", ""); w.Code != 201 {
		t.Fatalf("trailing whitespace: %d %s", w.Code, w.Body)
	}
	deep := `{"chain":"c","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{"x":` + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + `}}`
	h2 := (&Server{Store: &memBackend{}}).Handler()
	if w := do(t, h2, "POST", "/v1/records", deep, ""); w.Code != 400 {
		t.Fatalf("deep nesting: %d", w.Code)
	}
}

func TestExportAndReplayCaps(t *testing.T) {
	be := &memBackend{}
	s := &Server{Store: be, Limits: Limits{MaxExportRecords: 5}}
	h := s.Handler()
	for i := 0; i < 6; i++ {
		if w := do(t, h, "POST", "/v1/records", `{"chain":"c","type":"t","goal_id":"g","actor_chain":[{"kind":"human","id":"a"}],"payload":{}}`, ""); w.Code != 201 {
			t.Fatal(w.Body)
		}
	}
	if w := do(t, h, "GET", "/v1/export?chain=c", "", ""); w.Code != 413 {
		t.Fatalf("export cap: %d", w.Code)
	}
	if w := do(t, h, "GET", "/v1/goals/g/replay", "", ""); w.Code != 413 {
		t.Fatalf("replay cap: %d", w.Code)
	}
	s.Limits.MaxExportRecords = 6
	h = s.Handler()
	if w := do(t, h, "GET", "/v1/export?chain=c", "", ""); w.Code != 200 {
		t.Fatalf("export at cap: %d", w.Code)
	}
}

func TestGoalsAndApprovalsPagination(t *testing.T) {
	// 10k goals, each with one approval request.
	m := projection.NewModel()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 10000; i++ {
		g := fmt.Sprintf("goal-%05d", i)
		pl, _ := json.Marshal(map[string]any{"request_id": "rk-" + g, "action_hash": "h" + g})
		m.Apply(store.Record{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), Chain: "c", Seq: int64(i + 1), Type: "ledger.approval.requested",
			GoalID: g, ActorChain: json.RawMessage(`[{"kind":"human","id":"a"}]`), Payload: pl, CreatedAt: now.Add(time.Duration(i) * time.Second)})
	}
	h := (&Server{Store: &memBackend{}, Projections: projection.ModelReader{M: m}, Limits: Limits{MaxPage: 3000}}).Handler()
	seen := map[string]bool{}
	after, pages := "", 0
	for {
		w := do(t, h, "GET", "/v1/goals?limit=4000&after="+after, "", "")
		var resp struct {
			Goals []projection.GoalSummary `json:"goals"`
			Next  string                   `json:"next_after"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String()[:200])
		}
		if len(resp.Goals) > 3000 {
			t.Fatalf("page larger than MaxPage: %d", len(resp.Goals))
		}
		for _, g := range resp.Goals {
			if seen[g.ID] {
				t.Fatalf("duplicate %s", g.ID)
			}
			seen[g.ID] = true
		}
		pages++
		if resp.Next == "" {
			break
		}
		after = resp.Next
	}
	if len(seen) != 10000 || pages != 4 {
		t.Fatalf("saw %d goals in %d pages", len(seen), pages)
	}
	w := do(t, h, "GET", "/v1/approvals?status=pending&limit=2", "", "")
	var ap struct {
		Approvals []projection.ApprovalNode `json:"approvals"`
		Next      string                    `json:"next_after"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ap); err != nil || w.Code != 200 {
		t.Fatalf("approvals: %d", w.Code)
	}
	if len(ap.Approvals) != 2 || ap.Next == "" {
		t.Fatalf("approvals page: %d next=%q", len(ap.Approvals), ap.Next)
	}
	if w := do(t, h, "GET", "/v1/approvals?limit=0", "", ""); w.Code != 400 {
		t.Fatalf("bad limit: %d", w.Code)
	}
}

func TestPageHelper(t *testing.T) {
	id := func(s string) string { return s }
	items := []string{"c", "a", "b", "d"}
	got, next := page(items, id, "", 2)
	if strings.Join(got, "") != "ab" || next != "b" {
		t.Fatal(got, next)
	}
	got, next = page(items, id, "b", 2)
	if strings.Join(got, "") != "cd" || next != "" {
		t.Fatal(got, next)
	}
	got, _ = page(items, id, "zz", 2)
	if got == nil || len(got) != 0 {
		t.Fatal(got)
	}
}

func TestLimitsFromEnv(t *testing.T) {
	env := map[string]string{"LEDGER_MAX_PAGE": "50", "LEDGER_MAX_BODY_BYTES": "100", "LEDGER_REQUEST_TIMEOUT": "5s", "LEDGER_MAX_EXPORT_RECORDS": "7"}
	l, err := LimitsFromEnv(func(k string) string { return env[k] })
	if err != nil || l.MaxPage != 50 || l.MaxBodyBytes != 100 || l.RequestTimeout != 5*time.Second || l.MaxExportRecords != 7 {
		t.Fatal(l, err)
	}
	for k, v := range map[string]string{"LEDGER_MAX_PAGE": "-1", "LEDGER_MAX_BODY_BYTES": "x", "LEDGER_REQUEST_TIMEOUT": "soon"} {
		if _, err := LimitsFromEnv(func(q string) string {
			if q == k {
				return v
			}
			return ""
		}); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
}

func TestRequestTimeoutApplied(t *testing.T) {
	s := &Server{Limits: Limits{RequestTimeout: time.Millisecond}}
	var dl bool
	h := s.withTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { _, dl = r.Context().Deadline() }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !dl {
		t.Fatal("no deadline")
	}
}

// FuzzPostRecord: arbitrary bodies never produce a 5xx and a 201 only for a valid append.
func FuzzPostRecord(f *testing.F) {
	f.Add([]byte(okBody))
	f.Add([]byte(`{"chain":"c","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":[1]}`))
	f.Add([]byte(`{"chain":"c\u0000","type":"t","actor_chain":[{"kind":"human","id":"a"}]}`))
	f.Add([]byte(okBody + `{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		be := &memBackend{}
		h := (&Server{Store: be, Limits: Limits{MaxBodyBytes: 1 << 16}}).Handler()
		w := do(t, h, "POST", "/v1/records", string(body), "")
		if w.Code >= 500 {
			t.Fatalf("5xx for %q: %s", body, w.Body)
		}
		if w.Code == 201 {
			if len(be.recs) != 1 {
				t.Fatal("201 without a record")
			}
			var req store.AppendRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("201 for undecodable body %q", body)
			}
			if err := req.Validate(); err != nil {
				t.Fatalf("201 for invalid request: %v", err)
			}
		} else if len(be.recs) != 0 {
			t.Fatalf("%d but a record was appended", w.Code)
		}
	})
}
