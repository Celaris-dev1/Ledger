package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// memBackend is an in-memory Backend for handler tests.
type memBackend struct{ recs []store.Record }

func (m *memBackend) Append(_ context.Context, req store.AppendRequest) (*store.Record, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ac, _ := json.Marshal(req.ActorChain)
	prev := ""
	var seq int64 = 1
	for _, r := range m.recs {
		if r.Chain == req.Chain {
			prev, seq = r.Hash, r.Seq+1
		}
	}
	r := store.Record{ID: "id", Chain: req.Chain, Seq: seq, Type: req.Type, GoalID: req.GoalID, ActorChain: ac, Payload: req.Payload, CreatedAt: time.Now().UTC(), PrevHash: prev}
	r.Hash, _ = store.ComputeHash(&r)
	m.recs = append(m.recs, r)
	return &r, nil
}
func (m *memBackend) List(context.Context, store.Query) ([]store.Record, error) { return m.recs, nil }
func (m *memBackend) Replay(_ context.Context, g string) ([]store.Record, error) {
	var out []store.Record
	for _, r := range m.recs {
		if r.GoalID == g {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memBackend) ChainRecords(_ context.Context, c string) ([]store.Record, error) {
	var out []store.Record
	for _, r := range m.recs {
		if r.Chain == c {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memBackend) Verify(ctx context.Context, c string) (store.VerifyResult, error) {
	r, _ := m.ChainRecords(ctx, c)
	return store.VerifyRecords(c, r), nil
}
func (m *memBackend) Head(ctx context.Context, c string) (int64, string, error) {
	r, _ := m.ChainRecords(ctx, c)
	if len(r) == 0 {
		return 0, "", nil
	}
	return r[len(r)-1].Seq, r[len(r)-1].Hash, nil
}

func do(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAPIContract(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	h := (&Server{Store: &memBackend{}, Token: "sekret", Key: key}).Handler()
	body := `{"chain":"gate","type":"gate.run.started","goal_id":"g1","actor_chain":[{"kind":"human","id":"alice"}],"payload":{"a":1}}`
	if w := do(t, h, "POST", "/v1/records", body, ""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	w := do(t, h, "POST", "/v1/records", body, "sekret")
	if w.Code != 201 {
		t.Fatalf("post: %d %s", w.Code, w.Body)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	for _, k := range []string{"id", "chain", "seq", "hash", "prev_hash", "created_at"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("response missing %s", k)
		}
	}
	bad := `{"chain":"gate","type":"x","actor_chain":[{"kind":"agent","id":"bot"}],"payload":{}}`
	if w := do(t, h, "POST", "/v1/records", bad, "sekret"); w.Code != 400 {
		t.Fatalf("agent-first actor chain: %d", w.Code)
	}
	w = do(t, h, "GET", "/v1/chains/gate/verify", "", "sekret")
	var v store.VerifyResult
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if !v.OK || v.Length != 1 || !strings.Contains(w.Body.String(), `"broken_at":null`) {
		t.Fatalf("verify: %s", w.Body)
	}
	w = do(t, h, "GET", "/v1/chains/gate/root", "", "sekret")
	var root anchor.Root
	_ = json.Unmarshal(w.Body.Bytes(), &root)
	if !anchor.VerifyRoot(root) || root.Head != v.Head || root.Seq != 1 {
		t.Fatalf("root: %s", w.Body)
	}
	w = do(t, h, "GET", "/v1/goals/g1/replay", "", "sekret")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "gate.run.started") {
		t.Fatalf("replay: %s", w.Body)
	}
	w = do(t, h, "GET", "/v1/export?goal_id=g1&format=html", "", "sekret")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Article 14") {
		t.Fatalf("export: %d", w.Code)
	}
}

type fakeAnchors struct{ verify bool }

func (f *fakeAnchors) ChainAnchors(_ context.Context, chain string, verify bool) (any, error) {
	f.verify = verify
	return map[string]any{"chain": chain, "anchors": []any{}}, nil
}

func TestAnchorsEndpoint(t *testing.T) {
	s := &Server{Store: &memBackend{}}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/v1/chains/c/anchors", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", rr.Code)
	}
	fa := &fakeAnchors{}
	s.Anchors = fa
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/v1/chains/c/anchors?verify=1", nil))
	if rr.Code != 200 || !fa.verify || !strings.Contains(rr.Body.String(), `"chain":"c"`) {
		t.Fatalf("%d %s", rr.Code, rr.Body)
	}
}
