package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

// memStore is an in-memory Backend + StreamSource over a correctly hash-chained record set.
type memStore struct {
	mu   sync.Mutex
	recs []store.Record
	b    *testfix.Builder
}

func (m *memStore) all() []store.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.Record(nil), m.recs...)
}

func (m *memStore) Append(_ context.Context, req store.AppendRequest) (*store.Record, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.b.Add(req.Chain, req.Type, req.GoalID, req.ActorChain, string(req.Payload))
	m.recs = append(m.recs, r)
	return &r, nil
}

func (m *memStore) List(_ context.Context, q store.Query) ([]store.Record, error) {
	var out []store.Record
	for _, r := range m.all() {
		if (q.Chain == "" || r.Chain == q.Chain) && (q.GoalID == "" || r.GoalID == q.GoalID) && r.Seq > q.AfterSeq {
			out = append(out, r)
		}
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (m *memStore) Replay(ctx context.Context, g string) ([]store.Record, error) {
	return m.List(ctx, store.Query{GoalID: g})
}
func (m *memStore) ChainRecords(ctx context.Context, c string) ([]store.Record, error) {
	return m.List(ctx, store.Query{Chain: c})
}
func (m *memStore) Verify(ctx context.Context, c string) (store.VerifyResult, error) {
	r, _ := m.ChainRecords(ctx, c)
	return store.VerifyRecords(c, r), nil
}
func (m *memStore) Head(ctx context.Context, c string) (int64, string, error) {
	r, _ := m.ChainRecords(ctx, c)
	if len(r) == 0 {
		return 0, "", nil
	}
	return r[len(r)-1].Seq, r[len(r)-1].Hash, nil
}
func (m *memStore) Chains(context.Context) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range m.all() {
		if !seen[r.Chain] {
			seen[r.Chain] = true
			out = append(out, r.Chain)
		}
	}
	sort.Strings(out)
	return out, nil
}
func (m *memStore) Heads(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for _, r := range m.all() {
		out[r.Chain] = r.Seq
	}
	return out, nil
}
func (m *memStore) Since(_ context.Context, cur map[string]int64, chain, goal string, limit int) (map[string][]store.Record, error) {
	out := map[string][]store.Record{}
	for _, r := range m.all() {
		if (chain == "" || r.Chain == chain) && (goal == "" || r.GoalID == goal) && r.Seq > cur[r.Chain] && len(out[r.Chain]) < limit {
			out[r.Chain] = append(out[r.Chain], r)
		}
	}
	return out, nil
}

type fakeReceipts struct{}

func (fakeReceipts) Receipts(_ context.Context, chain string) ([]anchoring.StoredReceipt, error) {
	if chain != "gate" {
		return nil, nil
	}
	return []anchoring.StoredReceipt{{Chain: "gate", Seq: 1, Backend: "rfc3161", Kind: "tsa"}, {Chain: "gate", Seq: 1, Backend: "git"}}, nil
}

const hostile = `</script><script>alert(1)</script><img src=x onerror=alert(2)>`

type env struct {
	ts     *httptest.Server
	st     *memStore
	authn  *auth.Authenticator
	tokens map[string]string
}

func newEnv(t *testing.T, open bool) *env {
	b := testfix.MultiProduct()
	hostileGoal := "javascript:alert(3)"
	b.Add("gate", "gate.stage.completed", "goal-incident-7", testfix.Actors(hostile, "agent<b>"),
		map[string]any{"run_id": "gate-run-3", "stage": hostile, "status": "pass", "summary": hostile, "url": "javascript:alert(4)"})
	b.Add("ledger", "ledger.goal.created", hostileGoal, testfix.Actors("h"), map[string]any{"title": hostile})
	st := &memStore{b: b, recs: append([]store.Record(nil), b.Recs...)}
	m := projection.NewModel()
	for _, r := range st.recs {
		m.Apply(r)
	}
	as := auth.NewMemory()
	e := &env{st: st, tokens: map[string]string{}}
	for _, role := range auth.Roles {
		p, _, err := auth.NewToken(context.Background(), as, role+"-tok", role, "test")
		if err != nil {
			t.Fatal(err)
		}
		e.tokens[role] = p
	}
	e.tokens["legacy"] = "legacy-secret"
	e.authn = auth.New(auth.Config{Open: open, LegacyToken: "legacy-secret"}, as)
	apiSrv := &api.Server{Store: st, Projections: projection.ModelReader{M: m}, Auth: e.authn}
	hub := NewHub()
	apiSrv.OnAppend = func(*store.Record) { hub.Kick() }
	ui := &Server{Store: st, Projections: projection.ModelReader{M: m}, Receipts: fakeReceipts{}, Auth: e.authn, API: apiSrv.Handler(),
		Stream: &Streamer{Src: st, Hub: hub, Poll: 50 * time.Millisecond, Heartbeat: time.Second, Batch: 3}}
	e.ts = httptest.NewServer(ui.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (e *env) req(t *testing.T, method, path, token, body string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	c := &http.Client{CheckRedirect: noRedirect}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return string(b)
}

// browser logs in with a token through the login form and returns a cookie client + CSRF.
func (e *env) browser(t *testing.T, role string) (*http.Client, string) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(e.ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(resp)
	csrf := between(page, `name="csrf_token" value="`, `"`)
	resp, err = c.PostForm(e.ts.URL+"/auth/token", url.Values{"token": {e.tokens[role]}, "csrf_token": {csrf}, "next": {"/goals"}})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(resp)
	if resp.Request.URL.Path != "/goals" {
		t.Fatalf("%s login landed on %s: %s", role, resp.Request.URL, body)
	}
	return c, between(body, `<meta name="csrf-token" content="`, `"`)
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	return s[:strings.Index(s, b)]
}

func TestPagesRenderAndEscape(t *testing.T) {
	e := newEnv(t, false)
	c, _ := e.browser(t, auth.RoleAuditor)
	pages := map[string]string{
		"/chains":                "gate",
		"/chains/gate":           "gate.stage.completed",
		"/goals":                 "goal-incident-7",
		"/goals?q=incident":      "goal-incident-7",
		"/goals/goal-incident-7": "Replay",
		"/goals/" + url.PathEscape("javascript:alert(3)"): "Replay",
		"/approvals?status=":                              "apr-1",
		"/budgets":                                        "Budgets",
		"/incidents/goal-incident-7":                      "Incident review",
		"/r/gate/5":                                       "Recomputed in your browser",
		"/r/gate/1":                                       "anchored",
	}
	for p, want := range pages {
		resp, err := c.Get(e.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(resp)
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Fatalf("%s: %d, missing %q", p, resp.StatusCode, want)
		}
		for _, bad := range []string{"<script>alert", "<img src=x", `href="javascript:`, "onerror=alert(2)>"} {
			if strings.Contains(body, bad) {
				t.Fatalf("%s: unescaped hostile content %q", p, bad)
			}
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Fatalf("%s: CSP %q", p, csp)
		}
		for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			if resp.Header.Get(h) == "" {
				t.Fatalf("%s: missing %s", p, h)
			}
		}
		if strings.Contains(body, " style=") || strings.Contains(body, "<script>") {
			t.Fatalf("%s: inline style/script would violate CSP", p)
		}
	}
	// the hostile payload is present, escaped, on the record page
	resp, _ := c.Get(e.ts.URL + "/r/gate/5")
	if body := readAll(resp); !strings.Contains(body, "&lt;/script&gt;&lt;script&gt;alert(1)") {
		t.Fatal("escaped payload missing")
	}
	// status JSON for the side panel
	resp, _ = c.Get(e.ts.URL + "/ui/api/status?chain=gate&seq=1")
	var st StatusResponse
	_ = json.Unmarshal([]byte(readAll(resp)), &st)
	if !st.RecordOK || !st.Anchor.Covered || st.Anchor.CoverSeq != 1 || len(st.Anchor.CoverWitnesses) != 2 {
		t.Fatalf("status %+v", st)
	}
	resp, _ = c.Get(e.ts.URL + "/r/nope/1")
	if resp.StatusCode != 404 {
		t.Fatalf("missing record: %d", resp.StatusCode)
	}
}

func TestRBACMatrix(t *testing.T) {
	e := newEnv(t, false)
	post := `{"chain":"x","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{}}`
	type route struct{ method, path, body string }
	routes := map[string]route{
		"append": {"POST", "/v1/records", post}, "records": {"GET", "/v1/records", ""}, "verify": {"GET", "/v1/chains/gate/verify", ""},
		"replay": {"GET", "/v1/goals/goal-incident-7/replay", ""}, "goals": {"GET", "/v1/goals", ""}, "stream": {"GET", "/v1/stream?from=start", ""},
		"export": {"GET", "/v1/export?chain=gate", ""}, "incident-md": {"GET", "/v1/incidents/goal-incident-7?format=md", ""},
		"whoami": {"GET", "/v1/whoami", ""},
	}
	allow := map[string][]string{
		"admin":   {"append", "records", "verify", "replay", "goals", "stream", "export", "incident-md", "whoami"},
		"auditor": {"records", "verify", "replay", "goals", "stream", "export", "incident-md", "whoami"},
		"viewer":  {"records", "verify", "replay", "goals", "stream", "whoami"},
		"writer":  {"append", "records", "verify", "replay", "whoami"},
		"legacy":  {"append", "records", "verify", "replay", "whoami"},
		"none":    {},
	}
	for who, ok := range allow {
		okSet := map[string]bool{}
		for _, r := range ok {
			okSet[r] = true
		}
		for name, rt := range routes {
			tok := e.tokens[who]
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			r, _ := http.NewRequestWithContext(ctx, rt.method, e.ts.URL+rt.path, strings.NewReader(rt.body))
			if tok != "" {
				r.Header.Set("Authorization", "Bearer "+tok)
			}
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			resp.Body.Close()
			cancel()
			got := resp.StatusCode < 300
			if got != okSet[name] {
				t.Errorf("%s %s: status %d, allowed=%v", who, name, resp.StatusCode, okSet[name])
			}
			if !got && who == "none" && resp.StatusCode != 401 {
				t.Errorf("none %s: want 401, got %d", name, resp.StatusCode)
			}
		}
	}
	// UI pages: writers cannot sign in, unauthenticated browsers are redirected to login
	resp := e.req(t, "GET", "/goals", "", "")
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=%2Fgoals") {
		t.Fatalf("anon ui: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := e.req(t, "GET", "/goals", e.tokens["writer"], ""); resp.StatusCode != 403 {
		t.Fatalf("writer ui: %d", resp.StatusCode)
	}
	if resp := e.req(t, "GET", "/admin", e.tokens["auditor"], ""); resp.StatusCode != 403 {
		t.Fatalf("auditor admin: %d", resp.StatusCode)
	}
	if resp := e.req(t, "GET", "/admin", e.tokens["admin"], ""); resp.StatusCode != 200 {
		t.Fatalf("admin admin: %d", resp.StatusCode)
	}
	// export links only shown to exporters
	vc, _ := e.browser(t, auth.RoleViewer)
	r, _ := vc.Get(e.ts.URL + "/goals/goal-incident-7")
	if strings.Contains(readAll(r), "/v1/export") {
		t.Fatal("viewer sees export link")
	}
	// writer token cannot log into the UI
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	lr, _ := c.Get(e.ts.URL + "/login")
	csrf := between(readAll(lr), `name="csrf_token" value="`, `"`)
	lr, _ = c.PostForm(e.ts.URL+"/auth/token", url.Values{"token": {e.tokens["writer"]}, "csrf_token": {csrf}})
	if readAll(lr); lr.Request.URL.Path != "/login" {
		t.Fatal("writer signed into UI")
	}
	// revoked tokens stop working
	toks, _ := e.authn.Store.ListTokens(context.Background())
	for _, tk := range toks {
		if tk.Role == "viewer" {
			_ = e.authn.Store.RevokeToken(context.Background(), tk.ID)
		}
	}
	if resp := e.req(t, "GET", "/v1/goals", e.tokens["viewer"], ""); resp.StatusCode != 401 {
		t.Fatalf("revoked token: %d", resp.StatusCode)
	}
	if r, _ := vc.Get(e.ts.URL + "/goals"); r.Request.URL.Path != "/login" {
		t.Fatal("session of revoked token still valid")
	}
}

func TestCSRFAndAdmin(t *testing.T) {
	e := newEnv(t, false)
	c, csrf := e.browser(t, auth.RoleAdmin)
	if csrf == "" {
		t.Fatal("no csrf meta")
	}
	// unsafe cookie request without token is refused
	resp, _ := c.PostForm(e.ts.URL+"/admin/tokens", url.Values{"name": {"x"}, "role": {"writer"}})
	if resp.StatusCode != 403 {
		t.Fatalf("no csrf: %d", resp.StatusCode)
	}
	// cross-origin with token is refused
	r, _ := http.NewRequest("POST", e.ts.URL+"/admin/tokens", strings.NewReader(url.Values{"name": {"x"}, "role": {"writer"}, "csrf_token": {csrf}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	if resp, _ := c.Do(r); resp.StatusCode != 403 {
		t.Fatalf("cross origin: %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(e.ts.URL+"/admin/tokens", url.Values{"name": {"agent-<b>"}, "role": {"writer"}, "csrf_token": {csrf}})
	body := readAll(resp)
	plain := between(body, `<pre class="payload mono" tabindex="0">`, `</pre>`)
	if resp.StatusCode != 200 || !strings.HasPrefix(plain, auth.TokenPrefix) || strings.Contains(body, "agent-<b>") {
		t.Fatalf("create: %d %q", resp.StatusCode, plain)
	}
	// the new writer token appends; its plaintext is not stored
	toks, _ := e.authn.Store.ListTokens(context.Background())
	for _, tk := range toks {
		if tk.Hash == plain || strings.Contains(tk.Hash, plain) {
			t.Fatal("plaintext stored")
		}
	}
	post := `{"chain":"new","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{}}`
	if resp := e.req(t, "POST", "/v1/records", plain, post); resp.StatusCode != 201 {
		t.Fatalf("new writer append: %d", resp.StatusCode)
	}
	// cookie POST to the API needs the CSRF header
	r, _ = http.NewRequest("POST", e.ts.URL+"/v1/records", strings.NewReader(post))
	if resp, _ := c.Do(r); resp.StatusCode != 403 {
		t.Fatalf("cookie api post without csrf: %d", resp.StatusCode)
	}
	r, _ = http.NewRequest("POST", e.ts.URL+"/v1/records", strings.NewReader(post))
	r.Header.Set(auth.CSRFHeader, csrf)
	if resp, _ := c.Do(r); resp.StatusCode != 201 {
		t.Fatalf("cookie api post with csrf: %d", resp.StatusCode)
	}
	// logout ends the session
	resp, _ = c.PostForm(e.ts.URL+"/auth/logout", url.Values{"csrf_token": {csrf}})
	readAll(resp)
	if r, _ := c.Get(e.ts.URL + "/chains"); r.Request.URL.Path != "/login" {
		t.Fatal("still signed in after logout")
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/goals?q=1": "/goals?q=1", "//evil.com": "/", "/\\evil.com": "/", "https://evil.com": "/",
		"/\t/evil.com": "/", "javascript:alert(1)": "/", "/auth/login": "/", "": "/"} {
		if got := auth.SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenModeUnchanged(t *testing.T) {
	e := newEnv(t, true)
	if resp := e.req(t, "GET", "/v1/export?chain=gate", "", ""); resp.StatusCode != 200 {
		t.Fatalf("open export: %d", resp.StatusCode)
	}
	resp := e.req(t, "GET", "/chains", "", "")
	if body := readAll(resp); resp.StatusCode != 200 || !strings.Contains(body, "Open mode") {
		t.Fatalf("open ui: %d", resp.StatusCode)
	}
}

type sseEvent struct{ id, event, data string }

func readEvents(t *testing.T, r *bufio.Reader, n int) []sseEvent {
	var out []sseEvent
	var cur sseEvent
	for len(out) < n {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended after %d events: %v", len(out), err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			if cur.event != "" {
				out = append(out, cur)
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, "id: "):
			cur.id = line[4:]
		case strings.HasPrefix(line, "event: "):
			cur.event = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.data = line[6:]
		}
	}
	return out
}

func openStream(t *testing.T, e *env, path, lastID string) (*bufio.Reader, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := http.NewRequestWithContext(ctx, "GET", e.ts.URL+path, nil)
	r.Header.Set("Authorization", "Bearer "+e.tokens["viewer"])
	if lastID != "" {
		r.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %v %v", err, resp)
	}
	return bufio.NewReader(resp.Body), func() { cancel(); resp.Body.Close() }
}

func TestStreamResume(t *testing.T) {
	e := newEnv(t, false)
	goal := "goal-incident-7"
	var want []string
	for _, r := range e.st.all() {
		if r.GoalID == goal {
			want = append(want, r.Chain+"#"+itoa(r.Seq))
		}
	}
	rd, stop := openStream(t, e, "/v1/stream?from=start&goal_id="+goal, "")
	first := readEvents(t, rd, 5)
	stop()
	// resume from the 5th event's id: no gaps, no duplicates
	rd, stop = openStream(t, e, "/v1/stream?goal_id="+goal, first[4].id)
	rest := readEvents(t, rd, len(want)-5)
	var got []string
	for _, ev := range append(first, rest...) {
		var r store.Record
		if err := json.Unmarshal([]byte(ev.data), &r); err != nil || ev.event != "record" || r.GoalID != goal {
			t.Fatalf("bad event %+v", ev)
		}
		got = append(got, r.Chain+"#"+itoa(r.Seq))
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	// live: an append is pushed to the open stream
	body := `{"chain":"harbour","type":"harbour.goal.transition","goal_id":"goal-incident-7","actor_chain":[{"kind":"human","id":"alice"}],"payload":{"to":"done"}}`
	if resp := e.req(t, "POST", "/v1/records", e.tokens["writer"], body); resp.StatusCode != 201 {
		t.Fatalf("append %d", resp.StatusCode)
	}
	live := readEvents(t, rd, 1)
	stop()
	if !strings.Contains(live[0].data, `"to":"done"`) {
		t.Fatalf("live event %+v", live[0])
	}
	// default start is "now": nothing old is replayed
	rd, stop = openStream(t, e, "/v1/stream?chain=gate", "")
	defer stop()
	line, _ := rd.ReadString('\n')
	if !strings.HasPrefix(line, "retry:") {
		t.Fatalf("preamble %q", line)
	}
	r, _ := http.NewRequest("GET", e.ts.URL+"/v1/stream", nil)
	r.Header.Set("Authorization", "Bearer "+e.tokens["viewer"])
	r.Header.Set("Last-Event-ID", "%%%")
	if resp, _ := http.DefaultClient.Do(r); resp.StatusCode != 400 {
		t.Fatalf("bad cursor: %d", resp.StatusCode)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestCursorRoundTrip(t *testing.T) {
	c := map[string]int64{"a b": 3, "gate": 12}
	got, ok := DecodeCursor(EncodeCursor(c))
	if !ok || got["a b"] != 3 || got["gate"] != 12 {
		t.Fatalf("%v", got)
	}
	if _, ok := DecodeCursor("gate=-1"); ok {
		t.Fatal("negative accepted")
	}
}
