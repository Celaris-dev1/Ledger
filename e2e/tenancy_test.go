//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// probe GETs a URL and returns status + up to ~1.5s of body (so SSE streams can be sampled).
func probe(t *testing.T, u, token string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body) // returns on EOF or when the context expires (SSE)
	return resp.StatusCode, string(b)
}

// tenantPaths are every read surface: API, projections, incident, export, UI pages, SSE.
func tenantPaths() []string {
	return []string{
		"/v1/records?chain=gate", "/v1/records?goal_id=g-shared", "/v1/records?chain=t/globex/gate", "/v1/records?chain=t/acme/gate",
		"/v1/chains/gate/verify", "/v1/chains/gate/root", "/v1/chains/gate/anchors", "/v1/goals/g-shared/replay",
		"/v1/export?goal_id=g-shared", "/v1/export?chain=gate&format=html",
		"/v1/goals", "/v1/goals/g-shared", "/v1/approvals", "/v1/budgets/g-shared", "/v1/incidents/g-shared?format=json",
		"/v1/stream?from=start", "/v1/stream?from=start&chain=gate", "/v1/stream?from=start&goal_id=g-shared",
		"/chains", "/chains/gate", "/chains/t%2Fglobex%2Fgate", "/goals", "/goals/g-shared", "/approvals", "/budgets?goal=g-shared",
		"/incidents/g-shared", "/r/t%2Fglobex%2Fgate/1", "/r/t%2Facme%2Fgate/1", "/r/t/globex/gate/1", "/ui/api/status",
	}
}

func seedTenants(t *testing.T, d *Daemon, tokA, tokB string) {
	t.Helper()
	for _, x := range []struct{ tok, marker string }{{tokA, "ACME-SECRET"}, {tokB, "GLOBEX-SECRET"}} {
		for i := 0; i < 3; i++ {
			d.Append(x.tok, map[string]any{"chain": "gate", "type": "gate.run.started", "goal_id": "g-shared",
				"actor_chain": []Actor{human("alice"), agent("coder")}, "payload": map[string]any{"run_id": fmt.Sprintf("r%d", i), "marker": x.marker}})
		}
	}
}

// assertIsolation: tenant A never sees B's data (and vice versa), anonymous sees nothing.
func assertIsolation(t *testing.T, d *Daemon, tokA, tokB string) {
	t.Helper()
	for _, p := range tenantPaths() {
		for _, c := range []struct {
			who, tok  string
			forbidden []string
		}{
			{"acme", tokA, []string{"GLOBEX-SECRET", "t/globex"}}, {"globex", tokB, []string{"ACME-SECRET", "t/acme"}},
			{"anonymous", "", []string{"SECRET", "t/acme", "t/globex"}}, {"bogus-token", "not-a-token", []string{"SECRET", "t/acme", "t/globex"}},
		} {
			st, body := probe(t, d.URL+p, c.tok)
			for _, f := range c.forbidden {
				if strings.Contains(body, f) {
					t.Errorf("CROSS-TENANT READ: %s GET %s -> %d contains %s:\n%.300s", c.who, p, st, f, body)
				}
			}
		}
	}
	// Own data is readable through the tenant-scoped contract routes.
	if st, body := probe(t, d.URL+"/v1/records?chain=gate", tokA); st != 200 || !strings.Contains(body, "ACME-SECRET") {
		t.Errorf("acme cannot read its own chain: %d %.200s", st, body)
	}
	if st, body := probe(t, d.URL+"/v1/goals/g-shared/replay", tokB); st != 200 || !strings.Contains(body, "GLOBEX-SECRET") {
		t.Errorf("globex cannot replay its own goal: %d %.200s", st, body)
	}
}

func createToken(t *testing.T, e *Env, name, role string) string {
	t.Helper()
	out := e.MustLedger("token", "create", "--name", name, "--role", role)
	tok := regexp.MustCompile(`ldg_[A-Za-z0-9_\-]+`).FindString(out)
	if tok == "" {
		t.Fatalf("no token in output: %s", out)
	}
	return tok
}

// uiLogin signs in with a token through the real login form; returns a cookie-carrying client.
func uiLogin(t *testing.T, d *Daemon, token string) (*http.Client, int, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(d.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(string(b))
	if m == nil {
		m = regexp.MustCompile(`name="(?:_csrf|csrf_token)" value="([^"]+)"`).FindStringSubmatch(string(b))
	}
	if m == nil {
		t.Fatalf("no CSRF field on /login:\n%s", b)
	}
	form := url.Values{"token": {token}, "next": {"/chains"}}
	form.Set(csrfField(string(b)), m[1])
	req, _ := http.NewRequest("POST", d.URL+"/auth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", d.URL)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return c, resp.StatusCode, resp.Header.Get("Location")
}

func csrfField(page string) string {
	m := regexp.MustCompile(`name="([^"]*csrf[^"]*)" value=`).FindStringSubmatch(page)
	if m == nil {
		return "csrf"
	}
	return m[1]
}

// TestTenancyWithRBAC runs ledgerd as it is really deployed: LEDGER_TOKENS for tenants, API
// tokens with roles, and each open-mode setting.
func TestTenancyWithRBAC(t *testing.T) {
	const tokA, tokB, ops = "tok-acme-0123456789", "tok-globex-0123456789", "tok-ops-0123456789"
	tenants := tokA + "=acme," + tokB + "=globex," + ops + "=*"

	t.Run("api-tokens", func(t *testing.T) {
		e := NewEnv(t).With("LEDGER_TOKENS", tenants)
		admin := createToken(t, e, "root", "admin")
		auditor := createToken(t, e, "aud", "auditor")
		viewer := createToken(t, e, "view", "viewer")
		writer := createToken(t, e, "harbour", "writer")
		d := e.Start()
		seedTenants(t, d, tokA, tokB)
		assertIsolation(t, d, tokA, tokB)

		// Writer: appends, cannot use the UI, projections, stream or export.
		d.Append(writer, map[string]any{"chain": "harbour", "type": "harbour.goal.transition", "goal_id": "g-w",
			"actor_chain": []Actor{human("bob")}, "payload": map[string]any{"to": "running"}})
		for _, p := range []string{"/chains", "/goals", "/v1/goals", "/v1/stream?from=start", "/v1/export?chain=harbour"} {
			if st, body := probe(t, d.URL+p, writer); st == 200 {
				t.Errorf("writer GET %s -> 200 %.200s", p, body)
			}
		}
		if _, st, loc := uiLogin(t, d, writer); st != http.StatusSeeOther || !strings.Contains(loc, "error") {
			t.Errorf("writer token signed in to the UI: %d %s", st, loc)
		}
		// Auditor exports; viewer can view but not export; admin can do both.
		for _, c := range []struct {
			tok        string
			export, ui bool
		}{{auditor, true, true}, {viewer, false, true}, {admin, true, true}} {
			st, _ := probe(t, d.URL+"/v1/export?chain=harbour", c.tok)
			if (st == 200) != c.export {
				t.Errorf("export as %s -> %d (want allowed=%v)", c.tok[:8], st, c.export)
			}
			st, _ = probe(t, d.URL+"/incidents/g-w?format=json&download=1", c.tok)
			_ = st
			cl, st, loc := uiLogin(t, d, c.tok)
			if st != http.StatusSeeOther || strings.Contains(loc, "error") {
				t.Errorf("UI login -> %d %s", st, loc)
				continue
			}
			resp, err := cl.Get(d.URL + "/chains")
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(b), "harbour") {
				t.Errorf("UI /chains after login: %d", resp.StatusCode)
			}
		}
		// Viewer cannot export through the CLI-equivalent API either, and cannot append.
		if r := d.Do("POST", "/v1/records", viewer, map[string]any{"chain": "x", "type": "x", "actor_chain": []Actor{human("v")}}); r.Status != 403 {
			t.Errorf("viewer append -> %d", r.Status)
		}
		// A tenant token cannot reach the operator routes, names cannot escape the tenant.
		for _, p := range []string{"/v1/goals", "/v1/incidents/g-shared", "/v1/stream?from=start", "/chains"} {
			if st, _ := probe(t, d.URL+p, tokA); st == 200 {
				t.Errorf("tenant token GET %s -> 200", p)
			}
		}
		if r := d.Do("POST", "/v1/records", tokA, map[string]any{"chain": "t/globex/gate", "type": "x", "actor_chain": []Actor{human("m")}}); r.Status == 201 {
			t.Errorf("tenant appended into another tenant's chain")
		}
		// Operator (*) sees both tenants' physical chains.
		if st, body := probe(t, d.URL+"/v1/records?chain=t/globex/gate", ops); st != 200 || !strings.Contains(body, "GLOBEX") {
			t.Errorf("operator read: %d %.200s", st, body)
		}
	})

	for _, mode := range []string{"auto", "off"} {
		t.Run("tenancy-only-auth-"+mode, func(t *testing.T) {
			// No API tokens, no LEDGER_TOKEN, no SSO: auto mode would be "open".
			e := NewEnv(t).With("LEDGER_TOKENS", tenants)
			if mode == "off" {
				e = e.With("LEDGER_AUTH", "off")
			}
			d := e.Start()
			seedTenants(t, d, tokA, tokB)
			assertIsolation(t, d, tokA, tokB)
		})
	}

	t.Run("auth-on-no-tenancy", func(t *testing.T) {
		e := NewEnv(t).With("LEDGER_AUTH", "on", "LEDGER_TOKEN", "legacy-writer-token")
		d := e.Start()
		d.Append("legacy-writer-token", map[string]any{"chain": "gate", "type": "gate.run.started", "actor_chain": []Actor{human("a")}, "payload": map[string]any{"marker": "SECRET"}})
		for _, p := range tenantPaths() {
			if st, body := probe(t, d.URL+p, ""); strings.Contains(body, "SECRET") {
				t.Errorf("anonymous GET %s -> %d leaks data", p, st)
			}
		}
		// LEDGER_TOKEN is a writer: may not read the UI.
		if st, _ := probe(t, d.URL+"/chains", "legacy-writer-token"); st == 200 {
			t.Errorf("legacy writer token reads the UI")
		}
	})
}
