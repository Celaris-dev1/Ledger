package tenant_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/api"
	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
	"github.com/Celaris-dev1/Ledger/internal/tenant"
)

func TestParseTokens(t *testing.T) {
	m, err := tenant.ParseTokens("a1=acme, g1=globex ,op=*,d=default")
	if err != nil || m["a1"] != "acme" || m["g1"] != "globex" || m["op"] != "*" || m["d"] != "default" {
		t.Fatal(m, err)
	}
	for _, bad := range []string{"x", "=acme", "t=Bad Tenant", "t=a/b"} {
		if _, err := tenant.ParseTokens(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

type client struct {
	t   *testing.T
	url string
	tok string
}

func (c client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.url+path, rd)
	req.Header.Set("Authorization", "Bearer "+c.tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func rec(chain, goal string, payload map[string]any) map[string]any {
	return map[string]any{"chain": chain, "type": "gate.run.decided", "goal_id": goal,
		"actor_chain": []map[string]string{{"kind": "human", "id": "alice"}}, "payload": payload}
}

// Strict isolation: no tenant can read, verify, replay, export or write another tenant's
// chains through the API, even with identical chain names and goal ids.
func TestNoCrossTenantReads(t *testing.T) {
	st := storetest.Open(t)
	srv := &api.Server{Store: st,
		Tenants: map[string]string{"tok-acme": "acme", "tok-globex": "globex", "tok-default": "default", "tok-op": "*"},
		TenantStore: func(t string) (api.Backend, error) {
			return tenant.New(st, t)
		}}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	acme, globex, def, op := client{t, hs.URL, "tok-acme"}, client{t, hs.URL, "tok-globex"}, client{t, hs.URL, "tok-default"}, client{t, hs.URL, "tok-op"}

	for i := 0; i < 3; i++ {
		if code, out := acme.do("POST", "/v1/records", rec("gate", "g1", map[string]any{"secret": "acme-" + string(rune('a'+i))})); code != 201 || out["chain"] != "gate" {
			t.Fatalf("acme append %d %v", code, out)
		}
	}
	if code, _ := globex.do("POST", "/v1/records", rec("gate", "g1", map[string]any{"secret": "globex"})); code != 201 {
		t.Fatal(code)
	}
	if code, _ := def.do("POST", "/v1/records", rec("gate", "g1", map[string]any{"secret": "default"})); code != 201 {
		t.Fatal(code)
	}
	// reserved prefix cannot be used to write into another tenant
	if code, _ := globex.do("POST", "/v1/records", rec("t/acme/gate", "g1", nil)); code != 400 {
		t.Fatalf("reserved prefix append: %d", code)
	}

	secrets := func(out map[string]any) []string {
		var s []string
		rs, _ := out["records"].([]any)
		for _, r := range rs {
			pl := r.(map[string]any)["payload"].(map[string]any)
			s = append(s, pl["secret"].(string))
		}
		return s
	}
	for _, c := range []struct {
		cl   client
		want string
		n    int
	}{{acme, "acme-", 3}, {globex, "globex", 1}, {def, "default", 1}} {
		for _, path := range []string{"/v1/records", "/v1/records?chain=gate", "/v1/goals/g1/replay", "/v1/export?chain=gate"} {
			code, out := c.cl.do("GET", path, nil)
			if code != 200 {
				t.Fatalf("%s %s: %d", c.cl.tok, path, code)
			}
			var got []string
			if strings.HasPrefix(path, "/v1/export") {
				chs := out["chains"].([]any)
				got = secrets(map[string]any{"records": chs[0].(map[string]any)["records"]})
			} else {
				got = secrets(out)
			}
			if len(got) != c.n {
				t.Fatalf("%s %s: got %v", c.cl.tok, path, got)
			}
			for _, g := range got {
				if !strings.HasPrefix(g, c.want) {
					t.Fatalf("CROSS-TENANT LEAK: %s read %q via %s", c.cl.tok, g, path)
				}
			}
		}
		code, v := c.cl.do("GET", "/v1/chains/gate/verify", nil)
		if code != 200 || v["ok"] != true || int(v["length"].(float64)) != c.n {
			t.Fatalf("%s verify %v", c.cl.tok, v)
		}
		// cannot address other tenants' physical chains
		for _, other := range []string{"t/acme/gate", "t/globex/gate"} {
			code, out := c.cl.do("GET", "/v1/records?chain="+other, nil)
			if code != 200 || len(secrets(out)) != 0 {
				t.Fatalf("%s read %s: %v", c.cl.tok, other, out)
			}
		}
		// cross-chain projection routes are operator-only
		if code, _ := c.cl.do("GET", "/v1/goals", nil); code != 403 {
			t.Fatalf("%s /v1/goals: %d", c.cl.tok, code)
		}
	}
	// operator sees everything, under physical names
	_, all := op.do("GET", "/v1/records", nil)
	if n := len(secrets(all)); n != 5 {
		t.Fatalf("operator sees %d", n)
	}
	// unknown token
	if code, _ := (client{t, hs.URL, "nope"}).do("GET", "/v1/records", nil); code != 401 {
		t.Fatal(code)
	}
	// tenant chains still verify as ordinary chains and the tenant is bound into the hash
	res, _ := st.Verify(context.Background(), "t/acme/gate")
	if !res.OK || res.Length != 3 {
		t.Fatal(res)
	}
	recs, _ := st.ChainRecords(context.Background(), "t/acme/gate")
	moved := recs[0]
	moved.Chain = "t/globex/gate"
	if h, _ := store.ComputeHash(&moved); h == recs[0].Hash {
		t.Fatal("tenant not bound into the hash")
	}
}

// ledgerd always enables RBAC (api.Server.Auth). Tenant tokens must still take the tenant path,
// and an unauthenticated request must never get operator access through RBAC open mode.
func TestTenancyWithRBAC(t *testing.T) {
	st := storetest.Open(t)
	for _, open := range []bool{true, false} {
		as := auth.NewMemory()
		admTok, _, err := auth.NewToken(context.Background(), as, "adm", auth.RoleAdmin, "test")
		if err != nil {
			t.Fatal(err)
		}
		srv := &api.Server{Store: st,
			Auth:    auth.New(auth.Config{Open: open}, as),
			Tenants: map[string]string{"tok-acme": "acme", "tok-globex": "globex"},
			TenantStore: func(t string) (api.Backend, error) {
				return tenant.New(st, t)
			}}
		hs := httptest.NewServer(srv.Handler())
		acme, globex, anon, adm := client{t, hs.URL, "tok-acme"}, client{t, hs.URL, "tok-globex"}, client{t, hs.URL, ""}, client{t, hs.URL, admTok}
		chain := fmt.Sprintf("rbac-%v", open)
		if code, out := acme.do("POST", "/v1/records", rec(chain, "g", map[string]any{"secret": "acme"})); code != 201 {
			t.Fatalf("open=%v acme append: %d %v", open, code, out)
		}
		if code, out := globex.do("GET", "/v1/records?chain="+chain, nil); code != 200 || len(out["records"].([]any)) != 0 {
			t.Fatalf("open=%v globex saw acme's chain: %d %v", open, code, out)
		}
		if code, _ := acme.do("GET", "/v1/goals", nil); code != 403 {
			t.Fatalf("open=%v tenant token on operator route: %d", open, code)
		}
		if code, _ := anon.do("GET", "/v1/records", nil); code != 401 {
			t.Fatalf("open=%v unauthenticated request with tenancy on: %d, want 401", open, code)
		}
		if code, out := adm.do("GET", "/v1/records?chain=t/acme/"+chain, nil); code != 200 || len(out["records"].([]any)) != 1 {
			t.Fatalf("open=%v RBAC admin (operator) read: %d %v", open, code, out)
		}
		hs.Close()
	}
}
