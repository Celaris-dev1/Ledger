//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The cross-product scenario (LEDGER_XPRODUCT=1): Warrant, Harbour, Gate and Proof are built
// from their sibling checkouts (read-only: every build output goes to a temp dir) and write to a
// real ledgerd through their own Ledger clients, each with its own writer API token.

func xproductRoot(t *testing.T) string {
	t.Helper()
	if os.Getenv("LEDGER_XPRODUCT") != "1" {
		t.Skip("set LEDGER_XPRODUCT=1 (and have Gate, Warrant, Harbour-, Proof checked out next to Ledger) to run")
	}
	root := os.Getenv("LEDGER_XPRODUCT_ROOT")
	if root == "" {
		root = filepath.Dir(repoRoot)
		// Ledger may be a worktree (…/Ledger/.claude/worktrees/x): look upwards for the siblings.
		for d := repoRoot; d != "/" && d != "."; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(filepath.Dir(d), "Warrant", "go.mod")); err == nil {
				root = filepath.Dir(d)
				break
			}
		}
	}
	for _, r := range []string{"Gate", "Warrant", "Harbour-", "Proof"} {
		if _, err := os.Stat(filepath.Join(root, r)); err != nil {
			t.Fatalf("LEDGER_XPRODUCT=1 but %s/%s is missing", root, r)
		}
	}
	return root
}

func goBuild(t *testing.T, repo, pkg, out string) string {
	t.Helper()
	c := exec.Command("go", "build", "-o", out, pkg)
	c.Dir = repo
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("building %s %s: %v\n%s", repo, pkg, err, b)
	}
	return out
}

// proc is a long-running product daemon.
type proc struct {
	name string
	cmd  *exec.Cmd
	log  *syncBuf
	done chan struct{}
}

func startProc(t *testing.T, name, bin string, args, env []string, dir, health string) *proc {
	t.Helper()
	p := &proc{name: name, log: &syncBuf{}, done: make(chan struct{})}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Dir = dir
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		<-p.done
		if t.Failed() {
			t.Logf("%s log:\n%s", name, p.log.String())
		}
	})
	eventually(t, 20*time.Second, func() string {
		select {
		case <-p.done:
			t.Fatalf("%s exited:\n%s", name, p.log.String())
		default:
		}
		resp, err := http.Get(health)
		if err != nil {
			return err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return resp.Status
		}
		return ""
	})
	return p
}

func runCmd(t *testing.T, dir string, env []string, name string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Env = append(os.Environ(), env...)
	out, err := c.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return string(out), code
}

func postJSON(t *testing.T, u string, hdr map[string]string, body any, into any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", u, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	if into != nil {
		_ = json.NewDecoder(resp.Body).Decode(into)
	}
	return resp.StatusCode
}

func TestCrossProductIncident(t *testing.T) {
	root := xproductRoot(t)
	bin := t.TempDir()
	const human = "alice@example.com"

	// Ledger, with one writer token per product (as deployed) and an auditor for reads.
	e := NewEnv(t)
	tok := map[string]string{}
	for _, p := range []string{"harbour", "warrant", "gate", "proof"} {
		tok[p] = createToken(t, e, p, "writer")
	}
	auditor := createToken(t, e, "auditor", "auditor")
	d := e.Start()
	ledgerEnv := func(p string) []string { return []string{"LEDGER_URL=" + d.URL, "LEDGER_TOKEN=" + tok[p]} }

	// ---- Harbour: a goal with two effects; its goal id is the shared goal/run id. ----
	harbourd := goBuild(t, filepath.Join(root, "Harbour-"), "./cmd/harbourd", filepath.Join(bin, "harbourd"))
	harbour := goBuild(t, filepath.Join(root, "Harbour-"), "./cmd/harbour", filepath.Join(bin, "harbour"))
	hschema := "xp_harbour_" + randHex(3)
	hc := adminConn(t, baseURL)
	if _, err := hc.Exec(t.Context(), "CREATE SCHEMA "+hschema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := adminConn(t, baseURL)
		_, _ = c.Exec(t.Context(), "DROP SCHEMA "+hschema+" CASCADE")
		c.Close(t.Context())
	})
	hc.Close(t.Context())
	haddr := freePort(t)
	hurl := "http://" + haddr
	startProc(t, "harbourd", harbourd, []string{"-addr", haddr, "-db", withSearchPath(baseURL, hschema), "-demo-dir", filepath.Join(bin, "harbour-data"), "-workers", "1"},
		ledgerEnv("harbour"), bin, hurl+"/healthz")
	henv := []string{"HARBOUR_URL=" + hurl, "HARBOUR_USER=" + human}
	out, code := runCmd(t, bin, henv, harbour, "submit", "-name", "xp-"+randHex(3), "-agent", "demo.writer", "-approve",
		"-input", `{"file":"release-notes.txt","lines":["v1.2: fix login","v1.2: faster search"]}`)
	if code != 0 {
		t.Fatalf("harbour submit: %s", out)
	}
	var hg map[string]any
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &hg); err != nil {
		t.Fatalf("harbour submit output: %v\n%s", err, out)
	}
	goal := str(hg["id"])
	if goal == "" {
		t.Fatalf("no harbour goal id: %s", out)
	}
	eventually(t, 30*time.Second, func() string {
		o, _ := runCmd(t, bin, henv, harbour, "get", goal)
		if !strings.Contains(o, `"done"`) {
			return "harbour goal not done: " + o
		}
		return ""
	})

	// ---- Warrant: mint for the human, delegate to a worker, one allowed and one denied call. ----
	warrantd := goBuild(t, filepath.Join(root, "Warrant"), "./cmd/warrantd", filepath.Join(bin, "warrantd"))
	tool := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"content":"# Release notes"}`)
	}))
	t.Cleanup(tool.Close)
	routes := filepath.Join(bin, "routes.json")
	_ = os.WriteFile(routes, []byte(`[{"tool":"*","upstream":"`+tool.URL+`/tool"}]`), 0o644)
	baddr, paddr := freePort(t), freePort(t)
	burl, purl := "http://"+baddr, "http://"+paddr
	startProc(t, "warrantd", warrantd, nil, append(ledgerEnv("warrant"),
		"WARRANT_ADMIN_TOKEN=xp-admin", "WARRANT_ADDR="+baddr, "WARRANT_PEP_ADDR="+paddr,
		"WARRANT_POLICY="+filepath.Join(root, "Warrant", "examples", "policy.json"), "WARRANT_ROUTES="+routes), bin, burl+"/healthz")
	adm := map[string]string{"Authorization": "Bearer xp-admin"}
	for _, w := range []string{"planner", "worker"} {
		if st := postJSON(t, burl+"/v1/workloads", adm, map[string]any{"name": w, "secret": w + "-registration-secret-0123"}, nil); st/100 != 2 {
			t.Fatalf("register %s: %d", w, st)
		}
	}
	svid := map[string]string{}
	for _, w := range []string{"planner", "worker"} {
		var id map[string]any
		if st := postJSON(t, burl+"/v1/identity", nil, map[string]any{"workload": w, "secret": w + "-registration-secret-0123"}, &id); st/100 != 2 {
			t.Fatalf("attest %s: %d %v", w, st, id)
		}
		svid[w] = str(id["svid"])
	}
	var root_, child map[string]any
	if st := postJSON(t, burl+"/v1/tokens", adm, map[string]any{"svid": svid["planner"], "human": human, "goal_id": goal,
		"scopes": []any{map[string]any{"tool": "fs.*", "resources": []string{"repo/acme/*", "secrets/*"}, "max_calls": 10}}, "ttl_seconds": 300}, &root_); st/100 != 2 {
		t.Fatalf("mint: %d %v", st, root_)
	}
	if st := postJSON(t, burl+"/v1/tokens/delegate", nil, map[string]any{"parent_token": root_["token"], "parent_svid": svid["planner"], "child_svid": svid["worker"], "goal_id": goal,
		"scopes": []any{map[string]any{"tool": "fs.read", "resources": []string{"repo/acme/*", "secrets/*"}, "max_calls": 3}}, "ttl_seconds": 60}, &child); st/100 != 2 {
		t.Fatalf("delegate: %d %v", st, child)
	}
	call := func(resource string) int {
		return postJSON(t, purl+"/call/fs.read", map[string]string{"Authorization": "Bearer " + str(child["token"]), "X-Warrant-SVID": svid["worker"]},
			map[string]any{"resource": resource, "args": map[string]any{"path": "notes.md"}}, nil)
	}
	if st := call("repo/acme/notes.md"); st != 200 {
		t.Fatalf("allowed call through the PEP: %d", st)
	}
	if st := call("secrets/prod.env"); st == 200 {
		t.Fatalf("forbidden call went through")
	}

	// ---- Gate: a real diff in a throwaway repo. ----
	gate := goBuild(t, filepath.Join(root, "Gate"), "./cmd/gate", filepath.Join(bin, "gate"))
	repo := filepath.Join(bin, "svc")
	_ = os.MkdirAll(repo, 0o755)
	_ = os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/svc\n\ngo 1.22\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repo, "add.go"), []byte("package svc\n\n// Add adds.\nfunc Add(a, b int) int { return a + b }\n"), 0o644)
	_ = os.WriteFile(filepath.Join(repo, "add_test.go"), []byte("package svc\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n"), 0o644)
	genv := []string{"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@x", "GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@x"}
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"commit", "-qm", "init"}} {
		if o, c := runCmd(t, repo, genv, "git", a...); c != 0 {
			t.Fatalf("git %v: %s", a, o)
		}
	}
	_ = os.WriteFile(filepath.Join(repo, "add.go"), []byte("package svc\n\n// Add adds.\nfunc Add(a, b int) int { return a + b }\n\n// Sub subtracts.\nfunc Sub(a, b int) int { return a - b }\n"), 0o644)
	diffOut, _ := runCmd(t, repo, nil, "git", "diff")
	_ = os.WriteFile(filepath.Join(bin, "change.diff"), []byte(diffOut), 0o644)
	_, _ = runCmd(t, repo, nil, "git", "checkout", "--", ".")
	gout, gcode := runCmd(t, bin, append(ledgerEnv("gate"), "GATE_PROFILE=off", "ANTHROPIC_API_KEY="), gate, "run", "--repo", repo, "--base", "HEAD",
		"--diff", filepath.Join(bin, "change.diff"), "--goal", goal, "--human", human, "--agent", "coder", "--agent-model", "m-1",
		"--sandbox", "local", "--no-explain", "--format", "json", "--exit-zero")
	if gcode != 0 {
		t.Fatalf("gate run: exit %d\n%s", gcode, gout)
	}

	// ---- Proof: capture a page from a local HTTP server, sealed. ----
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nAllow: /\n")
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>Release notes</title></head><body>v1.2</body></html>`)
		}
	}))
	t.Cleanup(site.Close)
	proofDist := buildProof(t, filepath.Join(root, "Proof"), bin)
	pout, pcode := runCmd(t, bin, append(ledgerEnv("proof"), "PROOF_DATA_DIR="+filepath.Join(bin, "proof-data"), "PROOF_HUMAN_ID="+human, "PROOF_DATABASE_URL="),
		"node", filepath.Join(proofDist, "cli.js"), "capture", site.URL+"/notes", "--run", goal, "--seal")
	if pcode != 0 {
		t.Fatalf("proof capture: exit %d\n%s", pcode, pout)
	}

	// ---- Assertions. ----
	var mismatches, known []string
	byChain := map[string][]map[string]any{}
	for _, c := range []string{"harbour", "warrant", "gate", "proof"} {
		recs := d.Records(auditor, c)
		if len(recs) == 0 {
			t.Fatalf("no %s records landed in Ledger", c)
		}
		byChain[c] = recs
		for _, r := range recs {
			ac, _ := r["actor_chain"].([]any)
			first, _ := ac[0].(map[string]any)
			if first["kind"] != "human" || first["id"] != human {
				mismatches = append(mismatches, fmt.Sprintf("%s %s: actor chain does not start with human %s: %v", c, r["type"], human, ac))
			}
			if str(r["goal_id"]) != goal {
				msg := fmt.Sprintf("%s %s#%v: goal_id %q, not the shared goal", c, r["type"], r["seq"], str(r["goal_id"]))
				if knownGap(c, str(r["type"])) {
					known = append(known, msg)
				} else {
					mismatches = append(mismatches, msg)
				}
			}
		}
		d.VerifyOK(auditor, c)
	}
	types := func(c string) string {
		var s []string
		for _, r := range byChain[c] {
			s = append(s, str(r["type"]))
		}
		return strings.Join(s, ",")
	}
	for c, want := range map[string][]string{
		"harbour": {"harbour.goal.transition", "harbour.effect.intent", "harbour.effect.result"},
		"warrant": {"warrant.token.issued", "warrant.call.allowed", "warrant.call.denied"},
		"gate":    {"gate.run.started", "gate.stage.completed", "gate.run.decided"},
		"proof":   {"proof.fetch.captured", "proof.manifest.signed"},
	} {
		for _, w := range want {
			if !strings.Contains(types(c), w) {
				t.Errorf("%s chain lacks %s (has %s)", c, w, types(c))
			}
		}
	}
	vo := e.MustLedger("verify")
	for _, c := range []string{"harbour", "warrant", "gate", "proof"} {
		if !strings.Contains(vo, "OK      "+c) {
			t.Errorf("ledger verify: %s not OK:\n%s", c, vo)
		}
	}

	// Projections: the goal tree holds work from every product.
	eventually(t, 20*time.Second, func() string {
		r := d.Do("GET", "/v1/goals/"+url.PathEscape(goal), auditor, nil)
		b := string(r.Body)
		for _, w := range []string{"harbour:", "gate:", "proof:", "fs.append"} {
			if !strings.Contains(b, w) {
				return fmt.Sprintf("goal tree lacks %q: %d %.1500s", w, r.Status, b)
			}
		}
		return ""
	})
	if r := d.Do("GET", "/v1/goals", auditor, nil); !strings.Contains(string(r.Body), goal) {
		t.Errorf("/v1/goals lacks %s", goal)
	}
	if r := d.Do("GET", "/v1/budgets/"+url.PathEscape(goal), auditor, nil); !strings.Contains(string(r.Body), "calls:") {
		t.Logf("note: no Warrant call budget under the shared goal: %s", r.Body)
	}
	e.MustLedger("project", "--check")

	// Incident review joins all four products into one narrative.
	incJSON := e.MustLedger("incident", "--goal", goal, "--format", "json")
	var inc struct {
		Summary struct {
			Records         int      `json:"records"`
			Chains          int      `json:"chains"`
			AllChainsIntact bool     `json:"all_chains_intact"`
			Humans          []string `json:"originating_humans"`
			Denials         int      `json:"denials"`
			Committed       int      `json:"effects_committed"`
		} `json:"summary"`
		Narrative []struct {
			Chain    string `json:"chain"`
			Type     string `json:"type"`
			LinkedBy string `json:"linked_by"`
		} `json:"narrative"`
	}
	if err := json.Unmarshal([]byte(incJSON), &inc); err != nil {
		t.Fatalf("incident json: %v\n%.500s", err, incJSON)
	}
	inNarr := map[string]int{}
	for _, n := range inc.Narrative {
		inNarr[n.Chain]++
	}
	total := 0
	for _, c := range []string{"harbour", "warrant", "gate", "proof"} {
		total += len(byChain[c])
		if inNarr[c] != len(byChain[c]) {
			t.Errorf("incident narrative has %d/%d %s records", inNarr[c], len(byChain[c]), c)
		}
	}
	if !inc.Summary.AllChainsIntact || len(inc.Summary.Humans) != 1 || inc.Summary.Humans[0] != human || inc.Summary.Denials < 1 || inc.Summary.Committed < 2 {
		t.Errorf("incident summary: %+v", inc.Summary)
	}
	for _, f := range []string{"html", "md"} {
		o := e.MustLedger("incident", "--goal", goal, "--format", f)
		for _, w := range []string{"harbour", "warrant", "gate", "proof"} {
			if !strings.Contains(o, w) {
				t.Errorf("incident %s lacks %s", f, w)
			}
		}
	}
	if r := d.Do("GET", "/v1/incidents/"+url.PathEscape(goal)+"?format=json", auditor, nil); r.Status != 200 {
		t.Errorf("GET incident: %d", r.Status)
	}
	if dump := os.Getenv("LEDGER_XPRODUCT_DUMP"); dump != "" {
		all, _ := json.MarshalIndent(byChain, "", " ")
		_ = os.WriteFile(filepath.Join(dump, "records.json"), all, 0o644)
		_ = os.WriteFile(filepath.Join(dump, "tree.json"), d.Do("GET", "/v1/goals/"+url.PathEscape(goal), auditor, nil).Body, 0o644)
		_ = os.WriteFile(filepath.Join(dump, "budgets.json"), d.Do("GET", "/v1/budgets/"+url.PathEscape(goal), auditor, nil).Body, 0o644)
		_ = os.WriteFile(filepath.Join(dump, "approvals.json"), d.Do("GET", "/v1/approvals", auditor, nil).Body, 0o644)
		_ = os.WriteFile(filepath.Join(dump, "incident.json"), []byte(incJSON), 0o644)
	}
	t.Logf("cross-product goal %s: %d records (%v), narrative %v", goal, total, map[string]int{"harbour": len(byChain["harbour"]), "warrant": len(byChain["warrant"]), "gate": len(byChain["gate"]), "proof": len(byChain["proof"])}, inNarr)
	// Warrant's goal-less call records must still be joined into the narrative, by token_id.
	for _, n := range inc.Narrative {
		if n.Chain == "warrant" && strings.HasPrefix(n.Type, "warrant.call.") && n.LinkedBy == "" {
			t.Errorf("warrant call not linked into the incident: %+v", n)
		}
	}
	for _, m := range mismatches {
		t.Errorf("CONTRACT: %s", m)
	}
	for _, m := range known {
		if os.Getenv("LEDGER_XPRODUCT_STRICT") == "1" {
			t.Errorf("CONTRACT (known, product-side): %s", m)
		} else {
			t.Logf("CONTRACT (known, product-side; LEDGER_XPRODUCT_STRICT=1 fails on it): %s", m)
		}
	}
}

// knownGap lists contract gaps that need a fix in another product (see the e2e report), so the
// suite stays green for Ledger while still printing them. LEDGER_XPRODUCT_STRICT=1 fails on them.
func knownGap(chain, typ string) bool {
	// Warrant: POST /v1/tokens and /v1/tokens/delegate accept goal_id and put it on
	// warrant.token.issued, but the token claims do not carry it, so warrant.call.allowed/denied
	// (internal/broker/service.go Authorize) are recorded without goal_id.
	return chain == "warrant" && strings.HasPrefix(typ, "warrant.call.")
}

// buildProof compiles Proof's TypeScript into a temp copy (the Proof checkout is not written to).
func buildProof(t *testing.T, src, tmp string) string {
	t.Helper()
	dst := filepath.Join(tmp, "proof")
	_ = os.MkdirAll(dst, 0o755)
	for _, f := range []string{"src", "package.json", "tsconfig.json"} {
		if o, c := runCmd(t, tmp, nil, "cp", "-r", filepath.Join(src, f), dst); c != 0 {
			t.Fatalf("cp %s: %s", f, o)
		}
	}
	if err := os.Symlink(filepath.Join(src, "node_modules"), filepath.Join(dst, "node_modules")); err != nil {
		t.Fatal(err)
	}
	if o, c := runCmd(t, dst, nil, "npx", "tsc", "-p", "."); c != 0 {
		t.Fatalf("building Proof: %s", o)
	}
	return filepath.Join(dst, "dist")
}
