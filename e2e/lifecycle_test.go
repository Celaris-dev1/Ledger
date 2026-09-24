//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// seedGoal appends a goal with steps, an attempt, an approval, a budget and a verification over
// two chains, all through POST /v1/records, and returns the appended records in order.
func seedGoal(t *testing.T, d *Daemon, token, goal string) []map[string]any {
	t.Helper()
	ac := []Actor{human("alice"), agent("planner")}
	action := map[string]any{"tool": "db.exec", "args": map[string]any{"stmt": "UPDATE plans SET tier='pro' WHERE id=7"}}
	recs := []map[string]any{
		{"chain": "agents", "type": "ledger.goal.created", "payload": map[string]any{"title": "Upgrade customer 7", "status": "running"}},
		{"chain": "agents", "type": "ledger.step.planned", "payload": map[string]any{"step_no": 1, "description": "change plan"}},
		{"chain": "agents", "type": "ledger.budget.allocated", "payload": map[string]any{"resource": "usd", "amount": 10}},
		{"chain": "agents", "type": "ledger.action.attempted", "payload": map[string]any{"attempt_id": goal + "-a1", "tool": "db.exec", "step_no": 1, "action": action}},
		{"chain": "ops", "type": "ledger.approval.requested", "payload": map[string]any{"request_id": goal + "-r1", "action": action, "reason": "writes prod"}},
		{"chain": "ops", "type": "ledger.approval.granted", "payload": map[string]any{"request_id": goal + "-r1", "action": action}},
		{"chain": "agents", "type": "ledger.budget.charged", "payload": map[string]any{"resource": "usd", "amount": 3.5}},
		{"chain": "agents", "type": "ledger.action.completed", "payload": map[string]any{"attempt_id": goal + "-a1", "outcome": "success"}},
		{"chain": "ops", "type": "ledger.verification.recorded", "payload": map[string]any{"verifier": "row-check", "passed": true, "attempt_id": goal + "-a1"}},
		{"chain": "agents", "type": "ledger.goal.status", "payload": map[string]any{"status": "done"}},
	}
	var out []map[string]any
	for _, r := range recs {
		r["goal_id"] = goal
		r["actor_chain"] = ac
		r["policy_version"] = "pol-7"
		out = append(out, d.Append(token, r))
	}
	return out
}

func TestLifecycleHTTPVerifyReplayProjectionsIncident(t *testing.T) {
	e := NewEnv(t)
	d := e.Start()
	goal := "g-life-" + randHex(3)
	seeded := seedGoal(t, d, "", goal)

	// Contract checks on POST /v1/records.
	if r := d.Do("POST", "/v1/records", "", map[string]any{"chain": "agents", "type": "x", "actor_chain": []Actor{agent("a")}, "payload": map[string]any{}}); r.Status != 400 {
		t.Fatalf("agent-first actor chain accepted: %d %s", r.Status, r.Body)
	}
	for i, rec := range seeded {
		if rec["id"] == "" || rec["hash"] == "" || rec["created_at"] == "" {
			t.Fatalf("receipt %d incomplete: %v", i, rec)
		}
	}

	// Verify: API and CLI.
	for _, c := range []string{"agents", "ops"} {
		v := d.VerifyOK("", c)
		if c == "agents" && num(v["length"]) != 7 {
			t.Fatalf("agents length = %v", v["length"])
		}
	}
	out := e.MustLedger("verify")
	if !strings.Contains(out, "OK      agents") || !strings.Contains(out, "OK      ops") {
		t.Fatalf("ledger verify:\n%s", out)
	}

	// Replay: API and CLI agree and follow append order across chains.
	var api struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(d.Do("GET", "/v1/goals/"+goal+"/replay", "", nil).Body, &api); err != nil {
		t.Fatal(err)
	}
	var cli struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(e.MustLedger("replay", "--goal", goal)), &cli); err != nil {
		t.Fatal(err)
	}
	if len(api.Records) != len(seeded) || len(cli.Records) != len(seeded) {
		t.Fatalf("replay lengths api=%d cli=%d want %d", len(api.Records), len(cli.Records), len(seeded))
	}
	for i := range seeded {
		if api.Records[i]["hash"] != seeded[i]["hash"] || cli.Records[i]["hash"] != seeded[i]["hash"] {
			t.Fatalf("replay[%d] out of order: api=%v cli=%v want %v", i, api.Records[i]["type"], cli.Records[i]["type"], seeded[i]["hash"])
		}
	}

	// Projections (async worker).
	eventually(t, 15*time.Second, func() string {
		r := d.Do("GET", "/v1/goals/"+goal, "", nil)
		if r.Status != 200 {
			return fmt.Sprintf("goal tree %d %s", r.Status, r.Body)
		}
		if !strings.Contains(string(r.Body), `"done"`) || !strings.Contains(string(r.Body), goal+"-a1") {
			return "goal tree incomplete: " + string(r.Body)
		}
		return ""
	})
	if r := d.Do("GET", "/v1/goals", "", nil); !strings.Contains(string(r.Body), goal) {
		t.Fatalf("/v1/goals lacks %s: %s", goal, r.Body)
	}
	tree := string(d.Do("GET", "/v1/goals/"+goal, "", nil).Body)
	for _, want := range []string{"Upgrade customer 7", "row-check", "success"} {
		if !strings.Contains(tree, want) {
			t.Errorf("goal tree lacks %q: %s", want, tree)
		}
	}
	appr := d.Do("GET", "/v1/approvals?status=approved", "", nil)
	if appr.Status != 200 || !strings.Contains(string(appr.Body), goal+"-r1") {
		t.Fatalf("approvals: %d %s", appr.Status, appr.Body)
	}
	bud := d.Do("GET", "/v1/budgets/"+goal, "", nil)
	if bud.Status != 200 || !strings.Contains(string(bud.Body), "6.5") {
		t.Fatalf("budgets (want balance 6.5): %d %s", bud.Status, bud.Body)
	}
	e.MustLedger("project", "--check")

	// Incident review: API and CLI, JSON/HTML/Markdown.
	inc := d.Do("GET", "/v1/incidents/"+goal+"?format=json", "", nil)
	if inc.Status != 200 || !strings.Contains(string(inc.Body), "alice") {
		t.Fatalf("incident: %d %s", inc.Status, inc.Body)
	}
	for _, f := range []string{"json", "html", "md"} {
		o := e.MustLedger("incident", "--goal", goal, "--format", f)
		if !strings.Contains(o, "Upgrade customer 7") && !strings.Contains(o, goal) {
			t.Errorf("incident --format %s lacks the goal:\n%.500s", f, o)
		}
	}
}

// ---- SDKs as real subprocesses ----

var (
	tsOnce sync.Once
	tsDist string
	tsErr  error
)

// buildTSSDK copies sdk/ts to a temp dir (the repo is never touched), npm ci + tsc there.
func buildTSSDK(t *testing.T) string {
	t.Helper()
	tsOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ledger-e2e-tssdk-")
		if err != nil {
			tsErr = err
			return
		}
		src := filepath.Join(repoRoot, "sdk", "ts")
		cp := exec.Command("cp", "-r", filepath.Join(src, "src"), filepath.Join(src, "package.json"), filepath.Join(src, "package-lock.json"), filepath.Join(src, "tsconfig.json"), dir)
		if out, err := cp.CombinedOutput(); err != nil {
			tsErr = fmt.Errorf("cp: %v %s", err, out)
			return
		}
		for _, args := range [][]string{{"npm", "ci", "--no-audit", "--no-fund", "--loglevel=error"}, {"npx", "tsc", "-p", "."}} {
			c := exec.Command(args[0], args[1:]...)
			c.Dir = dir
			if out, err := c.CombinedOutput(); err != nil {
				tsErr = fmt.Errorf("%v: %v\n%s", args, err, out)
				return
			}
		}
		tsDist = filepath.Join(dir, "dist")
	})
	if tsErr != nil {
		t.Fatalf("building TS SDK: %v", tsErr)
	}
	return tsDist
}

type sdkProc struct {
	cmd    *exec.Cmd
	lines  chan string
	output *syncBuf
	done   chan error
}

func startSDK(t *testing.T, lang string, env []string, args ...string) *sdkProc {
	t.Helper()
	var cmd *exec.Cmd
	switch lang {
	case "python":
		cmd = exec.Command("python3", append([]string{filepath.Join(repoRoot, "e2e", "testdata", "sdk_driver.py")}, args...)...)
		env = append(env, "PYTHONPATH="+filepath.Join(repoRoot, "sdk", "python"))
	case "ts":
		cmd = exec.Command("node", append([]string{filepath.Join(repoRoot, "e2e", "testdata", "sdk_driver.mjs"), buildTSSDK(t)}, args...)...)
	}
	cmd.Env = append(os.Environ(), env...)
	p := &sdkProc{cmd: cmd, lines: make(chan string, 100), output: &syncBuf{}, done: make(chan error, 1)}
	pr, pw := io.Pipe()
	cmd.Stdout = io.MultiWriter(pw, p.output)
	cmd.Stderr = p.output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
	}()
	go func() { err := cmd.Wait(); pw.Close(); p.done <- err }()
	return p
}

func (p *sdkProc) waitLine(t *testing.T, prefix string, timeout time.Duration) string {
	t.Helper()
	tm := time.After(timeout)
	for {
		select {
		case l := <-p.lines:
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-tm:
			t.Fatalf("SDK driver: no %q line within %s; output:\n%s", prefix, timeout, p.output.String())
		}
	}
}

func (p *sdkProc) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("SDK driver failed: %v\n%s", err, p.output.String())
		}
	case <-time.After(60 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatalf("SDK driver hung:\n%s", p.output.String())
	}
}

// TestSDKOutageSpoolReplay: a real SDK process writes while ledgerd is up, then while it is down
// (records stay in the on-disk spool and the process exits), then a new process starts while
// ledgerd is still down, reloads the spool, keeps retrying, and drains once ledgerd restarts —
// with the first acknowledged POST's response lost so the SDK re-sends it. The chain must hold
// every record exactly once, in order.
func TestSDKOutageSpoolReplay(t *testing.T) {
	for _, lang := range []string{"python", "ts"} {
		t.Run(lang, func(t *testing.T) {
			e := NewEnv(t)
			d := e.Start()
			chain, goal := "sdk-"+lang, "g-sdk-"+lang
			spool := filepath.Join(e.Dir, "spool.jsonl")
			env := []string{"LEDGER_URL=" + d.URL}

			p := startSDK(t, lang, env, spool, chain, goal, "0", "5", "20")
			if l := p.waitLine(t, "pending=", 30*time.Second); l != "pending=0" {
				t.Fatalf("phase 1: %s", l)
			}
			p.wait(t)

			d.Kill() // crash: nothing is listening now
			p = startSDK(t, lang, env, spool, chain, goal, "5", "5", "1")
			if l := p.waitLine(t, "pending=", 30*time.Second); l != "pending=5" {
				t.Fatalf("phase 2 (ledgerd down): %s", l)
			}
			p.wait(t)
			if b, _ := os.ReadFile(spool); strings.Count(string(b), "\n") != 5 {
				t.Fatalf("spool should hold the 5 undelivered records:\n%s", b)
			}

			p = startSDK(t, lang, env, spool, chain, goal, "10", "5", "40", "lose-first-ack")
			p.waitLine(t, "queued", 30*time.Second)
			time.Sleep(700 * time.Millisecond) // let it fail a few retries against the dead port
			d.Restart()
			if l := p.waitLine(t, "pending=", 50*time.Second); l != "pending=0" {
				t.Fatalf("phase 3: %s\n%s", l, p.output.String())
			}
			p.wait(t)

			recs := d.Records("", chain)
			if len(recs) != 15 {
				t.Fatalf("want 15 records exactly once, got %d", len(recs))
			}
			keys := map[string]bool{}
			for i, r := range recs {
				pl := r["payload"].(map[string]any)
				if int(pl["n"].(float64)) != i {
					t.Fatalf("record %d has n=%v: out of order or duplicated", i, pl["n"])
				}
				// GET /v1/records does not return idempotency_key (not part of the record); the
				// payload counter above proves exactly-once delivery.
				keys[str(r["id"])] = true
				ac := r["actor_chain"].([]any)
				if ac[0].(map[string]any)["kind"] != "human" {
					t.Fatalf("actor chain not human-first: %v", ac)
				}
			}
			d.VerifyOK("", chain)
		})
	}
}

// TestSSEResumeAcrossRestart: a client reads a few records from /v1/stream, ledgerd restarts,
// more records arrive while nobody is connected, and reconnecting with Last-Event-ID yields
// exactly the missed records (no gaps, no duplicates), then live ones.
func TestSSEResumeAcrossRestart(t *testing.T) {
	e := NewEnv(t)
	d := e.Start()
	appendN := func(chain string, from, n int) {
		for i := from; i < from+n; i++ {
			d.Append("", map[string]any{"chain": chain, "type": "ledger.memory.written", "goal_id": "g-sse",
				"actor_chain": []Actor{human("alice"), agent("streamer")}, "payload": map[string]any{"key": "k", "n": i}})
		}
	}
	appendN("s1", 0, 2)
	ch, cancel := openSSE(t, d.URL+"/v1/stream?goal_id=g-sse&from=start", "", "")
	var lastID string
	seen := map[string]bool{}
	got := func(ev sseEvent, m map[string]any) {
		k := fmt.Sprintf("%s/%v", m["chain"], m["seq"])
		if seen[k] {
			t.Fatalf("duplicate SSE record %s", k)
		}
		seen[k] = true
		lastID = ev.ID
	}
	for i := 0; i < 2; i++ {
		got(nextRecord(t, ch, 10*time.Second))
	}
	appendN("s2", 0, 1) // live
	got(nextRecord(t, ch, 10*time.Second))
	cancel()

	d.Restart()
	appendN("s1", 2, 3)
	appendN("s2", 1, 2)
	ch, cancel = openSSE(t, d.URL+"/v1/stream?goal_id=g-sse", "", lastID)
	defer cancel()
	for i := 0; i < 5; i++ {
		got(nextRecord(t, ch, 10*time.Second))
	}
	appendN("s1", 5, 1)
	got(nextRecord(t, ch, 10*time.Second))
	if len(seen) != 9 {
		t.Fatalf("saw %d distinct records, want 9: %v", len(seen), seen)
	}
	select {
	case ev := <-ch:
		if ev.Event == "record" {
			t.Fatalf("unexpected extra record %s", ev.Data)
		}
	case <-time.After(1500 * time.Millisecond):
	}
}
