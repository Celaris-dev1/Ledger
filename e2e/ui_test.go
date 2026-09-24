//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// playwrightDir returns a directory whose node_modules holds playwright: LEDGER_E2E_PLAYWRIGHT_DIR,
// or a fresh `npm install playwright` in a temp dir outside the repo (browsers are not downloaded;
// the test uses LEDGER_E2E_CHROMIUM).
func playwrightDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("LEDGER_E2E_PLAYWRIGHT_DIR"); d != "" {
		return d
	}
	dir := t.TempDir()
	c := exec.Command("npm", "install", "--no-audit", "--no-fund", "--loglevel=error", "playwright@1.55")
	c.Dir = dir
	c.Env = append(os.Environ(), "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("npm install playwright: %v\n%s", err, out)
	}
	return dir
}

type uiResult struct {
	Events           int      `json:"events"`
	Clock0           string   `json:"clock0"`
	Clock1           string   `json:"clock1"`
	PlayedSamples    []string `json:"playedSamples"`
	PlayStoppedAtEnd bool     `json:"playStoppedAtEnd"`
	Results          []struct {
		Check string `json:"check"`
		Hash  string `json:"hash"`
	} `json:"results"`
	Errors []string `json:"errors"`
}

func runUI(t *testing.T, pw, chrome string, d *Daemon, token, goal string) uiResult {
	t.Helper()
	c := exec.Command("node", filepath.Join(repoRoot, "e2e", "testdata", "ui_replay.cjs"), d.URL, token, goal)
	c.Env = append(os.Environ(), "NODE_PATH="+filepath.Join(pw, "node_modules"), "CHROME="+chrome)
	out, err := c.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("playwright: %v\n%s\n%s", err, out, stderr)
	}
	var r uiResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("playwright output: %v\n%s", err, out)
	}
	return r
}

func TestUIReplayBrowserHashCheck(t *testing.T) {
	chrome := os.Getenv("LEDGER_E2E_CHROMIUM")
	if chrome == "" {
		chrome = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Skipf("no Chromium at %s (set LEDGER_E2E_CHROMIUM)", chrome)
	}
	pw := playwrightDir(t)
	e := NewEnv(t)
	admin := createToken(t, e, "ui-admin", "auditor")
	writer := createToken(t, e, "seeder", "writer")
	d := e.Start()
	goal := "g-ui-" + randHex(3)
	seedGap = 150 * time.Millisecond
	seeded := seedGoal(t, d, writer, goal)
	seedGap = 0
	want := map[string]bool{}
	for _, r := range seeded {
		want[str(r["hash"])] = true
	}

	r := runUI(t, pw, chrome, d, admin, goal)
	if len(r.Errors) > 0 {
		t.Errorf("browser errors: %v", r.Errors)
	}
	if r.Events != len(seeded) || len(r.Results) != len(seeded) {
		t.Fatalf("replay shows %d events (%d checked), want %d", r.Events, len(r.Results), len(seeded))
	}
	if r.Clock0 == r.Clock1 || len(r.PlayedSamples) == 0 || !r.PlayStoppedAtEnd {
		t.Fatalf("play did not advance through the timeline: clock %q -> %q, samples %v, stopped=%v", r.Clock0, r.Clock1, r.PlayedSamples, r.PlayStoppedAtEnd)
	}
	for _, s := range r.PlayedSamples {
		if s != "match" {
			t.Fatalf("hash check during playback: %v", r.PlayedSamples)
		}
	}
	got := map[string]bool{}
	for i, x := range r.Results {
		if x.Check != "match" {
			t.Errorf("event %d (%s): browser hash check %s", i, x.Hash, x.Check)
		}
		got[x.Hash] = true
	}
	if len(got) != len(want) {
		t.Fatalf("panel showed %d distinct records, want %d", len(got), len(want))
	}

	// Tamper one record in the database (superuser, trigger disabled, no rehash).
	victim := seeded[3]
	e.PSQL(fmt.Sprintf(`BEGIN; ALTER TABLE records DISABLE TRIGGER USER;
UPDATE records SET payload='{"attempt_id":"forged","tool":"rm -rf"}' WHERE id='%s';
ALTER TABLE records ENABLE TRIGGER USER; COMMIT;`, victim["id"]))
	r = runUI(t, pw, chrome, d, admin, goal)
	bad := 0
	for _, x := range r.Results {
		switch {
		case x.Hash == str(victim["hash"]):
			if x.Check != "MISMATCH" {
				t.Errorf("tampered record %s: browser check says %s", x.Hash, x.Check)
			}
			bad++
		case x.Check != "match":
			t.Errorf("untouched record %s: %s", x.Hash, x.Check)
		}
	}
	if bad != 1 {
		t.Fatalf("tampered record not found in the replay: %+v", r.Results)
	}
}
