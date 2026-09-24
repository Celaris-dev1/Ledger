package web

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Inputs that stress every corner of Go's canonical JSON: number literals, key order by UTF-8
// bytes (astral vs BMP), escapes Go emits (\b \f \u00XX  ), HTML characters that must
// NOT be escaped, lone surrogates, duplicate keys, deep nesting and hostile strings.
var goldenInputs = []string{
	`{"b":1,"a":2}`,
	`{"n":1.0,"e":1E+2,"neg":-0,"big":123456789012345678901234567890,"f":0.1,"exp":1e-7,"z":0,"i":-17}`,
	`{"s":"<script>alert(1)</script> &     \u0000 \u001f \u007f \b \f \n \r \t \"q\" \\ \/ end"}`,
	`{"é":1,"e":2,"😀":3,"￿":4,"z":5,"Z":6,"":7,"ｚ":8,"Ā":9}`,
	`{"lone":"\ud800x","pair":"😀","lowonly":"\udc00","raw":"😀日本語"}`,
	`{"dup":1,"dup":2,"x":{"dup":"a","dup":"b"}}`,
	`[1,[2,[3,[4,[]]]],{},{"a":[]},null,true,false,"x"]`,
	`  { "url" : "javascript:alert(1)" , "html" : "</script><img src=x onerror=alert(1)>" }  `,
	`{"nested":{"b":{"d":1,"c":2},"a":[{"z":1,"y":2}]}}`,
	`"just a string with é"`,
	`12.50`,
	`{"ctl":"\u0001\u0002\u0003\u000b\u000e\u001b"}`,
}

type goldenCase struct {
	Name       string `json:"name"`
	RecordText string `json:"record_text,omitempty"`
	InputText  string `json:"input_text,omitempty"`
	Canonical  string `json:"canonical"`
	Hash       string `json:"hash,omitempty"`
}

func goldenCases(t *testing.T) []goldenCase {
	var out []goldenCase
	prev := ""
	for i, in := range goldenInputs {
		c, err := canon.CanonicalBytes([]byte(in))
		if err != nil {
			t.Fatalf("input %d: %v", i, err)
		}
		out = append(out, goldenCase{Name: "canon-" + string(rune('a'+i)), InputText: in, Canonical: string(c)})
		// as a record payload (only objects are valid payloads, but the hash covers any JSON)
		ac, _ := canon.CanonicalBytes([]byte(`[{"kind":"human","id":"álice <admin>"},{"kind":"agent","id":"planner","model":"m","model_version":"1.0"}]`))
		rec := store.Record{ID: "0f8fad5b-d9cb-469f-a165-70867728950e", Chain: "gate", Seq: int64(i + 1), Type: "gate.run.started",
			ActorChain: ac, Payload: c, CreatedAt: time.Date(2026, 9, 1, 12, 0, i, 123456000*(i%2), time.UTC), PrevHash: prev}
		if i%3 == 0 {
			rec.GoalID = "goal-" + string(rune('a'+i))
			rec.PolicyVersion = "pv-2026.09"
		}
		if rec.Hash, err = store.ComputeHash(&rec); err != nil {
			t.Fatal(err)
		}
		body, _ := store.HashBody(&rec)
		bc, _ := canon.Marshal(body)
		bc, _ = canon.CanonicalBytes(bc)
		txt, _ := json.Marshal(rec) // exactly what the API sends (HTML-escaped by encoding/json)
		out = append(out, goldenCase{Name: "record-" + string(rune('a'+i)), RecordText: string(txt), Canonical: string(bc), Hash: rec.Hash})
		prev = rec.Hash
	}
	return out
}

const goldenRunner = `
const fs = require("fs");
const C = require(process.argv[2]);
const cases = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
(async () => {
  let bad = 0;
  for (const c of cases) {
    try {
      if (c.input_text !== undefined && c.input_text !== "") {
        const got = C.canonical(C.parse(c.input_text));
        if (got !== c.canonical) { bad++; console.log("MISMATCH " + c.name + "\n go: " + c.canonical + "\n js: " + got); }
        continue;
      }
      const rec = C.parse(c.record_text);
      const r = await C.recordHash(rec);
      if (r.canonical !== c.canonical) { bad++; console.log("CANON MISMATCH " + c.name + "\n go: " + c.canonical + "\n js: " + r.canonical); }
      if (r.hex !== c.hash) { bad++; console.log("HASH MISMATCH " + c.name + " go " + c.hash + " js " + r.hex + " (" + r.engine + ")"); }
      const fb = C.sha256Fallback(new TextEncoder().encode(C.plain(rec).prev_hash + "\n" + r.canonical));
      if (fb !== c.hash) { bad++; console.log("FALLBACK SHA MISMATCH " + c.name); }
    } catch (e) { bad++; console.log("ERROR " + c.name + ": " + e); }
  }
  console.log("checked " + cases.length + " cases, " + bad + " mismatches");
  process.exit(bad ? 1 : 0);
})();
`

// TestBrowserCanonicalGolden runs the embedded canon.js under node against Go's canonical
// JSON and record hashes. Skips when node is not installed.
func TestBrowserCanonicalGolden(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found: browser canonicalisation golden test skipped")
	}
	dir := t.TempDir()
	js, err := fs.ReadFile(StaticFS(), "canon.js")
	if err != nil {
		t.Fatal(err)
	}
	canonPath := filepath.Join(dir, "canon.js")
	_ = os.WriteFile(canonPath, js, 0o600)
	runner := filepath.Join(dir, "run.js")
	_ = os.WriteFile(runner, []byte(goldenRunner), 0o600)
	cases := goldenCases(t)
	b, _ := json.Marshal(cases)
	casesPath := filepath.Join(dir, "cases.json")
	_ = os.WriteFile(casesPath, b, 0o600)
	out, err := exec.Command(node, runner, canonPath, casesPath).CombinedOutput()
	if err != nil {
		t.Fatalf("node golden run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "0 mismatches") {
		t.Fatalf("unexpected output: %s", out)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}
