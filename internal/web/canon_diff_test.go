package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Celaris-dev1/Ledger/internal/canon"
)

// Differential test: the browser canon.js and Go's internal/canon must agree on acceptance and
// on the exact canonical text for every input in the fuzz corpus (internal/canon/testdata/fuzz),
// the golden inputs and a few thousand generated hostile documents. LEDGER_CANON_CORPUS may
// name extra directories (e.g. $(go env GOCACHE)/fuzz/.../FuzzCanonical) separated by ':'.

const diffRunner = `
const fs = require("fs");
const C = require(process.argv[2]);
const cases = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
let bad = 0;
for (const c of cases) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(c.in, "base64"));
  let got = null;
  try { got = C.canonical(C.parse(text)); } catch (e) { got = null; }
  const want = c.ok ? c.canon : null;
  if (got !== want) {
    bad++;
    if (bad <= 20) console.log("MISMATCH input=" + JSON.stringify(text).slice(0, 300) + "\n go: " + String(want).slice(0, 300) + "\n js: " + String(got).slice(0, 300));
  }
}
console.log("checked " + cases.length + " cases, " + bad + " mismatches");
process.exit(bad ? 1 : 0);
`

type diffCase struct {
	In    string `json:"in"`
	OK    bool   `json:"ok"`
	Canon string `json:"canon,omitempty"`
}

// readCorpusDir loads Go fuzz corpus files ("go test fuzz v1" + one []byte/string literal).
func readCorpusDir(dir string) [][]byte {
	var out [][]byte
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		lines := strings.SplitN(string(b), "\n", 3)
		if len(lines) < 2 || !strings.HasPrefix(lines[0], "go test fuzz v1") {
			continue
		}
		lit := strings.TrimSpace(lines[1])
		for _, p := range []string{"[]byte(", "string("} {
			if strings.HasPrefix(lit, p) && strings.HasSuffix(lit, ")") {
				if s, err := strconv.Unquote(lit[len(p) : len(lit)-1]); err == nil {
					out = append(out, []byte(s))
				}
			}
		}
	}
	return out
}

func genJSON(r *rand.Rand, depth int) string {
	strs := []string{`""`, `"a"`, `"é"`, `"😀"`, `"\ud800"`, `"\udc00x"`, `"😀"`, `"<&>"`, `"  "`,
		`"\u0000\u001f\u007f"`, `"\/\b\f\n\r\t"`, `"ｚ"`, `"￿"`, `"Ā"`, `"�"`, `"\""`, `"\\"`}
	nums := []string{"0", "-0", "1.0", "1e2", "1E+2", "-1.5e-7", "123456789012345678901234567890", "0.1", "12.50", "-17"}
	switch k := r.Intn(10); {
	case depth > 4 || k < 3:
		switch r.Intn(4) {
		case 0:
			return strs[r.Intn(len(strs))]
		case 1:
			return nums[r.Intn(len(nums))]
		case 2:
			return []string{"true", "false", "null"}[r.Intn(3)]
		default:
			return strconv.Quote(string(rune(r.Intn(0x10FFFF))))
		}
	case k < 6:
		n := r.Intn(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = genJSON(r, depth+1)
		}
		return "[" + strings.Join(parts, " ,") + "]"
	default:
		n := r.Intn(5)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = strs[r.Intn(len(strs))] + ":" + genJSON(r, depth+1)
		}
		return "{ " + strings.Join(parts, ",\n") + "}"
	}
}

func TestBrowserCanonDifferential(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found")
	}
	var inputs [][]byte
	for _, s := range goldenInputs {
		inputs = append(inputs, []byte(s))
	}
	inputs = append(inputs, readCorpusDir(filepath.Join("..", "canon", "testdata", "fuzz", "FuzzCanonical"))...)
	for _, d := range filepath.SplitList(os.Getenv("LEDGER_CANON_CORPUS")) {
		inputs = append(inputs, readCorpusDir(d)...)
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 3000; i++ {
		s := genJSON(r, 0)
		if i%10 == 0 {
			s += []string{" x", "{}", " ", "]", "\n"}[r.Intn(5)]
		}
		inputs = append(inputs, []byte(s))
	}
	inputs = append(inputs, []byte(strings.Repeat("[", 10001)+strings.Repeat("]", 10001)),
		[]byte(strings.Repeat("[", 9999)+strings.Repeat("]", 9999)))
	var cases []diffCase
	for _, in := range inputs {
		if !utf8.Valid(in) {
			continue // the browser only ever sees valid UTF-8 (the API emits canonical, valid text)
		}
		c := diffCase{In: base64.StdEncoding.EncodeToString(in)}
		if out, err := canon.CanonicalBytes(in); err == nil {
			c.OK, c.Canon = true, string(out)
		}
		cases = append(cases, c)
	}
	dir := t.TempDir()
	js, err := fs.ReadFile(StaticFS(), "canon.js")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "canon.js"), js, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run.js"), []byte(diffRunner), 0o600)
	b, _ := json.Marshal(cases)
	_ = os.WriteFile(filepath.Join(dir, "cases.json"), b, 0o600)
	out, err := exec.Command(node, "--stack-size=65500", filepath.Join(dir, "run.js"), filepath.Join(dir, "canon.js"), filepath.Join(dir, "cases.json")).CombinedOutput()
	if err != nil {
		t.Fatalf("differential failed: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)), fmt.Sprintf("(%d inputs)", len(cases)))
}
