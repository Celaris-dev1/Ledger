package incident

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var funcs = template.FuncMap{
	"ts":    func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000Z") },
	"short": func(s string) string { return shortHash(s) },
	"deref": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
}

func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// html/template escapes every interpolated value; the page has no scripts and no
// external resources.
var page = template.Must(template.New("incident").Funcs(funcs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Incident review {{.GoalID}}</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#d8dde3;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--chip:#f3f5f7}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2b3038;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--chip:#1a1e24}}
body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0 auto;max-width:1100px;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.muted{color:var(--muted)}.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.warn{color:var(--warn);font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}code{font:12px ui-monospace,Menlo,monospace;background:var(--chip);padding:1px 4px;border-radius:4px;word-break:break-all}
.chip{display:inline-block;padding:1px 8px;border-radius:10px;background:var(--chip);font-size:12px}
.wrap{overflow-x:auto}
</style></head><body>
<h1>Incident review: <code>{{.GoalID}}</code></h1>
<div class="muted">Generated {{ts .GeneratedAt}} from Ledger hash chains.</div>
<p>{{if .Summary.AllChainsIntact}}<span class="ok">All source chains verify.</span>{{else}}<span class="bad">At least one source chain FAILS verification: treat this narrative as untrusted.</span>{{end}}
{{.Summary.Headline}}</p>
<p class="muted">Originating humans: {{range $i, $h := .Summary.Humans}}{{if $i}}, {{end}}{{$h}}{{end}}</p>

<h2>Chain verification per source</h2>
<div class="wrap"><table><tr><th>Chain</th><th>Status</th><th>Length</th><th>Head</th><th>Records in incident</th></tr>
{{range .Chains}}<tr><td>{{.Chain}}</td><td>{{if .OK}}<span class="ok">intact</span>{{else}}<span class="bad">BROKEN at seq {{deref .BrokenAt}}</span> {{.Reason}}{{end}}</td><td>{{.Length}}</td><td><code>{{short .Head}}</code></td><td>{{.Records}}</td></tr>
{{end}}</table></div>

<h2>Who authorised what</h2>
<div class="wrap"><table><tr><th>When</th><th>Decision</th><th>Who</th><th>What</th><th>Record</th></tr>
{{range .Authorisations}}<tr><td>{{ts .At}}</td><td>{{if eq .Decision "denied" "revoked"}}<span class="bad">{{.Decision}}</span>{{else}}<span class="chip">{{.Decision}}</span>{{end}}</td><td>{{.Who}}</td><td>{{.What}}</td><td><code>{{.Source}}</code></td></tr>
{{else}}<tr><td colspan="5" class="muted">No authorisation records.</td></tr>{{end}}</table></div>

<h2>What ran</h2>
<div class="wrap"><table><tr><th>When</th><th>Who</th><th>What</th><th>Record</th></tr>
{{range .Ran}}<tr><td>{{ts .At}}</td><td>{{.Who}}</td><td>{{.Summary}}</td><td><code>{{.Chain}}#{{.Seq}}</code></td></tr>
{{else}}<tr><td colspan="4" class="muted">Nothing recorded as run.</td></tr>{{end}}</table></div>

<h2>What was verified</h2>
<div class="wrap"><table><tr><th>When</th><th>Verifier</th><th>Result</th><th>Detail</th><th>Record</th></tr>
{{range .Verifications}}<tr><td>{{ts .At}}</td><td>{{.Verifier}}</td><td>{{if .Passed}}<span class="ok">pass</span>{{else}}<span class="bad">fail</span>{{end}}</td><td>{{.Detail}}</td><td><code>{{.Source}}</code></td></tr>
{{else}}<tr><td colspan="5" class="muted">No verification records.</td></tr>{{end}}</table></div>

<h2>Effects: committed vs not</h2>
<div class="wrap"><table><tr><th>Effect</th><th>Tool</th><th>Status</th><th>Intent record</th><th>Result record</th></tr>
{{range .Effects}}<tr><td><code>{{.ID}}</code></td><td>{{.Tool}}</td><td>{{if .Committed}}<span class="ok">{{.Status}}</span>{{else}}<span class="warn">{{.Status}}</span>{{end}}</td><td><code>{{.IntentRecordID}}</code></td><td><code>{{.ResultRecordID}}</code></td></tr>
{{else}}<tr><td colspan="5" class="muted">No side effects recorded.</td></tr>{{end}}</table></div>

<h2>Full narrative</h2>
<div class="wrap"><table><tr><th>When</th><th>Source</th><th>Type</th><th>Who</th><th>What</th><th>Linked by</th><th>Hash</th></tr>
{{range .Narrative}}<tr><td>{{ts .At}}</td><td><code>{{.Chain}}#{{.Seq}}</code></td><td>{{.Type}}</td><td>{{.Who}}</td><td>{{.Summary}}</td><td>{{.LinkedBy}}</td><td><code title="{{.Hash}}">{{short .Hash}}</code></td></tr>
{{end}}</table></div>
<p class="muted">Every line is a record in a SHA-256 hash chain; verify independently with <code>ledger verify</code> or GET /v1/chains/{chain}/verify.</p>
</body></html>
`))

// WriteHTML writes a self-contained HTML page (all values escaped).
func WriteHTML(w io.Writer, r *Report) error { return page.Execute(w, r) }

// md escapes text for a Markdown table cell (also neutralises raw HTML).
func md(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\\', '`', '*', '_', '[', ']', '(', ')', '#', '|', '!', '~', '{', '}':
			b.WriteByte('\\')
			b.WriteRune(c)
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// WriteMarkdown writes the report as Markdown.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000Z") }
	p("# Incident review: %s\n\n", md(r.GoalID))
	if r.Summary.AllChainsIntact {
		p("**All source chains verify.** ")
	} else {
		p("**WARNING: at least one source chain FAILS verification.** ")
	}
	p("%s\n\nOriginating humans: %s\n\n", md(r.Summary.Headline), md(strings.Join(r.Summary.Humans, ", ")))
	p("## Chain verification per source\n\n| Chain | Status | Length | Head | Records in incident |\n|---|---|---|---|---|\n")
	for _, c := range r.Chains {
		st := "intact"
		if !c.OK {
			st = fmt.Sprintf("BROKEN at seq %d: %s", derefI(c.BrokenAt), c.Reason)
		}
		p("| %s | %s | %d | %s | %d |\n", md(c.Chain), md(st), c.Length, md(shortHash(c.Head)), c.Records)
	}
	p("\n## Who authorised what\n\n| When | Decision | Who | What | Record |\n|---|---|---|---|---|\n")
	for _, a := range r.Authorisations {
		p("| %s | %s | %s | %s | %s |\n", ts(a.At), md(a.Decision), md(a.Who), md(a.What), md(a.Source))
	}
	p("\n## What ran\n\n| When | Who | What | Record |\n|---|---|---|---|\n")
	for _, e := range r.Ran {
		p("| %s | %s | %s | %s |\n", ts(e.At), md(e.Who), md(e.Summary), md(fmt.Sprintf("%s#%d", e.Chain, e.Seq)))
	}
	p("\n## What was verified\n\n| When | Verifier | Result | Detail | Record |\n|---|---|---|---|---|\n")
	for _, v := range r.Verifications {
		res := "pass"
		if !v.Passed {
			res = "**fail**"
		}
		p("| %s | %s | %s | %s | %s |\n", ts(v.At), md(v.Verifier), res, md(v.Detail), md(v.Source))
	}
	p("\n## Effects: committed vs not\n\n| Effect | Tool | Status | Intent record | Result record |\n|---|---|---|---|---|\n")
	for _, e := range r.Effects {
		p("| %s | %s | %s | %s | %s |\n", md(e.ID), md(e.Tool), md(e.Status), md(e.IntentRecordID), md(e.ResultRecordID))
	}
	p("\n## Full narrative\n\n| When | Source | Type | Who | What | Linked by | Hash |\n|---|---|---|---|---|---|---|\n")
	for _, e := range r.Narrative {
		p("| %s | %s | %s | %s | %s | %s | %s |\n", ts(e.At), md(fmt.Sprintf("%s#%d", e.Chain, e.Seq)), md(e.Type), md(e.Who), md(e.Summary), md(e.LinkedBy), md(shortHash(e.Hash)))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func derefI(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
