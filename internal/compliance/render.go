package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"github.com/Celaris-dev1/Ledger/internal/canon"
)

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"raw":   canonText,
	"upper": strings.ToUpper,
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format(time.RFC3339)
	},
	"deref": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Title}}</title>
<meta name="ledger-document-hash" content="{{.DocumentHash}}">
<style>
:root{--fg:#1a1a1a;--muted:#555;--line:#ccc;--pass:#0a6b2d;--gap:#b00020;--manual:#7a5b00;--bg:#fff}
@media (prefers-color-scheme:dark){:root{--fg:#e8e8e8;--muted:#aaa;--line:#444;--pass:#5fd38a;--gap:#ff6b81;--manual:#e6c35c;--bg:#161616}}
body{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 16px;line-height:1.5;color:var(--fg);background:var(--bg)}
table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}
code{font-size:.8rem;word-break:break-all}.note{color:var(--muted);font-size:.9rem}
.pass{color:var(--pass);font-weight:600}.gap{color:var(--gap);font-weight:600}.manual{color:var(--manual);font-weight:600}
.ctl{border:1px solid var(--line);border-radius:6px;padding:.6rem .9rem;margin:.8rem 0}.ctl h4{margin:.1rem 0}
</style></head><body>
<h1>{{.Title}}</h1>
<p>Template <code>{{.Template}}</code> · {{.Source}}<br>Generated {{.GeneratedAt}} · Scope: chains {{range .Scope.Chains}}<code>{{.}}</code> {{end}}{{if .Scope.GoalID}}· goal <code>{{.Scope.GoalID}}</code> {{end}}· from {{date .Scope.From}} to {{date .Scope.To}} · {{.RecordCount}} records in scope</p>
<p class="note">{{.Disclaimer}}</p>
<h2>Summary</h2>
<p><span class="pass">{{.Totals.Pass}} pass</span> · <span class="gap">{{.Totals.Gap}} gap</span> · <span class="manual">{{.Totals.Manual}} manual</span></p>
<table><tr><th>Control</th><th>Citation</th><th>Title</th><th>Status</th></tr>
{{range .Controls}}<tr><td>{{.ID}}</td><td>{{.Citation}}</td><td>{{.Title}}</td><td class="{{.Status}}">{{upper .Status}}</td></tr>{{end}}</table>
<h2>Controls</h2>
{{$sec := ""}}{{range .Controls}}{{if ne .Section $sec}}{{$sec = .Section}}<h3>{{.Section}}</h3>{{end}}
<div class="ctl"><h4>{{.ID}} — {{.Title}} <span class="{{.Status}}">[{{upper .Status}}]</span></h4>
<p><b>{{.Citation}}.</b> {{.Requirement}}</p>
<p class="note">Evidence query: {{.EvidenceQuery}}</p>
<p>{{.Summary}}</p>
{{if .Evidence}}<table><tr><th>Chain/seq</th><th>Type</th><th>At</th><th>Record hash</th></tr>{{range .Evidence}}<tr><td>{{.Chain}}/{{.Seq}}</td><td><code>{{.Type}}</code></td><td>{{.At}}</td><td><code>{{.Hash}}</code></td></tr>{{end}}</table>{{if gt .Count (len .Evidence)}}<p class="note">{{len .Evidence}} of {{.Count}} evidence records listed; all are in the JSON pack.</p>{{end}}{{end}}
</div>{{end}}
<h2>Integrity appendix</h2>
<p>{{if .Integrity.AllChainsIntact}}<span class="pass">All chains verified intact.</span>{{else}}<span class="gap">One or more chains FAILED verification.</span>{{end}}
{{if .Integrity.AnchorsChecked}}{{if .Integrity.AnchorsOK}}<span class="pass">All external anchors verified.</span>{{else}}<span class="gap">External anchor verification reported problems.</span>{{end}}{{else}}<span class="gap">External anchors not checked.</span>{{end}}</p>
<table><tr><th>Chain</th><th>Length</th><th>In scope</th><th>Verification</th><th>Head</th><th>Signed root</th></tr>
{{range .Integrity.Chains}}<tr><td>{{.Chain}}</td><td>{{.Verify.Length}}</td><td>{{.RecordsInScope}}</td><td>{{if .Verify.OK}}<span class="pass">intact</span>{{else}}<span class="gap">broken at seq {{deref .Verify.BrokenAt}}: {{.Verify.Reason}}</span>{{end}}</td><td><code>{{.Verify.Head}}</code></td><td>{{if .Root}}seq {{.Root.Seq}} key <code>{{.Root.KeyID}}</code>{{else}}—{{end}}</td></tr>{{end}}</table>
<h3>External anchor receipts</h3>
{{range .Integrity.Chains}}{{if .Anchors}}<h4>{{.Chain}} — {{if .Anchors.OK}}<span class="pass">ok</span>{{else}}<span class="gap">problems</span>{{end}}, last anchored seq {{.Anchors.LastAnchored}}</h4>
{{range .Anchors.Findings}}<p class="gap">{{.}}</p>{{end}}{{range .Anchors.Warnings}}<p class="note">warning: {{.}}</p>{{end}}
<table><tr><th>Seq</th><th>Backend</th><th>Kind</th><th>Anchored at</th><th>Key</th><th>Status</th><th>Head</th></tr>{{range .Anchors.Checks}}<tr><td>{{.Seq}}</td><td>{{.Backend}}</td><td>{{.Kind}}</td><td>{{date .AnchoredAt}}</td><td><code>{{.KeyID}}</code></td><td class="{{if eq .Status "ok"}}pass{{else if eq .Status "unverifiable"}}manual{{else}}gap{{end}}">{{.Status}}{{if .Detail}}: {{.Detail}}{{end}}</td><td><code>{{.Head}}</code></td></tr>{{else}}<tr><td colspan="7">No receipts.</td></tr>{{end}}</table>{{else}}<p class="note">{{.Chain}}: anchoring not configured for this export.</p>{{end}}{{end}}
<h3>Root-key rotation history</h3>
<table><tr><th>Rotated at</th><th>Old key</th><th>New key</th></tr>{{range .Integrity.KeyRotations}}<tr><td>{{.RotatedAt}}</td><td><code>{{.OldKeyID}}</code></td><td><code>{{.NewKeyID}}</code></td></tr>{{else}}<tr><td colspan="3">No rotations recorded.</td></tr>{{end}}</table>
{{range .Integrity.RotationErrors}}<p class="gap">{{.}}</p>{{end}}
<h2>Retention, legal holds and erasures</h2>
<table><tr><th>Chain</th><th>Regime</th><th>Minimum retention</th><th>Set by</th><th>Set at</th></tr>{{range $k, $v := .Retention.Policies}}<tr><td>{{$k}}</td><td>{{$v.Regime}}</td><td>{{$v.MinRetention}}</td><td>{{$v.SetBy}}</td><td>{{$v.SetAt}}</td></tr>{{else}}<tr><td colspan="5">No retention policies recorded.</td></tr>{{end}}</table>
<h3>Legal holds</h3>
<table><tr><th>Hold</th><th>Reason</th><th>Scope</th><th>Created</th><th>Released</th></tr>{{range .Retention.Holds}}<tr><td>{{.ID}}</td><td>{{.Reason}}</td><td>{{if .All}}all{{else}}{{range .Chains}}<code>{{.}}</code> {{end}}{{range .SubjectKeys}}<code>{{.}}</code> {{end}}{{end}}</td><td>{{.CreatedBy}} {{.CreatedAt}}</td><td>{{if .Released}}{{.ReleasedBy}} {{.ReleasedAt}}: {{.ReleaseNote}}{{else}}<b>active</b>{{end}}</td></tr>{{else}}<tr><td colspan="5">No legal holds.</td></tr>{{end}}</table>
<h3>Erasures (crypto-shredding)</h3>
<table><tr><th>Subject key</th><th>When</th><th>Reason / basis</th><th>Records</th><th>Retention override</th></tr>{{range .Retention.Erasures}}<tr><td><code>{{.SubjectKeyID}}</code></td><td>{{.ErasedAt}}</td><td>{{.Reason}} {{.LegalBasis}}</td><td>{{.RecordsAffected}}</td><td>{{.RetentionOverride}}</td></tr>{{else}}<tr><td colspan="5">No erasures.</td></tr>{{end}}</table>
<h2>Document integrity</h2>
<p>Document hash (sha256 of the canonical JSON pack without hash/signature): <code>{{.DocumentHash}}</code><br>
{{with .Signature}}Signed with {{.Algorithm}} key <code>{{.KeyID}}</code>; signature <code>{{.Signature}}</code>; public key <code>{{.PublicKey}}</code>{{else}}<span class="gap">Unsigned.</span>{{end}}</p>
<h2>Appendix — records in scope</h2>
<table><tr><th>Chain/seq</th><th>Time</th><th>Type</th><th>Goal</th><th>Actors</th><th>Payload</th><th>Hash</th></tr>
{{range .Records}}<tr><td>{{.Chain}}/{{.Seq}}</td><td>{{.CreatedAt.Format "2006-01-02T15:04:05.000Z07:00"}}</td><td><code>{{.Type}}</code></td><td>{{.GoalID}}</td><td><code>{{raw .ActorChain}}</code></td><td><code>{{raw .Payload}}</code></td><td><code>{{.Hash}}</code></td></tr>{{end}}</table>
</body></html>
`))

// WriteHTML renders the human-readable pack.
func WriteHTML(w io.Writer, r Report) error { return htmlTmpl.Execute(w, r) }

// PDFRecordLimit caps the record appendix in the PDF (the embedded JSON has all records).
const PDFRecordLimit = 400

// RenderPDF renders the pack as a PDF (pure Go, go-pdf/fpdf, MIT). The signed JSON pack is
// embedded as the attachment "report.json"; the document hash and signature are printed on
// the cover and stored in the PDF Subject/Keywords metadata.
func RenderPDF(r Report) ([]byte, error) {
	gen, _ := time.Parse(time.RFC3339, r.GeneratedAt)
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCatalogSort(true)
	pdf.SetCreationDate(gen)
	pdf.SetModificationDate(gen)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.SetTitle(r.Title, true)
	pdf.SetAuthor("Ledger", true)
	pdf.SetCreator("ledger export --regime", true)
	pdf.SetSubject("ledger-document-hash sha256:"+r.DocumentHash, false)
	kw := "template:" + r.Template + " document_hash:" + r.DocumentHash
	if r.Signature != nil {
		kw += " signature_alg:" + r.Signature.Algorithm + " signature_key:" + r.Signature.KeyID + " signature:" + r.Signature.Signature
	}
	pdf.SetKeywords(kw, false)
	js, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	pdf.SetAttachments([]fpdf.Attachment{{Content: js, Filename: "report.json", Description: "Signed Ledger compliance pack (JSON); document_hash + signature verify with `ledger export --verify`"}})
	pdf.SetAutoPageBreak(true, 15)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-10)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(0, 4, tr(fmt.Sprintf("%s · sha256:%s · page %d", r.Template, short(r.DocumentHash), pdf.PageNo())), "", 0, "C", false, 0, "")
	})
	pdf.AddPage()
	w, _ := pdf.GetPageSize()
	lm, _, rm, _ := pdf.GetMargins()
	width := w - lm - rm

	h1 := func(s string) {
		pdf.SetTextColor(20, 20, 20)
		pdf.SetFont("Helvetica", "B", 16)
		pdf.MultiCell(width, 7, tr(s), "", "L", false)
		pdf.Ln(2)
	}
	h2 := func(s string) {
		pdf.Ln(3)
		pdf.SetTextColor(20, 20, 20)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.MultiCell(width, 6, tr(s), "", "L", false)
		pdf.Ln(1)
	}
	body := func(s string, size float64) {
		pdf.SetTextColor(30, 30, 30)
		pdf.SetFont("Helvetica", "", size)
		pdf.MultiCell(width, size*0.5, tr(s), "", "L", false)
	}
	mono := func(s string) {
		pdf.SetTextColor(30, 30, 30)
		pdf.SetFont("Courier", "", 7)
		pdf.MultiCell(width, 3.4, tr(s), "", "L", false)
	}
	status := func(st string) {
		switch st {
		case Pass:
			pdf.SetTextColor(10, 107, 45)
		case Gap:
			pdf.SetTextColor(176, 0, 32)
		default:
			pdf.SetTextColor(122, 91, 0)
		}
		pdf.SetFont("Helvetica", "B", 9)
	}

	h1(r.Title)
	body(fmt.Sprintf("Template %s\n%s\nGenerated %s", r.Template, r.Source, r.GeneratedAt), 9)
	sc := "Scope: chains " + strings.Join(r.Scope.Chains, ", ")
	if r.Scope.GoalID != "" {
		sc += "; goal " + r.Scope.GoalID
	}
	sc += fmt.Sprintf("; from %s to %s; %d records in scope.", fmtT(r.Scope.From), fmtT(r.Scope.To), r.RecordCount)
	body(sc, 9)
	pdf.Ln(2)
	body(r.Disclaimer, 8)
	h2("Summary")
	body(fmt.Sprintf("%d pass · %d gap · %d manual", r.Totals.Pass, r.Totals.Gap, r.Totals.Manual), 10)
	pdf.Ln(1)
	for _, c := range r.Controls {
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(32, 4.5, tr(c.ID), "", 0, "L", false, 0, "")
		pdf.CellFormat(width-32-18, 4.5, tr(trunc(c.Title, 95)), "", 0, "L", false, 0, "")
		status(c.Status)
		pdf.CellFormat(18, 4.5, strings.ToUpper(c.Status), "", 1, "R", false, 0, "")
	}
	h2("Document integrity")
	body("Document hash (sha256 of the canonical JSON pack embedded in this PDF as report.json, without hash and signature fields):", 8)
	mono(r.DocumentHash)
	if r.Signature != nil {
		body(fmt.Sprintf("Signed by the ledger root key (%s, key id %s). Signature (base64) and public key:", r.Signature.Algorithm, r.Signature.KeyID), 8)
		mono(r.Signature.Signature)
		mono(r.Signature.PublicKey)
	} else {
		body("UNSIGNED.", 8)
	}

	pdf.AddPage()
	h1("Controls")
	sec := ""
	for _, c := range r.Controls {
		if c.Section != sec {
			sec = c.Section
			h2(sec)
		}
		pdf.SetFont("Helvetica", "B", 9.5)
		pdf.SetTextColor(20, 20, 20)
		pdf.MultiCell(width, 5, tr(c.ID+" — "+c.Title), "", "L", false)
		status(c.Status)
		pdf.MultiCell(width, 4.5, strings.ToUpper(c.Status), "", "L", false)
		body(c.Citation+". "+c.Requirement, 8)
		pdf.SetFont("Helvetica", "I", 7.5)
		pdf.SetTextColor(85, 85, 85)
		pdf.MultiCell(width, 3.6, tr("Evidence query: "+c.EvidenceQuery), "", "L", false)
		body(c.Summary, 8)
		for _, e := range c.Evidence {
			mono(fmt.Sprintf("  %s/%d %s %s %s", e.Chain, e.Seq, e.Type, e.At, short(e.Hash)))
		}
		if c.Count > len(c.Evidence) && len(c.Evidence) > 0 {
			body(fmt.Sprintf("  (%d of %d evidence records listed; all are in report.json)", len(c.Evidence), c.Count), 7)
		}
		pdf.Ln(2.5)
	}

	pdf.AddPage()
	h1("Integrity appendix")
	for _, c := range r.Integrity.Chains {
		st := "intact"
		if !c.Verify.OK {
			at := int64(0)
			if c.Verify.BrokenAt != nil {
				at = *c.Verify.BrokenAt
			}
			st = fmt.Sprintf("BROKEN at seq %d: %s", at, c.Verify.Reason)
		}
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(20, 20, 20)
		pdf.MultiCell(width, 4.5, tr(fmt.Sprintf("Chain %s — length %d, %d in scope — %s", c.Chain, c.Verify.Length, c.RecordsInScope, st)), "", "L", false)
		mono("head " + c.Verify.Head)
		if c.Root != nil {
			mono(fmt.Sprintf("signed root seq %d key %s sig %s", c.Root.Seq, c.Root.KeyID, trunc(c.Root.Signature, 60)))
		}
		if c.Anchors == nil {
			body("External anchors: not checked (anchoring not configured for this export).", 8)
		} else {
			body(fmt.Sprintf("External anchors: ok=%v, rewritten=%v, last anchored seq %d, %d receipt(s).", c.Anchors.OK, c.Anchors.Rewritten, c.Anchors.LastAnchored, len(c.Anchors.Checks)), 8)
			for _, f := range c.Anchors.Findings {
				status(Gap)
				pdf.MultiCell(width, 4, tr(f), "", "L", false)
			}
			for _, a := range c.Anchors.Checks {
				mono(fmt.Sprintf("  seq %d %-14s %-8s %s key %s: %s %s", a.Seq, a.Backend, a.Kind, fmtT(a.AnchoredAt), a.KeyID, a.Status, trunc(a.Detail, 60)))
			}
		}
		pdf.Ln(2)
	}
	h2("Root-key rotation history")
	if len(r.Integrity.KeyRotations) == 0 {
		body("No rotations recorded.", 8)
	}
	for _, k := range r.Integrity.KeyRotations {
		mono(fmt.Sprintf("%s  %s -> %s", k.RotatedAt, k.OldKeyID, k.NewKeyID))
	}
	for _, e := range r.Integrity.RotationErrors {
		status(Gap)
		pdf.MultiCell(width, 4, tr(e), "", "L", false)
	}
	h2("Retention policies, legal holds, erasures")
	if len(r.Retention.Policies) == 0 {
		body("No retention policies recorded.", 8)
	}
	pk := make([]string, 0, len(r.Retention.Policies))
	for k := range r.Retention.Policies {
		pk = append(pk, k)
	}
	sort.Strings(pk)
	for _, k := range pk {
		p := r.Retention.Policies[k]
		body(fmt.Sprintf("Policy %s: %s minimum (%s), set by %s at %s", k, p.MinRetention, p.Regime, p.SetBy, p.SetAt), 8)
	}
	for _, h := range r.Retention.Holds {
		state := "ACTIVE"
		if h.Released {
			state = "released by " + h.ReleasedBy + " at " + h.ReleasedAt + ": " + h.ReleaseNote
		}
		body(fmt.Sprintf("Hold %s (%s) created by %s at %s — %s", h.ID, h.Reason, h.CreatedBy, h.CreatedAt, state), 8)
	}
	for _, e := range r.Retention.Erasures {
		body(fmt.Sprintf("Erasure %s at %s: %s %s, %d record payload(s) crypto-shredded; override: %s", e.SubjectKeyID, e.ErasedAt, e.Reason, e.LegalBasis, e.RecordsAffected, orDash(e.RetentionOverride)), 8)
	}

	pdf.AddPage()
	h1("Appendix — records in scope")
	n := len(r.Records)
	if n > PDFRecordLimit {
		body(fmt.Sprintf("First %d of %d records; every record is in the embedded report.json.", PDFRecordLimit, n), 8)
		n = PDFRecordLimit
	}
	for _, rec := range r.Records[:n] {
		mono(fmt.Sprintf("%s/%d %s %s goal=%s", rec.Chain, rec.Seq, rec.CreatedAt.UTC().Format(time.RFC3339), rec.Type, rec.GoalID))
		mono("  actors " + trunc(displayJSON(rec.ActorChain), 150))
		mono("  payload " + trunc(displayJSON(rec.Payload), 300))
		mono("  hash " + rec.Hash)
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// displayJSON prints stored JSON in canonical form (the form the hash covers), so the PDF is
// a pure function of the embedded report: the embedded report.json re-marshals raw payloads
// (compacted, HTML-escaped) and VerifyPDF re-renders from it.
func displayJSON(b json.RawMessage) string {
	if c, err := canon.CanonicalBytes(b); err == nil {
		return string(c)
	}
	return string(b)
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func trunc(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n]) + "…"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// canonText renders embedded JSON canonically, so a report rendered from its JSON round trip
// (json.Marshal HTML-escapes raw messages: "<" becomes <) prints the same text.
func canonText(b json.RawMessage) string {
	if c, err := canon.CanonicalBytes(b); err == nil {
		return string(c)
	}
	return string(b)
}

func fmtT(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}
