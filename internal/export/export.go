// Package export builds the auditor pack: raw JSON plus an HTML narrative mapped to
// EU AI Act Article 12 (record-keeping) and Article 14 (human oversight) headings.
// Templates are a separate layer (this file) so other regimes can be added alongside.
package export

import (
	"archive/zip"
	"encoding/json"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// ChainSection is one chain in the pack.
type ChainSection struct {
	Verify  store.VerifyResult `json:"verify"`
	Root    *anchor.Root       `json:"root,omitempty"`
	Records []store.Record     `json:"records"`
}

// Pack is the auditor pack's JSON form.
type Pack struct {
	Format      string         `json:"format"`
	GeneratedAt string         `json:"generated_at"`
	GoalID      string         `json:"goal_id,omitempty"`
	Chains      []ChainSection `json:"chains"`
	Summary     Summary        `json:"summary"`
}

// Summary holds derived facts used by the narrative.
type Summary struct {
	TotalRecords     int               `json:"total_records"`
	AllChainsIntact  bool              `json:"all_chains_intact"`
	FirstRecord      string            `json:"first_record,omitempty"`
	LastRecord       string            `json:"last_record,omitempty"`
	RecordTypes      map[string]int    `json:"record_types"`
	Humans           []string          `json:"originating_humans"`
	Agents           []string          `json:"agents_and_models"`
	PolicyVersions   []string          `json:"policy_versions"`
	OversightRecords []OversightRecord `json:"oversight_records"`
}

// OversightRecord is a record evidencing a human-oversight or control decision.
type OversightRecord struct {
	Chain string `json:"chain"`
	Seq   int64  `json:"seq"`
	Type  string `json:"type"`
	Human string `json:"human"`
	At    string `json:"at"`
}

var oversightMarkers = []string{"approv", "denied", "decided", "revoked", "override", "halt", "stop", "transition"}

// Build assembles a pack from chain sections.
func Build(goalID string, sections []ChainSection) Pack {
	p := Pack{Format: "ledger-auditor-pack/v1", GeneratedAt: time.Now().UTC().Format(time.RFC3339), GoalID: goalID, Chains: sections}
	s := Summary{AllChainsIntact: true, RecordTypes: map[string]int{}}
	humans, agents, policies := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var first, last time.Time
	for _, c := range sections {
		if !c.Verify.OK {
			s.AllChainsIntact = false
		}
		for _, r := range c.Records {
			s.TotalRecords++
			s.RecordTypes[r.Type]++
			if first.IsZero() || r.CreatedAt.Before(first) {
				first = r.CreatedAt
			}
			if r.CreatedAt.After(last) {
				last = r.CreatedAt
			}
			if r.PolicyVersion != "" {
				policies[r.PolicyVersion] = true
			}
			var actors []store.Actor
			_ = json.Unmarshal(r.ActorChain, &actors)
			human := ""
			for i, a := range actors {
				if i == 0 && a.Kind == "human" {
					human = a.ID
					humans[a.ID] = true
				} else if a.Kind != "human" {
					label := a.Kind + ":" + a.ID
					if a.Model != "" {
						label += " (" + a.Model
						if a.ModelVersion != "" {
							label += "@" + a.ModelVersion
						}
						label += ")"
					}
					agents[label] = true
				}
			}
			lt := strings.ToLower(r.Type)
			for _, m := range oversightMarkers {
				if strings.Contains(lt, m) {
					s.OversightRecords = append(s.OversightRecords, OversightRecord{r.Chain, r.Seq, r.Type, human, r.CreatedAt.Format(time.RFC3339)})
					break
				}
			}
		}
	}
	if !first.IsZero() {
		s.FirstRecord, s.LastRecord = first.Format(time.RFC3339), last.Format(time.RFC3339)
	}
	s.Humans, s.Agents, s.PolicyVersions = keys(humans), keys(agents), keys(policies)
	p.Summary = s
	return p
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var narrative = template.Must(template.New("n").Funcs(template.FuncMap{
	"raw": func(b json.RawMessage) string { return string(b) },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Ledger Auditor Pack</title>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a}
h1,h2,h3{line-height:1.2}table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}
code{font-size:.8rem;word-break:break-all}.ok{color:#0a6b2d}.bad{color:#b00020;font-weight:bold}.note{color:#555;font-size:.9rem}</style></head><body>
<h1>Ledger Auditor Pack</h1>
<p>Generated {{.GeneratedAt}}{{if .GoalID}} for goal <code>{{.GoalID}}</code>{{end}}. Format <code>{{.Format}}</code>. The accompanying <code>pack.json</code> contains every record verbatim; this narrative is derived from it.</p>
<p class="note">This pack maps Ledger evidence to EU AI Act headings to assist review. It is not legal advice and does not by itself establish conformity.</p>

<h2>Integrity summary</h2>
<p>{{if .Summary.AllChainsIntact}}<span class="ok">All {{len .Chains}} chain(s) verified intact.</span>{{else}}<span class="bad">One or more chains FAILED verification — see below.</span>{{end}}
{{.Summary.TotalRecords}} records between {{.Summary.FirstRecord}} and {{.Summary.LastRecord}}.</p>
<table><tr><th>Chain</th><th>Length</th><th>Status</th><th>Head hash</th><th>Signed root</th></tr>
{{range .Chains}}<tr><td>{{.Verify.Chain}}</td><td>{{.Verify.Length}}</td><td>{{if .Verify.OK}}<span class="ok">intact</span>{{else}}<span class="bad">broken at seq {{.Verify.BrokenAt}}: {{.Verify.Reason}}</span>{{end}}</td><td><code>{{.Verify.Head}}</code></td><td>{{if .Root}}seq {{.Root.Seq}}, Ed25519 key <code>{{.Root.PublicKey}}</code>{{else}}—{{end}}</td></tr>{{end}}
</table>

<h2>Article 12 — Record-keeping</h2>
<h3>Art. 12(1) Automatic recording of events over the lifetime of the system</h3>
<p>Every decision point is written by the system itself (via the Ledger SDK/API) to an append-only store. Database triggers reject UPDATE, DELETE and TRUNCATE on records. Each record includes <code>sha256(prev_hash + "\n" + canonical_json(record))</code>, forming a per-chain hash chain; chain roots are signed with Ed25519 and anchored outside the database.</p>
<h3>Art. 12(2)(a) Identifying situations that may present a risk or lead to substantial modification</h3>
<p>Record types logged ({{len .Summary.RecordTypes}} distinct):</p>
<table><tr><th>Type</th><th>Count</th></tr>{{range $k, $v := .Summary.RecordTypes}}<tr><td><code>{{$k}}</code></td><td>{{$v}}</td></tr>{{end}}</table>
<h3>Art. 12(2)(b) Facilitating post-market monitoring</h3>
<p>Policy versions evaluated: {{if .Summary.PolicyVersions}}{{range .Summary.PolicyVersions}}<code>{{.}}</code> {{end}}{{else}}none recorded{{end}}. Records are queryable by chain, goal and sequence and can be replayed per goal.</p>
<h3>Art. 12(2)(c) Monitoring the operation of the system</h3>
<p>Agents and models acting: {{if .Summary.Agents}}{{range .Summary.Agents}}<code>{{.}}</code> {{end}}{{else}}none recorded{{end}}.</p>
<h3>Art. 12(3) Specific logging for remote biometric identification</h3>
<p class="note">Not applicable unless the deployment performs remote biometric identification; Ledger records reference period, reference database and verifying persons only if the emitting system supplies them in the payload.</p>

<h2>Article 14 — Human oversight</h2>
<h3>Art. 14(1)–(3) Effective oversight by natural persons</h3>
<p>Every record's <code>actor_chain</code> begins with the originating human; the API rejects any record without one. Originating humans in this pack: {{if .Summary.Humans}}{{range .Summary.Humans}}<code>{{.}}</code> {{end}}{{else}}none{{end}}.</p>
<h3>Art. 14(4)(d)–(e) Ability to decide not to use, override, or interrupt the system</h3>
<p>Records evidencing approval, denial, revocation, halting or state transitions:</p>
<table><tr><th>When</th><th>Chain/seq</th><th>Type</th><th>Originating human</th></tr>
{{range .Summary.OversightRecords}}<tr><td>{{.At}}</td><td>{{.Chain}}/{{.Seq}}</td><td><code>{{.Type}}</code></td><td>{{.Human}}</td></tr>{{else}}<tr><td colspan="4">No oversight-type records in scope.</td></tr>{{end}}</table>
<h3>Art. 14(5) Verification by at least two natural persons (where required)</h3>
<p class="note">Where dual verification is required, look for two distinct human actors on the relevant approval records above.</p>

<h2>Appendix — record timeline</h2>
{{range .Chains}}<h3>Chain {{.Verify.Chain}}</h3>
<table><tr><th>Seq</th><th>Time</th><th>Type</th><th>Goal</th><th>Actors</th><th>Payload</th><th>Hash</th></tr>
{{range .Records}}<tr><td>{{.Seq}}</td><td>{{.CreatedAt.Format "2006-01-02T15:04:05.000Z07:00"}}</td><td><code>{{.Type}}</code></td><td>{{.GoalID}}</td><td><code>{{raw .ActorChain}}</code></td><td><code>{{raw .Payload}}</code></td><td><code>{{.Hash}}</code></td></tr>{{end}}
</table>{{end}}
</body></html>
`))

// WriteHTML renders the narrative.
func WriteHTML(w io.Writer, p Pack) error { return narrative.Execute(w, p) }

// WriteZip writes pack.json + narrative.html into a zip archive.
func WriteZip(w io.Writer, p Pack) error {
	zw := zip.NewWriter(w)
	jw, err := zw.Create("pack.json")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(jw)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return err
	}
	hw, err := zw.Create("narrative.html")
	if err != nil {
		return err
	}
	if err := WriteHTML(hw, p); err != nil {
		return err
	}
	return zw.Close()
}
