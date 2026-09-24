// Package compliance renders auditor packs from versioned regime templates.
//
// This is the "separate templated layer" of the spec: the record store knows nothing about
// regimes. A Template is a list of controls; each control states the requirement (with its
// citation), the evidence query it runs over the ledger, and evaluates to
//
//	pass    the ledger holds evidence that satisfies the stated evidence criterion
//	gap     the evidence criterion is not met (missing, failing, late, or broken)
//	manual  an organisational control Ledger cannot evidence; the auditor must obtain it
//
// A pass is never a claim of regulatory compliance, only that the named evidence exists and
// verifies. Every report also carries the integrity evidence (chain verification, external
// anchor receipts and their re-verification, key-rotation history, retention/holds/erasures),
// a document hash and a signature by the ledger root key.
package compliance

import (
	"fmt"
	"sort"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/retention"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Statuses.
const (
	Pass   = "pass"
	Gap    = "gap"
	Manual = "manual"
)

// Scope selects what a report covers.
type Scope struct {
	Chains []string  `json:"chains"`
	GoalID string    `json:"goal_id,omitempty"`
	From   time.Time `json:"from,omitempty"`
	To     time.Time `json:"to,omitempty"`
}

// ChainEvidence is the integrity evidence for one chain.
type ChainEvidence struct {
	Chain          string                 `json:"chain"`
	Verify         store.VerifyResult     `json:"verify"`
	RecordsInScope int                    `json:"records_in_scope"`
	Root           *anchor.Root           `json:"signed_root,omitempty"`
	Anchors        *anchoring.ChainReport `json:"anchors,omitempty"` // nil: anchoring not configured
}

// Evidence is everything the controls evaluate.
type Evidence struct {
	Scope     Scope
	Chains    []ChainEvidence
	Records   []store.Record // records in scope, (created_at, chain, seq) order
	Rotations []anchor.Rotation
	RotErrors []string
	Retention retention.State
	Now       time.Time
}

// Ref points at a record that evidences a finding.
type Ref struct {
	Chain string `json:"chain"`
	Seq   int64  `json:"seq"`
	Type  string `json:"type"`
	Hash  string `json:"hash"`
	At    string `json:"at"`
}

// RefOf builds a Ref.
func RefOf(r store.Record) Ref {
	return Ref{r.Chain, r.Seq, r.Type, r.Hash, r.CreatedAt.UTC().Format(time.RFC3339)}
}

// MaxRefs caps the evidence references listed per control (the count is always complete).
const MaxRefs = 25

// Finding is a control's evaluation.
type Finding struct {
	Status   string         `json:"status"`
	Summary  string         `json:"summary"`
	Count    int            `json:"evidence_count"`
	Evidence []Ref          `json:"evidence,omitempty"`
	Metrics  map[string]any `json:"metrics,omitempty"`
}

func refs(recs []store.Record) []Ref {
	out := []Ref{}
	for i, r := range recs {
		if i == MaxRefs {
			break
		}
		out = append(out, RefOf(r))
	}
	return out
}

// Control is one requirement of a template.
type Control struct {
	ID            string
	Citation      string
	Title         string
	Requirement   string // what the regime asks (paraphrased)
	EvidenceQuery string // the evidence criterion evaluated over the ledger
	Eval          func(*Evidence) Finding
}

// Section groups controls.
type Section struct {
	Title    string
	Controls []Control
}

// Template is a versioned regime template.
type Template struct {
	Regime     string
	Version    string
	Title      string
	Source     string // legal instrument / criteria set the citations refer to
	Disclaimer string
	Sections   []Section
}

// ID is "<regime>@<version>".
func (t Template) ID() string { return t.Regime + "@" + t.Version }

var registry = map[string][]Template{}

// Register adds a template version (versions sort lexically; latest wins by default).
func Register(t Template) {
	registry[t.Regime] = append(registry[t.Regime], t)
	sort.Slice(registry[t.Regime], func(i, j int) bool { return registry[t.Regime][i].Version < registry[t.Regime][j].Version })
}

// Lookup returns a template by regime and version ("" = latest).
func Lookup(regime, version string) (Template, error) {
	ts := registry[regime]
	if len(ts) == 0 {
		return Template{}, fmt.Errorf("unknown regime %q (have %v)", regime, Regimes())
	}
	if version == "" {
		return ts[len(ts)-1], nil
	}
	for _, t := range ts {
		if t.Version == version {
			return t, nil
		}
	}
	return Template{}, fmt.Errorf("regime %s has no template version %s", regime, version)
}

// Regimes lists registered regimes.
func Regimes() []string {
	var out []string
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- report ----

// ControlResult is a control plus its finding, as rendered.
type ControlResult struct {
	Section       string `json:"section"`
	ID            string `json:"id"`
	Citation      string `json:"citation"`
	Title         string `json:"title"`
	Requirement   string `json:"requirement"`
	EvidenceQuery string `json:"evidence_query"`
	Finding
}

// Totals counts statuses.
type Totals struct {
	Pass   int `json:"pass"`
	Gap    int `json:"gap"`
	Manual int `json:"manual"`
}

// Integrity is the regime-independent integrity appendix.
type Integrity struct {
	AllChainsIntact bool              `json:"all_chains_intact"`
	AnchorsChecked  bool              `json:"anchors_checked"`
	AnchorsOK       bool              `json:"anchors_ok"`
	Chains          []ChainEvidence   `json:"chains"`
	KeyRotations    []anchor.Rotation `json:"key_rotations"`
	RotationErrors  []string          `json:"key_rotation_errors,omitempty"`
}

// Report is the auditor pack (JSON form); HTML and PDF render it.
type Report struct {
	Format       string          `json:"format"`
	Template     string          `json:"template"`
	Title        string          `json:"title"`
	Source       string          `json:"source"`
	Disclaimer   string          `json:"disclaimer"`
	GeneratedAt  string          `json:"generated_at"`
	Scope        Scope           `json:"scope"`
	RecordCount  int             `json:"records_in_scope"`
	Totals       Totals          `json:"totals"`
	Controls     []ControlResult `json:"controls"`
	Integrity    Integrity       `json:"integrity"`
	Retention    retention.State `json:"retention"`
	Records      []store.Record  `json:"records"`
	DocumentHash string          `json:"document_hash,omitempty"`
	Signature    *keys.Signature `json:"signature,omitempty"`
}

// ReportFormat identifies the JSON layout.
const ReportFormat = "ledger-compliance-report/v1"

// Evaluate runs every control of t over ev.
func Evaluate(t Template, ev *Evidence) Report {
	r := Report{Format: ReportFormat, Template: t.ID(), Title: t.Title, Source: t.Source, Disclaimer: t.Disclaimer,
		GeneratedAt: ev.Now.UTC().Format(time.RFC3339), Scope: ev.Scope, RecordCount: len(ev.Records),
		Retention: ev.Retention, Records: ev.Records}
	if r.Records == nil {
		r.Records = []store.Record{}
	}
	for _, s := range t.Sections {
		for _, c := range s.Controls {
			f := c.Eval(ev)
			if f.Evidence == nil {
				f.Evidence = []Ref{}
			}
			switch f.Status {
			case Pass:
				r.Totals.Pass++
			case Gap:
				r.Totals.Gap++
			default:
				f.Status = Manual
				r.Totals.Manual++
			}
			r.Controls = append(r.Controls, ControlResult{Section: s.Title, ID: c.ID, Citation: c.Citation, Title: c.Title,
				Requirement: c.Requirement, EvidenceQuery: c.EvidenceQuery, Finding: f})
		}
	}
	in := Integrity{AllChainsIntact: true, AnchorsOK: true, Chains: ev.Chains, KeyRotations: ev.Rotations, RotationErrors: ev.RotErrors}
	if in.Chains == nil {
		in.Chains = []ChainEvidence{}
	}
	if in.KeyRotations == nil {
		in.KeyRotations = []anchor.Rotation{}
	}
	for _, c := range ev.Chains {
		if !c.Verify.OK {
			in.AllChainsIntact = false
		}
		if c.Anchors != nil {
			in.AnchorsChecked = true
			if !c.Anchors.OK {
				in.AnchorsOK = false
			}
		}
	}
	if !in.AnchorsChecked {
		in.AnchorsOK = false
	}
	r.Integrity = in
	return r
}
