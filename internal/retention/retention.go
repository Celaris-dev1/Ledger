// Package retention implements per-chain retention policies, legal holds and data-subject
// erasure by crypto-shredding.
//
// Append-only is sacred: nothing here ever deletes or edits a record. All state (policies,
// holds, erasures) is itself recorded in the `ledger` system chain and derived by folding
// over it, so it is hash-chained, anchored and exported like everything else.
//
//   - "Expiry" of a record past its minimum retention only makes it *eligible* for
//     crypto-shredding / archival; Ledger never removes it.
//   - Erasure destroys a data subject's data key (payloads encrypted with keys.Seal become
//     unreadable) and appends a `ledger.erasure` record. Hashes cover the ciphertext, so every
//     chain still verifies afterwards.
//   - An active legal hold covering an affected chain or subject blocks erasure.
package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// SystemChain is where retention/hold/erasure records live (shared with key rotations).
const SystemChain = "ledger"

// Record types.
const (
	TypePolicySet    = "ledger.retention.policy.set"
	TypeHoldCreated  = "ledger.hold.created"
	TypeHoldReleased = "ledger.hold.released"
	TypeErasure      = "ledger.erasure"
)

// RegimeMinimums are the default minimum retention periods per regime.
//
//	hipaa      6y  45 CFR 164.316(b)(2)(i): documentation retained 6 years
//	eu-ai-act  6m  Art. 19(1) / Art. 26(6): logs kept at least six months (unless other law says otherwise)
//	soc2       1y  not fixed by the criteria; 1 year is the common audit-period convention
var RegimeMinimums = map[string]string{"hipaa": "6y", "eu-ai-act": "6m", "soc2": "1y"}

// Policy is a retention policy for a chain ("*" = every chain without its own policy).
type Policy struct {
	Chain        string `json:"chain"`
	Regime       string `json:"regime,omitempty"`
	MinRetention string `json:"min_retention"` // e.g. 6y, 18m, 400d
	Reason       string `json:"reason,omitempty"`
	SetBy        string `json:"set_by,omitempty"`
	SetAt        string `json:"set_at,omitempty"`
	RecordSeq    int64  `json:"record_seq,omitempty"`
}

var durRe = regexp.MustCompile(`^(\d+)([ymd])$`)

// ParseRetention validates a retention period.
func ParseRetention(s string) (years, months, days int, err error) {
	m := durRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, 0, fmt.Errorf("retention %q must look like 6y, 18m or 400d", s)
	}
	n, _ := strconv.Atoi(m[1])
	switch m[2] {
	case "y":
		return n, 0, 0, nil
	case "m":
		return 0, n, 0, nil
	}
	return 0, 0, n, nil
}

// Until returns the end of retention for a record created at t.
func (p Policy) Until(t time.Time) time.Time {
	y, m, d, err := ParseRetention(p.MinRetention)
	if err != nil {
		return t
	}
	return t.AddDate(y, m, d)
}

// Hold is a legal hold. Scope: chains and/or subject key ids; All covers everything.
type Hold struct {
	ID          string   `json:"hold_id"`
	Reason      string   `json:"reason"`
	Chains      []string `json:"chains,omitempty"`
	SubjectKeys []string `json:"subject_key_ids,omitempty"`
	All         bool     `json:"all,omitempty"`
	CreatedBy   string   `json:"created_by"`
	CreatedAt   string   `json:"created_at"`
	Released    bool     `json:"released"`
	ReleasedBy  string   `json:"released_by,omitempty"`
	ReleasedAt  string   `json:"released_at,omitempty"`
	ReleaseNote string   `json:"release_reason,omitempty"`
}

// Covers reports whether an active hold covers chain or subject key id.
func (h Hold) Covers(chain, subjectKey string) bool {
	if h.Released {
		return false
	}
	if h.All {
		return true
	}
	for _, c := range h.Chains {
		if c == chain && chain != "" {
			return true
		}
	}
	for _, k := range h.SubjectKeys {
		if k == subjectKey && subjectKey != "" {
			return true
		}
	}
	return false
}

// Erasure is the payload of a ledger.erasure record.
type Erasure struct {
	SubjectKeyID      string   `json:"subject_key_id"`
	Reason            string   `json:"reason"`
	LegalBasis        string   `json:"legal_basis,omitempty"`
	Method            string   `json:"method"` // crypto-shred
	RecordsAffected   int      `json:"records_affected"`
	Chains            []string `json:"chains"`
	RetentionOverride string   `json:"retention_override,omitempty"`
	HoldsChecked      int      `json:"holds_checked"`
	ErasedAt          string   `json:"erased_at"`
}

// State is the folded retention state of the system chain.
type State struct {
	Policies map[string]Policy `json:"policies"`
	Holds    []Hold            `json:"holds"`
	Erasures []Erasure         `json:"erasures"`
}

// Fold derives the state from system-chain records (in seq order).
func Fold(recs []store.Record) State {
	st := State{Policies: map[string]Policy{}}
	idx := map[string]int{}
	for _, r := range recs {
		actor := firstHuman(r.ActorChain)
		switch r.Type {
		case TypePolicySet:
			var p Policy
			if json.Unmarshal(r.Payload, &p) == nil && p.Chain != "" {
				p.SetBy, p.SetAt, p.RecordSeq = actor, r.CreatedAt.Format(time.RFC3339), r.Seq
				st.Policies[p.Chain] = p
			}
		case TypeHoldCreated:
			var h Hold
			if json.Unmarshal(r.Payload, &h) == nil && h.ID != "" {
				if _, dup := idx[h.ID]; dup {
					continue
				}
				h.CreatedBy, h.CreatedAt, h.Released = actor, r.CreatedAt.Format(time.RFC3339), false
				idx[h.ID] = len(st.Holds)
				st.Holds = append(st.Holds, h)
			}
		case TypeHoldReleased:
			var rel struct {
				ID     string `json:"hold_id"`
				Reason string `json:"reason"`
			}
			if json.Unmarshal(r.Payload, &rel) == nil {
				if i, ok := idx[rel.ID]; ok && !st.Holds[i].Released {
					st.Holds[i].Released, st.Holds[i].ReleasedBy = true, actor
					st.Holds[i].ReleasedAt, st.Holds[i].ReleaseNote = r.CreatedAt.Format(time.RFC3339), rel.Reason
				}
			}
		case TypeErasure:
			var e Erasure
			if json.Unmarshal(r.Payload, &e) == nil {
				st.Erasures = append(st.Erasures, e)
			}
		}
	}
	return st
}

func firstHuman(ac json.RawMessage) string {
	var a []store.Actor
	if json.Unmarshal(ac, &a) == nil && len(a) > 0 {
		return a[0].ID
	}
	return ""
}

// PolicyFor returns the policy for a chain (its own, else "*"), and whether one exists.
func (s State) PolicyFor(chain string) (Policy, bool) {
	if p, ok := s.Policies[chain]; ok {
		return p, true
	}
	p, ok := s.Policies["*"]
	return p, ok
}

// ActiveHolds lists unreleased holds.
func (s State) ActiveHolds() []Hold {
	var out []Hold
	for _, h := range s.Holds {
		if !h.Released {
			out = append(out, h)
		}
	}
	return out
}

// Service applies retention operations against a store.
type Service struct {
	Store    *store.Store
	DataKeys keys.DataKeyStore
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// State reads and folds the system chain.
func (s *Service) State(ctx context.Context) (State, error) {
	recs, err := s.Store.ChainRecords(ctx, SystemChain)
	if err != nil {
		return State{}, err
	}
	return Fold(recs), nil
}

func (s *Service) record(ctx context.Context, typ, operator string, payload any) (*store.Record, error) {
	if strings.TrimSpace(operator) == "" {
		return nil, errors.New("an operator (human actor) is required")
	}
	b, _ := json.Marshal(payload)
	return s.Store.Append(ctx, store.AppendRequest{Chain: SystemChain, Type: typ,
		ActorChain: []store.Actor{{Kind: "human", ID: operator}, {Kind: "service", ID: "ledger-retention"}}, Payload: b})
}

// SetPolicy records a retention policy. A regime's statutory minimum cannot be undercut.
func (s *Service) SetPolicy(ctx context.Context, p Policy, operator string) (*store.Record, error) {
	if p.Chain == "" {
		return nil, errors.New("policy chain is required (a chain name or *)")
	}
	if p.MinRetention == "" {
		p.MinRetention = RegimeMinimums[p.Regime]
	}
	if _, _, _, err := ParseRetention(p.MinRetention); err != nil {
		return nil, err
	}
	if min, ok := RegimeMinimums[p.Regime]; ok {
		t0 := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		if (Policy{MinRetention: p.MinRetention}).Until(t0).Before((Policy{MinRetention: min}).Until(t0)) {
			return nil, fmt.Errorf("%s requires at least %s retention", p.Regime, min)
		}
	} else if p.Regime != "" {
		return nil, fmt.Errorf("unknown regime %q (hipaa|eu-ai-act|soc2)", p.Regime)
	}
	p.SetBy, p.SetAt, p.RecordSeq = "", "", 0
	return s.record(ctx, TypePolicySet, operator, p)
}

// CreateHold records a legal hold.
func (s *Service) CreateHold(ctx context.Context, h Hold, operator string) (*store.Record, error) {
	if h.ID == "" || strings.TrimSpace(h.Reason) == "" {
		return nil, errors.New("a hold needs an id and a reason")
	}
	if !h.All && len(h.Chains) == 0 && len(h.SubjectKeys) == 0 {
		return nil, errors.New("a hold needs a scope: chains, subjects, or all")
	}
	st, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range st.Holds {
		if x.ID == h.ID {
			return nil, fmt.Errorf("hold %s already exists", h.ID)
		}
	}
	h.CreatedBy, h.CreatedAt, h.Released = "", "", false
	return s.record(ctx, TypeHoldCreated, operator, h)
}

// ReleaseHold records the release of an active hold.
func (s *Service) ReleaseHold(ctx context.Context, id, reason, operator string) (*store.Record, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, errors.New("releasing a hold needs a reason")
	}
	st, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range st.Holds {
		if h.ID == id {
			if h.Released {
				return nil, fmt.Errorf("hold %s is already released", id)
			}
			return s.record(ctx, TypeHoldReleased, operator, map[string]string{"hold_id": id, "reason": reason})
		}
	}
	return nil, fmt.Errorf("no hold %s", id)
}

// ErrLegalHold is returned when an active legal hold blocks an erasure.
var ErrLegalHold = errors.New("blocked by legal hold")

// ErrRetention is returned when erasure would undercut a minimum retention period.
var ErrRetention = errors.New("blocked by minimum retention")

// EraseRequest describes a data-subject erasure.
type EraseRequest struct {
	Subject    string
	Reason     string
	LegalBasis string // e.g. "GDPR Art. 17"
	Operator   string
	// OverrideRetention allows shredding records still inside a minimum-retention period;
	// the justification is recorded in the erasure record. Legal holds cannot be overridden.
	OverrideRetention string
}

// affected returns (chain, created_at) of records whose payload is an envelope for keyID.
func (s *Service) affected(ctx context.Context, keyID string) (map[string]time.Time, int, error) {
	rows, err := s.Store.Pool.Query(ctx, `SELECT chain, max(created_at), count(*) FROM records
		WHERE payload->>'ledger_envelope' = $1 AND payload->>'key_id' = $2 GROUP BY chain`, keys.EnvelopeFormat, keyID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	total := 0
	for rows.Next() {
		var c string
		var t time.Time
		var n int
		if err := rows.Scan(&c, &t, &n); err != nil {
			return nil, 0, err
		}
		out[c], total = t, total+n
	}
	return out, total, rows.Err()
}

// Erase crypto-shreds a data subject: checks holds and retention, destroys the key, and
// records a ledger.erasure record. No record is modified or deleted.
func (s *Service) Erase(ctx context.Context, req EraseRequest) (*store.Record, Erasure, error) {
	if s.DataKeys == nil {
		return nil, Erasure{}, errors.New("erasure requires a data key store (LEDGER_DATA_KEY_DIR)")
	}
	if req.Subject == "" || strings.TrimSpace(req.Reason) == "" {
		return nil, Erasure{}, errors.New("erasure needs a subject and a reason")
	}
	keyID := s.DataKeys.KeyIDFor(req.Subject)
	st, err := s.State(ctx)
	if err != nil {
		return nil, Erasure{}, err
	}
	chains, n, err := s.affected(ctx, keyID)
	if err != nil {
		return nil, Erasure{}, err
	}
	names := make([]string, 0, len(chains))
	for c := range chains {
		names = append(names, c)
	}
	sort.Strings(names)
	holds := st.ActiveHolds()
	for _, h := range holds {
		if h.Covers("", keyID) {
			return nil, Erasure{}, fmt.Errorf("%w %s (%s)", ErrLegalHold, h.ID, h.Reason)
		}
		for _, c := range names {
			if h.Covers(c, "") {
				return nil, Erasure{}, fmt.Errorf("%w %s on chain %s (%s)", ErrLegalHold, h.ID, c, h.Reason)
			}
		}
	}
	now := s.now()
	for _, c := range names {
		if p, ok := st.PolicyFor(c); ok && now.Before(p.Until(chains[c])) && req.OverrideRetention == "" {
			return nil, Erasure{}, fmt.Errorf("%w: chain %s has %s retention (%s) until %s; pass an override justification to shred anyway",
				ErrRetention, c, p.MinRetention, p.Regime, p.Until(chains[c]).Format("2006-01-02"))
		}
	}
	if _, err := s.DataKeys.Destroy(req.Subject); err != nil {
		return nil, Erasure{}, fmt.Errorf("destroy key: %w", err)
	}
	e := Erasure{SubjectKeyID: keyID, Reason: req.Reason, LegalBasis: req.LegalBasis, Method: "crypto-shred",
		RecordsAffected: n, Chains: names, RetentionOverride: req.OverrideRetention, HoldsChecked: len(holds),
		ErasedAt: now.Format(time.RFC3339)}
	if e.Chains == nil {
		e.Chains = []string{}
	}
	rec, err := s.record(ctx, TypeErasure, req.Operator, e)
	if err != nil {
		return nil, e, fmt.Errorf("key destroyed but the erasure record failed (re-run erase to record it): %w", err)
	}
	return rec, e, nil
}

// ChainStatus is the retention status of one chain.
type ChainStatus struct {
	Chain           string `json:"chain"`
	Policy          string `json:"policy,omitempty"`
	Regime          string `json:"regime,omitempty"`
	Records         int64  `json:"records"`
	Oldest          string `json:"oldest,omitempty"`
	PastRetention   int64  `json:"past_minimum_retention"` // eligible for shredding/archival; never deleted
	UnderHold       bool   `json:"under_legal_hold"`
	HeldBy          string `json:"held_by,omitempty"`
	NoPolicyWarning bool   `json:"no_policy,omitempty"`
}

// Status reports per-chain retention status.
func (s *Service) Status(ctx context.Context) ([]ChainStatus, error) {
	st, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.Pool.Query(ctx, `SELECT chain, count(*), min(created_at) FROM records GROUP BY chain ORDER BY chain`)
	if err != nil {
		return nil, err
	}
	type agg struct {
		c string
		n int64
		t time.Time
	}
	var as []agg
	for rows.Next() {
		var a agg
		if err := rows.Scan(&a.c, &a.n, &a.t); err != nil {
			rows.Close()
			return nil, err
		}
		as = append(as, a)
	}
	rows.Close()
	now := s.now()
	var out []ChainStatus
	for _, a := range as {
		cs := ChainStatus{Chain: a.c, Records: a.n, Oldest: a.t.UTC().Format(time.RFC3339)}
		if p, ok := st.PolicyFor(a.c); ok {
			cs.Policy, cs.Regime = p.MinRetention, p.Regime
			// records created before (now - retention) are past their minimum
			y, m, d, _ := ParseRetention(p.MinRetention)
			cut := now.AddDate(-y, -m, -d)
			if err := s.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM records WHERE chain=$1 AND created_at < $2`, a.c, cut).Scan(&cs.PastRetention); err != nil {
				return nil, err
			}
		} else {
			cs.NoPolicyWarning = true
		}
		for _, h := range st.ActiveHolds() {
			if h.Covers(a.c, "") {
				cs.UnderHold, cs.HeldBy = true, h.ID
				break
			}
		}
		out = append(out, cs)
	}
	return out, nil
}
