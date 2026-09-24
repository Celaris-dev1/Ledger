package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/incident"
	"github.com/Celaris-dev1/Ledger/internal/projection"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

var funcs = template.FuncMap{
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05Z")
	},
	"seg": url.PathEscape,
	"q":   url.QueryEscape,
	"deref": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
	"money": func(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) },
	"raw": func(b json.RawMessage) string {
		if len(b) == 0 {
			return ""
		}
		var out bytes.Buffer
		if json.Indent(&out, b, "", "  ") != nil {
			return string(b)
		}
		return out.String()
	},
	"join":   strings.Join,
	"sub":    func(a, b int64) int64 { return a - b },
	"derefb": func(p *bool) bool { return p != nil && *p },
	"derefT": func(p *time.Time) time.Time {
		if p == nil {
			return time.Time{}
		}
		return *p
	},
}

var pages = map[string]*template.Template{}

func init() {
	layout := template.Must(template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html"))
	entries, _ := templateFS.ReadDir("templates")
	for _, e := range entries {
		n := e.Name()
		if n == "layout.html" {
			continue
		}
		pages[strings.TrimSuffix(n, ".html")] = template.Must(template.Must(layout.Clone()).ParseFS(templateFS, "templates/"+n))
	}
}

// Page is the data every template receives.
type Page struct {
	Title     string
	Nav       string
	P         *auth.Principal
	CSRF      string
	Open      bool
	CanExport bool
	IsAdmin   bool
	Data      any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name, title, nav string, data any) {
	p := auth.FromContext(r.Context())
	pg := Page{Title: title, Nav: nav, P: p, Data: data, Open: s.Auth != nil && s.Auth.Cfg.Open}
	if p != nil {
		pg.CanExport, pg.IsAdmin = p.Can(auth.PermExport), p.Can(auth.PermAdmin)
		if p.Session != nil {
			pg.CSRF = p.Session.CSRF
		}
	}
	var buf bytes.Buffer
	if err := pages[name].ExecuteTemplate(&buf, "layout.html", pg); err != nil {
		s.logf("ledgerd: ui: render %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type errData struct {
	Status int
	Msg    string
}

func (s *Server) denied(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if p, err := s.Auth.Authenticate(r); err == nil && p != nil {
		r = r.WithContext(auth.WithPrincipal(r.Context(), p))
	}
	s.render(w, r, status, "error", http.StatusText(status), "", errData{status, msg})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.logf("ledgerd: ui: %s: %v", r.URL.Path, err)
	s.render(w, r, http.StatusInternalServerError, "error", "Error", "", errData{500, "internal error"})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, msg string) {
	s.render(w, r, http.StatusNotFound, "error", "Not found", "", errData{404, msg})
}

// ---- login ----

type loginData struct {
	SSO   bool
	Next  string
	Error string
	CSRF  string
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	next := auth.SafeNext(r.URL.Query().Get("next"))
	if s.Auth.Cfg.Open {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	if p, err := s.Auth.Authenticate(r); err == nil && p != nil && p.Can(auth.PermView) && r.URL.Query().Get("error") == "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	d := loginData{SSO: s.Auth.SSOEnabled(), Next: next, Error: r.URL.Query().Get("error"), CSRF: s.Auth.LoginCSRF(w, r)}
	if len(d.Error) > 200 {
		d.Error = d.Error[:200]
	}
	s.render(w, r, http.StatusOK, "login", "Sign in", "", d)
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, auth.FromContext(r.Context()))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- chains ----

// AnchorInfo summarises external anchoring for a chain (or for one seq of it).
type AnchorInfo struct {
	Configured bool      `json:"configured"`
	LastSeq    int64     `json:"last_anchored_seq"`
	LastAt     time.Time `json:"last_anchored_at"`
	Witnesses  []string  `json:"witnesses"` // backend/kind of the receipts at LastSeq
	Receipts   int       `json:"receipts"`
	// For a specific seq: the first anchor at or after it.
	Covered        bool      `json:"covered"`
	CoverSeq       int64     `json:"cover_seq,omitempty"`
	CoverAt        time.Time `json:"cover_at,omitempty"`
	CoverWitnesses []string  `json:"cover_witnesses,omitempty"`
	// CoverConsistent: the anchored head equals the current hash of record CoverSeq.
	CoverConsistent *bool  `json:"cover_consistent,omitempty"`
	Error           string `json:"error,omitempty"`
}

func witnesses(rs []anchoring.StoredReceipt, seq int64) ([]string, time.Time) {
	seen := map[string]bool{}
	var out []string
	var at time.Time
	for _, r := range rs {
		if r.Seq != seq {
			continue
		}
		w := r.Backend
		if r.Kind != "" && r.Kind != r.Backend {
			w += " (" + r.Kind + ")"
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
		if r.AnchoredAt.After(at) {
			at = r.AnchoredAt
		}
	}
	sort.Strings(out)
	return out, at
}

func (s *Server) anchorInfo(ctx context.Context, chain string, seq int64) AnchorInfo {
	if s.Receipts == nil {
		return AnchorInfo{}
	}
	ai := AnchorInfo{Configured: true}
	rs, err := s.Receipts.Receipts(ctx, chain)
	if err != nil {
		s.logf("ledgerd: ui: receipts %s: %v", chain, err)
		ai.Error = "could not read anchor receipts"
		return ai
	}
	ai.Receipts = len(rs)
	for _, r := range rs {
		if r.Seq > ai.LastSeq {
			ai.LastSeq = r.Seq
		}
		if seq > 0 && r.Seq >= seq && (!ai.Covered || r.Seq < ai.CoverSeq) {
			ai.Covered, ai.CoverSeq = true, r.Seq
		}
	}
	if ai.LastSeq > 0 {
		ai.Witnesses, ai.LastAt = witnesses(rs, ai.LastSeq)
	}
	if ai.Covered {
		ai.CoverWitnesses, ai.CoverAt = witnesses(rs, ai.CoverSeq)
		if rec, err := s.recordAt(ctx, chain, ai.CoverSeq); err == nil && rec != nil {
			ok := false
			for _, r := range rs {
				if r.Seq == ai.CoverSeq && r.Head == rec.Hash {
					ok = true
				}
			}
			ai.CoverConsistent = &ok
		}
	}
	return ai
}

type chainRow struct {
	Name   string
	Length int64
	Head   string
	Verify store.VerifyResult
	Anchor AnchorInfo
	Err    string
}

func (s *Server) chains(w http.ResponseWriter, r *http.Request) {
	names, err := s.Store.Chains(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows := make([]chainRow, 0, len(names))
	for _, n := range names {
		row := chainRow{Name: n}
		row.Length, row.Head, err = s.Store.Head(r.Context(), n)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if row.Verify, err = s.chainVerify(r.Context(), n); err != nil {
			row.Err = "verification failed to run"
			s.logf("ledgerd: ui: verify %s: %v", n, err)
		}
		row.Anchor = s.anchorInfo(r.Context(), n, 0)
		rows = append(rows, row)
	}
	s.render(w, r, http.StatusOK, "chains", "Chains", "chains", rows)
}

type chainPage struct {
	Name      string
	Head      int64
	Verify    store.VerifyResult
	Records   []store.Record
	Newer     int64 // "from" of the newer page (0 = none)
	Older     int64
	FirstSeq  int64
	LastSeq   int64
	PageLimit int64
}

const chainPageSize = 50

func (s *Server) chainRecords(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("chain")
	head, _, err := s.Store.Head(r.Context(), name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if head == 0 {
		s.notFound(w, r, "no such chain")
		return
	}
	top := head
	if v, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64); err == nil && v > 0 && v < head {
		top = v
	}
	lo := top - chainPageSize + 1
	if lo < 1 {
		lo = 1
	}
	recs, err := s.Store.List(r.Context(), store.Query{Chain: name, AfterSeq: lo - 1, Limit: int(top - lo + 1)})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var keep []store.Record
	for _, rc := range recs {
		if rc.Seq >= lo && rc.Seq <= top {
			keep = append(keep, rc)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Seq > keep[j].Seq })
	pg := chainPage{Name: name, Head: head, Records: keep, FirstSeq: lo, LastSeq: top}
	pg.Verify, _ = s.chainVerify(r.Context(), name)
	if top < head {
		pg.Newer = min(top+chainPageSize, head)
	}
	if lo > 1 {
		pg.Older = lo - 1
	}
	s.render(w, r, http.StatusOK, "chain", "Chain "+name, "chains", pg)
}

// recordAt fetches one record by (chain, seq); nil when absent.
func (s *Server) recordAt(ctx context.Context, chain string, seq int64) (*store.Record, error) {
	if seq < 1 {
		return nil, nil
	}
	recs, err := s.Store.List(ctx, store.Query{Chain: chain, AfterSeq: seq - 1, Limit: 5})
	if err != nil {
		return nil, err
	}
	for i := range recs {
		if recs[i].Chain == chain && recs[i].Seq == seq {
			return &recs[i], nil
		}
	}
	return nil, nil
}

// ---- goals ----

func (s *Server) projRows(ctx context.Context, goal string) (*projection.Rows, error) {
	if s.Projections == nil {
		return nil, nil
	}
	return s.Projections.Rows(ctx, goal)
}

type goalsData struct {
	Enabled  bool
	Q        string
	Status   string
	Goals    []projection.GoalSummary
	Total    int
	Statuses []string
}

func (s *Server) goals(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := r.URL.Query().Get("status")
	d := goalsData{Enabled: s.Projections != nil, Q: q, Status: status}
	rows, err := s.projRows(r.Context(), "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rows != nil {
		all := projection.Goals(rows)
		d.Total = len(all)
		lq := strings.ToLower(q)
		seen := map[string]bool{}
		for _, g := range all {
			if !seen[g.Status] && g.Status != "" {
				seen[g.Status] = true
				d.Statuses = append(d.Statuses, g.Status)
			}
		}
		sort.Strings(d.Statuses)
		for _, g := range all {
			if status != "" && g.Status != status {
				continue
			}
			if lq != "" && !strings.Contains(strings.ToLower(g.ID+"\x00"+g.Title+"\x00"+g.OriginatingHumanID+"\x00"+g.Status), lq) {
				continue
			}
			d.Goals = append(d.Goals, g)
		}
	}
	s.render(w, r, http.StatusOK, "goals", "Goals", "goals", d)
}

type goalData struct {
	ID        string
	Tree      *projection.GoalTree
	Projected bool
	Records   int
	Chains    []string
	Humans    []string
	First     time.Time
	Last      time.Time
}

func (s *Server) goal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("goal_id")
	d := goalData{ID: id, Projected: s.Projections != nil}
	rows, err := s.projRows(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rows != nil {
		d.Tree, _ = projection.BuildTree(rows, id)
	}
	recs, err := s.Store.Replay(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if d.Tree == nil && len(recs) == 0 {
		s.notFound(w, r, "no records or projection for this goal")
		return
	}
	d.Records = len(recs)
	seenC, seenH := map[string]bool{}, map[string]bool{}
	for i, rc := range recs {
		if i == 0 {
			d.First = rc.CreatedAt
		}
		d.Last = rc.CreatedAt
		if !seenC[rc.Chain] {
			seenC[rc.Chain] = true
			d.Chains = append(d.Chains, rc.Chain)
		}
		var actors []store.Actor
		if json.Unmarshal(rc.ActorChain, &actors) == nil && len(actors) > 0 && !seenH[actors[0].ID] {
			seenH[actors[0].ID] = true
			d.Humans = append(d.Humans, actors[0].ID)
		}
	}
	title := "Goal " + id
	if d.Tree != nil && d.Tree.Goal.Title != "" {
		title = d.Tree.Goal.Title
	}
	s.render(w, r, http.StatusOK, "goal", title, "goals", d)
}

type approvalsData struct {
	Enabled   bool
	Status    string
	Approvals []projection.ApprovalNode
	Counts    map[string]int
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		status = "pending"
	}
	if _, ok := r.URL.Query()["status"]; !ok {
		status = "pending"
	}
	d := approvalsData{Enabled: s.Projections != nil, Status: status, Counts: map[string]int{}}
	rows, err := s.projRows(r.Context(), "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rows != nil {
		for _, a := range rows.Approvals {
			d.Counts[a.Status()]++
			d.Counts["all"]++
		}
		d.Approvals = projection.Approvals(rows, status)
	}
	s.render(w, r, http.StatusOK, "approvals", "Approvals", "approvals", d)
}

type budgetsData struct {
	Enabled bool
	Goal    string
	Budgets []projection.BudgetSummary
}

func (s *Server) budgets(w http.ResponseWriter, r *http.Request) {
	goal := strings.TrimSpace(r.URL.Query().Get("goal"))
	d := budgetsData{Enabled: s.Projections != nil, Goal: goal}
	rows, err := s.projRows(r.Context(), goal)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rows != nil {
		d.Budgets = projection.Budgets(rows, goal)
		sort.SliceStable(d.Budgets, func(i, j int) bool { return d.Budgets[i].Overspent && !d.Budgets[j].Overspent })
	}
	s.render(w, r, http.StatusOK, "budgets", "Budgets", "budgets", d)
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("goal_id")
	rep, err := incident.Build(r.Context(), s.Store, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rep == nil {
		s.notFound(w, r, "no records for this goal")
		return
	}
	s.render(w, r, http.StatusOK, "incident", "Incident review "+id, "goals", rep)
}

// ---- record permalink ----

type recordData struct {
	Rec       store.Record
	Actors    []store.Actor
	HumanOK   bool
	Payload   string
	B64       string // base64 of the record JSON, re-hashed in the browser
	PrevHash  string // hash of record seq-1 as stored (for the browser link check)
	HasPrev   bool
	Verify    store.VerifyResult
	RecordOK  bool
	Anchor    AnchorInfo
	ChainHead int64
}

func (s *Server) record(w http.ResponseWriter, r *http.Request) {
	chain := r.PathValue("chain")
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || seq < 1 {
		s.notFound(w, r, "bad sequence number")
		return
	}
	rec, err := s.recordAt(r.Context(), chain, seq)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rec == nil {
		s.notFound(w, r, "no such record")
		return
	}
	d := recordData{Rec: *rec}
	_ = json.Unmarshal(rec.ActorChain, &d.Actors)
	d.HumanOK = len(d.Actors) > 0 && d.Actors[0].Kind == "human"
	d.Payload = funcs["raw"].(func(json.RawMessage) string)(rec.Payload)
	b, _ := json.Marshal(rec)
	d.B64 = base64.StdEncoding.EncodeToString(b)
	if seq > 1 {
		if prev, err := s.recordAt(r.Context(), chain, seq-1); err == nil && prev != nil {
			d.PrevHash, d.HasPrev = prev.Hash, true
		}
	}
	d.Verify, err = s.chainVerify(r.Context(), chain)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.RecordOK = d.Verify.OK || (d.Verify.BrokenAt != nil && *d.Verify.BrokenAt > seq)
	d.ChainHead, _, _ = s.Store.Head(r.Context(), chain)
	d.Anchor = s.anchorInfo(r.Context(), chain, seq)
	s.render(w, r, http.StatusOK, "record", fmt.Sprintf("%s #%d", chain, seq), "chains", d)
}

// StatusResponse is GET /ui/api/status?chain=&seq= (the replay side panel).
type StatusResponse struct {
	Chain    string     `json:"chain"`
	Seq      int64      `json:"seq"`
	ChainOK  bool       `json:"chain_ok"`
	Length   int        `json:"length"`
	BrokenAt *int64     `json:"broken_at"`
	Reason   string     `json:"reason,omitempty"`
	RecordOK bool       `json:"record_ok"` // the chain verifies up to and including this seq
	Anchor   AnchorInfo `json:"anchor"`
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	seq, err := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
	if chain == "" || err != nil || seq < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "chain and seq are required"})
		return
	}
	v, err := s.chainVerify(r.Context(), chain)
	if err != nil {
		s.logf("ledgerd: ui: status: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	out := StatusResponse{Chain: chain, Seq: seq, ChainOK: v.OK, Length: v.Length, BrokenAt: v.BrokenAt, Reason: v.Reason,
		RecordOK: int64(v.Length) >= seq && (v.OK || (v.BrokenAt != nil && *v.BrokenAt > seq)), Anchor: s.anchorInfo(r.Context(), chain, seq)}
	writeJSON(w, http.StatusOK, out)
}

// ---- admin ----

type adminData struct {
	Tokens   []auth.Token
	Users    []auth.User
	Roles    []string
	NewToken string
	NewName  string
	Error    string
	SSO      bool
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request, d adminData) {
	var err error
	if s.Auth.Store == nil {
		d.Error = "no token store configured"
	} else {
		if d.Tokens, err = s.Auth.Store.ListTokens(r.Context()); err != nil {
			s.fail(w, r, err)
			return
		}
		if d.Users, err = s.Auth.Store.ListUsers(r.Context()); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	d.Roles, d.SSO = auth.Roles, s.Auth.SSOEnabled()
	status := http.StatusOK
	if d.Error != "" {
		status = http.StatusBadRequest
	}
	s.render(w, r, status, "admin", "Access", "admin", d)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) { s.adminPage(w, r, adminData{}) }

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	if s.Auth.Store == nil {
		s.adminPage(w, r, adminData{Error: "no token store configured"})
		return
	}
	p := auth.FromContext(r.Context())
	plain, t, err := auth.NewToken(r.Context(), s.Auth.Store, r.PostFormValue("name"), r.PostFormValue("role"), p.Label())
	if err != nil {
		s.adminPage(w, r, adminData{Error: err.Error()})
		return
	}
	s.logf("ledgerd: token %s (%s, %s) created by %s", t.ID, t.Name, t.Role, p.Label())
	s.adminPage(w, r, adminData{NewToken: plain, NewName: t.Name})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if s.Auth.Store == nil {
		s.adminPage(w, r, adminData{Error: "no token store configured"})
		return
	}
	if err := s.Auth.Store.RevokeToken(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			s.adminPage(w, r, adminData{Error: "no such token"})
			return
		}
		s.fail(w, r, err)
		return
	}
	s.logf("ledgerd: token %s revoked by %s", r.PathValue("id"), auth.FromContext(r.Context()).Label())
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	if s.Auth.Store == nil {
		s.adminPage(w, r, adminData{Error: "no user store configured"})
		return
	}
	id := r.PathValue("id")
	p := auth.FromContext(r.Context())
	if role := r.PostFormValue("role"); role != "" {
		if !auth.ValidRole(role) {
			s.adminPage(w, r, adminData{Error: "unknown role"})
			return
		}
		if p.Kind == "user" && p.ID == id && role != auth.RoleAdmin {
			s.adminPage(w, r, adminData{Error: "you cannot demote yourself"})
			return
		}
		if err := s.Auth.Store.SetUserRole(r.Context(), id, role); err != nil {
			s.adminPage(w, r, adminData{Error: "no such user"})
			return
		}
	}
	if v := r.PostFormValue("disabled"); v != "" {
		if p.Kind == "user" && p.ID == id {
			s.adminPage(w, r, adminData{Error: "you cannot disable yourself"})
			return
		}
		if err := s.Auth.Store.SetUserDisabled(r.Context(), id, v == "true"); err != nil {
			s.adminPage(w, r, adminData{Error: "no such user"})
			return
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
