package api

import (
	"net/http"

	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/incident"
	"github.com/Celaris-dev1/Ledger/internal/projection"
)

// Query API over the projections and the cross-product incident review.
//
//	GET /v1/goals                       goal summaries
//	GET /v1/goals/{goal_id}             goal → steps → attempts → verifications/approvals (+ evidence record ids/hashes)
//	GET /v1/approvals?status=pending|approved|denied
//	GET /v1/budgets/{goal_id}           running balances, overspend flagged
//	GET /v1/incidents/{goal_id}?format=json|html|md
//	GET /v1/projections/vocabulary      the ledger.* payload convention and product mappings
func (s *Server) registerProjections(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/goals", s.guard(auth.PermView, s.listGoals))
	mux.HandleFunc("GET /v1/goals/{goal_id}", s.guard(auth.PermView, s.goalTree))
	mux.HandleFunc("GET /v1/approvals", s.guard(auth.PermView, s.approvals))
	mux.HandleFunc("GET /v1/budgets/{goal_id}", s.guard(auth.PermView, s.budgets))
	mux.HandleFunc("GET /v1/incidents/{goal_id}", s.guard(auth.PermView, s.incident))
	mux.HandleFunc("GET /v1/projections/vocabulary", s.guard(auth.PermView, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"version": projection.Version, "vocabulary": projection.Vocabulary, "product_mappings": projection.ProductMappings})
	}))
}

func (s *Server) rows(w http.ResponseWriter, r *http.Request, goal string) (*projection.Rows, bool) {
	if s.Projections == nil {
		writeErr(w, http.StatusServiceUnavailable, "projections are not enabled on this server")
		return nil, false
	}
	rows, err := s.Projections.Rows(r.Context(), goal)
	if err != nil {
		s.internal(w, err)
		return nil, false
	}
	return rows, true
}

func (s *Server) listGoals(w http.ResponseWriter, r *http.Request) {
	rows, ok := s.rows(w, r, "")
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"goals": projection.Goals(rows)})
}

func (s *Server) goalTree(w http.ResponseWriter, r *http.Request) {
	goal := r.PathValue("goal_id")
	rows, ok := s.rows(w, r, goal)
	if !ok {
		return
	}
	tree, found := projection.BuildTree(rows, goal)
	if !found {
		writeErr(w, http.StatusNotFound, "goal not found (or not yet projected)")
		return
	}
	writeJSON(w, 200, tree)
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		writeErr(w, 400, "status must be pending, approved or denied")
		return
	}
	rows, ok := s.rows(w, r, "")
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"approvals": projection.Approvals(rows, status)})
}

func (s *Server) budgets(w http.ResponseWriter, r *http.Request) {
	goal := r.PathValue("goal_id")
	rows, ok := s.rows(w, r, goal)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"goal_id": goal, "budgets": projection.Budgets(rows, goal)})
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	src, ok := s.Store.(incident.Source)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "incident review needs a store that can list chains")
		return
	}
	goal := r.PathValue("goal_id")
	rep, err := incident.Build(r.Context(), src, goal)
	if err != nil {
		s.internal(w, err)
		return
	}
	if rep == nil {
		writeErr(w, http.StatusNotFound, "no records for goal")
		return
	}
	format := r.URL.Query().Get("format")
	if p := auth.FromContext(r.Context()); p != nil && format != "" && format != "json" && !p.Can(auth.PermExport) {
		writeErr(w, http.StatusForbidden, "role "+p.Role+" may not export")
		return
	}
	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		_ = incident.WriteHTML(w, rep)
	case "md", "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_ = incident.WriteMarkdown(w, rep)
	default:
		writeJSON(w, 200, rep)
	}
}
