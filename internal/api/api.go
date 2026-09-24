// Package api implements the Ledger HTTP API (see README "HTTP API").
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/export"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// Backend is what the API needs from storage (lets handlers be tested without Postgres).
type Backend interface {
	Append(ctx context.Context, req store.AppendRequest) (*store.Record, error)
	List(ctx context.Context, q store.Query) ([]store.Record, error)
	Replay(ctx context.Context, goalID string) ([]store.Record, error)
	Verify(ctx context.Context, chain string) (store.VerifyResult, error)
	Head(ctx context.Context, chain string) (int64, string, error)
	ChainRecords(ctx context.Context, chain string) ([]store.Record, error)
}

// Server holds dependencies.
type Server struct {
	Store Backend
	Token string
	Key   ed25519.PrivateKey
	// Anchors serves GET /v1/chains/{chain}/anchors (optional; 501 when nil).
	Anchors AnchorSource
}

// AnchorSource lists (and optionally re-verifies) external anchor receipts of a chain.
type AnchorSource interface {
	ChainAnchors(ctx context.Context, chain string, verify bool) (any, error)
}

// AppendResponse is the 201 body of POST /v1/records.
type AppendResponse struct {
	ID        string `json:"id"`
	Chain     string `json:"chain"`
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	PrevHash  string `json:"prev_hash"`
	CreatedAt string `json:"created_at"`
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("POST /v1/records", s.auth(s.postRecord))
	mux.HandleFunc("GET /v1/records", s.auth(s.listRecords))
	mux.HandleFunc("GET /v1/chains/{chain}/verify", s.auth(s.verify))
	mux.HandleFunc("GET /v1/chains/{chain}/root", s.auth(s.root))
	mux.HandleFunc("GET /v1/chains/{chain}/anchors", s.auth(s.anchors))
	mux.HandleFunc("GET /v1/goals/{goal_id}/replay", s.auth(s.replay))
	mux.HandleFunc("GET /v1/export", s.auth(s.export))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			want := "Bearer " + s.Token
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
				writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	log.Printf("ledgerd: internal error: %v", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) postRecord(w http.ResponseWriter, r *http.Request) {
	var req store.AppendRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	rec, err := s.Store.Append(r.Context(), req)
	var ve *store.ValidationError
	if errors.As(err, &ve) {
		writeErr(w, http.StatusBadRequest, ve.Msg)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, AppendResponse{rec.ID, rec.Chain, rec.Seq, rec.Hash, rec.PrevHash, rec.CreatedAt.Format(time.RFC3339Nano)})
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request) {
	q := store.Query{Chain: r.URL.Query().Get("chain"), GoalID: r.URL.Query().Get("goal_id")}
	var err error
	if v := r.URL.Query().Get("after_seq"); v != "" {
		if q.AfterSeq, err = strconv.ParseInt(v, 10, 64); err != nil {
			writeErr(w, 400, "after_seq must be an integer")
			return
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if q.Limit, err = strconv.Atoi(v); err != nil {
			writeErr(w, 400, "limit must be an integer")
			return
		}
	}
	recs, err := s.Store.List(r.Context(), q)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"records": recs})
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	res, err := s.Store.Verify(r.Context(), r.PathValue("chain"))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	chain := r.PathValue("chain")
	seq, head, err := s.Store.Head(r.Context(), chain)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, anchor.Sign(s.Key, chain, seq, head))
}

// GET /v1/chains/{chain}/anchors[?verify=1]
func (s *Server) anchors(w http.ResponseWriter, r *http.Request) {
	if s.Anchors == nil {
		writeErr(w, http.StatusNotImplemented, "external anchoring is not configured on this server")
		return
	}
	v := r.URL.Query().Get("verify")
	out, err := s.Anchors.ChainAnchors(r.Context(), r.PathValue("chain"), v == "1" || v == "true")
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	goal := r.PathValue("goal_id")
	recs, err := s.Store.Replay(r.Context(), goal)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"goal_id": goal, "records": recs})
}

// GET /v1/export?chain=a&chain=b | goal_id=g [&format=json|html|zip]
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	p, err := BuildPack(r.Context(), s.Store, s.Key, r.URL.Query()["chain"], r.URL.Query().Get("goal_id"))
	if err != nil {
		s.internal(w, err)
		return
	}
	switch r.URL.Query().Get("format") {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = export.WriteHTML(w, p)
	case "zip":
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="ledger-auditor-pack.zip"`)
		_ = export.WriteZip(w, p)
	default:
		writeJSON(w, 200, p)
	}
}

// BuildPack assembles an auditor pack for the given chains, or for every chain touched by goalID.
func BuildPack(ctx context.Context, st Backend, key ed25519.PrivateKey, chains []string, goalID string) (export.Pack, error) {
	var goalRecs map[string][]store.Record
	if goalID != "" {
		recs, err := st.Replay(ctx, goalID)
		if err != nil {
			return export.Pack{}, err
		}
		goalRecs = map[string][]store.Record{}
		for _, rc := range recs {
			if _, ok := goalRecs[rc.Chain]; !ok && len(chains) == 0 {
				chains = append(chains, rc.Chain)
			}
			goalRecs[rc.Chain] = append(goalRecs[rc.Chain], rc)
		}
	}
	var sections []export.ChainSection
	for _, c := range chains {
		v, err := st.Verify(ctx, c)
		if err != nil {
			return export.Pack{}, err
		}
		sec := export.ChainSection{Verify: v}
		if goalRecs != nil {
			sec.Records = goalRecs[c]
		} else if sec.Records, err = st.ChainRecords(ctx, c); err != nil {
			return export.Pack{}, err
		}
		if key != nil {
			seq, head, err := st.Head(ctx, c)
			if err != nil {
				return export.Pack{}, err
			}
			root := anchor.Sign(key, c, seq, head)
			sec.Root = &root
		}
		sections = append(sections, sec)
	}
	return export.Build(goalID, sections), nil
}
