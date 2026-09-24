package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits bound what one request may cost. Zero values take the defaults below.
type Limits struct {
	// MaxBodyBytes caps a POST /v1/records body (413 beyond it). Default 4 MiB.
	MaxBodyBytes int64
	// MaxPage is the largest (and default) page of GET /v1/goals and GET /v1/approvals.
	MaxPage int
	// MaxExportRecords caps GET /v1/export and GET /v1/goals/{id}/replay (413 beyond it; page
	// through GET /v1/records or use `ledger backup` for larger chains). Default 200000.
	MaxExportRecords int
	// RequestTimeout bounds each API request's context (not the SSE stream). Default 2m.
	RequestTimeout time.Duration
}

const (
	defaultMaxBody   = 4 << 20
	defaultMaxPage   = 1000
	defaultMaxExport = 200000
	defaultTimeout   = 2 * time.Minute
)

func (s *Server) maxBody() int64 {
	if s.Limits.MaxBodyBytes > 0 {
		return s.Limits.MaxBodyBytes
	}
	return defaultMaxBody
}

func (s *Server) maxPage() int {
	if s.Limits.MaxPage > 0 {
		return s.Limits.MaxPage
	}
	return defaultMaxPage
}

func (s *Server) maxExport() int {
	if s.Limits.MaxExportRecords > 0 {
		return s.Limits.MaxExportRecords
	}
	return defaultMaxExport
}

// LimitsFromEnv reads LEDGER_MAX_BODY_BYTES, LEDGER_MAX_PAGE, LEDGER_MAX_EXPORT_RECORDS and
// LEDGER_REQUEST_TIMEOUT (a Go duration).
func LimitsFromEnv(getenv func(string) string) (Limits, error) {
	var l Limits
	for _, v := range []struct {
		k string
		p *int
	}{{"LEDGER_MAX_PAGE", &l.MaxPage}, {"LEDGER_MAX_EXPORT_RECORDS", &l.MaxExportRecords}} {
		if s := getenv(v.k); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 {
				return l, fmt.Errorf("%s must be a positive integer", v.k)
			}
			*v.p = n
		}
	}
	if s := getenv("LEDGER_MAX_BODY_BYTES"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return l, errors.New("LEDGER_MAX_BODY_BYTES must be a positive integer")
		}
		l.MaxBodyBytes = n
	}
	if s := getenv("LEDGER_REQUEST_TIMEOUT"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return l, errors.New("LEDGER_REQUEST_TIMEOUT must be a positive duration (e.g. 90s)")
		}
		l.RequestTimeout = d
	}
	return l, nil
}

// withTimeout bounds the request context.
func (s *Server) withTimeout(next http.Handler) http.Handler {
	d := s.Limits.RequestTimeout
	if d <= 0 {
		d = defaultTimeout
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path/query values reach Postgres text parameters, which reject NUL and invalid UTF-8
		// (a 500 from the database): make them client errors up front.
		bad := !textOK(r.URL.Path)
		for _, vs := range r.URL.Query() {
			for _, v := range vs {
				bad = bad || !textOK(v)
			}
		}
		if bad {
			writeErr(w, http.StatusBadRequest, "path and query parameters must be valid UTF-8 without NUL")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func textOK(s string) bool { return utf8.ValidString(s) && strings.IndexByte(s, 0) < 0 }

// pageParams parses ?limit=&after= for the paginated list routes.
func (s *Server) pageParams(w http.ResponseWriter, r *http.Request) (after string, limit int, ok bool) {
	limit = s.maxPage()
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive integer")
			return "", 0, false
		}
		limit = min(n, limit)
	}
	return r.URL.Query().Get("after"), limit, true
}

// page returns the items with key > after (sorted by key), at most limit of them, and the
// cursor for the next page ("" when this is the last page).
func page[T any](items []T, key func(T) string, after string, limit int) ([]T, string) {
	sorted := append([]T(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool { return key(sorted[i]) < key(sorted[j]) })
	start := sort.Search(len(sorted), func(i int) bool { return key(sorted[i]) > after })
	if after == "" {
		start = 0
	}
	out := sorted[start:]
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = key(out[len(out)-1])
	}
	if out == nil {
		out = []T{}
	}
	return out, next
}

func tooLarge(w http.ResponseWriter, n, max int, what string) {
	writeErr(w, http.StatusRequestEntityTooLarge,
		fmt.Sprintf("%s has %d records, more than this server returns in one response (%d, LEDGER_MAX_EXPORT_RECORDS); page through GET /v1/records?chain=…&after_seq=… or use `ledger backup`", what, n, max))
}
