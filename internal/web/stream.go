package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// StreamSource is what GET /v1/stream reads.
type StreamSource interface {
	// Heads returns the current head seq of every chain.
	Heads(ctx context.Context) (map[string]int64, error)
	// Since returns, per chain, up to limit records with seq > cursor[chain] (0 when absent),
	// restricted to chain/goal when non-empty, each chain in seq order.
	Since(ctx context.Context, cursor map[string]int64, chain, goal string, limit int) (map[string][]store.Record, error)
}

// Hub fans out "something was appended" wake-ups to stream subscribers. Wake-ups are hints:
// subscribers always re-read with their cursor, so a lost wake-up only adds poll latency.
type Hub struct {
	mu   sync.Mutex
	subs map[chan struct{}]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan struct{}]struct{}{}} }

// Kick wakes every subscriber (never blocks).
func (h *Hub) Kick() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subs {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}

// Subscribe returns a wake-up channel and its cancel func.
func (h *Hub) Subscribe() (<-chan struct{}, func()) {
	c := make(chan struct{}, 1)
	h.mu.Lock()
	h.subs[c] = struct{}{}
	h.mu.Unlock()
	return c, func() {
		h.mu.Lock()
		delete(h.subs, c)
		h.mu.Unlock()
	}
}

// Subscribers is the number of open streams.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// EncodeCursor renders a per-chain cursor as an SSE event id ("chainA=12&chainB=3").
func EncodeCursor(c map[string]int64) string {
	v := url.Values{}
	for k, s := range c {
		if s > 0 {
			v.Set(k, strconv.FormatInt(s, 10))
		}
	}
	return v.Encode()
}

// DecodeCursor parses an event id; ok is false for garbage.
func DecodeCursor(s string) (map[string]int64, bool) {
	out := map[string]int64{}
	if s == "" {
		return out, true
	}
	v, err := url.ParseQuery(s)
	if err != nil || len(v) > 10000 {
		return nil, false
	}
	for k, vs := range v {
		n, err := strconv.ParseInt(vs[0], 10, 64)
		// (NUL cannot be a chain name and would make the Postgres query fail)
		if err != nil || n < 0 || k == "" || strings.IndexByte(k, 0) >= 0 {
			return nil, false
		}
		out[k] = n
	}
	return out, true
}

// mergeByTime interleaves per-chain seq-ordered lists by created_at while keeping each chain
// a prefix (so a truncated batch never skips a record of any chain).
func mergeByTime(per map[string][]store.Record) []store.Record {
	chains := make([]string, 0, len(per))
	for c := range per {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	idx := make([]int, len(chains))
	var out []store.Record
	for {
		best := -1
		for i, c := range chains {
			if idx[i] >= len(per[c]) {
				continue
			}
			if best < 0 || per[c][idx[i]].CreatedAt.Before(per[chains[best]][idx[best]].CreatedAt) {
				best = i
			}
		}
		if best < 0 {
			return out
		}
		out = append(out, per[chains[best]][idx[best]])
		idx[best]++
	}
}

// Streamer serves GET /v1/stream?chain=&goal_id= as Server-Sent Events.
//
// Each event is one record ("event: record", data = the record JSON exactly as GET
// /v1/records returns it) and its id is the per-chain cursor after that record, so a client
// that reconnects with Last-Event-ID (or ?cursor=) resumes without gaps or duplicates.
// Without a cursor the stream starts at the current heads (?from=start replays from seq 1).
type Streamer struct {
	Src       StreamSource
	Hub       *Hub          // optional; without it the stream only polls
	Poll      time.Duration // fallback poll interval (default 2s)
	Heartbeat time.Duration // comment ping interval (default 15s)
	Batch     int           // max records per chain per read (default 200)
	Logger    *log.Logger
}

func (s *Streamer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	chain, goal := q.Get("chain"), q.Get("goal_id")
	poll, beat, batch := s.Poll, s.Heartbeat, s.Batch
	if poll <= 0 {
		poll = 2 * time.Second
	}
	if beat <= 0 {
		beat = 15 * time.Second
	}
	if batch <= 0 {
		batch = 200
	}
	rc := http.NewResponseController(w)
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = q.Get("cursor")
	}
	var cursor map[string]int64
	if raw != "" {
		c, ok := DecodeCursor(raw)
		if !ok {
			http.Error(w, `{"error":"invalid cursor / Last-Event-ID"}`, http.StatusBadRequest)
			return
		}
		cursor = c
	} else if q.Get("from") == "start" {
		cursor = map[string]int64{}
	} else {
		heads, err := s.Src.Heads(ctx)
		if err != nil {
			s.logf("stream: heads: %v", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		cursor = map[string]int64{}
		for c, h := range heads {
			if chain == "" || c == chain {
				cursor[c] = h
			}
		}
	}
	var wake <-chan struct{}
	if s.Hub != nil {
		c, cancel := s.Hub.Subscribe()
		defer cancel()
		wake = c
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("retry: 2000\n: ledger stream " + EncodeCursor(cursor) + "\n\n")); err != nil {
		return
	}
	_ = rc.Flush()
	pollT := time.NewTicker(poll)
	defer pollT.Stop()
	beatT := time.NewTicker(beat)
	defer beatT.Stop()
	for {
		// drain everything available
		for {
			heads, err := s.Src.Heads(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.logf("stream: heads: %v", err)
				}
				return
			}
			per, err := s.Src.Since(ctx, cursor, chain, goal, batch)
			if err != nil {
				if ctx.Err() == nil {
					s.logf("stream: read: %v", err)
				}
				return
			}
			full := false
			for _, rec := range mergeByTime(per) {
				cursor[rec.Chain] = rec.Seq
				b, _ := json.Marshal(rec)
				if _, err := w.Write([]byte("id: " + EncodeCursor(cursor) + "\nevent: record\ndata: " + string(b) + "\n\n")); err != nil {
					return
				}
			}
			for _, recs := range per {
				if len(recs) >= batch {
					full = true
				}
			}
			// Chains that returned less than a full batch were read up to their head
			// snapshot: advance past records that did not match the goal filter.
			for c, hs := range heads {
				if chain != "" && c != chain {
					continue
				}
				if len(per[c]) < batch && hs > cursor[c] {
					cursor[c] = hs
				}
			}
			_ = rc.Flush()
			if !full {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-pollT.C:
		case <-beatT.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

func (s *Streamer) logf(f string, a ...any) {
	if s.Logger != nil {
		s.Logger.Printf(f, a...)
	} else {
		log.Printf(f, a...)
	}
}
