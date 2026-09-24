package anchoring

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

// SystemChain holds Ledger's own events (key rotations).
const SystemChain = "ledger"

// RotationType is the record type of a key rotation.
const RotationType = "ledger.key.rotated"

// Service anchors chains and verifies anchors against a Postgres store.
type Service struct {
	Store    *store.Store
	Key      ed25519.PrivateKey
	Keyring  *anchor.Keyring // optional; enables trusted-key checks
	Backends []Backend
	Verifier Verifier
	Quorum   int      // RFC 3161 quorum (for reporting)
	RootDirs []string // external anchor directories scanned by VerifyAll (file backend dir, git clone roots/)
	Log      *log.Logger
	// keyMu guards Key and the Keyring's state: RotateKey may run while the scheduler signs.
	keyMu sync.RWMutex
}

func (s *Service) logf(f string, a ...any) {
	if s.Log != nil {
		s.Log.Printf(f, a...)
	}
}

// InsertReceipt stores a receipt row (append-only table).
func (s *Service) InsertReceipt(ctx context.Context, subj Subject, r Receipt) (int64, error) {
	var id int64
	m := r.Meta
	if len(m) == 0 {
		m = json.RawMessage(`{}`)
	}
	err := s.Store.Pool.QueryRow(ctx, `INSERT INTO anchor_receipts
		(chain, seq, head, root_digest, key_id, root_json, backend, kind, receipt, meta, anchored_at, verified_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()) RETURNING id`,
		subj.Root.Chain, subj.Root.Seq, subj.Root.Head, subj.DigestHex(), subj.Root.KeyID, string(subj.RootJSON),
		r.Backend, r.Kind, r.Bytes, string(m), r.AnchoredAt).Scan(&id)
	return id, err
}

// Receipts returns all receipts for a chain.
func (s *Service) Receipts(ctx context.Context, chain string) ([]StoredReceipt, error) {
	rows, err := s.Store.Pool.Query(ctx, `SELECT id, chain, seq, head, root_digest, key_id, root_json, backend, kind,
		receipt, meta::text, anchored_at, verified_at FROM anchor_receipts WHERE chain=$1 ORDER BY seq, id`, chain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredReceipt{}
	for rows.Next() {
		var r StoredReceipt
		var m string
		if err := rows.Scan(&r.ID, &r.Chain, &r.Seq, &r.Head, &r.RootDigest, &r.KeyID, &r.RootJSON, &r.Backend, &r.Kind,
			&r.Receipt, &m, &r.AnchoredAt, &r.VerifiedAt); err != nil {
			return nil, err
		}
		r.Meta = json.RawMessage(m)
		r.AnchoredAt, r.VerifiedAt = r.AnchoredAt.UTC(), r.VerifiedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastAnchor returns the highest anchored seq of a chain and when it was stored.
func (s *Service) LastAnchor(ctx context.Context, chain string) (int64, time.Time, error) {
	var seq int64
	var at *time.Time
	err := s.Store.Pool.QueryRow(ctx, `SELECT COALESCE(max(seq),0), max(created_at) FROM anchor_receipts WHERE chain=$1`, chain).Scan(&seq, &at)
	if at == nil {
		return seq, time.Time{}, err
	}
	return seq, *at, err
}

// Result summarises one AnchorChain call.
type Result struct {
	Chain    string   `json:"chain"`
	Seq      int64    `json:"seq"`
	Head     string   `json:"head"`
	KeyID    string   `json:"key_id"`
	Receipts []string `json:"receipts"`
	Errors   []string `json:"errors,omitempty"`
}

// AnchorChain verifies the chain, signs its head and sends it to every backend.
// It fails only if the chain is broken or no backend produced a receipt.
func (s *Service) AnchorChain(ctx context.Context, chain string) (Result, error) {
	v, err := s.Store.Verify(ctx, chain)
	if err != nil {
		return Result{}, err
	}
	if !v.OK {
		return Result{}, fmt.Errorf("refusing to anchor broken chain %s (broken_at=%d: %s)", chain, *v.BrokenAt, v.Reason)
	}
	res := Result{Chain: chain, Seq: int64(v.Length), Head: v.Head}
	if v.Length == 0 {
		return res, errors.New("chain is empty")
	}
	s.keyMu.RLock()
	key := s.Key
	s.keyMu.RUnlock()
	root := anchor.Sign(key, chain, res.Seq, res.Head)
	res.KeyID = root.KeyID
	if err := s.Store.SaveAnchor(ctx, chain, root.Seq, root.Head, root.Signature, root.PublicKey); err != nil {
		return res, err
	}
	subj := NewSubject(root)
	for _, b := range s.Backends {
		recs, err := b.Anchor(ctx, subj)
		if err != nil {
			res.Errors = append(res.Errors, b.Name()+": "+err.Error())
			s.logf("anchoring: %s seq=%d backend %s: %v", chain, res.Seq, b.Name(), err)
		}
		for _, r := range recs {
			if _, err := s.Verifier.VerifyReceipt(r, subj); err != nil && !errors.Is(err, ErrUnverifiable) {
				res.Errors = append(res.Errors, r.Backend+": receipt failed verification: "+err.Error())
				continue
			}
			id, err := s.InsertReceipt(ctx, subj, r)
			if err != nil {
				return res, err
			}
			res.Receipts = append(res.Receipts, fmt.Sprintf("%s#%d", r.Backend, id))
		}
	}
	if len(res.Receipts) == 0 && len(s.Backends) > 0 {
		return res, fmt.Errorf("no backend produced a receipt: %s", strings.Join(res.Errors, "; "))
	}
	return res, nil
}

// Rotations reads key rotations recorded in the system chain.
func (s *Service) Rotations(ctx context.Context) ([]anchor.Rotation, error) {
	recs, err := s.Store.ChainRecords(ctx, SystemChain)
	if err != nil {
		return nil, err
	}
	var out []anchor.Rotation
	for _, r := range recs {
		if r.Type != RotationType {
			continue
		}
		var rot anchor.Rotation
		if err := json.Unmarshal(r.Payload, &rot); err == nil {
			out = append(out, rot)
		}
	}
	return out, nil
}

// Trust builds the trusted key set: keyring public keys plus keys introduced by valid rotations.
// Without a keyring it returns nil (roots are checked against their embedded key only).
func (s *Service) Trust(ctx context.Context) (anchor.TrustSet, []string, error) {
	if s.Keyring == nil {
		return nil, nil, nil
	}
	base := anchor.TrustSet{}
	s.keyMu.RLock()
	for id, pub := range s.Keyring.Public {
		base[id] = pub
	}
	s.keyMu.RUnlock()
	rots, err := s.Rotations(ctx)
	if err != nil {
		return nil, nil, err
	}
	ts, errs := anchor.TrustFromRotations(base, rots)
	var w []string
	for _, e := range errs {
		w = append(w, "key rotation record: "+e.Error())
	}
	return ts, w, nil
}

// RotateKey rotates the keyring's active key and records the rotation in the system chain.
func (s *Service) RotateKey(ctx context.Context, operator string, keepOld bool) (anchor.Rotation, *store.Record, error) {
	if s.Keyring == nil {
		return anchor.Rotation{}, nil, errors.New("key rotation requires LEDGER_KEYRING_DIR")
	}
	s.keyMu.Lock()
	rot, err := s.Keyring.Rotate(keepOld)
	if err == nil {
		s.Key = s.Keyring.Active
	}
	s.keyMu.Unlock()
	if err != nil {
		return rot, nil, err
	}
	pl, _ := json.Marshal(rot)
	if operator == "" {
		operator = "operator"
	}
	rec, err := s.Store.Append(ctx, store.AppendRequest{Chain: SystemChain, Type: RotationType,
		ActorChain: []store.Actor{{Kind: "human", ID: operator}, {Kind: "service", ID: "ledger-keyring"}},
		Payload:    pl})
	return rot, rec, err
}

// VerifyChainAnchors runs VerifyChain for one chain using stored receipts plus external root dirs.
func (s *Service) VerifyChainAnchors(ctx context.Context, chain string) (ChainReport, error) {
	recs, err := s.Store.ChainRecords(ctx, chain)
	if err != nil {
		return ChainReport{}, err
	}
	rcpts, err := s.Receipts(ctx, chain)
	if err != nil {
		return ChainReport{}, err
	}
	for _, d := range s.RootDirs {
		ext, err := ScanRootDir(d, chain)
		if err != nil {
			return ChainReport{}, err
		}
		rcpts = append(rcpts, ext...)
	}
	trust, tw, err := s.Trust(ctx)
	if err != nil {
		return ChainReport{}, err
	}
	rep := VerifyChain(chain, recs, rcpts, Options{Verifier: s.Verifier, Trust: trust, Quorum: s.Quorum})
	rep.Warnings = append(rep.Warnings, tw...)
	// head pointer check (truncation) as in plain verify
	if hs, hh, err := s.Store.Head(ctx, chain); err == nil && rep.ChainIntact && (hs != int64(len(recs)) || hh != rep.Head) {
		rep.ChainIntact, rep.OK = false, false
		rep.Findings = append(rep.Findings, "chain head pointer disagrees with records (truncation?)")
	}
	return rep, nil
}

// ChainAnchors backs GET /v1/chains/{chain}/anchors.
func (s *Service) ChainAnchors(ctx context.Context, chain string, verify bool) (any, error) {
	rcpts, err := s.Receipts(ctx, chain)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"chain": chain, "anchors": rcpts}
	if verify {
		rep, err := s.VerifyChainAnchors(ctx, chain)
		if err != nil {
			return nil, err
		}
		out["verification"] = rep
	}
	return out, nil
}

// ---- scheduler ----

// Scheduler anchors each chain's head every Interval and whenever EveryN new records accumulate.
type Scheduler struct {
	Svc      *Service
	Interval time.Duration // 0 disables time-based anchoring
	EveryN   int64         // 0 disables count-based anchoring
	Poll     time.Duration // how often heads are checked (default 10s)
	Now      func() time.Time
}

// Tick checks every chain once and anchors those that are due; it returns the chains anchored.
func (sc *Scheduler) Tick(ctx context.Context) ([]Result, error) {
	now := time.Now
	if sc.Now != nil {
		now = sc.Now
	}
	chains, err := sc.Svc.Store.Chains(ctx)
	if err != nil {
		return nil, err
	}
	var done []Result
	for _, c := range chains {
		head, _, err := sc.Svc.Store.Head(ctx, c)
		if err != nil {
			return done, err
		}
		last, lastAt, err := sc.Svc.LastAnchor(ctx, c)
		if err != nil {
			return done, err
		}
		if head <= last {
			continue
		}
		due := (sc.EveryN > 0 && head-last >= sc.EveryN) ||
			(sc.Interval > 0 && (lastAt.IsZero() || now().Sub(lastAt) >= sc.Interval))
		if !due {
			continue
		}
		res, err := sc.Svc.AnchorChain(ctx, c)
		if err != nil {
			sc.Svc.logf("anchoring: %s: %v", c, err)
			continue
		}
		sc.Svc.logf("anchoring: %s seq=%d head=%s receipts=%v", c, res.Seq, res.Head, res.Receipts)
		done = append(done, res)
	}
	return done, nil
}

// Run ticks until ctx is done.
func (sc *Scheduler) Run(ctx context.Context) {
	p := sc.Poll
	if p <= 0 {
		p = 10 * time.Second
	}
	t := time.NewTicker(p)
	defer t.Stop()
	for {
		if _, err := sc.Tick(ctx); err != nil && ctx.Err() == nil {
			sc.Svc.logf("anchoring: tick: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---- configuration from environment ----

// Config is read from LEDGER_* environment variables (see README "External anchoring").
type Config struct {
	TSAs       []*tsa.Client
	TSAQuorum  int
	TrustPath  string
	GitRemote  string
	GitWorkDir string
	GitBranch  string
	GitSign    bool
	AnchorDir  string
	Interval   time.Duration
	EveryN     int64
	Poll       time.Duration
	Warnings   []string
}

// ConfigFromEnv parses the anchoring environment. getenv is os.Getenv in production.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := Config{TrustPath: getenv("LEDGER_TSA_TRUST"), GitRemote: getenv("LEDGER_ANCHOR_GIT_REMOTE"),
		GitWorkDir: getenv("LEDGER_ANCHOR_GIT_DIR"), GitBranch: getenv("LEDGER_ANCHOR_GIT_BRANCH"),
		GitSign: getenv("LEDGER_ANCHOR_GIT_SIGN") == "1", AnchorDir: getenv("LEDGER_ANCHOR_DIR")}
	var opt tsa.Options
	if c.TrustPath != "" {
		pool, err := tsa.LoadTrustBundle(c.TrustPath)
		if err != nil {
			return c, err
		}
		opt.Roots = pool
	}
	// LEDGER_TSA_URLS="freetsa=https://freetsa.org/tsr,digicert=http://timestamp.digicert.com"
	for _, part := range strings.Split(getenv("LEDGER_TSA_URLS"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, url, ok := strings.Cut(part, "=")
		if !ok {
			url, name = part, fmt.Sprintf("tsa%d", len(c.TSAs)+1)
		}
		c.TSAs = append(c.TSAs, &tsa.Client{Name: name, URL: url, HTTP: nil, Opt: opt})
	}
	if len(c.TSAs) > 0 && opt.Roots == nil {
		return c, errors.New("LEDGER_TSA_URLS set but LEDGER_TSA_TRUST (PEM trust bundle of the TSA roots) is not")
	}
	c.TSAQuorum = len(c.TSAs)
	if v := getenv("LEDGER_TSA_QUORUM"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > len(c.TSAs) {
			return c, fmt.Errorf("LEDGER_TSA_QUORUM must be 1..%d", len(c.TSAs))
		}
		c.TSAQuorum = n
	}
	if c.GitRemote != "" && c.GitWorkDir == "" {
		c.GitWorkDir = filepath.Join(os.TempDir(), "ledger-anchor-git")
		c.Warnings = append(c.Warnings, "LEDGER_ANCHOR_GIT_DIR not set; using "+c.GitWorkDir)
	}
	var err error
	if v := getenv("LEDGER_ANCHOR_INTERVAL"); v != "" {
		if c.Interval, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("LEDGER_ANCHOR_INTERVAL: %w", err)
		}
	}
	if v := getenv("LEDGER_ANCHOR_EVERY"); v != "" {
		if c.EveryN, err = strconv.ParseInt(v, 10, 64); err != nil {
			return c, fmt.Errorf("LEDGER_ANCHOR_EVERY: %w", err)
		}
	}
	c.Poll = 10 * time.Second
	if v := getenv("LEDGER_ANCHOR_POLL"); v != "" {
		if c.Poll, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("LEDGER_ANCHOR_POLL: %w", err)
		}
	}
	return c, nil
}

// Backends builds the configured backends (in order: file, git, rfc3161).
func (c Config) Backends() []Backend {
	var out []Backend
	if c.AnchorDir != "" {
		out = append(out, &FileBackend{Dir: c.AnchorDir})
	}
	if c.GitWorkDir != "" {
		out = append(out, &GitBackend{Remote: c.GitRemote, WorkDir: c.GitWorkDir, Branch: c.GitBranch, SignCommits: c.GitSign})
	}
	if len(c.TSAs) > 0 {
		out = append(out, &TSABackend{Clients: c.TSAs, Quorum: c.TSAQuorum})
	}
	return out
}

// Service builds a Service from the config.
func (c Config) Service(st *store.Store, key ed25519.PrivateKey, kr *anchor.Keyring, lg *log.Logger) *Service {
	s := &Service{Store: st, Key: key, Keyring: kr, Backends: c.Backends(), Quorum: c.TSAQuorum, Log: lg}
	if len(c.TSAs) > 0 {
		s.Verifier.TSARoots = c.TSAs[0].Opt.Roots
	} else if c.TrustPath != "" {
		s.Verifier.TSARoots, _ = tsa.LoadTrustBundle(c.TrustPath)
	}
	if c.GitWorkDir != "" {
		if _, err := os.Stat(filepath.Join(c.GitWorkDir, ".git")); err == nil {
			s.Verifier.GitDir = c.GitWorkDir
		}
		s.RootDirs = append(s.RootDirs, filepath.Join(c.GitWorkDir, "roots"))
	}
	if c.AnchorDir != "" {
		s.RootDirs = append(s.RootDirs, c.AnchorDir)
	}
	return s
}
