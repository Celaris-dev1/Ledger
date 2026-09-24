// Package anchoring pushes signed chain roots to external witnesses (RFC 3161 time-stamp
// authorities, a git repository, a local directory), stores the receipts append-only, and
// re-verifies them offline to prove the current chain still extends every anchored head.
//
// Threat model: a database administrator can disable the append-only triggers, edit a record and
// recompute every later hash plus the chains.head pointer. Plain `ledger verify` then passes,
// because the chain is internally consistent. It cannot forge (a) TSA tokens over the old root
// digest, (b) commits already pushed to a repository they do not control, or (c) new roots
// signed by a key they do not hold — so `ledger verify --anchors` catches the rewrite.
package anchoring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa"
)

// Subject is what gets anchored: a signed root and its digest.
type Subject struct {
	Root     anchor.Root
	RootJSON []byte
	Digest   []byte // sha256(anchor.Message(chain, seq, head)) — the RFC 3161 messageImprint
}

// Digest returns the anchoring digest of (chain, seq, head).
func Digest(chain string, seq int64, head string) []byte {
	d := sha256.Sum256(anchor.Message(chain, seq, head))
	return d[:]
}

// NewSubject wraps a signed root.
func NewSubject(r anchor.Root) Subject {
	return Subject{Root: r, RootJSON: anchor.MarshalRoot(r), Digest: Digest(r.Chain, r.Seq, r.Head)}
}

// DigestHex is the hex digest.
func (s Subject) DigestHex() string { return hex.EncodeToString(s.Digest) }

// Receipt is proof from one backend that a subject existed at AnchoredAt.
type Receipt struct {
	Backend    string          `json:"backend"`
	Kind       string          `json:"kind"`
	Bytes      []byte          `json:"receipt"`
	Meta       json.RawMessage `json:"meta"`
	AnchoredAt time.Time       `json:"anchored_at"`
}

// Kinds.
const (
	KindRFC3161 = "rfc3161"
	KindGit     = "git"
	KindFile    = "file"
)

// Backend anchors a subject. It may return receipts together with an error (e.g. partial quorum).
type Backend interface {
	Name() string
	Anchor(ctx context.Context, s Subject) ([]Receipt, error)
}

func meta(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// ---- RFC 3161 (N-of-M) ----

// TSABackend stamps with several TSAs and requires Quorum valid tokens.
type TSABackend struct {
	Clients []*tsa.Client
	Quorum  int
}

// Name implements Backend.
func (b *TSABackend) Name() string { return KindRFC3161 }

// Anchor requests a token from every TSA concurrently; every returned token is already verified.
func (b *TSABackend) Anchor(ctx context.Context, s Subject) ([]Receipt, error) {
	type res struct {
		r   Receipt
		err error
	}
	out := make([]res, len(b.Clients))
	var wg sync.WaitGroup
	for i, c := range b.Clients {
		wg.Add(1)
		go func(i int, c *tsa.Client) {
			defer wg.Done()
			tok, info, err := c.Stamp(ctx, s.Digest)
			if err != nil {
				out[i].err = fmt.Errorf("%s: %w", c.Name, err)
				return
			}
			out[i].r = Receipt{Backend: KindRFC3161 + ":" + c.Name, Kind: KindRFC3161, Bytes: tok,
				Meta: meta(map[string]any{"url": c.URL, "serial": info.Serial, "policy": info.Policy,
					"signer": info.SignerName, "signer_cert_sha256": info.SignerSHA256, "nonce": info.Nonce}),
				AnchoredAt: info.GenTime}
		}(i, c)
	}
	wg.Wait()
	var recs []Receipt
	var errs []error
	for _, o := range out {
		if o.err != nil {
			errs = append(errs, o.err)
		} else {
			recs = append(recs, o.r)
		}
	}
	q := b.Quorum
	if q <= 0 {
		q = 1
	}
	if len(recs) < q {
		errs = append([]error{fmt.Errorf("rfc3161 quorum not met: %d of %d TSAs, need %d", len(recs), len(b.Clients), q)}, errs...)
		return recs, errors.Join(errs...)
	}
	if len(errs) > 0 { // quorum met; report the stragglers without failing
		return recs, &PartialError{errors.Join(errs...)}
	}
	return recs, nil
}

// PartialError marks a backend that succeeded overall but had failing members.
type PartialError struct{ Err error }

func (e *PartialError) Error() string { return "partial: " + e.Err.Error() }
func (e *PartialError) Unwrap() error { return e.Err }

// ---- local directory ----

// FileBackend writes roots with anchor.Write (dir/<chain>/<seq>.json).
type FileBackend struct{ Dir string }

// Name implements Backend.
func (b *FileBackend) Name() string { return KindFile }

// Anchor implements Backend.
func (b *FileBackend) Anchor(_ context.Context, s Subject) ([]Receipt, error) {
	p, err := anchor.Write(b.Dir, s.Root)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(p)
	return []Receipt{{Backend: KindFile, Kind: KindFile, Bytes: s.RootJSON, Meta: meta(map[string]string{"path": abs}), AnchoredAt: time.Now().UTC()}}, nil
}

// ---- git repository ----

// GitBackend commits roots to a git repository via the git CLI and pushes them.
type GitBackend struct {
	Remote      string // clone URL or path; empty = local-only repository in WorkDir
	WorkDir     string // local clone managed by ledgerd
	Branch      string // default "main"
	SignCommits bool   // pass -S (requires git signing to be configured)
	AuthorName  string
	AuthorEmail string
	mu          sync.Mutex
}

// Name implements Backend.
func (b *GitBackend) Name() string { return KindGit }

func (b *GitBackend) git(ctx context.Context, args ...string) (string, error) {
	return runGit(ctx, b.WorkDir, args...)
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func (b *GitBackend) branch() string {
	if b.Branch == "" {
		return "main"
	}
	return b.Branch
}

func (b *GitBackend) prepare(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(b.WorkDir, ".git")); err != nil {
		if err := os.MkdirAll(b.WorkDir, 0o755); err != nil {
			return err
		}
		if b.Remote != "" {
			if _, err := runGit(ctx, filepath.Dir(b.WorkDir), "clone", "--quiet", b.Remote, b.WorkDir); err != nil {
				return err
			}
		} else if _, err := b.git(ctx, "init", "--quiet", "-b", b.branch()); err != nil {
			return err
		}
	}
	if b.Remote != "" {
		if _, err := b.git(ctx, "fetch", "--quiet", "origin"); err != nil {
			return err
		}
		if _, err := b.git(ctx, "rev-parse", "--verify", "--quiet", "origin/"+b.branch()); err == nil {
			if _, err := b.git(ctx, "checkout", "--quiet", "-B", b.branch(), "origin/"+b.branch()); err != nil {
				return err
			}
			return nil
		}
	}
	_, err := b.git(ctx, "checkout", "--quiet", "-B", b.branch())
	return err
}

// Anchor commits roots/<chain>/<seq>.json and pushes; the receipt records the commit sha.
func (b *GitBackend) Anchor(ctx context.Context, s Subject) ([]Receipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.prepare(ctx); err != nil {
		return nil, err
	}
	p, err := anchor.Write(filepath.Join(b.WorkDir, "roots"), s.Root)
	if err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(b.WorkDir, p)
	rel = filepath.ToSlash(rel)
	if _, err := b.git(ctx, "add", "roots"); err != nil {
		return nil, err
	}
	name, email := b.AuthorName, b.AuthorEmail
	if name == "" {
		name = "ledgerd"
	}
	if email == "" {
		email = "ledgerd@localhost"
	}
	args := []string{"-c", "user.name=" + name, "-c", "user.email=" + email, "commit", "--quiet", "--allow-empty",
		"-m", fmt.Sprintf("anchor %s seq=%d head=%s key=%s", s.Root.Chain, s.Root.Seq, s.Root.Head, s.Root.KeyID)}
	if b.SignCommits {
		args = append(args, "-S")
	}
	if _, err := b.git(ctx, args...); err != nil {
		return nil, err
	}
	sha, err := b.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	ct, _ := b.git(ctx, "show", "-s", "--format=%cI", "HEAD")
	at, err := time.Parse(time.RFC3339, ct)
	if err != nil {
		at = time.Now()
	}
	pushed := false
	if b.Remote != "" {
		if _, err := b.git(ctx, "push", "--quiet", "origin", "HEAD:refs/heads/"+b.branch()); err != nil {
			return nil, err
		}
		pushed = true
	}
	return []Receipt{{Backend: KindGit, Kind: KindGit, Bytes: s.RootJSON, AnchoredAt: at.UTC(),
		Meta: meta(map[string]any{"remote": b.Remote, "branch": b.branch(), "commit": sha, "path": rel, "pushed": pushed})}}, nil
}

// ---- offline verification ----

// Verifier re-checks stored receipts without network access.
type Verifier struct {
	TSARoots *x509.CertPool // trust bundle for RFC 3161 tokens
	// GitDir, if set, is a clone or bare repository used to confirm that each git receipt's commit
	// exists and contains exactly the anchored bytes.
	GitDir string
}

// ErrUnverifiable marks receipts that cannot be checked with the given configuration.
var ErrUnverifiable = errors.New("unverifiable")

// VerifyReceipt checks r proves s; it returns the attested time.
func (v Verifier) VerifyReceipt(r Receipt, s Subject) (time.Time, error) {
	switch r.Kind {
	case KindRFC3161:
		if v.TSARoots == nil {
			return time.Time{}, fmt.Errorf("%w: no TSA trust bundle configured", ErrUnverifiable)
		}
		info, err := tsa.VerifyToken(r.Bytes, s.Digest, tsa.Options{Roots: v.TSARoots})
		if err != nil {
			return time.Time{}, err
		}
		return info.GenTime, nil
	case KindGit, KindFile:
		var root anchor.Root
		if err := json.Unmarshal(r.Bytes, &root); err != nil {
			return time.Time{}, errors.New("receipt is not a root JSON")
		}
		if root.Chain != s.Root.Chain || root.Seq != s.Root.Seq || root.Head != s.Root.Head || root.Signature != s.Root.Signature {
			return time.Time{}, errors.New("receipt root differs from the anchored root")
		}
		if r.Kind == KindGit && v.GitDir != "" {
			var m struct{ Commit, Path string }
			_ = json.Unmarshal(r.Meta, &m)
			got, err := runGit(context.Background(), v.GitDir, "show", m.Commit+":"+m.Path)
			if err != nil {
				return time.Time{}, fmt.Errorf("commit %s not found in %s: %v", m.Commit, v.GitDir, err)
			}
			if got != strings.TrimSpace(string(r.Bytes)) {
				return time.Time{}, fmt.Errorf("commit %s holds different bytes at %s", m.Commit, m.Path)
			}
		}
		return r.AnchoredAt, nil
	}
	return time.Time{}, fmt.Errorf("%w: unknown receipt kind %q", ErrUnverifiable, r.Kind)
}
