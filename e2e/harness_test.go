//go:build e2e

// Package e2e runs the real ledgerd and ledger binaries (built once in TestMain) against
// Postgres, the Python and TypeScript SDKs as subprocesses, a headless browser, and — with
// LEDGER_XPRODUCT=1 — the other products' binaries. Run with scripts/e2e.sh.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Celaris-dev1/Ledger/internal/license"
)

// devLicenseToken is an Enterprise license signed with the repo's public dev key, used so
// e2e can exercise Enterprise-gated features (compliance export, multi-tenancy, KMS/Vault
// signers) against binaries built with -tags licensedev. It never verifies in a plain
// `go build` release binary.
func devLicenseToken(t *testing.T) string {
	t.Helper()
	tok, err := license.Sign(license.DevSigner(), &license.License{
		LicenseID: "lic_e2e", Customer: "e2e", Product: "ledger", Edition: license.EditionEnterprise,
		Seats: 100, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var (
	binDir   string // ledgerd + ledger
	repoRoot string
	baseURL  string // LEDGER_TEST_DATABASE_URL
)

func TestMain(m *testing.M) {
	baseURL = os.Getenv("LEDGER_TEST_DATABASE_URL")
	if baseURL == "" {
		fmt.Println("e2e: LEDGER_TEST_DATABASE_URL not set; skipping")
		os.Exit(0)
	}
	_, file, _, _ := runtime.Caller(0)
	repoRoot = filepath.Dir(filepath.Dir(file))
	var err error
	if binDir, err = os.MkdirTemp("", "ledger-e2e-bin-"); err != nil {
		panic(err)
	}
	for _, b := range []string{"ledgerd", "ledger"} {
		// -tags licensedev: e2e exercises Enterprise-gated features (compliance export,
		// multi-tenancy) using a throwaway license signed with the repo's public dev key
		// (see internal/license). A plain `go build` (no tags) never trusts that key.
		cmd := exec.Command("go", "build", "-tags", "licensedev", "-o", filepath.Join(binDir, b), "./cmd/"+b)
		cmd.Dir = repoRoot
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: building %s: %v\n", b, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(binDir)
	os.Exit(code)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Env is one isolated Ledger installation: a throwaway schema plus its key, anchor and data-key dirs.
type Env struct {
	t      *testing.T
	Dir    string
	Schema string
	DBURL  string // schema-scoped (search_path) URL for the binaries
	Vars   map[string]string
}

func adminConn(t testing.TB, u string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// withSearchPath returns u with search_path=schema (pgx runtime parameter).
func withSearchPath(u, schema string) string {
	pu, _ := url.Parse(u)
	q := pu.Query()
	q.Set("search_path", schema)
	pu.RawQuery = q.Encode()
	return pu.String()
}

// NewEnv creates a throwaway schema (dropped on cleanup) and per-env directories.
func NewEnv(t *testing.T) *Env {
	t.Helper()
	schema := "ledger_e2e_" + randHex(4)
	c := adminConn(t, baseURL)
	if _, err := c.Exec(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	c.Close(context.Background())
	t.Cleanup(func() {
		c := adminConn(t, baseURL)
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})
	return newEnvAt(t, withSearchPath(baseURL, schema), schema)
}

// NewDatabaseEnv creates a whole fresh database (dropped on cleanup).
func NewDatabaseEnv(t *testing.T) *Env {
	t.Helper()
	name := "ledger_e2e_" + randHex(4)
	c := adminConn(t, baseURL)
	if _, err := c.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	c.Close(context.Background())
	t.Cleanup(func() {
		c := adminConn(t, baseURL)
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
	})
	pu, _ := url.Parse(baseURL)
	pu.Path = "/" + name
	return newEnvAt(t, pu.String(), "public")
}

func newEnvAt(t *testing.T, dbURL, schema string) *Env {
	dir := t.TempDir()
	e := &Env{t: t, Dir: dir, Schema: schema, DBURL: dbURL, Vars: map[string]string{
		"LEDGER_DATABASE_URL": dbURL,
		"LEDGER_KEY_FILE":     filepath.Join(dir, "ledger_ed25519.key"),
		"LEDGER_ANCHOR_DIR":   filepath.Join(dir, "anchors"),
		"LEDGER_STREAM_POLL":  "500ms",
		"LEDGER_LICENSE":      devLicenseToken(t),
	}}
	return e
}

// With returns a copy of the env with extra variables.
func (e *Env) With(kv ...string) *Env {
	c := *e
	c.Vars = map[string]string{}
	for k, v := range e.Vars {
		c.Vars[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		c.Vars[kv[i]] = kv[i+1]
	}
	return &c
}

func (e *Env) environ(extra map[string]string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LEDGER_") {
			continue // never leak the caller's Ledger config into a child
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(e.Vars))
	for k := range e.Vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+e.Vars[k])
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

// Ledger runs the ledger CLI and returns combined stdout, stderr and the exit code.
func (e *Env) Ledger(args ...string) (string, string, int) {
	e.t.Helper()
	cmd := exec.Command(filepath.Join(binDir, "ledger"), args...)
	cmd.Env = e.environ(nil)
	cmd.Dir = e.Dir
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatalf("ledger %v: %v", args, err)
	}
	return so.String(), se.String(), code
}

// MustLedger runs the CLI and fails the test on a non-zero exit.
func (e *Env) MustLedger(args ...string) string {
	e.t.Helper()
	so, se, code := e.Ledger(args...)
	if code != 0 {
		e.t.Fatalf("ledger %s: exit %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, so, se)
	}
	return so
}

// PSQL runs SQL through the real psql client as the Postgres superuser, in this env's schema.
func (e *Env) PSQL(sql string) string {
	e.t.Helper()
	pu, _ := url.Parse(e.DBURL)
	q := pu.Query()
	q.Del("search_path")
	pu.RawQuery = q.Encode()
	cmd := exec.Command("psql", pu.String(), "-v", "ON_ERROR_STOP=1", "-qAt", "-f", "-")
	cmd.Env = append(os.Environ(), "PGOPTIONS=-c search_path="+e.Schema)
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("psql: %v\n%s\nSQL:\n%s", err, out, sql)
	}
	return string(out)
}

func freePort(t testing.TB) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Daemon is a running ledgerd.
type Daemon struct {
	e    *Env
	Addr string
	URL  string
	cmd  *exec.Cmd
	log  *syncBuf
	done chan struct{}
	all  *syncBuf // every run's log (for failure dumps)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Start runs ledgerd on a free port and waits for /healthz.
func (e *Env) Start() *Daemon {
	e.t.Helper()
	d := &Daemon{e: e, Addr: freePort(e.t), all: &syncBuf{}}
	d.URL = "http://" + d.Addr
	d.start()
	e.t.Cleanup(func() {
		d.Stop()
		if e.t.Failed() {
			e.t.Logf("ledgerd log (%s):\n%s", d.Addr, d.all.String())
		}
	})
	return d
}

func (d *Daemon) start() {
	t := d.e.t
	t.Helper()
	d.log = &syncBuf{}
	d.cmd = exec.Command(filepath.Join(binDir, "ledgerd"))
	d.cmd.Env = d.e.environ(map[string]string{"LEDGER_ADDR": d.Addr})
	d.cmd.Dir = d.e.Dir
	w := io.MultiWriter(d.log, d.all)
	d.cmd.Stdout, d.cmd.Stderr = w, w
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	d.done = make(chan struct{})
	go func(c *exec.Cmd, done chan struct{}) { _ = c.Wait(); close(done) }(d.cmd, d.done)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-d.done:
			t.Fatalf("ledgerd exited during startup:\n%s", d.log.String())
		default:
		}
		resp, err := http.Get(d.URL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ledgerd did not become healthy:\n%s", d.log.String())
}

// Stop sends SIGTERM (then SIGKILL) and waits; idempotent.
func (d *Daemon) Stop() {
	if d.cmd == nil || d.cmd.Process == nil {
		return
	}
	select {
	case <-d.done:
	default:
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-d.done:
		case <-time.After(10 * time.Second):
			_ = d.cmd.Process.Kill()
			<-d.done
		}
	}
	d.cmd = nil
}

// Kill stops ledgerd abruptly (SIGKILL), like a crash.
func (d *Daemon) Kill() {
	if d.cmd == nil {
		return
	}
	_ = d.cmd.Process.Kill()
	<-d.done
	d.cmd = nil
}

// Restart stops and starts ledgerd on the same address with the same environment.
func (d *Daemon) Restart() {
	d.Stop()
	d.start()
}

// Log is the current run's output.
func (d *Daemon) Log() string { return d.log.String() }

// Resp is an HTTP response.
type Resp struct {
	Status int
	Body   []byte
	Header http.Header
}

func (r Resp) JSON(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("not JSON (%d): %s", r.Status, r.Body)
	}
	return m
}

var httpc = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// Do performs a request; token may be "".
func (d *Daemon) Do(method, path, token string, body any) Resp {
	d.e.t.Helper()
	return doReq(d.e.t, method, d.URL+path, token, body)
}

func doReq(t testing.TB, method, u, token string, body any) Resp {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		t.Fatal(err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return Resp{resp.StatusCode, b, resp.Header}
}

// Actor is an actor-chain element.
type Actor = map[string]string

func human(id string) Actor { return Actor{"kind": "human", "id": id} }
func agent(id string) Actor {
	return Actor{"kind": "agent", "id": id, "model": "e2e-model", "model_version": "1"}
}

// Append posts a record and fails the test unless it gets 201 (or 200 on an idempotent retry).
func (d *Daemon) Append(token string, rec map[string]any) map[string]any {
	d.e.t.Helper()
	r := d.Do("POST", "/v1/records", token, rec)
	if r.Status != 201 && r.Status != 200 {
		d.e.t.Fatalf("append %v: %d %s", rec["type"], r.Status, r.Body)
	}
	return r.JSON(d.e.t)
}

// Records lists a chain's records (all pages).
func (d *Daemon) Records(token, chain string) []map[string]any {
	d.e.t.Helper()
	var out []map[string]any
	after := int64(-1)
	for {
		p := fmt.Sprintf("/v1/records?chain=%s&limit=1000", url.QueryEscape(chain))
		if after >= 0 {
			p += fmt.Sprintf("&after_seq=%d", after)
		}
		r := d.Do("GET", p, token, nil)
		if r.Status != 200 {
			d.e.t.Fatalf("list %s: %d %s", chain, r.Status, r.Body)
		}
		var body struct {
			Records []map[string]any `json:"records"`
		}
		if err := json.Unmarshal(r.Body, &body); err != nil {
			d.e.t.Fatal(err)
		}
		out = append(out, body.Records...)
		if len(body.Records) < 1000 {
			return out
		}
		after = int64(body.Records[len(body.Records)-1]["seq"].(float64))
	}
}

// VerifyOK asserts GET /v1/chains/{chain}/verify reports ok.
func (d *Daemon) VerifyOK(token, chain string) map[string]any {
	d.e.t.Helper()
	r := d.Do("GET", "/v1/chains/"+url.PathEscape(chain)+"/verify", token, nil)
	m := r.JSON(d.e.t)
	if r.Status != 200 || m["ok"] != true {
		d.e.t.Fatalf("verify %s: %d %s", chain, r.Status, r.Body)
	}
	return m
}

// eventually polls f until it returns "" (success) or the timeout elapses.
func eventually(t testing.TB, timeout time.Duration, f func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		if last = f(); last == "" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s: %s", timeout, last)
}

// sseClient reads Server-Sent Events.
type sseEvent struct {
	ID, Event, Data string
}

func openSSE(t testing.TB, u, token, lastID string) (<-chan sseEvent, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		t.Fatalf("SSE %s: %d %s", u, resp.StatusCode, b)
	}
	ch := make(chan sseEvent, 1000)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.Data != "" || ev.Event != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "id:"):
				ev.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			case strings.HasPrefix(line, "event:"):
				ev.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				ev.Data += strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
			}
		}
	}()
	return ch, cancel
}

// nextRecord waits for the next "record" event.
func nextRecord(t testing.TB, ch <-chan sseEvent, timeout time.Duration) (sseEvent, map[string]any) {
	t.Helper()
	tm := time.After(timeout)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("SSE stream closed")
			}
			if ev.Event != "record" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(ev.Data), &m); err != nil {
				t.Fatalf("bad SSE data %q", ev.Data)
			}
			return ev, m
		case <-tm:
			t.Fatal("timed out waiting for an SSE record")
		}
	}
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func num(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}
