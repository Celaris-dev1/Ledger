package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
	"github.com/Celaris-dev1/Ledger/internal/testfix"
)

type fixture struct {
	src    *store.Store
	kr     *anchor.Keyring
	signer keys.Signer
	dir    string
	m      Manifest
}

func setup(t *testing.T) fixture {
	t.Helper()
	src := storetest.Open(t)
	ctx := context.Background()
	for _, r := range testfix.MultiProduct().Recs {
		if _, err := src.Append(ctx, testfix.Request(r)); err != nil {
			t.Fatal(err)
		}
	}
	// a tenant chain, an idempotent record and a payload with HTML-special characters
	if _, err := src.Append(ctx, store.AppendRequest{Chain: "t/acme/gate", Type: "gate.run.started", IdempotencyKey: "k-1",
		ActorChain: []store.Actor{{Kind: "human", ID: "a"}}, Payload: json.RawMessage(`{"diff":"<script>&amp;</script>"}`)}); err != nil {
		t.Fatal(err)
	}
	kr, err := anchor.OpenKeyring(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := &anchoring.Service{Store: src, Key: kr.Active, Keyring: kr, Backends: []anchoring.Backend{&anchoring.FileBackend{Dir: t.TempDir()}}}
	for _, c := range []string{"gate", "harbour"} {
		if _, err := svc.AnchorChain(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), "bk")
	signer := keys.Ed25519Signer{Key: kr.Active}
	m, err := Create(ctx, src, dir, Options{Signer: signer, Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{src, kr, signer, dir, m}
}

func trustOf(kr *anchor.Keyring) anchor.TrustSet {
	ts := anchor.TrustSet{}
	for id, p := range kr.Public {
		ts[id] = p
	}
	return ts
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if f.m.Records != 21 || len(f.m.Chains) != 7 || f.m.Receipts != 2 {
		t.Fatalf("%d records %d chains %d receipts", f.m.Records, len(f.m.Chains), f.m.Receipts)
	}
	if _, err := Record(ctx, f.src, f.m, f.dir, "ops"); err != nil {
		t.Fatal(err)
	}
	// keys.json carries public material only
	kb, _ := os.ReadFile(filepath.Join(f.dir, "keys.json"))
	seed := f.kr.Active.Seed()
	if bytes.Contains(kb, []byte(b64(seed))) || bytes.Contains(kb, []byte(b64(f.kr.Active))) {
		t.Fatal("private key in backup")
	}
	dst := storetest.Open(t)
	L, err := Restore(ctx, dst, f.dir, VerifyOptions{Trust: trustOf(f.kr)})
	if err != nil {
		t.Fatal(err)
	}
	// file receipts verify fully and the manifest key is trusted: nothing to warn about
	if len(L.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", L.Warnings)
	}
	for _, c := range f.m.Chains {
		a, _ := f.src.ChainRecords(ctx, c.Name)
		b, _ := dst.ChainRecords(ctx, c.Name)
		if c.Name == "ledger" {
			a = a[:len(b)] // the backup record was appended after the snapshot
		}
		if len(a) != len(b) {
			t.Fatalf("%s: %d vs %d", c.Name, len(a), len(b))
		}
		for i := range a {
			ja, _ := json.Marshal(a[i])
			jb, _ := json.Marshal(b[i])
			if !bytes.Equal(ja, jb) {
				t.Fatalf("%s/%d differs:\n%s\n%s", c.Name, i+1, ja, jb)
			}
		}
		if v, _ := dst.Verify(ctx, c.Name); !v.OK {
			t.Fatal(v)
		}
	}
	// tenant column rebuilt by the trigger; anchors re-verify in the restored database
	ten, _ := dst.ListTenant(ctx, "acme", store.Query{})
	if len(ten) != 1 || !strings.Contains(string(ten[0].Payload), "<script>") {
		t.Fatalf("%+v", ten)
	}
	svc := &anchoring.Service{Store: dst, Keyring: f.kr}
	rep, err := svc.VerifyChainAnchors(ctx, "gate")
	if err != nil || !rep.OK || len(rep.Checks) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	// restoring again is a conflict, never a merge
	if _, err := Restore(ctx, dst, f.dir, VerifyOptions{Trust: trustOf(f.kr)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	// verify-only (Load) also works without trust, with a warning
	L2, err := Load(f.dir, VerifyOptions{})
	if err != nil || len(L2.Warnings) == 0 {
		t.Fatal(err)
	}
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy")
	_ = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	return dst
}

func resign(t *testing.T, dir string, s keys.Signer, edit func(m *Manifest)) {
	t.Helper()
	var m Manifest
	b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	_ = json.Unmarshal(b, &m)
	for i, fe := range m.Files {
		h, n, _ := fileHash(filepath.Join(dir, fe.Path))
		m.Files[i].SHA256, m.Files[i].Bytes = h, n
	}
	if edit != nil {
		edit(&m)
	}
	m.ManifestHash, _ = manifestHash(m)
	sig, _ := keys.SignDetached(context.Background(), s, []byte(SignaturePrefix+m.ManifestHash))
	m.Signature = &sig
	b, _ = json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644)
}

func TestRestoreRejectsTampering(t *testing.T) {
	f := setup(t)
	trust := VerifyOptions{Trust: trustOf(f.kr)}
	gateFile := ""
	for _, c := range f.m.Chains {
		if c.Name == "gate" {
			gateFile = c.File
		}
	}
	edit := func(dir string) {
		p := filepath.Join(dir, gateFile)
		b, _ := os.ReadFile(p)
		b = bytes.Replace(b, []byte(`"stage":"security","status":"fail"`), []byte(`"stage":"security","status":"pass"`), 1)
		_ = os.WriteFile(p, b, 0o644)
	}
	cases := []struct {
		name string
		mut  func(dir string)
		want string
	}{
		{"edited record, manifest untouched", edit, "altered"},
		{"edited record, manifest re-hashed but not re-signed", func(dir string) {
			edit(dir)
			var m Manifest
			b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
			_ = json.Unmarshal(b, &m)
			for i, fe := range m.Files {
				m.Files[i].SHA256, m.Files[i].Bytes, _ = fileHash(filepath.Join(dir, fe.Path))
			}
			m.ManifestHash, _ = manifestHash(m)
			b, _ = json.Marshal(m)
			_ = os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644)
		}, "signature"},
		{"edited record, re-signed by an attacker key", func(dir string) {
			edit(dir)
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			resign(t, dir, keys.Ed25519Signer{Key: k}, nil)
		}, "untrusted key"},
		{"edited record, re-signed by the real key (stolen): hash chain catches it", func(dir string) {
			edit(dir)
			resign(t, dir, f.signer, nil)
		}, "does not verify"},
		{"history rewritten and re-signed with the real key: anchors catch it", func(dir string) {
			// drop the last gate record and fix up heads: the chain verifies, but the anchored head is gone
			p := filepath.Join(dir, gateFile)
			b, _ := os.ReadFile(p)
			lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
			var last store.Record
			_ = json.Unmarshal(lines[len(lines)-2], &last)
			_ = os.WriteFile(p, append(bytes.Join(lines[:len(lines)-1], []byte("\n")), '\n'), 0o644)
			fix := func(cs []ChainHead) {
				for i := range cs {
					if cs[i].Name == "gate" {
						cs[i].HeadSeq, cs[i].Head = last.Seq, last.Hash
					}
				}
			}
			var heads []ChainHead
			hb, _ := os.ReadFile(filepath.Join(dir, "chains.json"))
			_ = json.Unmarshal(hb, &heads)
			fix(heads)
			hb, _ = json.Marshal(heads)
			_ = os.WriteFile(filepath.Join(dir, "chains.json"), append(hb, '\n'), 0o644)
			resign(t, dir, f.signer, func(m *Manifest) { fix(m.Chains); m.Records-- })
		}, "anchor receipts of gate"},
		{"extra file smuggled in", func(dir string) { _ = os.WriteFile(filepath.Join(dir, "evil.jsonl"), []byte("{}"), 0o644) }, "unlisted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyDir(t, f.dir)
			c.mut(dir)
			dst := storetest.Open(t)
			_, err := Restore(context.Background(), dst, dir, trust)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
			var n int
			_ = dst.Pool.QueryRow(context.Background(), `SELECT count(*) FROM records`).Scan(&n)
			if n != 0 {
				t.Fatal("rejected backup partially restored")
			}
		})
	}
}
