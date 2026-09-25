package archive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/license"
	"github.com/Celaris-dev1/Ledger/internal/store"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

// installDevLicense unlocks Enterprise features for this test process, the same way other
// Enterprise-gated packages do (see internal/license/license_test.go, internal/compliance).
func installDevLicense(t *testing.T) {
	t.Helper()
	license.TrustDevKeyForTesting()
	lic := &license.License{
		LicenseID: "test", Customer: "Test Co", Product: "ledger", Edition: license.EditionEnterprise,
		Seats: 10, IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	tok, err := license.Sign(license.DevSigner(), lic)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEDGER_LICENSE", tok)
	t.Setenv("LEDGER_LICENSE_FILE", "")
	license.Reload()
	t.Cleanup(func() { license.Reload() })
}

func TestRunRequiresLicense(t *testing.T) {
	t.Setenv("LEDGER_LICENSE", "")
	t.Setenv("LEDGER_LICENSE_FILE", "")
	license.Reload()
	t.Cleanup(func() { license.Reload() })

	svc := &Service{}
	if _, err := svc.Run(context.Background(), nil); err == nil {
		t.Fatal("expected archive.Run to require a license")
	}
	if _, err := svc.Verify(context.Background(), nil); err == nil {
		t.Fatal("expected archive.Verify to require a license")
	}
}

func TestLocalKeyFileWrapUnwrap(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "archive.key")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, []byte(b64Encode(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEDGER_ARCHIVE_KEY_FILE", keyPath)
	lk, ok, err := LocalKeyFileFromEnv(os.Getenv)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}

	plaintext := []byte("a sealed bundle's bytes")
	enc, err := Seal(lk, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(enc) {
		t.Fatal("expected Seal output to look like an envelope")
	}
	dec, err := Open(lk, enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(plaintext) {
		t.Fatalf("got %q want %q", dec, plaintext)
	}

	// A different key must not open it.
	other := filepath.Join(dir, "other.key")
	otherKey := make([]byte, 32)
	otherKey[0] = 0xff
	os.WriteFile(other, []byte(b64Encode(otherKey)), 0o600)
	lk2 := &LocalKeyFile{Path: other}
	if _, err := Open(lk2, enc); err == nil {
		t.Fatal("expected decrypt failure with the wrong key")
	}
}

func TestLocalKeyFileFromEnvUnset(t *testing.T) {
	t.Setenv("LEDGER_ARCHIVE_KEY_FILE", "")
	_, ok, err := LocalKeyFileFromEnv(os.Getenv)
	if err != nil || ok {
		t.Fatalf("expected ok=false err=nil for unset env, got ok=%v err=%v", ok, err)
	}
}

func TestS3ConfigFromEnv(t *testing.T) {
	for _, k := range []string{"LEDGER_ARCHIVE_S3_ENDPOINT", "LEDGER_ARCHIVE_S3_BUCKET", "LEDGER_ARCHIVE_S3_REGION", "LEDGER_ARCHIVE_S3_ACCESS_KEY_ID", "LEDGER_ARCHIVE_S3_SECRET_ACCESS_KEY", "LEDGER_ARCHIVE_S3_PATH_STYLE"} {
		t.Setenv(k, "")
	}
	if _, ok, err := S3ConfigFromEnv(os.Getenv); ok || err != nil {
		t.Fatalf("expected unconfigured, got ok=%v err=%v", ok, err)
	}

	t.Setenv("LEDGER_ARCHIVE_S3_ENDPOINT", "http://127.0.0.1:9000")
	t.Setenv("LEDGER_ARCHIVE_S3_BUCKET", "b")
	if _, _, err := S3ConfigFromEnv(os.Getenv); err == nil {
		t.Fatal("expected error: missing access/secret key")
	}

	t.Setenv("LEDGER_ARCHIVE_S3_ACCESS_KEY_ID", "ak")
	t.Setenv("LEDGER_ARCHIVE_S3_SECRET_ACCESS_KEY", "sk")
	t.Setenv("LEDGER_ARCHIVE_S3_PATH_STYLE", "1")
	cfg, ok, err := S3ConfigFromEnv(os.Getenv)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !cfg.PathStyle || cfg.Region != "us-east-1" {
		t.Fatalf("cfg=%+v", cfg)
	}
}

// TestArchiveRunAndVerify exercises the full flow end-to-end: append records to a real
// Postgres-backed store (skipped cleanly if LEDGER_TEST_DATABASE_URL is unset), seal them with
// archive.Run into a fake S3 with Object Lock, and confirm archive.Verify finds them all good
// and confirm it detects a segment that a tamper (bypassing Object Lock server-side) corrupts,
// plus a chain that was never archived.
func TestArchiveRunAndVerify(t *testing.T) {
	installDevLicense(t)
	st := storetest.Open(t)
	ctx := context.Background()

	appendRecords := func(chain string, n int) {
		for i := 0; i < n; i++ {
			if _, err := st.Append(ctx, store.AppendRequest{
				Chain: chain, Type: "test.record",
				ActorChain: []store.Actor{{Kind: "human", ID: "tester"}},
				Payload:    json.RawMessage(`{"i":` + itoaTest(i) + `}`),
			}); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
	}
	appendRecords("chain-a", 5)
	appendRecords("chain-b", 3)

	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	c := f.client(true)

	signer := keys.Ed25519Signer{Key: testEd25519Key(t)}

	svc := &Service{Store: st, S3: c, Signer: signer, LockMode: LockCompliance}
	segs, err := svc.Run(ctx, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(segs) != 2 {
		t.Fatalf("got %d segments, want 2", len(segs))
	}
	for _, s := range segs {
		if s.RetainUntil.Before(time.Now().Add(24 * time.Hour)) {
			t.Fatalf("segment %s retain-until %s looks too short for the 6-month default", s.Key, s.RetainUntil)
		}
	}

	rep, err := svc.Verify(ctx, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected clean verify, got %+v", rep)
	}
	for _, name := range []string{"chain-a", "chain-b"} {
		cv := rep.Chains[name]
		if !cv.OK || cv.SegmentsFound != 1 || len(cv.MissingRanges) != 0 {
			t.Fatalf("chain %s: %+v", name, cv)
		}
	}

	// Append more records to chain-a without re-archiving: Verify should now report a missing
	// range for the unarchived tail.
	appendRecords("chain-a", 2)
	rep2, err := svc.Verify(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.OK {
		t.Fatal("expected verify to catch the unarchived tail of chain-a")
	}
	if len(rep2.Chains["chain-a"].MissingRanges) == 0 {
		t.Fatal("expected a missing range for chain-a's new records")
	}

	// Simulate detection of a corrupted/overwritten object: directly mutate the fake's stored
	// bytes for chain-b's segment (Object Lock blocks this over the wire; a compromised or
	// misconfigured bucket-side actor doing it anyway is exactly what Verify must still catch).
	f.mu.Lock()
	for k, obj := range f.objects {
		if len(k) > 7 && k[:7] == "chain-b" {
			obj.body[len(obj.body)/2] ^= 0xff
		}
	}
	f.mu.Unlock()
	rep3, err := svc.Verify(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep3.OK || rep3.Chains["chain-b"].OK {
		t.Fatal("expected verify to detect the corrupted chain-b segment")
	}
	if len(rep3.Chains["chain-b"].SegmentsBad) == 0 {
		t.Fatal("expected chain-b's corrupted segment to be listed as bad")
	}
}

// TestArchiveRunEncrypted checks that segments round-trip through envelope encryption end to
// end, and that Verify without the key source fails closed instead of silently skipping them.
func TestArchiveRunEncrypted(t *testing.T) {
	installDevLicense(t)
	st := storetest.Open(t)
	ctx := context.Background()

	if _, err := st.Append(ctx, store.AppendRequest{
		Chain: "secret-chain", Type: "test.record",
		ActorChain: []store.Actor{{Kind: "human", ID: "tester"}},
		Payload:    json.RawMessage(`{"x":1}`),
	}); err != nil {
		t.Fatal(err)
	}

	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	c := f.client(true)

	dir := t.TempDir()
	keyPath := dir + "/archive.key"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	os.WriteFile(keyPath, []byte(b64Encode(key)), 0o600)
	lk := &LocalKeyFile{Path: keyPath}

	svc := &Service{Store: st, S3: c, KeySource: lk, LockMode: LockCompliance}
	segs, err := svc.Run(ctx, []string{"secret-chain"})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || !segs[0].Encrypted {
		t.Fatalf("expected 1 encrypted segment, got %+v", segs)
	}

	raw, err := c.Get(ctx, segs[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEnvelope(raw) {
		t.Fatal("expected the uploaded object to be an envelope, not a plain bundle")
	}

	// Verify with the key configured succeeds.
	rep, err := svc.Verify(ctx, []string{"secret-chain"})
	if err != nil || !rep.OK {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}

	// Verify without the key source fails closed rather than silently treating the segment as
	// missing or, worse, as verified.
	svc2 := &Service{Store: st, S3: c, LockMode: LockCompliance}
	rep2, err := svc2.Verify(ctx, []string{"secret-chain"})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.OK {
		t.Fatal("expected verify without the archive key to fail closed on an encrypted segment")
	}
}

func itoaTest(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func testEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
