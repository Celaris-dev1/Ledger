package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/keys"
)

func testEnv(t *testing.T) Envelope {
	t.Helper()
	ph, err := PayloadHash(map[string]any{"decision": "allow", "run_id": "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{
		Version:     Version,
		Product:     "gate",
		Kind:        "gate.verdict",
		GoalID:      "goal-1",
		Actors:      []Actor{{Kind: "human", ID: "alice"}, {Kind: "agent", ID: "gate-ci", Model: "gate"}},
		Subject:     "run-1",
		PayloadHash: ph,
		Links:       []Link{{Product: "warrant", ID: "tok-1", Hash: ph}},
		IssuedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// fixedRand is a deterministic io.Reader so generated test vectors are reproducible.
type fixedRand struct{ seed byte }

func (r *fixedRand) Read(p []byte) (int, error) {
	for i := range p {
		r.seed = r.seed*31 + 7
		p[i] = r.seed
	}
	return len(p), nil
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := keys.Ed25519Signer{Key: priv}
	env, err := Sign(context.Background(), s, testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, "ed25519", pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsTamperedPayloadHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := keys.Ed25519Signer{Key: priv}
	env, _ := Sign(context.Background(), s, testEnv(t))
	tampered := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if tampered == env.PayloadHash {
		tampered = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	}
	env.PayloadHash = tampered
	if err := Verify(env, "ed25519", pub); err == nil {
		t.Fatal("expected verify to fail on tampered payload_hash")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	s := keys.Ed25519Signer{Key: priv}
	env, _ := Sign(context.Background(), s, testEnv(t))
	if err := Verify(env, "ed25519", otherPub); err == nil {
		t.Fatal("expected verify to fail with wrong key")
	}
}

func TestValidateStructureRejectsBadActorChain(t *testing.T) {
	env := testEnv(t)
	env.Actors = []Actor{{Kind: "agent", ID: "bot"}}
	if err := validateStructure(env); err == nil {
		t.Fatal("expected error: actor_chain must start with human")
	}
}

func TestValidateStructureRejectsUnknownProduct(t *testing.T) {
	env := testEnv(t)
	env.Product = "spreadsheet"
	if err := validateStructure(env); err == nil {
		t.Fatal("expected error: unknown product")
	}
}

// TestConformanceVectors regenerates testdata/receipts (valid/ and invalid/) from a fixed,
// deterministic key so this repo's copy and every other product's copy validate against
// byte-identical fixtures. It always runs (fast, deterministic) so the checked-in vectors
// never drift from what this package actually accepts.
func TestConformanceVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "receipts")
	if err := os.MkdirAll(filepath.Join(dir, "valid"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "invalid"), 0o755); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(&fixedRand{seed: 42})
	if err != nil {
		t.Fatal(err)
	}
	s := keys.Ed25519Signer{Key: priv}
	write := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("valid/key.json", map[string]string{"algorithm": "ed25519", "public_key": b64(pub), "key_id": s.KeyID()})

	env1, err := Sign(context.Background(), s, testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	write("valid/gate-verdict.json", env1)

	env2 := testEnv(t)
	env2.Product, env2.Kind, env2.Subject, env2.Links = "warrant", "warrant.decision", "tok-1", nil
	env2, err = Sign(context.Background(), s, env2)
	if err != nil {
		t.Fatal(err)
	}
	write("valid/warrant-decision.json", env2)

	bad1 := env1
	bad1.Signature = flipLastByte(env1.Signature)
	write("invalid/bad-signature.json", bad1)

	bad2 := env1
	bad2.Version = "stack-receipt/v0"
	write("invalid/bad-version.json", bad2)

	bad3 := env1
	bad3.Actors = []Actor{{Kind: "agent", ID: "bot"}}
	write("invalid/missing-human-actor.json", bad3)

	bad4 := env1
	bad4.PayloadHash = "not-hex"
	write("invalid/malformed-payload-hash.json", bad4)

	// Sanity: every "valid" fixture we just wrote actually verifies, and every "invalid" one
	// fails, using only what's on disk plus valid/key.json — this is what other products'
	// emitter tests do against their copies.
	assertVector(t, filepath.Join(dir, "valid", "gate-verdict.json"), pub, true)
	assertVector(t, filepath.Join(dir, "valid", "warrant-decision.json"), pub, true)
	assertVector(t, filepath.Join(dir, "invalid", "bad-signature.json"), pub, false)
	assertVector(t, filepath.Join(dir, "invalid", "bad-version.json"), pub, false)
	assertVector(t, filepath.Join(dir, "invalid", "missing-human-actor.json"), pub, false)
	assertVector(t, filepath.Join(dir, "invalid", "malformed-payload-hash.json"), pub, false)
}

func assertVector(t *testing.T, path string, pub ed25519.PublicKey, wantOK bool) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		if wantOK {
			t.Fatalf("%s: unmarshal: %v", path, err)
		}
		return
	}
	err = Verify(env, "ed25519", pub)
	if wantOK && err != nil {
		t.Errorf("%s: expected valid, got %v", path, err)
	}
	if !wantOK && err == nil {
		t.Errorf("%s: expected invalid, but verified OK", path)
	}
}

func flipLastByte(s string) string {
	b := []byte(s)
	if len(b) == 0 {
		return s
	}
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}
