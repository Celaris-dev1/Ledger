package receiptkeys

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestEnrollListRevoke(t *testing.T) {
	st := storetest.Open(t)
	rk := Open(st.Pool)
	ctx := t.Context()

	if _, err := rk.Enroll(ctx, "", Key{KeyID: "gate-1", Product: "gate", Alg: "ed25519", PublicKey: b64("pubkey-bytes-32-long-aaaaaaaaaa"), EnrolledBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	if _, err := rk.Enroll(ctx, "", Key{KeyID: "proof-1", Product: "proof", Alg: "ed25519", PublicKey: b64("pubkey-bytes-32-long-bbbbbbbbbb")}); err != nil {
		t.Fatal(err)
	}

	// Duplicate key id rejected.
	if _, err := rk.Enroll(ctx, "", Key{KeyID: "gate-1", Product: "gate", Alg: "ed25519", PublicKey: b64("x")}); err != ErrExists {
		t.Fatalf("duplicate enroll: got %v, want ErrExists", err)
	}

	ks, err := rk.List(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 2 {
		t.Fatalf("List() = %d keys, want 2", len(ks))
	}

	gate, err := rk.List(ctx, "", "gate")
	if err != nil {
		t.Fatal(err)
	}
	if len(gate) != 1 || gate[0].KeyID != "gate-1" {
		t.Fatalf("List(product=gate) = %+v", gate)
	}

	// Unenrolled key: unknown -> not trusted.
	if _, _, ok := rk.Trust(ctx, "")("nope", time.Now()); ok {
		t.Error("unknown key reported trusted")
	}

	// Enrolled, unrevoked -> trusted:true.
	alg, pub, ok := rk.Trust(ctx, "")("gate-1", time.Now())
	if !ok || alg != "ed25519" || string(pub) != "pubkey-bytes-32-long-aaaaaaaaaa" {
		t.Fatalf("Trust(gate-1) = alg=%q pub=%q ok=%v", alg, pub, ok)
	}

	// Revoke, then check revocation-time semantics: a receipt issued before revocation stays
	// trusted, one issued after does not.
	before := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	if err := rk.Revoke(ctx, "", "gate-1", "compromised"); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()

	if _, _, ok := rk.Trust(ctx, "")("gate-1", before); !ok {
		t.Error("receipt issued before revocation should still be trusted")
	}
	if _, _, ok := rk.Trust(ctx, "")("gate-1", after); ok {
		t.Error("receipt issued after revocation should not be trusted")
	}
	if _, _, ok := rk.Trust(ctx, "")("gate-1", time.Time{}); ok {
		t.Error("zero issuedAt (treated as now) should not trust a revoked key")
	}

	// Revoking an unknown key id fails.
	if err := rk.Revoke(ctx, "", "does-not-exist", "x"); err != ErrNotFound {
		t.Fatalf("revoke unknown: got %v, want ErrNotFound", err)
	}

	// Other product's key unaffected.
	if _, _, ok := rk.Trust(ctx, "")("proof-1", time.Now()); !ok {
		t.Error("proof-1 should still be trusted")
	}

	// Revoked key still shows up in List with revoked_at/reason set.
	ks, err = rk.List(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, k := range ks {
		if k.KeyID == "gate-1" {
			found = true
			if k.RevokedAt == nil || k.Reason != "compromised" {
				t.Errorf("revoked key metadata: %+v", k)
			}
		}
	}
	if !found {
		t.Error("revoked key missing from List")
	}
}

func TestEnrollValidation(t *testing.T) {
	st := storetest.Open(t)
	rk := Open(st.Pool)
	ctx := t.Context()

	cases := []Key{
		{KeyID: "", Product: "gate", Alg: "ed25519", PublicKey: b64("x")},
		{KeyID: "k1", Product: "", Alg: "ed25519", PublicKey: b64("x")},
		{KeyID: "k1", Product: "gate", Alg: "not-an-alg", PublicKey: b64("x")},
		{KeyID: "k1", Product: "gate", Alg: "ed25519", PublicKey: "not-base64!!"},
	}
	for i, c := range cases {
		if _, err := rk.Enroll(ctx, "", c); err == nil {
			t.Errorf("case %d: expected error, got none", i)
		}
	}
}

func TestTenantIsolation(t *testing.T) {
	st := storetest.Open(t)
	rk := Open(st.Pool)
	ctx := t.Context()

	if _, err := rk.Enroll(ctx, "acme", Key{KeyID: "shared-id", Product: "gate", Alg: "ed25519", PublicKey: b64("acme-key")}); err != nil {
		t.Fatal(err)
	}
	if _, err := rk.Enroll(ctx, "globex", Key{KeyID: "shared-id", Product: "gate", Alg: "ed25519", PublicKey: b64("globex-key")}); err != nil {
		t.Fatal(err) // same key id, different tenant: allowed
	}

	_, pub, ok := rk.Trust(ctx, "acme")("shared-id", time.Now())
	if !ok || string(pub) != "acme-key" {
		t.Fatalf("acme trust: pub=%q ok=%v", pub, ok)
	}
	_, pub, ok = rk.Trust(ctx, "globex")("shared-id", time.Now())
	if !ok || string(pub) != "globex-key" {
		t.Fatalf("globex trust: pub=%q ok=%v", pub, ok)
	}

	// Revoking in one tenant doesn't affect the other.
	if err := rk.Revoke(ctx, "acme", "shared-id", "x"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := rk.Trust(ctx, "acme")("shared-id", time.Now()); ok {
		t.Error("acme key should be revoked")
	}
	if _, _, ok := rk.Trust(ctx, "globex")("shared-id", time.Now()); !ok {
		t.Error("globex key should be unaffected by acme's revocation")
	}
}
