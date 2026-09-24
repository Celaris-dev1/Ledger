package api

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/receiptkeys"
	"github.com/Celaris-dev1/Ledger/internal/storetest"
)

func TestReceiptKeysEndpoints(t *testing.T) {
	st := storetest.Open(t)
	h := (&Server{Store: &memBackend{}, Token: "sekret", ReceiptKeys: receiptkeys.Open(st.Pool)}).Handler()

	pub := base64.StdEncoding.EncodeToString([]byte("thirty-two-byte-ed25519-pubkey!!"))

	// Unauthenticated: 401.
	if w := do(t, h, "POST", "/v1/receipt-keys", `{}`, ""); w.Code != 401 {
		t.Fatalf("unauthenticated enroll: %d", w.Code)
	}

	// Enroll.
	body := `{"product":"gate","key_id":"gate-1","alg":"ed25519","public_key":"` + pub + `"}`
	w := do(t, h, "POST", "/v1/receipt-keys", body, "sekret")
	if w.Code != 201 {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	var enrolled receiptkeys.Key
	if err := json.Unmarshal(w.Body.Bytes(), &enrolled); err != nil || enrolled.KeyID != "gate-1" {
		t.Fatalf("enroll response: %v %s", err, w.Body.String())
	}

	// Duplicate: 409.
	if w := do(t, h, "POST", "/v1/receipt-keys", body, "sekret"); w.Code != 409 {
		t.Fatalf("duplicate enroll: %d %s", w.Code, w.Body.String())
	}

	// Bad public_key: 400.
	bad := `{"product":"gate","key_id":"gate-2","alg":"ed25519","public_key":"not base64!"}`
	if w := do(t, h, "POST", "/v1/receipt-keys", bad, "sekret"); w.Code != 400 {
		t.Fatalf("bad public_key: %d", w.Code)
	}

	// List.
	w = do(t, h, "GET", "/v1/receipt-keys", "", "sekret")
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var listed struct {
		Keys []receiptkeys.Key `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 1 {
		t.Fatalf("list response: %v %+v", err, listed)
	}

	// Revoke.
	w = do(t, h, "POST", "/v1/receipt-keys/gate-1/revoke", `{"reason":"rotated"}`, "sekret")
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}

	// Revoke unknown: 404.
	if w := do(t, h, "POST", "/v1/receipt-keys/nope/revoke", `{}`, "sekret"); w.Code != 404 {
		t.Fatalf("revoke unknown: %d", w.Code)
	}

	// Listing now shows the key revoked.
	w = do(t, h, "GET", "/v1/receipt-keys?product=gate", "", "sekret")
	listed.Keys = nil
	_ = json.Unmarshal(w.Body.Bytes(), &listed)
	if len(listed.Keys) != 1 || listed.Keys[0].RevokedAt == nil || listed.Keys[0].Reason != "rotated" {
		t.Fatalf("post-revoke list: %+v", listed)
	}
}

func TestReceiptKeysDisabled(t *testing.T) {
	h := (&Server{Store: &memBackend{}, Token: "sekret"}).Handler()
	if w := do(t, h, "GET", "/v1/receipt-keys", "", "sekret"); w.Code != 503 {
		t.Fatalf("disabled receipt-keys: %d", w.Code)
	}
}
