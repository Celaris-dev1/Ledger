package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/keys"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

func TestAppendWithDataSubjectEncryptsAndShredsVerifiably(t *testing.T) {
	be := &memBackend{}
	ks := &keys.FileDataKeyStore{Dir: t.TempDir()}
	s := &Server{Store: be, DataKeys: ks}
	h := s.Handler()
	body := `{"chain":"clinic","type":"note.created","data_subject":"patient-1","actor_chain":[{"kind":"human","id":"dr-a"}],"payload":{"name":"Jane Doe"}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/records", strings.NewReader(body)))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	stored := be.recs[0]
	if strings.Contains(string(stored.Payload), "Jane") || !strings.Contains(string(stored.Payload), keys.EnvelopeFormat) {
		t.Fatalf("payload not encrypted: %s", stored.Payload)
	}
	pt, err := keys.Open(ks, "clinic", "note.created", stored.Payload)
	if err != nil || !strings.Contains(string(pt), "Jane") {
		t.Fatal(err)
	}
	if _, err := ks.Destroy("patient-1"); err != nil {
		t.Fatal(err)
	}
	// chain still verifies after shredding: the hash covers the ciphertext
	if v := store.VerifyRecords("clinic", be.recs); !v.OK {
		t.Fatal(v)
	}
	if _, err := keys.Open(ks, "clinic", "note.created", stored.Payload); err == nil {
		t.Fatal("plaintext recoverable after shredding")
	}
	// the erased subject cannot be written again
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/records", strings.NewReader(body)))
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	// without a key store, data_subject is refused rather than silently stored in clear
	w = httptest.NewRecorder()
	(&Server{Store: &memBackend{}}).Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/records", strings.NewReader(body)))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestRootWithECDSASigner(t *testing.T) {
	be := &memBackend{}
	_, _ = be.Append(context.Background(), store.AppendRequest{Chain: "c", Type: "t", ActorChain: []store.Actor{{Kind: "human", ID: "a"}}, Payload: json.RawMessage(`{}`)})
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &Server{Store: be, Signer: keys.ECDSASigner{Key: ec}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/chains/c/root", nil))
	var root anchor.Root
	_ = json.Unmarshal(w.Body.Bytes(), &root)
	if root.Alg != keys.AlgECDSAP256 || !anchor.VerifyRoot(root) || root.Seq != 1 {
		t.Fatalf("%+v", root)
	}
}
