package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Celaris-dev1/Ledger/internal/auth"
	"github.com/Celaris-dev1/Ledger/internal/receiptkeys"
)

// Operator-only management of the stack-receipt/v1 trust keyring (see internal/receiptkeys):
//
//	POST   /v1/receipt-keys              enroll a product's receipt-signing public key
//	GET    /v1/receipt-keys?product=P    list enrolled keys (optionally filtered by product)
//	POST   /v1/receipt-keys/{key_id}/revoke   revoke a key
//
// All three require PermAdmin: enrolling or revoking a trusted signer is a security-sensitive
// operation, same tier as issuing/revoking an API token.
func (s *Server) registerReceiptKeys(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/receipt-keys", s.guard(auth.PermAdmin, s.enrollReceiptKey))
	mux.HandleFunc("GET /v1/receipt-keys", s.guard(auth.PermAdmin, s.listReceiptKeys))
	mux.HandleFunc("POST /v1/receipt-keys/{key_id}/revoke", s.guard(auth.PermAdmin, s.revokeReceiptKey))
}

func (s *Server) rkStore() *receiptkeys.Store {
	return s.ReceiptKeys
}

type enrollReceiptKeyRequest struct {
	Product   string `json:"product"`
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"` // base64
}

func (s *Server) enrollReceiptKey(w http.ResponseWriter, r *http.Request) {
	rk := s.rkStore()
	if rk == nil {
		writeErr(w, http.StatusServiceUnavailable, "receipt-key enrollment is not enabled on this server")
		return
	}
	var req enrollReceiptKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.maxBody())).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed JSON body: "+err.Error())
		return
	}
	if req.Alg == "" {
		req.Alg = "ed25519"
	}
	if _, err := base64.StdEncoding.DecodeString(req.PublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "public_key must be base64")
		return
	}
	operator := ""
	if p := auth.FromContext(r.Context()); p != nil {
		operator = p.Label()
	}
	k, err := rk.Enroll(r.Context(), tenantOf(r), receiptkeys.Key{
		Product: req.Product, KeyID: req.KeyID, Alg: req.Alg, PublicKey: req.PublicKey, EnrolledBy: operator,
	})
	if err != nil {
		if err == receiptkeys.ErrExists {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, k)
}

func (s *Server) listReceiptKeys(w http.ResponseWriter, r *http.Request) {
	rk := s.rkStore()
	if rk == nil {
		writeErr(w, http.StatusServiceUnavailable, "receipt-key enrollment is not enabled on this server")
		return
	}
	ks, err := rk.List(r.Context(), tenantOf(r), r.URL.Query().Get("product"))
	if err != nil {
		s.internal(w, err)
		return
	}
	if ks == nil {
		ks = []receiptkeys.Key{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": ks})
}

type revokeReceiptKeyRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) revokeReceiptKey(w http.ResponseWriter, r *http.Request) {
	rk := s.rkStore()
	if rk == nil {
		writeErr(w, http.StatusServiceUnavailable, "receipt-key enrollment is not enabled on this server")
		return
	}
	keyID := r.PathValue("key_id")
	var req revokeReceiptKeyRequest
	if r.ContentLength != 0 {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, s.maxBody())).Decode(&req)
	}
	if err := rk.Revoke(r.Context(), tenantOf(r), keyID, req.Reason); err != nil {
		if err == receiptkeys.ErrNotFound {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// tenantOf returns the request's tenant scope if multi-tenancy middleware set one (via
// context.WithValue(tenantKey{}, ...) in guard), else the default tenant.
func tenantOf(r *http.Request) string {
	if t, ok := r.Context().Value(tenantKey{}).(string); ok && t != "" {
		return t
	}
	return receiptkeys.DefaultTenant
}
