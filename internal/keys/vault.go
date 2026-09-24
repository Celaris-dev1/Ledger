package keys

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var randReader io.Reader = rand.Reader

// VaultTransit signs with a HashiCorp Vault Transit key (type ed25519 or ecdsa-p256) over the
// plain HTTP API. The private key never leaves Vault.
//
//	GET  {addr}/v1/{mount}/keys/{name}               -> public key of latest_version
//	POST {addr}/v1/{mount}/sign/{name}/sha2-256      {"input": b64(msg)} -> "vault:vN:b64sig"
type VaultTransit struct {
	Addr      string // e.g. https://vault.example:8200
	Token     string
	Namespace string // optional (Vault Enterprise)
	Mount     string // default "transit"
	KeyName   string
	Client    *http.Client

	alg     string
	pub     []byte
	version int
}

// NewVaultTransit fetches the key's public half and algorithm.
func NewVaultTransit(ctx context.Context, v *VaultTransit) (*VaultTransit, error) {
	if v.Mount == "" {
		v.Mount = "transit"
	}
	if v.Client == nil {
		v.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if v.Addr == "" || v.KeyName == "" {
		return nil, errors.New("vault: address and key name are required")
	}
	var out struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := v.do(ctx, http.MethodGet, "keys/"+v.KeyName, nil, &out); err != nil {
		return nil, err
	}
	k, ok := out.Data.Keys[strconv.Itoa(out.Data.LatestVersion)]
	if !ok {
		return nil, fmt.Errorf("vault: key %s has no version %d", v.KeyName, out.Data.LatestVersion)
	}
	v.version = out.Data.LatestVersion
	switch out.Data.Type {
	case "ed25519":
		b, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(b) != 32 {
			return nil, errors.New("vault: malformed ed25519 public key")
		}
		v.alg, v.pub = AlgEd25519, b
	case "ecdsa-p256":
		blk, _ := pem.Decode([]byte(k.PublicKey))
		if blk == nil {
			return nil, errors.New("vault: malformed ecdsa public key PEM")
		}
		if _, err := ParseECDSAPublic(blk.Bytes); err != nil {
			return nil, err
		}
		v.alg, v.pub = AlgECDSAP256, blk.Bytes
	default:
		return nil, fmt.Errorf("vault: key type %q cannot sign ledger roots (use ed25519 or ecdsa-p256)", out.Data.Type)
	}
	return v, nil
}

func (v *VaultTransit) Algorithm() string { return v.alg }
func (v *VaultTransit) PublicKey() []byte { return v.pub }
func (v *VaultTransit) KeyID() string     { return KeyIDFor(v.alg, v.pub) }

// Sign asks Vault to sign msg; for ecdsa-p256 Vault hashes with SHA-256 and returns ASN.1 DER.
func (v *VaultTransit) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	body := map[string]any{"input": base64.StdEncoding.EncodeToString(msg), "key_version": v.version}
	if v.alg == AlgECDSAP256 {
		body["marshaling_algorithm"] = "asn1"
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := v.do(ctx, http.MethodPost, "sign/"+v.KeyName+"/sha2-256", body, &out); err != nil {
		return nil, err
	}
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, errors.New("vault: unexpected signature format")
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault: signature: %w", err)
	}
	if err := VerifySignature(v.alg, v.pub, msg, sig); err != nil {
		return nil, fmt.Errorf("vault: returned signature does not verify: %w", err)
	}
	return sig, nil
}

func (v *VaultTransit) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(v.Addr, "/")+"/v1/"+v.Mount+"/"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("vault: %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("vault: decode: %w", err)
	}
	return nil
}
