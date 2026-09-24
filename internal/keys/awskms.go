package keys

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWSKMS signs with an AWS KMS asymmetric key (KeySpec ECC_NIST_P256, usage SIGN_VERIFY) using
// raw SigV4-signed HTTP calls to the KMS JSON API (no AWS SDK dependency). KMS does not offer
// Ed25519 signing, so KMS-held roots are ECDSA P-256; verifiers accept both algorithms.
type AWSKMS struct {
	Region       string
	KeyRef       string // key id, ARN or alias/...
	AccessKey    string
	SecretKey    string
	SessionToken string // optional
	Endpoint     string // default https://kms.{region}.amazonaws.com (override for tests / VPC endpoints)
	Client       *http.Client
	Now          func() time.Time

	pub []byte
}

// NewAWSKMS fetches and checks the public key (GetPublicKey).
func NewAWSKMS(ctx context.Context, k *AWSKMS) (*AWSKMS, error) {
	if k.Region == "" || k.KeyRef == "" || k.AccessKey == "" || k.SecretKey == "" {
		return nil, errors.New("awskms: region, key id and credentials are required")
	}
	if k.Endpoint == "" {
		k.Endpoint = "https://kms." + k.Region + ".amazonaws.com"
	}
	if k.Client == nil {
		k.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if k.Now == nil {
		k.Now = time.Now
	}
	var out struct {
		PublicKey         string   `json:"PublicKey"`
		KeySpec           string   `json:"KeySpec"`
		KeyUsage          string   `json:"KeyUsage"`
		SigningAlgorithms []string `json:"SigningAlgorithms"`
	}
	if err := k.call(ctx, "GetPublicKey", map[string]any{"KeyId": k.KeyRef}, &out); err != nil {
		return nil, err
	}
	if out.KeySpec != "ECC_NIST_P256" || out.KeyUsage != "SIGN_VERIFY" {
		return nil, fmt.Errorf("awskms: key must be ECC_NIST_P256/SIGN_VERIFY, got %s/%s", out.KeySpec, out.KeyUsage)
	}
	der, err := base64.StdEncoding.DecodeString(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: public key: %w", err)
	}
	if _, err := ParseECDSAPublic(der); err != nil {
		return nil, err
	}
	k.pub = der
	return k, nil
}

func (k *AWSKMS) Algorithm() string { return AlgECDSAP256 }
func (k *AWSKMS) PublicKey() []byte { return k.pub }
func (k *AWSKMS) KeyID() string     { return KeyIDFor(AlgECDSAP256, k.pub) }

// Sign calls KMS Sign with MessageType RAW and ECDSA_SHA_256 (KMS hashes the message).
func (k *AWSKMS) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"Signature"`
	}
	if err := k.call(ctx, "Sign", map[string]any{"KeyId": k.KeyRef, "Message": base64.StdEncoding.EncodeToString(msg),
		"MessageType": "RAW", "SigningAlgorithm": "ECDSA_SHA_256"}, &out); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("awskms: signature: %w", err)
	}
	if err := VerifySignature(AlgECDSAP256, k.pub, msg, sig); err != nil {
		return nil, fmt.Errorf("awskms: returned signature does not verify: %w", err)
	}
	return sig, nil
}

func (k *AWSKMS) call(ctx context.Context, action string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.Endpoint+"/", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+action)
	if k.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", k.SessionToken)
	}
	SignV4(req, b, Credentials{k.AccessKey, k.SecretKey}, k.Region, "kms", k.Now())
	resp, err := k.Client.Do(req)
	if err != nil {
		return fmt.Errorf("awskms: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("awskms: %s: HTTP %d: %s", action, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return json.Unmarshal(rb, out)
}

// ---- SigV4 ----

// Credentials are AWS access keys.
type Credentials struct{ AccessKey, SecretKey string }

func sha256hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func uriEncode(s string, path bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || (path && c == '/') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// CanonicalRequest builds the SigV4 canonical request and the signed-headers list.
func CanonicalRequest(req *http.Request, body []byte) (string, string) {
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	// canonical query
	q := req.URL.Query()
	qk := make([]string, 0, len(q))
	for k := range q {
		qk = append(qk, k)
	}
	sort.Strings(qk)
	var qs []string
	for _, k := range qk {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			qs = append(qs, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	// canonical headers: host + every header we set
	hdr := map[string]string{"host": req.Host}
	if hdr["host"] == "" {
		hdr["host"] = req.URL.Host
	}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "user-agent" {
			continue
		}
		hdr[lk] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
	}
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + hdr[n] + "\n")
	}
	signed := strings.Join(names, ";")
	return strings.Join([]string{req.Method, path, strings.Join(qs, "&"), ch.String(), signed, sha256hex(body)}, "\n"), signed
}

// SignV4 adds X-Amz-Date and Authorization headers to req.
func SignV4(req *http.Request, body []byte, c Credentials, region, service string, now time.Time) {
	t := now.UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	creq, signed := CanonicalRequest(req, body)
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256hex([]byte(creq))
	k := hmacSHA256([]byte("AWS4"+c.SecretKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", c.AccessKey, scope, signed, sig))
}
