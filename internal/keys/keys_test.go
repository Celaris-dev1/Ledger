package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeVault implements the two Transit endpoints Ledger uses.
func fakeVault(t *testing.T, typ string) (*httptest.Server, *int) {
	t.Helper()
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.test" {
			http.Error(w, `{"errors":["permission denied"]}`, 403)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/transit/keys/root":
			pub := base64.StdEncoding.EncodeToString(edKey.Public().(ed25519.PublicKey))
			if typ == "ecdsa-p256" {
				der, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
				pub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": typ, "latest_version": 2,
				"keys": map[string]any{"2": map[string]any{"public_key": pub}}}})
		case r.Method == "POST" && r.URL.Path == "/v1/transit/sign/root/sha2-256":
			calls++
			var in struct {
				Input      string `json:"input"`
				KeyVersion int    `json:"key_version"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			msg, _ := base64.StdEncoding.DecodeString(in.Input)
			var sig []byte
			if typ == "ecdsa-p256" {
				d := sha256.Sum256(msg)
				sig, _ = ecdsa.SignASN1(rand.Reader, ecKey, d[:])
			} else {
				sig = ed25519.Sign(edKey, msg)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": "vault:v2:" + base64.StdEncoding.EncodeToString(sig)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestVaultTransitBothAlgorithms(t *testing.T) {
	for _, typ := range []string{"ed25519", "ecdsa-p256"} {
		t.Run(typ, func(t *testing.T) {
			srv, calls := fakeVault(t, typ)
			ctx := context.Background()
			v, err := SignerFromEnv(ctx, env(map[string]string{"LEDGER_SIGNER": "vault", "LEDGER_VAULT_ADDR": srv.URL,
				"LEDGER_VAULT_TOKEN": "s.test", "LEDGER_VAULT_TRANSIT_KEY": "root"}), nil)
			if err != nil {
				t.Fatal(err)
			}
			want := AlgEd25519
			if typ == "ecdsa-p256" {
				want = AlgECDSAP256
			}
			if v.Algorithm() != want || !strings.HasPrefix(v.KeyID(), strings.SplitN(want, "-", 2)[0]) {
				t.Fatalf("alg %s id %s", v.Algorithm(), v.KeyID())
			}
			sig, err := SignDetached(ctx, v, []byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if sig.Verify([]byte("hellp")) == nil {
				t.Fatal("tampered message verified")
			}
			if *calls != 1 {
				t.Fatalf("calls=%d", *calls)
			}
		})
	}
	// bad token is a clear error, not a crash
	srv, _ := fakeVault(t, "ed25519")
	if _, err := NewVaultTransit(context.Background(), &VaultTransit{Addr: srv.URL, Token: "nope", KeyName: "root"}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error, got %v", err)
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// fakeKMS verifies the SigV4 signature of every request (recomputing it with the shared secret)
// and implements GetPublicKey + Sign with a real P-256 key.
func fakeKMS(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		ts, _ := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		chk, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
		for h, v := range r.Header {
			if h != "Authorization" && h != "Accept-Encoding" && h != "Content-Length" && h != "User-Agent" {
				chk.Header[h] = v
			}
		}
		chk.Host = r.Host
		SignV4(chk, body, Credentials{"AKIDTEST", secret}, "eu-west-1", "kms", ts)
		// compare only the signed parts we reproduce (Accept-Encoding etc. are added by the transport after signing)
		if chk.Header.Get("Authorization") != auth {
			http.Error(w, `{"__type":"InvalidSignatureException"}`, 400)
			return
		}
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
			_ = json.NewEncoder(w).Encode(map[string]any{"KeyId": in["KeyId"], "PublicKey": base64.StdEncoding.EncodeToString(der),
				"KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": []string{"ECDSA_SHA_256"}})
		case "TrentService.Sign":
			if in["MessageType"] != "RAW" || in["SigningAlgorithm"] != "ECDSA_SHA_256" {
				http.Error(w, "bad params", 400)
				return
			}
			msg, _ := base64.StdEncoding.DecodeString(in["Message"])
			d := sha256.Sum256(msg)
			sig, _ := ecdsa.SignASN1(rand.Reader, k, d[:])
			_ = json.NewEncoder(w).Encode(map[string]any{"Signature": base64.StdEncoding.EncodeToString(sig)})
		default:
			http.Error(w, "unknown target", 400)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAWSKMSSignsWithSigV4(t *testing.T) {
	srv := fakeKMS(t, "secret-1")
	ctx := context.Background()
	s, err := SignerFromEnv(ctx, env(map[string]string{"LEDGER_SIGNER": "awskms", "LEDGER_KMS_KEY_ID": "alias/ledger-root",
		"AWS_REGION": "eu-west-1", "AWS_ACCESS_KEY_ID": "AKIDTEST", "AWS_SECRET_ACCESS_KEY": "secret-1", "LEDGER_KMS_ENDPOINT": srv.URL}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Algorithm() != AlgECDSAP256 || !strings.HasPrefix(s.KeyID(), "ecdsa-p256:") {
		t.Fatalf("%s %s", s.Algorithm(), s.KeyID())
	}
	sig, err := SignDetached(ctx, s, []byte("root message"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify([]byte("root message")); err != nil {
		t.Fatal(err)
	}
	// wrong secret -> fake rejects the SigV4 signature
	_, err = NewAWSKMS(ctx, &AWSKMS{Region: "eu-west-1", KeyRef: "k", AccessKey: "AKIDTEST", SecretKey: "wrong", Endpoint: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "InvalidSignature") {
		t.Fatalf("want signature rejection, got %v", err)
	}
}

// AWS's published SigV4 example (IAM ListUsers, docs "Create a signed AWS API request").
func TestSigV4KnownVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	ts := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	SignV4(req, nil, Credentials{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam", ts)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestVerifySignatureMixedAlgorithms(t *testing.T) {
	ctx := context.Background()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, s := range []Signer{Ed25519Signer{ed}, ECDSASigner{ec}} {
		sig, err := SignDetached(ctx, s, []byte("m"))
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Verify([]byte("m")); err != nil {
			t.Fatalf("%s: %v", s.Algorithm(), err)
		}
		bad := sig
		bad.KeyID = "ed25519:0000"
		if bad.Verify([]byte("m")) == nil {
			t.Fatal("key id mismatch accepted")
		}
	}
}

func TestEnvelopeCryptoShredding(t *testing.T) {
	ks := &FileDataKeyStore{Dir: t.TempDir()}
	plain := []byte(`{"patient":"Jane Doe","dx":"J45"}`)
	env, err := Seal(ks, "subject-42", "clinic", "note.created", plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env), "Jane") {
		t.Fatal("plaintext leaked into envelope")
	}
	got, err := Open(ks, "clinic", "note.created", env)
	if err != nil || string(got) != string(plain) {
		t.Fatalf("open: %v %s", err, got)
	}
	if _, err := Open(ks, "other-chain", "note.created", env); err == nil {
		t.Fatal("AAD not bound to chain")
	}
	id, err := ks.Destroy("subject-42")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ks, "clinic", "note.created", env); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("want ErrKeyDestroyed, got %v", err)
	}
	if _, _, err := ks.GetOrCreate("subject-42"); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatal("shredded subject key silently re-created")
	}
	// no key material remains on disk
	ents, _ := os.ReadDir(ks.Dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".key") {
			t.Fatalf("key file %s survived", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(ks.Dir, strings.ReplaceAll(id, ":", "_")+".destroyed")); err != nil {
		t.Fatal("no tombstone")
	}
	// other subjects unaffected
	env2, _ := Seal(ks, "subject-7", "clinic", "t", []byte(`{}`))
	if _, err := Open(ks, "clinic", "t", env2); err != nil {
		t.Fatal(err)
	}
}
