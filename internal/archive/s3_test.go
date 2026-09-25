package archive

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 is an httptest server that speaks just enough of the S3 REST API for S3Client, and
// enforces Object Lock semantics: an object PUT with a lock mode + retain-until date cannot be
// overwritten or deleted before that date, exactly like a real bucket with Object Lock enabled
// (Compliance mode: not even the bucket owner can shorten or remove it). It also validates every
// request's SigV4 Authorization header, rejecting bad signatures the way a real S3 endpoint would
// (403 SignatureDoesNotMatch).
type fakeS3 struct {
	mu       sync.Mutex
	objects  map[string]*fakeObject
	region   string
	access   string
	secret   string
	bucket   string
	now      func() time.Time
	endpoint string
}

type fakeObject struct {
	body        []byte
	lockMode    string
	retainUntil time.Time
}

func newFakeS3(t *testing.T) (*httptest.Server, *fakeS3) {
	t.Helper()
	f := &fakeS3{
		objects: map[string]*fakeObject{},
		region:  "us-east-1",
		access:  "test-access",
		secret:  "test-secret",
		bucket:  "test-bucket",
		now:     time.Now,
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	if !f.validSig(r, body) {
		http.Error(w, "SignatureDoesNotMatch", http.StatusForbidden)
		return
	}

	// Path-style only in this fake: /{bucket}/{key...} or /{bucket} for list.
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] != f.bucket {
		http.Error(w, "NoSuchBucket", http.StatusNotFound)
		return
	}
	if len(parts) == 1 || parts[1] == "" {
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			f.list(w, r)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := parts[1]

	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.Method {
	case http.MethodPut:
		if got := r.Header.Get("Content-MD5"); got != "" {
			sum := md5.Sum(body)
			want := base64.StdEncoding.EncodeToString(sum[:])
			if got != want {
				http.Error(w, "BadDigest", http.StatusBadRequest)
				return
			}
		}
		if existing, ok := f.objects[key]; ok && existing.lockMode != "" && f.now().Before(existing.retainUntil) {
			http.Error(w, "AccessDenied: object is under Object Lock retention until "+existing.retainUntil.Format(time.RFC3339), http.StatusForbidden)
			return
		}
		obj := &fakeObject{body: append([]byte{}, body...)}
		if m := r.Header.Get("x-amz-object-lock-mode"); m != "" {
			obj.lockMode = m
			ru, err := time.Parse(time.RFC3339, r.Header.Get("x-amz-object-lock-retain-until-date"))
			if err != nil {
				http.Error(w, "InvalidArgument: bad retain-until date", http.StatusBadRequest)
				return
			}
			obj.retainUntil = ru
		}
		f.objects[key] = obj
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		obj, ok := f.objects[key]
		if !ok {
			http.Error(w, "NoSuchKey", http.StatusNotFound)
			return
		}
		w.Write(obj.body)
	case http.MethodHead:
		obj, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if obj.lockMode != "" {
			w.Header().Set("x-amz-object-lock-mode", obj.lockMode)
			w.Header().Set("x-amz-object-lock-retain-until-date", obj.retainUntil.Format(time.RFC3339))
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if existing, ok := f.objects[key]; ok && existing.lockMode != "" && f.now().Before(existing.retainUntil) {
			http.Error(w, "AccessDenied: object is under Object Lock retention", http.StatusForbidden)
			return
		}
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3) list(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	f.mu.Lock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	f.mu.Unlock()
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	for _, k := range keys {
		fmt.Fprintf(&sb, "<Contents><Key>%s</Key></Contents>", k)
	}
	sb.WriteString(`<IsTruncated>false</IsTruncated></ListBucketResult>`)
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(sb.String()))
}

// validSig recomputes the SigV4 signature the same way S3Client.SignV4 does and compares it
// against the Authorization header, rejecting any mismatch — this is what makes the fake
// meaningfully validate signatures rather than just accept anything with an Authorization
// header present.
func (f *fakeS3) validSig(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return false
	}
	amzDate := r.Header.Get("x-amz-date")
	at, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return false
	}
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		return false
	}
	if payloadHash != emptyPayloadHash {
		if got := sha256Hex(body); got != payloadHash {
			return false
		}
	}

	// Reconstruct the request the way the client saw it (its Host header) to recompute the
	// expected signature.
	want := &http.Request{Method: r.Method, URL: r.URL, Header: r.Header.Clone(), Host: r.Host}
	SignV4(want, payloadHash, at, f.region, "s3", f.access, f.secret)
	return want.Header.Get("Authorization") == auth
}

func (f *fakeS3) client(pathStyle bool) *S3Client {
	return &S3Client{Cfg: S3Config{
		Endpoint: f.endpoint, Bucket: f.bucket, Region: f.region,
		AccessKey: f.access, SecretKey: f.secret, PathStyle: pathStyle,
	}}
}

func TestS3ClientPutGetHead(t *testing.T) {
	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	c := f.client(true)

	body := []byte("hello segment")
	ctx := context.Background()
	if err := c.Put(ctx, "chain/seg1", body, PutOptions{ContentType: "application/octet-stream"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := c.Get(ctx, "chain/seg1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q want %q", got, body)
	}
	if _, err := c.Head(ctx, "chain/seg1"); err != nil {
		t.Fatalf("head: %v", err)
	}
	if _, err := c.Get(ctx, "chain/missing"); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestS3ClientObjectLockRefusesOverwrite(t *testing.T) {
	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	c := f.client(true)
	ctx := context.Background()

	retain := time.Now().Add(24 * time.Hour)
	if err := c.Put(ctx, "chain/seg1", []byte("v1"), PutOptions{LockMode: LockCompliance, RetainUntil: retain}); err != nil {
		t.Fatalf("initial put: %v", err)
	}
	if err := c.Put(ctx, "chain/seg1", []byte("v2 - tampered"), PutOptions{}); err == nil {
		t.Fatal("expected Object Lock to refuse overwrite before retain-until")
	}
	got, err := c.Get(ctx, "chain/seg1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1" {
		t.Fatalf("object was overwritten despite Object Lock: got %q", got)
	}
}

func TestS3ClientObjectLockRefusesDelete(t *testing.T) {
	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	c := f.client(true)
	ctx := context.Background()

	retain := time.Now().Add(24 * time.Hour)
	if err := c.Put(ctx, "chain/seg1", []byte("v1"), PutOptions{LockMode: LockCompliance, RetainUntil: retain}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/"+f.bucket+"/chain/seg1", nil)
	SignV4(req, emptyPayloadHash, time.Now().UTC(), f.region, "s3", f.access, f.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		t.Fatalf("expected delete to be refused, got status %d", resp.StatusCode)
	}
}

func TestS3ClientObjectLockAllowsDeleteAfterRetention(t *testing.T) {
	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	fixedNow := time.Now()
	f.now = func() time.Time { return fixedNow }
	c := f.client(true)
	ctx := context.Background()

	retain := fixedNow.Add(-time.Hour) // already elapsed
	if err := c.Put(ctx, "chain/seg1", []byte("v1"), PutOptions{LockMode: LockCompliance, RetainUntil: retain}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/"+f.bucket+"/chain/seg1", nil)
	SignV4(req, emptyPayloadHash, time.Now().UTC(), f.region, "s3", f.access, f.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("expected delete to succeed after retention elapsed, got %d", resp.StatusCode)
	}
}

func TestS3ClientRejectsBadSignature(t *testing.T) {
	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	ctx := context.Background()

	// Client signing with the wrong secret should be rejected by the fake's own validation.
	bad := &S3Client{Cfg: S3Config{Endpoint: srv.URL, Bucket: f.bucket, Region: f.region, AccessKey: f.access, SecretKey: "wrong-secret", PathStyle: true}}
	if err := bad.Put(ctx, "chain/seg1", []byte("x"), PutOptions{}); err == nil {
		t.Fatal("expected signature rejection with wrong secret key")
	}
}

func TestS3ClientList(t *testing.T) {
	srv, f := newFakeS3(t)
	f.endpoint = srv.URL
	c := f.client(true)
	ctx := context.Background()
	for _, k := range []string{"chainA/seg1", "chainA/seg2", "chainB/seg1"} {
		if err := c.Put(ctx, k, []byte("x"), PutOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := c.List(ctx, "chainA/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2: %v", len(keys), keys)
	}
}
