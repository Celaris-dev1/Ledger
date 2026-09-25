// Package archive implements the customer-owned storage mode for EU AI Act Art. 19/26 "logs
// under the deployer's control": periodically (and on demand via `ledger archive`) it seals a
// chain's records into the same offline-verifiable bundle format used by `ledger bundle`
// (internal/bundle), optionally envelope-encrypts that bundle, and writes it to a customer's own
// S3-compatible bucket under Object Lock so neither Ledger nor the vendor can alter or delete it
// before the retention period elapses.
//
// The S3 client here is intentionally minimal and dependency-free: it implements just enough of
// the S3 REST API (PUT/GET/HEAD/List, SigV4 signing) to write and read back sealed segments
// against AWS S3 or an S3-compatible service such as MinIO. It is not a general-purpose SDK.
package archive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3Config configures the S3-compatible endpoint. Secrets (AccessKey/SecretKey) must come from
// the environment (LEDGER_ARCHIVE_S3_ACCESS_KEY_ID / LEDGER_ARCHIVE_S3_SECRET_ACCESS_KEY), never
// from a config file or CLI flag, so they never land in shell history or process listings beyond
// what the environment already exposes.
type S3Config struct {
	Endpoint  string // e.g. https://s3.us-east-1.amazonaws.com or http://127.0.0.1:9000 (MinIO)
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	// PathStyle addresses the bucket as {endpoint}/{bucket}/{key} instead of the AWS-style
	// virtual-hosted {bucket}.{endpoint}/{key}. MinIO and most non-AWS S3-compatible services
	// need this.
	PathStyle bool
}

// S3ConfigFromEnv reads S3Config from the environment. It returns ok=false (and a zero Config)
// when no archive endpoint is configured at all, so callers can treat archiving as optional.
func S3ConfigFromEnv(getenv func(string) string) (cfg S3Config, ok bool, err error) {
	cfg = S3Config{
		Endpoint:  strings.TrimSuffix(getenv("LEDGER_ARCHIVE_S3_ENDPOINT"), "/"),
		Bucket:    getenv("LEDGER_ARCHIVE_S3_BUCKET"),
		Region:    getenv("LEDGER_ARCHIVE_S3_REGION"),
		AccessKey: getenv("LEDGER_ARCHIVE_S3_ACCESS_KEY_ID"),
		SecretKey: getenv("LEDGER_ARCHIVE_S3_SECRET_ACCESS_KEY"),
	}
	switch strings.ToLower(getenv("LEDGER_ARCHIVE_S3_PATH_STYLE")) {
	case "1", "true", "yes":
		cfg.PathStyle = true
	}
	if cfg.Endpoint == "" && cfg.Bucket == "" {
		return S3Config{}, false, nil
	}
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return S3Config{}, false, errors.New("archive: LEDGER_ARCHIVE_S3_ENDPOINT, _BUCKET, _ACCESS_KEY_ID and _SECRET_ACCESS_KEY must all be set")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return cfg, true, nil
}

// S3Client is a minimal SigV4 S3 client: PUT (with Object Lock headers), HEAD, GET and List
// (ListObjectsV2). No AWS SDK dependency.
type S3Client struct {
	Cfg    S3Config
	HTTP   *http.Client
	Now    func() time.Time                                          // for tests; defaults to time.Now
	Signer func(req *http.Request, payloadHash string, at time.Time) // for tests; defaults to SigV4
}

func (c *S3Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *S3Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

func (c *S3Client) objectURL(key string) string {
	if c.Cfg.PathStyle {
		return fmt.Sprintf("%s/%s/%s", c.Cfg.Endpoint, c.Cfg.Bucket, encodePath(key))
	}
	// Virtual-hosted style: bucket becomes part of the host.
	u, _ := url.Parse(c.Cfg.Endpoint)
	host := c.Cfg.Bucket + "." + u.Host
	return fmt.Sprintf("%s://%s/%s", u.Scheme, host, encodePath(key))
}

func encodePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// ObjectLockMode is the S3 Object Lock retention mode.
type ObjectLockMode string

const (
	LockCompliance ObjectLockMode = "COMPLIANCE"
	LockGovernance ObjectLockMode = "GOVERNANCE"
)

// PutOptions carries Object Lock and integrity headers for a segment upload.
type PutOptions struct {
	LockMode    ObjectLockMode // empty = no Object Lock header sent
	RetainUntil time.Time      // required when LockMode is set
	ContentType string
}

// Put uploads body at key, computing Content-MD5 for integrity and, when opts.LockMode is set,
// the x-amz-object-lock-mode / x-amz-object-lock-retain-until-date headers that place the object
// under Object Lock retention on a bucket that has Object Lock enabled.
func (c *S3Client) Put(ctx context.Context, key string, body []byte, opts PutOptions) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.objectURL(key), bytes.NewReader(body))
	if err != nil {
		return err
	}
	sum := md5.Sum(body)
	req.Header.Set("Content-MD5", base64Std(sum[:]))
	req.ContentLength = int64(len(body))
	if opts.ContentType != "" {
		req.Header.Set("Content-Type", opts.ContentType)
	}
	if opts.LockMode != "" {
		if opts.RetainUntil.IsZero() {
			return errors.New("archive: object lock mode set without a retain-until date")
		}
		req.Header.Set("x-amz-object-lock-mode", string(opts.LockMode))
		req.Header.Set("x-amz-object-lock-retain-until-date", opts.RetainUntil.UTC().Format(time.RFC3339))
	}
	c.sign(req, sha256Hex(body), c.now())
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return httpError("PUT", key, resp)
	}
	return nil
}

// Head returns the object's response headers (used to read back its Object Lock metadata) or
// an error satisfying errors.Is(err, ErrNotFound) if it does not exist.
func (c *S3Client) Head(ctx context.Context, key string) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.objectURL(key), nil)
	if err != nil {
		return nil, err
	}
	c.sign(req, emptyPayloadHash, c.now())
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("archive: HEAD %s: %w", key, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		return nil, httpError("HEAD", key, resp)
	}
	return resp.Header, nil
}

// Get downloads the object at key.
func (c *S3Client) Get(ctx context.Context, key string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.objectURL(key), nil)
	if err != nil {
		return nil, err
	}
	c.sign(req, emptyPayloadHash, c.now())
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("archive: GET %s: %w", key, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		return nil, httpError("GET", key, resp)
	}
	return io.ReadAll(resp.Body)
}

// ErrNotFound is returned by Head/Get for a missing object.
var ErrNotFound = errors.New("object not found")

type listResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated bool   `xml:"IsTruncated"`
	NextToken   string `xml:"NextContinuationToken"`
}

// List returns every object key under prefix (ListObjectsV2, paginated transparently).
func (c *S3Client) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		if prefix != "" {
			q.Set("prefix", prefix)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		base := c.Cfg.Endpoint
		bucket := c.Cfg.Bucket
		var reqURL string
		if c.Cfg.PathStyle {
			reqURL = fmt.Sprintf("%s/%s?%s", base, bucket, q.Encode())
		} else {
			u, _ := url.Parse(base)
			reqURL = fmt.Sprintf("%s://%s.%s/?%s", u.Scheme, bucket, u.Host, q.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		c.sign(req, emptyPayloadHash, c.now())
		resp, err := c.client().Do(req)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("archive: list %s: status %d: %s", prefix, resp.StatusCode, string(b))
		}
		var lr listResult
		if err := xml.Unmarshal(b, &lr); err != nil {
			return nil, fmt.Errorf("archive: list %s: %w", prefix, err)
		}
		for _, o := range lr.Contents {
			out = append(out, o.Key)
		}
		if !lr.IsTruncated || lr.NextToken == "" {
			break
		}
		token = lr.NextToken
	}
	sort.Strings(out)
	return out, nil
}

func httpError(method, key string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("archive: %s %s: status %d: %s", method, key, resp.StatusCode, string(b))
}

// --- SigV4 ---

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func base64Std(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		sb.WriteByte(alphabet[(n>>18)&0x3f])
		sb.WriteByte(alphabet[(n>>12)&0x3f])
		if rem > 1 {
			sb.WriteByte(alphabet[(n>>6)&0x3f])
		} else {
			sb.WriteByte('=')
		}
		if rem > 2 {
			sb.WriteByte(alphabet[n&0x3f])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// sign adds SigV4 auth headers to req (service "s3"), or delegates to c.Signer if set (tests).
func (c *S3Client) sign(req *http.Request, payloadHash string, at time.Time) {
	if c.Signer != nil {
		c.Signer(req, payloadHash, at)
		return
	}
	SignV4(req, payloadHash, at, c.Cfg.Region, "s3", c.Cfg.AccessKey, c.Cfg.SecretKey)
}

// SignV4 signs req in place per AWS Signature Version 4, service "s3" (or the given service).
// It is exported so tests (including a fake S3 server's own verification) can reproduce it.
func SignV4(req *http.Request, payloadHash string, at time.Time, region, service, accessKey, secretKey string) {
	amzDate := at.Format("20060102T150405Z")
	dateStamp := at.Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.Header.Set("Host", req.Host)

	headerNames, canonicalHeaders := canonicalHeaders(req)
	signedHeaders := strings.Join(headerNames, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := signingKey(secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

func canonicalURI(p string) string {
	if p == "" {
		p = "/"
	}
	return encodePath(strings.TrimPrefix(p, "/")) // encodePath doesn't touch leading slash logic
}

func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	vals, _ := url.ParseQuery(raw)
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string{}, vals[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func canonicalHeaders(req *http.Request) (names []string, canonical string) {
	include := map[string]string{}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk == "host" || strings.HasPrefix(lk, "x-amz-") || lk == "content-type" || lk == "content-md5" {
			include[lk] = strings.Join(v, ",")
		}
	}
	include["host"] = req.Host
	for k := range include {
		names = append(names, k)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, k := range names {
		sb.WriteString(k)
		sb.WriteByte(':')
		sb.WriteString(strings.TrimSpace(include[k]))
		sb.WriteByte('\n')
	}
	return names, sb.String()
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}
