// Package tsatest provides an in-process RFC 3161 time-stamp authority backed by a freshly
// generated test CA. It produces genuine CMS SignedData tokens so the real verifier is exercised.
package tsatest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa"
)

// CA is a test root that issues TSA certificates.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed root CA.
func NewCA(name string) *CA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: k}
}

// Pool returns a CertPool holding the root.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// PEM returns the root in PEM form.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// WriteBundle writes the root PEM to dir/name and returns the path.
func (ca *CA) WriteBundle(dir, name string) string {
	p := filepath.Join(dir, name)
	_ = os.WriteFile(p, ca.PEM(), 0o644)
	return p
}

var serial atomic.Int64

// Issue creates a TSA signing certificate (critical EKU timeStamping unless eku is false).
func (ca *CA) Issue(cn string, eku bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100 + serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if eku {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &k.PublicKey, ca.Key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

// TSA is a fake time-stamp authority.
type TSA struct {
	CA     *CA
	Cert   *x509.Certificate
	Key    *ecdsa.PrivateKey
	Server *httptest.Server

	mu sync.Mutex
	// Mutators for negative tests.
	Reject       bool             // return status rejection (2)
	WrongImprint bool             // stamp a different digest
	TamperTST    bool             // flip a byte of the TSTInfo after signing
	Now          func() time.Time // genTime source
	Requests     int
	Hook         func(resp []byte) []byte // arbitrary post-processing of the DER response
}

// New starts a TSA whose signer is issued by ca.
func New(ca *CA, name string) *TSA {
	c, k := ca.Issue(name, true)
	t := &TSA{CA: ca, Cert: c, Key: k, Now: time.Now}
	t.Server = httptest.NewServer(http.HandlerFunc(t.serve))
	return t
}

// URL of the TSA endpoint.
func (t *TSA) URL() string { return t.Server.URL + "/tsr" }

// Close stops the server.
func (t *TSA) Close() { t.Server.Close() }

// Set applies f under the lock.
func (t *TSA) Set(f func(t *TSA)) { t.mu.Lock(); f(t); t.mu.Unlock() }

func (t *TSA) serve(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Requests++
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/timestamp-query" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	digest, nonce, err := tsa.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var resp []byte
	if t.Reject {
		resp, _ = asn1.Marshal(struct {
			Status struct {
				Status int
			}
		}{Status: struct{ Status int }{2}})
	} else {
		if t.WrongImprint {
			d := sha256.Sum256([]byte("something else"))
			digest = d[:]
		}
		resp = t.Respond(digest, nonce)
	}
	if t.Hook != nil {
		resp = t.Hook(resp)
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(resp)
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tsa.MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
}

type attr struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func setOf(elems ...[]byte) []byte {
	sort.Slice(elems, func(i, j int) bool { return bytes.Compare(elems[i], elems[j]) < 0 })
	return bytes.Join(elems, nil)
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func rawSet(content []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: content}
}

// Respond builds a granted DER TimeStampResp for digest.
func (t *TSA) Respond(digest []byte, nonce *big.Int) []byte {
	sha256Alg := algID{Algorithm: tsa.OIDSHA256, Parameters: asn1.NullRawValue}
	tst := mustMarshal(tstInfo{
		Version: 1, Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		MessageImprint: tsa.MessageImprint{HashAlgorithm: tsa.AlgorithmIdentifier(sha256Alg), HashedMessage: digest},
		SerialNumber:   big.NewInt(serial.Add(1)), GenTime: t.Now().UTC().Truncate(time.Second), Nonce: nonce,
	})
	md := sha256.Sum256(tst)
	certHash := sha256.Sum256(t.Cert.Raw)
	// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }; ESSCertIDv2 with default sha256
	essV2 := mustMarshal(struct{ Certs []struct{ Hash []byte } }{Certs: []struct{ Hash []byte }{{Hash: certHash[:]}}})
	attrs := [][]byte{
		mustMarshal(attr{tsa.OIDAttrContentType, rawSet(mustMarshal(tsa.OIDTSTInfo))}),
		mustMarshal(attr{tsa.OIDAttrMessageDigest, rawSet(mustMarshal(md[:]))}),
		mustMarshal(attr{tsa.OIDAttrSigningCertV2, rawSet(essV2)}),
	}
	attrSet := setOf(attrs...)
	toSign := mustMarshal(rawSet(attrSet))
	h := sha256.Sum256(toSign)
	sig, err := t.Key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}
	if t.TamperTST {
		tst = append([]byte(nil), tst...)
		tst[len(tst)-3] ^= 0x01
	}
	ias := struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: t.Cert.RawIssuer}, t.Cert.SerialNumber}
	signerInfo := struct {
		Version     int
		SID         asn1.RawValue
		DigestAlg   algID
		SignedAttrs asn1.RawValue
		SigAlg      algID
		Signature   []byte
	}{
		Version: 1, SID: asn1.RawValue{FullBytes: mustMarshal(ias)}, DigestAlg: sha256Alg,
		SignedAttrs: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrSet},
		SigAlg:      algID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:   sig,
	}
	sd := struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		Encap            struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue
		}
		Certs       asn1.RawValue
		SignerInfos asn1.RawValue
	}{Version: 3}
	sd.DigestAlgorithms = rawSet(mustMarshal(sha256Alg))
	sd.Encap.Type = tsa.OIDTSTInfo
	sd.Encap.Content = explicit0(mustMarshal(tst))
	sd.Certs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append([]byte{}, t.Cert.Raw...)}
	sd.SignerInfos = rawSet(mustMarshal(signerInfo))
	ci := struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{tsa.OIDSignedData, explicit0(mustMarshal(sd))}
	resp := struct {
		Status struct{ Status int }
		Token  asn1.RawValue
	}{Token: asn1.RawValue{FullBytes: mustMarshal(ci)}}
	return mustMarshal(resp)
}

func explicit0(inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}
