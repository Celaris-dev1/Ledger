// Package tsa implements an RFC 3161 time-stamp protocol client and a verifier for the
// returned tokens (CMS SignedData, RFC 5652), using only encoding/asn1 and crypto/x509.
//
// Verification checks: PKIStatus granted, eContentType id-ct-TSTInfo, messageImprint equals the
// expected digest, (optionally) the nonce, the signedAttrs contentType + messageDigest, the
// ESS signing-certificate binding when present, the signature by the signer certificate, and the
// signer's chain to a configured trust bundle with the timeStamping EKU, evaluated at genTime.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // registers crypto.SHA1 for ESSCertID v1
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-384/512
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

// Object identifiers used by RFC 3161 / RFC 5652 / RFC 5035.
var (
	OIDSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	OIDAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	OIDSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

func hashForOID(o asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case o.Equal(OIDSHA256):
		return crypto.SHA256, true
	case o.Equal(OIDSHA384):
		return crypto.SHA384, true
	case o.Equal(OIDSHA512):
		return crypto.SHA512, true
	case o.Equal(OIDSHA1):
		return crypto.SHA1, true
	}
	return 0, false
}


// AlgorithmIdentifier is the X.509 AlgorithmIdentifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// MessageImprint binds the time-stamp to our data.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

// BuildRequest DER-encodes a TimeStampReq for a SHA-256 digest with certReq=true.
func BuildRequest(digest []byte, nonce *big.Int) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, errors.New("tsa: digest must be SHA-256 (32 bytes)")
	}
	return asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
		Nonce:   nonce,
		CertReq: true,
	})
}

// ParseRequest decodes a TimeStampReq (used by test servers).
func ParseRequest(der []byte) (digest []byte, nonce *big.Int, err error) {
	var r timeStampReq
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("trailing data")
	}
	if !r.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDSHA256) {
		return nil, nil, errors.New("unsupported hash")
	}
	return r.MessageImprint.HashedMessage, r.Nonce, nil
}

// PKIStatus values.
const (
	StatusGranted         = 0
	StatusGrantedWithMods = 1
)

type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// ParseResponse checks the PKIStatus and returns the DER TimeStampToken (a CMS ContentInfo).
func ParseResponse(der []byte) ([]byte, error) {
	var r timeStampResp
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil {
		return nil, fmt.Errorf("tsa: malformed TimeStampResp: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("tsa: trailing data after TimeStampResp")
	}
	if r.Status.Status != StatusGranted && r.Status.Status != StatusGrantedWithMods {
		msg := ""
		for _, s := range r.Status.StatusString {
			var str string
			if _, err := asn1.Unmarshal(s.FullBytes, &str); err == nil {
				msg += " " + str
			}
		}
		return nil, fmt.Errorf("tsa: request rejected (status %d, failInfo %x)%s", r.Status.Status, r.Status.FailInfo.Bytes, msg)
	}
	if len(r.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("tsa: granted response carries no timeStampToken")
	}
	return r.TimeStampToken.FullBytes, nil
}

// ---- CMS structures ----

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // SET OF
}

// Info is what a verified token attests.
type Info struct {
	GenTime      time.Time         `json:"gen_time"`
	Serial       string            `json:"serial"`
	Policy       string            `json:"policy"`
	Nonce        string            `json:"nonce,omitempty"`
	HashedMsg    []byte            `json:"-"`
	Signer       *x509.Certificate `json:"-"`
	SignerName   string            `json:"signer"`
	SignerSHA256 string            `json:"signer_cert_sha256"`
}

// children splits the contents of a constructed value into its DER elements.
func children(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

// parseTSTInfo walks TSTInfo element by element (robust to the many OPTIONAL fields).
func parseTSTInfo(der []byte) (*Info, asn1.ObjectIdentifier, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence {
		return nil, nil, errors.New("tsa: malformed TSTInfo")
	}
	els, err := children(seq.Bytes)
	if err != nil || len(els) < 5 {
		return nil, nil, errors.New("tsa: malformed TSTInfo fields")
	}
	var version int
	if _, err := asn1.Unmarshal(els[0].FullBytes, &version); err != nil || version != 1 {
		return nil, nil, errors.New("tsa: unsupported TSTInfo version")
	}
	var policy asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(els[1].FullBytes, &policy); err != nil {
		return nil, nil, errors.New("tsa: bad TSTInfo policy")
	}
	var mi MessageImprint
	if _, err := asn1.Unmarshal(els[2].FullBytes, &mi); err != nil {
		return nil, nil, errors.New("tsa: bad messageImprint")
	}
	var serial *big.Int
	if _, err := asn1.Unmarshal(els[3].FullBytes, &serial); err != nil {
		return nil, nil, errors.New("tsa: bad serialNumber")
	}
	var gen time.Time
	if _, err := asn1.UnmarshalWithParams(els[4].FullBytes, &gen, "generalized"); err != nil {
		return nil, nil, fmt.Errorf("tsa: bad genTime: %w", err)
	}
	info := &Info{GenTime: gen.UTC(), Serial: serial.String(), Policy: policy.String(), HashedMsg: mi.HashedMessage}
	for _, e := range els[5:] {
		if e.Class == asn1.ClassUniversal && e.Tag == asn1.TagInteger {
			var n *big.Int
			if _, err := asn1.Unmarshal(e.FullBytes, &n); err == nil {
				info.Nonce = n.String()
			}
		}
	}
	return info, mi.HashAlgorithm.Algorithm, nil
}

// Options control token verification.
type Options struct {
	Roots *x509.CertPool // trust bundle (required)
	// Intermediates optionally supplements certificates carried in the token.
	Intermediates *x509.CertPool
	// Nonce, when non-nil, must equal the token's nonce.
	Nonce *big.Int
}

// VerifyToken verifies a DER TimeStampToken against the expected SHA-256 digest.
func VerifyToken(token, digest []byte, opt Options) (*Info, error) {
	if opt.Roots == nil {
		return nil, errors.New("tsa: no trust bundle configured")
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(token, &ci); err != nil || len(rest) != 0 {
		return nil, errors.New("tsa: malformed token ContentInfo")
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		return nil, errors.New("tsa: token is not CMS SignedData")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("tsa: malformed SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(OIDTSTInfo) {
		return nil, errors.New("tsa: eContentType is not id-ct-TSTInfo")
	}
	var tstDER []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstDER); err != nil || len(tstDER) == 0 {
		return nil, errors.New("tsa: missing TSTInfo eContent")
	}
	info, miAlg, err := parseTSTInfo(tstDER)
	if err != nil {
		return nil, err
	}

	// certificates
	var certs []*x509.Certificate
	if len(sd.Certificates.Bytes) > 0 {
		els, err := children(sd.Certificates.Bytes)
		if err != nil {
			return nil, errors.New("tsa: malformed certificate set")
		}
		for _, e := range els {
			if e.Class != asn1.ClassUniversal || e.Tag != asn1.TagSequence {
				continue // other certificate choices are ignored
			}
			c, err := x509.ParseCertificate(e.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("tsa: bad certificate in token: %w", err)
			}
			certs = append(certs, c)
		}
	}

	sis, err := children(sd.SignerInfos.Bytes)
	if err != nil || len(sis) != 1 || sis[0].Class != asn1.ClassUniversal || sis[0].Tag != asn1.TagSequence {
		return nil, errors.New("tsa: token must carry exactly one SignerInfo")
	}
	signer, digAlg, err := verifySignerInfo(sis[0].Bytes, tstDER, certs)
	if err != nil {
		return nil, err
	}
	if sd.Version != 1 && sd.Version != 3 {
		return nil, errors.New("tsa: unexpected SignedData version")
	}
	algs, err := children(sd.DigestAlgorithms.Bytes)
	listed := false
	for _, a := range algs {
		var ai AlgorithmIdentifier
		if _, e := asn1.Unmarshal(a.FullBytes, &ai); e == nil && ai.Algorithm.Equal(digAlg) && nullParams(ai) {
			listed = true
		}
	}
	if err != nil || !listed || sd.DigestAlgorithms.Tag != asn1.TagSet || sd.DigestAlgorithms.Class != asn1.ClassUniversal || sd.SignerInfos.Tag != asn1.TagSet || sd.SignerInfos.Class != asn1.ClassUniversal {
		return nil, errors.New("tsa: SignedData digestAlgorithms does not list the signer digest")
	}
	if !miAlg.Equal(OIDSHA256) || !bytes.Equal(info.HashedMsg, digest) {
		return nil, errors.New("tsa: messageImprint does not match the anchored root digest")
	}
	if opt.Nonce != nil && info.Nonce != opt.Nonce.String() {
		return nil, errors.New("tsa: nonce mismatch")
	}
	inter := x509.NewCertPool()
	if opt.Intermediates != nil {
		inter = opt.Intermediates.Clone()
	}
	for _, c := range certs {
		if c != signer {
			inter.AddCert(c)
		}
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots: opt.Roots, Intermediates: inter, CurrentTime: info.GenTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return nil, fmt.Errorf("tsa: signer certificate not trusted: %w", err)
	}
	hasTS := false
	for _, u := range signer.ExtKeyUsage {
		hasTS = hasTS || u == x509.ExtKeyUsageTimeStamping
	}
	if !hasTS {
		return nil, errors.New("tsa: signer certificate lacks the timeStamping extended key usage")
	}
	info.Signer = signer
	info.SignerName = signer.Subject.String()
	fp := sha256.Sum256(signer.Raw)
	info.SignerSHA256 = fmt.Sprintf("%x", fp)
	return info, nil
}

func verifySignerInfo(siBody, content []byte, certs []*x509.Certificate) (*x509.Certificate, asn1.ObjectIdentifier, error) {
	els, err := children(siBody)
	if err != nil || len(els) < 5 {
		return nil, nil, errors.New("tsa: malformed SignerInfo")
	}
	i := 0
	var version int
	if _, err := asn1.Unmarshal(els[i].FullBytes, &version); err != nil || (version != 1 && version != 3) {
		return nil, nil, errors.New("tsa: bad SignerInfo version")
	}
	i++
	sid := els[i]
	i++
	var signer *x509.Certificate
	switch {
	case sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence:
		var ias issuerAndSerial
		if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
			return nil, nil, errors.New("tsa: bad signer identifier")
		}
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.SerialNumber) == 0 {
				signer = c
			}
		}
	case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0:
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				signer = c
			}
		}
	}
	if signer == nil {
		return nil, nil, errors.New("tsa: signer certificate not included in token (certReq)")
	}
	var digAlg AlgorithmIdentifier
	if _, err := asn1.Unmarshal(els[i].FullBytes, &digAlg); err != nil {
		return nil, nil, errors.New("tsa: bad digestAlgorithm")
	}
	i++
	h, ok := hashForOID(digAlg.Algorithm)
	if !ok || !nullParams(digAlg) || h == crypto.SHA1 {
		return nil, nil, fmt.Errorf("tsa: unsupported digest algorithm %v", digAlg.Algorithm)
	}
	if !(els[i].Class == asn1.ClassContextSpecific && els[i].Tag == 0) {
		return nil, nil, errors.New("tsa: SignerInfo has no signedAttrs (required for TST tokens)")
	}
	signedAttrs := els[i]
	i++
	var sigAlg AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(els[i].FullBytes, &sigAlg); err != nil || len(rest) != 0 || !knownSigAlg(sigAlg) {
		return nil, nil, errors.New("tsa: unsupported or malformed signatureAlgorithm")
	}
	i++
	if i >= len(els) {
		return nil, nil, errors.New("tsa: truncated SignerInfo")
	}
	var sig []byte
	if _, err := asn1.Unmarshal(els[i].FullBytes, &sig); err != nil {
		return nil, nil, errors.New("tsa: bad signature")
	}

	// signedAttrs checks
	attrs, err := children(signedAttrs.Bytes)
	if err != nil {
		return nil, nil, errors.New("tsa: malformed signedAttrs")
	}
	hh := h.New()
	hh.Write(content)
	contentDigest := hh.Sum(nil)
	var sawCT, sawMD bool
	for _, a := range attrs {
		var at attribute
		if _, err := asn1.Unmarshal(a.FullBytes, &at); err != nil {
			return nil, nil, errors.New("tsa: malformed attribute")
		}
		vals, err := children(at.Values.Bytes)
		if err != nil || len(vals) != 1 {
			return nil, nil, errors.New("tsa: attribute must have one value")
		}
		switch {
		case at.Type.Equal(OIDAttrContentType):
			var ct asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(vals[0].FullBytes, &ct); err != nil || !ct.Equal(OIDTSTInfo) {
				return nil, nil, errors.New("tsa: contentType attribute is not id-ct-TSTInfo")
			}
			sawCT = true
		case at.Type.Equal(OIDAttrMessageDigest):
			var md []byte
			if _, err := asn1.Unmarshal(vals[0].FullBytes, &md); err != nil || !bytes.Equal(md, contentDigest) {
				return nil, nil, errors.New("tsa: messageDigest attribute does not match TSTInfo (token altered)")
			}
			sawMD = true
		case at.Type.Equal(OIDAttrSigningCert), at.Type.Equal(OIDAttrSigningCertV2):
			if err := checkESSCertID(vals[0].FullBytes, at.Type.Equal(OIDAttrSigningCertV2), signer); err != nil {
				return nil, nil, err
			}
		}
	}
	if !sawCT || !sawMD {
		return nil, nil, errors.New("tsa: signedAttrs missing contentType or messageDigest")
	}
	// The signature covers the DER of signedAttrs re-tagged as a SET.
	toSign := append([]byte{0x31}, signedAttrs.FullBytes[1:]...)
	sh := h.New()
	sh.Write(toSign)
	sum := sh.Sum(nil)
	switch pub := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, h, sum, sig); err != nil {
			if err2 := rsa.VerifyPSS(pub, h, sum, sig, nil); err2 != nil {
				return nil, nil, errors.New("tsa: signature verification failed")
			}
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sum, sig) {
			return nil, nil, errors.New("tsa: signature verification failed")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, toSign, sig) {
			return nil, nil, errors.New("tsa: signature verification failed")
		}
	default:
		return nil, nil, fmt.Errorf("tsa: unsupported signer key type %T", pub)
	}
	return signer, digAlg.Algorithm, nil
}

var sigAlgOIDs = []asn1.ObjectIdentifier{
	{1, 2, 840, 113549, 1, 1, 1},  // rsaEncryption
	{1, 2, 840, 113549, 1, 1, 10}, // RSASSA-PSS
	{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
	{1, 2, 840, 113549, 1, 1, 12}, // sha384WithRSAEncryption
	{1, 2, 840, 113549, 1, 1, 13}, // sha512WithRSAEncryption
	{1, 2, 840, 10045, 4, 3, 2},   // ecdsa-with-SHA256
	{1, 2, 840, 10045, 4, 3, 3},   // ecdsa-with-SHA384
	{1, 2, 840, 10045, 4, 3, 4},   // ecdsa-with-SHA512
	{1, 3, 101, 112},              // Ed25519
}

func knownSigAlg(a AlgorithmIdentifier) bool {
	for _, o := range sigAlgOIDs {
		if a.Algorithm.Equal(o) {
			return o[len(o)-1] == 10 || nullParams(a)
		}
	}
	return false
}

// nullParams reports whether a digest AlgorithmIdentifier has absent or NULL parameters
// (the only encodings RFC 5754 allows), so unsigned fields cannot be malleated.
func nullParams(a AlgorithmIdentifier) bool {
	return len(a.Parameters.FullBytes) == 0 || bytes.Equal(a.Parameters.FullBytes, []byte{5, 0})
}

// checkESSCertID verifies the first ESSCertID(v2) in SigningCertificate(V2) hashes the signer cert.
func checkESSCertID(der []byte, v2 bool, signer *x509.Certificate) error {
	var sc asn1.RawValue
	if _, err := asn1.Unmarshal(der, &sc); err != nil {
		return errors.New("tsa: bad signingCertificate attribute")
	}
	outer, err := children(sc.Bytes)
	if err != nil || len(outer) == 0 {
		return errors.New("tsa: bad signingCertificate attribute")
	}
	ids, err := children(outer[0].Bytes)
	if err != nil || len(ids) == 0 {
		return errors.New("tsa: empty signingCertificate attribute")
	}
	f, err := children(ids[0].Bytes)
	if err != nil || len(f) == 0 {
		return errors.New("tsa: bad ESSCertID")
	}
	h := crypto.SHA1
	idx := 0
	if v2 {
		h = crypto.SHA256
		if f[0].Class == asn1.ClassUniversal && f[0].Tag == asn1.TagSequence {
			var alg AlgorithmIdentifier
			if _, err := asn1.Unmarshal(f[0].FullBytes, &alg); err != nil {
				return errors.New("tsa: bad ESSCertIDv2 hash algorithm")
			}
			var ok bool
			if h, ok = hashForOID(alg.Algorithm); !ok {
				return errors.New("tsa: unsupported ESSCertIDv2 hash")
			}
			idx = 1
		}
	}
	if idx >= len(f) {
		return errors.New("tsa: bad ESSCertID")
	}
	var certHash []byte
	if _, err := asn1.Unmarshal(f[idx].FullBytes, &certHash); err != nil {
		return errors.New("tsa: bad ESSCertID hash")
	}
	hh := h.New()
	hh.Write(signer.Raw)
	if !bytes.Equal(hh.Sum(nil), certHash) {
		return errors.New("tsa: signingCertificate attribute does not match the signer certificate")
	}
	return nil
}

// LoadTrustBundle reads a PEM bundle into a CertPool.
func LoadTrustBundle(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("tsa: no certificates in trust bundle %s", path)
	}
	return p, nil
}

// Client talks to one TSA.
type Client struct {
	Name string
	URL  string
	HTTP *http.Client
	Opt  Options
}

// Stamp requests a token for digest, verifies it, and returns the token DER and its Info.
func (c *Client) Stamp(ctx context.Context, digest []byte) ([]byte, *Info, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, nil, err
	}
	reqDER, err := BuildRequest(digest, nonce)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("tsa %s: %w", c.Name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("tsa %s: HTTP %d", c.Name, resp.StatusCode)
	}
	tok, err := ParseResponse(body)
	if err != nil {
		return nil, nil, err
	}
	opt := c.Opt
	opt.Nonce = nonce
	info, err := VerifyToken(tok, digest, opt)
	if err != nil {
		return nil, nil, err
	}
	return tok, info, nil
}
