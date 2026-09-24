package compliance

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/canon"
	"github.com/Celaris-dev1/Ledger/internal/keys"
)

// SignaturePrefix is prepended to the document hash before signing.
const SignaturePrefix = "ledger-compliance-report/v1\n"

// DocumentHash is sha256 over the canonical JSON of the report without document_hash and
// signature. It is what the ledger key signs and what the PDF/HTML print.
func DocumentHash(r Report) (string, error) {
	r.DocumentHash, r.Signature = "", nil
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	c, err := canon.CanonicalBytes(b)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return hex.EncodeToString(h[:]), nil
}

// Sign sets DocumentHash and Signature.
func Sign(ctx context.Context, r *Report, s keys.Signer) error {
	h, err := DocumentHash(*r)
	if err != nil {
		return err
	}
	sig, err := keys.SignDetached(ctx, s, []byte(SignaturePrefix+h))
	if err != nil {
		return err
	}
	r.DocumentHash, r.Signature = h, &sig
	return nil
}

// Verify recomputes the document hash and checks the signature. If trust is non-nil the
// signing key must be in it (ids from the keyring / rotations, or ECDSA KMS/Vault keys).
func Verify(r Report, trust anchor.TrustSet) error {
	h, err := DocumentHash(r)
	if err != nil {
		return err
	}
	if h != r.DocumentHash {
		return fmt.Errorf("document hash mismatch: content hashes to %s, report states %s (report altered)", h, r.DocumentHash)
	}
	if r.Signature == nil {
		return errors.New("report is not signed")
	}
	if err := r.Signature.Verify([]byte(SignaturePrefix + h)); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if trust != nil {
		if _, ok := trust[r.Signature.KeyID]; !ok {
			return fmt.Errorf("signed by untrusted key %s", r.Signature.KeyID)
		}
	}
	return nil
}

// VerifyPDF verifies a pack PDF: the embedded report must verify (Verify), and the PDF itself
// must be exactly what RenderPDF produces for that report. Without the second check the pages
// an auditor reads (and the metadata) could be edited freely while the untouched embedded
// attachment still verified. RenderPDF is deterministic, so a byte comparison is exact.
func VerifyPDF(pdf []byte, trust anchor.TrustSet) (Report, error) {
	r, err := ExtractFromPDF(pdf)
	if err != nil {
		return Report{}, err
	}
	if err := Verify(r, trust); err != nil {
		return r, err
	}
	want, err := RenderPDF(r)
	if err != nil {
		return r, fmt.Errorf("re-rendering the signed report: %w", err)
	}
	if !bytes.Equal(want, pdf) {
		return r, errors.New("PDF pages/metadata differ from the rendering of the signed embedded report (PDF altered, or rendered by a different Ledger version)")
	}
	return r, nil
}

var embedRe = regexp.MustCompile(`/Type /EmbeddedFile /Length (\d+) /Filter /FlateDecode`)

// ExtractFromPDF returns the report.json embedded in a pack PDF (first embedded file).
func ExtractFromPDF(pdf []byte) (Report, error) {
	m := embedRe.FindSubmatchIndex(pdf)
	if m == nil {
		return Report{}, errors.New("no embedded report in PDF")
	}
	n, _ := strconv.Atoi(string(pdf[m[2]:m[3]]))
	rest := pdf[m[1]:]
	i := bytes.Index(rest, []byte("stream\n"))
	if i < 0 || i+7+n > len(rest) {
		return Report{}, errors.New("malformed embedded file stream")
	}
	zr, err := zlib.NewReader(bytes.NewReader(rest[i+7 : i+7+n]))
	if err != nil {
		return Report{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 1<<30))
	if err != nil {
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return Report{}, fmt.Errorf("embedded report: %w", err)
	}
	return r, nil
}
