package compliance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/keys"
)

// Regression (e2e suite): `ledger export --verify report.pdf` only checked the embedded
// report.json, so the rendered pages and metadata of a signed PDF could be edited and still
// verify as OK.
func TestVerifyPDFRejectsEditedPages(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	s := keys.Ed25519Signer{Key: ed}
	r := signedReport(t, s)
	// Stored payloads keep their exact text (SDKs send `{"a": 1}` with spaces); the embedded
	// report.json compacts and HTML-escapes it, and the re-render must still match.
	r.Records[0].Payload = []byte(`{"b": "<x> & y",  "a": [1, 2.50]}`)
	if err := Sign(context.Background(), &r, s); err != nil {
		t.Fatal(err)
	}
	pdf, err := RenderPDF(r)
	if err != nil {
		t.Fatal(err)
	}
	// Round trip through the embedded JSON must re-render byte-identically.
	if _, err := VerifyPDF(pdf, nil); err != nil {
		t.Fatalf("pristine PDF: %v", err)
	}
	// Edit the visible metadata (outside the embedded attachment): the title an auditor sees.
	i := bytes.Index(pdf, []byte("/Title"))
	if i < 0 {
		t.Fatal("no /Title in PDF")
	}
	edited := bytes.Clone(pdf)
	edited[i+8] ^= 0x01
	if _, err := ExtractFromPDF(edited); err != nil {
		t.Fatalf("edit should leave the attachment intact: %v", err)
	}
	if _, err := VerifyPDF(edited, nil); err == nil {
		t.Fatal("PDF with edited pages/metadata verified")
	}
	// Appending bytes after %%EOF (an incremental update) is also refused.
	if _, err := VerifyPDF(append(bytes.Clone(pdf), []byte("\n1 0 obj << >> endobj\n%%EOF\n")...), nil); err == nil {
		t.Fatal("PDF with an incremental update verified")
	}
}
