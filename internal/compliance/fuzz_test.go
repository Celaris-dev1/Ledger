package compliance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/keys"
)

var (
	fuzzOnce     sync.Once
	fuzzReport   Report
	fuzzJSON     []byte
	fuzzPDF      []byte
	fuzzTrust    anchor.TrustSet
	fuzzSignerKy = ed25519.NewKeyFromSeed(make([]byte, 32))
)

func fuzzPack(t *testing.T) {
	fuzzOnce.Do(func() {
		s := keys.Ed25519Signer{Key: fuzzSignerKy}
		fuzzReport = signedReport(t, s)
		fuzzJSON, _ = json.Marshal(fuzzReport)
		var err error
		if fuzzPDF, err = RenderPDF(fuzzReport); err != nil {
			t.Fatal(err)
		}
		fuzzTrust = anchor.TrustSet{s.KeyID(): s.PublicKey()}
	})
}

// FuzzVerifyReportJSON: a report JSON verifies only when it states the signed document.
func FuzzVerifyReportJSON(f *testing.F) {
	f.Add(uint32(0), byte('x'), []byte(nil))
	f.Add(uint32(500), byte(' '), []byte(`,"extra":1`))
	f.Fuzz(func(t *testing.T, pos uint32, val byte, ins []byte) {
		fuzzPack(t)
		b := append([]byte(nil), fuzzJSON...)
		p := int(pos) % len(b)
		if len(ins) > 0 {
			b = append(append(append([]byte(nil), b[:p]...), ins...), b[p:]...)
		} else {
			b[p] = val
		}
		var r Report
		if json.Unmarshal(b, &r) != nil || Verify(r, fuzzTrust) != nil {
			return
		}
		h, _ := DocumentHash(r)
		if h != fuzzReport.DocumentHash {
			t.Fatalf("altered report verified (hash %s)", h)
		}
	})
}

// FuzzExtractFromPDF: arbitrary edits of a genuine pack PDF never panic the extractor, and
// an embedded report that verifies is the signed one; page edits are flagged by VerifyPDF.
func FuzzExtractFromPDF(f *testing.F) {
	f.Add(uint32(0), byte('x'), []byte(nil), uint8(0))
	f.Add(uint32(100), byte('9'), []byte("/Type /EmbeddedFile /Length 99999999999999999999 /Filter /FlateDecode stream\n"), uint8(1))
	f.Add(uint32(0), byte(0), []byte("%PDF-1.3 /Type /EmbeddedFile /Length 9223372036854775807 /Filter /FlateDecode stream\nxx"), uint8(2))
	f.Fuzz(func(t *testing.T, pos uint32, val byte, ins []byte, mode uint8) {
		fuzzPack(t)
		var b []byte
		switch mode % 3 {
		case 0:
			b = append([]byte(nil), fuzzPDF...)
			b[int(pos)%len(b)] = val
		case 1:
			p := int(pos) % len(fuzzPDF)
			b = append(append(append([]byte(nil), fuzzPDF[:p]...), ins...), fuzzPDF[p:]...)
		default:
			b = ins
		}
		r, pagesMatch, err := VerifyPDF(b, fuzzTrust)
		if err != nil {
			return
		}
		if r.DocumentHash != fuzzReport.DocumentHash {
			t.Fatal("PDF with a different report verified")
		}
		if pagesMatch && !bytes.Equal(b, fuzzPDF) {
			t.Fatal("edited PDF reported as matching its rendering")
		}
	})
}

// Regression (hardening fuzz): a /Length near MaxInt overflowed the bounds check and panicked;
// the inflate limit was 1 GiB.
func TestExtractFromPDFHostileLength(t *testing.T) {
	for _, n := range []string{"9223372036854775807", "9223372036854775800", "99999999999999999999"} {
		pdf := []byte(fmt.Sprintf("%%PDF-1.3\n/Type /EmbeddedFile /Length %s /Filter /FlateDecode >>\nstream\nabc", n))
		if _, err := ExtractFromPDF(pdf); err == nil {
			t.Fatalf("length %s accepted", n)
		}
	}
	fuzzPack(t)
	edited := bytes.Replace(fuzzPDF, []byte("Art. 19"), []byte("Art. 18"), 1)
	if bytes.Equal(edited, fuzzPDF) {
		edited = append(append([]byte(nil), fuzzPDF...), []byte("\n% edited\n")...)
	}
	r, match, err := VerifyPDF(edited, fuzzTrust)
	if err != nil || match || !strings.EqualFold(r.DocumentHash, fuzzReport.DocumentHash) {
		t.Fatalf("page edit: err=%v match=%v", err, match)
	}
	if _, match, err := VerifyPDF(fuzzPDF, fuzzTrust); err != nil || !match {
		t.Fatalf("genuine PDF: %v %v", match, err)
	}
}
