package tsa_test

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa"
	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa/tsatest"
)

var (
	fuzzOnce          sync.Once
	fuzzPool          *x509.CertPool
	fuzzResp, fuzzTok []byte
	fuzzDigest        = digest("fuzz root")
)

// realToken loads a genuine response/token issued once by the test TSA (testdata/fuzzbase;
// regenerate with LEDGER_REGEN_TSA_FIXTURE=1). A fixed base keeps fuzz crashers reproducible.
func realToken(t testing.TB) ([]byte, []byte, *x509.CertPool) {
	fuzzOnce.Do(func() {
		if os.Getenv("LEDGER_REGEN_TSA_FIXTURE") == "1" {
			ca := tsatest.NewCA("Fuzz TSA Root")
			ft := tsatest.New(ca, "Fuzz TSA")
			resp := ft.Respond(fuzzDigest, big.NewInt(424242))
			ft.Close()
			_ = os.MkdirAll("testdata/fuzzbase", 0o755)
			_ = os.WriteFile("testdata/fuzzbase/ca.pem", ca.PEM(), 0o644)
			_ = os.WriteFile("testdata/fuzzbase/resp.der", resp, 0o644)
		}
		var err error
		if fuzzPool, err = tsa.LoadTrustBundle("testdata/fuzzbase/ca.pem"); err != nil {
			panic(err)
		}
		if fuzzResp, err = os.ReadFile("testdata/fuzzbase/resp.der"); err != nil {
			panic(err)
		}
		if fuzzTok, err = tsa.ParseResponse(fuzzResp); err != nil {
			panic(err)
		}
	})
	if _, err := tsa.VerifyToken(fuzzTok, fuzzDigest, tsa.Options{Roots: fuzzPool}); err != nil {
		t.Fatalf("base token does not verify: %v", err)
	}
	return fuzzResp, fuzzTok, fuzzPool
}

// mutate applies one structural edit chosen by the fuzzer.
func mutate(b []byte, op uint8, pos uint16, val byte, ins []byte) []byte {
	if len(b) == 0 {
		return b
	}
	p := int(pos) % len(b)
	out := append([]byte(nil), b...)
	switch op % 6 {
	case 0: // xor a byte
		out[p] ^= val | 1
	case 1: // set a byte
		out[p] = val
	case 2: // insert bytes
		out = append(out[:p], append(append([]byte(nil), ins...), b[p:]...)...)
	case 3: // delete a run
		n := 1 + int(val)%16
		if p+n > len(out) {
			n = len(out) - p
		}
		out = append(out[:p], out[p+n:]...)
	case 4: // truncate
		out = out[:p]
	case 5: // duplicate a run
		n := 1 + int(val)%32
		if p+n > len(b) {
			n = len(b) - p
		}
		out = append(out[:p+n], append(append([]byte(nil), b[p:p+n]...), b[p+n:]...)...)
	}
	return out
}

// FuzzVerifyMutatedToken: no edit of a genuine token (or of the response carrying it) may
// verify, and nothing panics.
func FuzzVerifyMutatedToken(f *testing.F) {
	f.Add(uint8(0), uint16(10), byte(0x40), []byte{0})
	f.Add(uint8(2), uint16(300), byte(1), []byte{0x31, 0x00})
	f.Add(uint8(5), uint16(50), byte(20), []byte(nil))
	f.Fuzz(func(t *testing.T, op uint8, pos uint16, val byte, ins []byte) {
		resp, tok, ca := realToken(t)
		opt := tsa.Options{Roots: ca, Nonce: big.NewInt(424242)}
		bad := mutate(tok, op, pos, val, ins)
		if !bytes.Equal(bad, tok) {
			if _, err := tsa.VerifyToken(bad, fuzzDigest, opt); err == nil {
				t.Fatalf("mutated token verified (op %d at %d): %x", op%6, int(pos)%len(tok), bad)
			}
		}
		badResp := mutate(resp, op, pos, val, ins)
		if got, err := tsa.ParseResponse(badResp); err == nil && !bytes.Equal(got, tok) {
			if _, err := tsa.VerifyToken(got, fuzzDigest, opt); err == nil {
				t.Fatalf("mutated response yielded a verifying different token")
			}
		}
	})
}

// FuzzParseAndVerify: arbitrary DER never panics the response/request/token parsers.
func FuzzParseAndVerify(f *testing.F) {
	resp, tok, _ := realToken(f)
	req, _ := tsa.BuildRequest(fuzzDigest, big.NewInt(1))
	f.Add(resp)
	f.Add(tok)
	f.Add(req)
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = tsa.ParseResponse(der)
		_, _, _ = tsa.ParseRequest(der)
		_, _ = tsa.VerifyToken(der, fuzzDigest, tsa.Options{Roots: fuzzPool})
	})
}

// Regressions (hardening fuzz): single edits of unsigned token fields that used to verify.
func TestTokenMalleabilityRegressions(t *testing.T) {
	_, tok, pool := realToken(t)
	edit := func(name string, find, repl []byte) {
		t.Helper()
		i := bytes.Index(tok, find)
		if i < 0 {
			t.Fatalf("%s: pattern not found", name)
		}
		bad := append(append(append([]byte(nil), tok[:i]...), repl...), tok[i+len(find):]...)
		if _, err := tsa.VerifyToken(bad, fuzzDigest, tsa.Options{Roots: pool}); err == nil {
			t.Errorf("%s: altered token verified", name)
		}
	}
	// SignedData version 3 -> 1
	edit("signeddata version", []byte{0x02, 0x01, 0x03, 0x31, 0x0f}, []byte{0x02, 0x01, 0x01, 0x31, 0x0f})
	// digestAlgorithms SET encoded as primitive
	edit("digestAlgorithms primitive", []byte{0x02, 0x01, 0x03, 0x31, 0x0f}, []byte{0x02, 0x01, 0x03, 0x11, 0x0f})
	// digestAlgorithms with the NULL parameter split out into a junk element
	edit("digestAlgorithms junk", []byte{0x31, 0x0f, 0x30, 0x0d}, []byte{0x31, 0x0f, 0x30, 0x0b})
	// signatureAlgorithm ecdsa-with-SHA256 -> ecdsa-with-SHA384 (last occurrence: SignerInfo)
	sigAlg := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	i := bytes.LastIndex(tok, sigAlg)
	bad := append([]byte(nil), tok...)
	bad[i+len(sigAlg)-1] = 0x03
	if _, err := tsa.VerifyToken(bad, fuzzDigest, tsa.Options{Roots: pool}); err == nil {
		t.Error("signatureAlgorithm rewrite verified")
	}
}
