package tsa_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa"
	"github.com/Celaris-dev1/Ledger/internal/anchor/tsa/tsatest"
)

func digest(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

func client(ft *tsatest.TSA, ca *tsatest.CA) *tsa.Client {
	return &tsa.Client{Name: "fake", URL: ft.URL(), Opt: tsa.Options{Roots: ca.Pool()}}
}

func TestStampAndVerify(t *testing.T) {
	ca := tsatest.NewCA("Test TSA Root")
	ft := tsatest.New(ca, "Test TSA 1")
	defer ft.Close()
	d := digest("root")
	tok, info, err := client(ft, ca).Stamp(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(info.GenTime) > time.Minute || info.SignerName == "" || info.Nonce == "" {
		t.Fatalf("bad info %+v", info)
	}
	// offline re-verification from stored bytes
	if _, err := tsa.VerifyToken(tok, d, tsa.Options{Roots: ca.Pool()}); err != nil {
		t.Fatal(err)
	}
	if _, err := tsa.VerifyToken(tok, digest("other"), tsa.Options{Roots: ca.Pool()}); err == nil || !strings.Contains(err.Error(), "messageImprint") {
		t.Fatalf("want imprint error, got %v", err)
	}
	other := tsatest.NewCA("Other Root")
	if _, err := tsa.VerifyToken(tok, d, tsa.Options{Roots: other.Pool()}); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("want trust error, got %v", err)
	}
	// flip every byte in turn: no single-byte corruption may still verify
	for i := range tok {
		bad := append([]byte(nil), tok...)
		bad[i] ^= 0x40
		if _, err := tsa.VerifyToken(bad, d, tsa.Options{Roots: ca.Pool()}); err == nil {
			t.Fatalf("tampered token (byte %d of %d) verified: %x", i, len(tok), tok[i-12:i+4])
		}
	}
}

func TestRejections(t *testing.T) {
	cases := map[string]struct {
		set  func(*tsatest.TSA)
		want string
	}{
		"status":   {func(f *tsatest.TSA) { f.Reject = true }, "rejected"},
		"imprint":  {func(f *tsatest.TSA) { f.WrongImprint = true }, "messageImprint"},
		"tampered": {func(f *tsatest.TSA) { f.TamperTST = true }, "messageDigest"},
		"garbage":  {func(f *tsatest.TSA) { f.Hook = func([]byte) []byte { return []byte("nope") } }, "malformed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ca := tsatest.NewCA("Root")
			ft := tsatest.New(ca, "TSA")
			defer ft.Close()
			ft.Set(tc.set)
			_, _, err := client(ft, ca).Stamp(context.Background(), digest("x"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSignerWithoutTimestampEKU(t *testing.T) {
	ca := tsatest.NewCA("Root")
	ft := tsatest.New(ca, "TSA")
	defer ft.Close()
	ft.Set(func(f *tsatest.TSA) { f.Cert, f.Key = ca.Issue("not a tsa", false) })
	if _, _, err := client(ft, ca).Stamp(context.Background(), digest("x")); err == nil {
		t.Fatal("token from non-timestamping cert accepted")
	}
}

func TestRequestRoundTrip(t *testing.T) {
	d := digest("a")
	der, err := tsa.BuildRequest(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := tsa.ParseRequest(der)
	if err != nil || string(got) != string(d) {
		t.Fatal(err)
	}
	if _, err := tsa.BuildRequest([]byte{1}, nil); err == nil {
		t.Fatal("short digest accepted")
	}
}

// TestLiveFreeTSA stamps against https://freetsa.org/tsr. Opt-in: LEDGER_LIVE_TSA=1.
// The trust anchor is freetsa's published root (LEDGER_LIVE_TSA_TRUST, else fetched over TLS).
func TestLiveFreeTSA(t *testing.T) {
	if os.Getenv("LEDGER_LIVE_TSA") != "1" {
		t.Skip("set LEDGER_LIVE_TSA=1 to run the live freetsa.org test")
	}
	var pemBytes []byte
	if p := os.Getenv("LEDGER_LIVE_TSA_TRUST"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes = b
	} else {
		resp, err := http.Get("https://freetsa.org/files/cacert.pem")
		if err != nil {
			t.Fatalf("fetch freetsa root: %v", err)
		}
		pemBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("no certs in freetsa trust bundle")
	}
	c := &tsa.Client{Name: "freetsa", URL: "https://freetsa.org/tsr", Opt: tsa.Options{Roots: roots}}
	d := digest("ledger live test " + time.Now().String())
	_, info, err := c.Stamp(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("freetsa genTime=%s signer=%s serial=%s", info.GenTime, info.SignerName, info.Serial)
}
