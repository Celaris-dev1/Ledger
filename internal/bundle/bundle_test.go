package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/anchor"
	"github.com/Celaris-dev1/Ledger/internal/anchoring"
	"github.com/Celaris-dev1/Ledger/internal/store"
)

const testChain = "tamper-test"

func buildTestBundle(t *testing.T) (Bundle, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	var recs []store.Record
	prev := ""
	for i, payload := range []string{`{"n":1}`, `{"n":2}`, `{"n":3}`} {
		r := store.Record{
			Chain: testChain, Seq: int64(i + 1), Type: "test.step",
			ActorChain: json.RawMessage(`[{"kind":"agent","id":"a"}]`),
			Payload:    json.RawMessage(payload),
			CreatedAt:  epoch.Add(time.Duration(i) * time.Minute),
			PrevHash:   prev,
		}
		h, err := store.ComputeHash(&r)
		if err != nil {
			t.Fatal(err)
		}
		r.Hash = h
		prev = h
		recs = append(recs, r)
	}
	root := anchor.Sign(priv, testChain, int64(len(recs)), recs[len(recs)-1].Hash)
	subj := anchoring.NewSubject(root)
	receipt := anchoring.StoredReceipt{
		ID: 1, Chain: testChain, Seq: root.Seq, Head: root.Head, RootDigest: subj.DigestHex(),
		KeyID: root.KeyID, RootJSON: string(subj.RootJSON), Backend: anchoring.KindFile, Kind: anchoring.KindFile,
		Receipt: subj.RootJSON, Meta: json.RawMessage(`{}`), AnchoredAt: epoch, VerifiedAt: epoch,
	}
	b := Bundle{
		Manifest: Manifest{Format: Format, CreatedAt: epoch.Format(time.RFC3339), Chains: []string{testChain}, TrustMode: "self-signed"},
		Chains:   map[string]Chain{testChain: {Records: recs, Receipts: []anchoring.StoredReceipt{receipt}}},
		Trust:    map[string]string{root.KeyID: base64.StdEncoding.EncodeToString(pub)},
	}
	b.Manifest.TrustMode = "keyring"
	return b, priv
}

func mustRoundTrip(t *testing.T, b Bundle) Bundle {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, b); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

func TestRoundTripVerifiesClean(t *testing.T) {
	b, _ := buildTestBundle(t)
	got := mustRoundTrip(t, b)
	rep, err := Verify(got)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected clean bundle to verify OK, got %+v", rep.Chains[testChain])
	}
}

// tarEntries rewrites a bundle's tar/gzip stream, replacing named entries via edit and dropping
// any entry named in drop.
func rewriteTar(t *testing.T, b Bundle, edit map[string]func([]byte) []byte, drop map[string]bool) []byte {
	t.Helper()
	var raw bytes.Buffer
	if err := Write(&raw, b); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&raw)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		data := make([]byte, hdr.Size)
		_, _ = tr.Read(data)
		if drop[hdr.Name] {
			continue
		}
		if f, ok := edit[hdr.Name]; ok {
			data = f(data)
		}
		hdr.Size = int64(len(data))
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	return out.Bytes()
}

func readBack(t *testing.T, raw []byte) (Bundle, error) {
	t.Helper()
	return Read(bytes.NewReader(raw))
}

// --- tamper matrix ---

func TestTamperModifyPayload(t *testing.T) {
	b, _ := buildTestBundle(t)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		recordsPath(testChain): func(data []byte) []byte {
			var recs []store.Record
			mustJSON(t, data, &recs)
			recs[1].Payload = json.RawMessage(`{"n":999}`)
			return toJSON(t, recs)
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokenAt(t, rep, 2, "recomputed hash")
}

func TestTamperModifyHash(t *testing.T) {
	b, _ := buildTestBundle(t)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		recordsPath(testChain): func(data []byte) []byte {
			var recs []store.Record
			mustJSON(t, data, &recs)
			recs[0].Hash = strings.Repeat("a", len(recs[0].Hash))
			recs[1].PrevHash = recs[0].Hash
			return toJSON(t, recs)
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokenAt(t, rep, 1, "")
}

func TestTamperDeleteRecord(t *testing.T) {
	b, _ := buildTestBundle(t)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		recordsPath(testChain): func(data []byte) []byte {
			var recs []store.Record
			mustJSON(t, data, &recs)
			recs = append(recs[:1], recs[2:]...)
			return toJSON(t, recs)
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokenAt(t, rep, 2, "")
}

func TestTamperReorderRecords(t *testing.T) {
	b, _ := buildTestBundle(t)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		recordsPath(testChain): func(data []byte) []byte {
			var recs []store.Record
			mustJSON(t, data, &recs)
			recs[1], recs[2] = recs[2], recs[1]
			return toJSON(t, recs)
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokenAt(t, rep, 2, "")
}

func TestTamperInsertRecord(t *testing.T) {
	b, _ := buildTestBundle(t)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		recordsPath(testChain): func(data []byte) []byte {
			var recs []store.Record
			mustJSON(t, data, &recs)
			extra := recs[1]
			extra.Payload = json.RawMessage(`{"n":"inserted"}`)
			recs = append(recs[:2], append([]store.Record{extra}, recs[2:]...)...)
			return toJSON(t, recs)
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("expected inserted record (bad seq) to be caught, got OK")
	}
}

func TestTamperSwapRootSignature(t *testing.T) {
	b, _ := buildTestBundle(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		anchorsPath(testChain): func(data []byte) []byte {
			var recs []anchoring.StoredReceipt
			mustJSON(t, data, &recs)
			var root anchor.Root
			mustJSON(t, []byte(recs[0].RootJSON), &root)
			forged := anchor.Sign(otherPriv, root.Chain, root.Seq, root.Head)
			recs[0].RootJSON = string(anchor.MarshalRoot(forged))
			recs[0].KeyID = forged.KeyID
			return toJSON(t, recs)
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	cr := rep.Chains[testChain]
	if cr.OK {
		t.Fatalf("expected forged root signature (untrusted key) to be rejected")
	}
	found := false
	for _, c := range cr.Checks {
		if c.Status == anchoring.StatusInvalid {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an invalid anchor check, got %+v", cr.Checks)
	}
}

func TestTamperSwapReceiptKey(t *testing.T) {
	// Swap the trusted key id set for an unrelated one: the root is still self-consistent (its
	// own embedded public key matches its own key id and signature), but that id is no longer
	// among the operator's trusted keys, so it must be rejected. This is the "receipt key" attack:
	// present a validly self-signed root whose signing key was never enrolled.
	b, _ := buildTestBundle(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		pathTrust: func([]byte) []byte {
			return toJSON(t, map[string]string{"unrelated-key-id": base64.StdEncoding.EncodeToString(otherPub)})
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("expected untrusted swapped key to be rejected")
	}
}

func TestTamperTruncateTail(t *testing.T) {
	// Truncating after the last anchored record IS detectable: the anchor was over seq 3 (the
	// whole chain here), so dropping it changes chain length under the anchored head. Anchoring
	// an earlier seq and truncating strictly after it is the documented blind spot (see
	// docs/forge-it.md "out of scope"): nothing here re-creates that case because it requires a
	// second, later anchor to prove absence of forward-hidden truncation — a bundle without one
	// cannot claim otherwise, and honesty about that gap is the point.
	b, _ := buildTestBundle(t)
	raw := rewriteTar(t, b, map[string]func([]byte) []byte{
		recordsPath(testChain): func(data []byte) []byte {
			var recs []store.Record
			mustJSON(t, data, &recs)
			return toJSON(t, recs[:2])
		},
	}, nil)
	got, err := readBack(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(got)
	if err != nil {
		t.Fatal(err)
	}
	cr := rep.Chains[testChain]
	if cr.OK {
		t.Fatalf("expected truncation past an anchored seq to be caught")
	}
	rewritten := false
	for _, c := range cr.Checks {
		if c.Status == anchoring.StatusRewritten {
			rewritten = true
		}
	}
	if !rewritten {
		t.Fatalf("expected a rewritten/truncated anchor check, got %+v", cr.Checks)
	}
}

func requireBrokenAt(t *testing.T, rep Report, seq int, contains string) {
	t.Helper()
	cr := rep.Chains[testChain]
	if cr.OK || cr.ChainIntact {
		t.Fatalf("expected chain to be broken, got %+v", cr)
	}
	if len(cr.Findings) == 0 {
		t.Fatalf("expected a finding naming the break")
	}
	joined := strings.Join(cr.Findings, "\n")
	if !strings.Contains(joined, "seq "+strconv.Itoa(seq)) {
		t.Fatalf("findings %q do not name seq %d", joined, seq)
	}
	if contains != "" && !strings.Contains(joined, contains) {
		t.Fatalf("findings %q do not contain %q", joined, contains)
	}
}

func mustJSON(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func toJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
