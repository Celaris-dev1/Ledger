package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Celaris-dev1/Ledger/internal/canon"
)

func fuzzRecord(chain, typ, goal, pv string, payload []byte, seq int64, nanos int64) (Record, bool) {
	pl, err := canon.CanonicalBytes(payload)
	if err != nil {
		return Record{}, false
	}
	ac, _ := canon.CanonicalBytes([]byte(`[{"kind":"human","id":"alice"}]`))
	return Record{ID: "0f8fad5b-d9cb-469f-a165-70867728950e", Chain: chain, Seq: seq, Type: typ, GoalID: goal,
		ActorChain: ac, PolicyVersion: pv, Payload: pl, CreatedAt: time.Unix(0, nanos).UTC(), PrevHash: "p"}, true
}

// FuzzRecordHash: changing any hashed field of a record changes its hash.
func FuzzRecordHash(f *testing.F) {
	f.Add("gate", "t.x", "g1", "pv", []byte(`{"a":1}`), int64(1), int64(1700000000000000000), uint8(0), "y")
	f.Add("", "", "", "", []byte(`{}`), int64(0), int64(0), uint8(7), "")
	f.Fuzz(func(t *testing.T, chain, typ, goal, pv string, payload []byte, seq, nanos int64, which uint8, alt string) {
		r, ok := fuzzRecord(chain, typ, goal, pv, payload, seq, nanos)
		if !ok {
			return
		}
		h1, err := ComputeHash(&r)
		if err != nil {
			t.Fatal(err)
		}
		if h2, _ := ComputeHash(&r); h2 != h1 {
			t.Fatal("hash not deterministic")
		}
		m := r
		// invalid UTF-8 collapses to U+FFFD in JSON; compare on the encoded form
		enc := func(s string) string { b, _ := json.Marshal(s); return string(b) }
		switch which % 9 {
		case 0:
			m.Chain = alt
			if enc(alt) == enc(r.Chain) {
				return
			}
		case 1:
			m.Type = alt
			if enc(alt) == enc(r.Type) {
				return
			}
		case 2:
			m.GoalID = alt
			if enc(alt) == enc(r.GoalID) {
				return
			}
		case 3:
			m.PolicyVersion = alt
			if enc(alt) == enc(r.PolicyVersion) {
				return
			}
		case 4:
			m.Seq = seq + 1
		case 5:
			m.CreatedAt = r.CreatedAt.Add(time.Nanosecond)
		case 6:
			m.PrevHash = r.PrevHash + alt + "x"
		case 7:
			c, err := canon.CanonicalBytes([]byte(alt))
			if err != nil || bytes.Equal(c, r.Payload) {
				return
			}
			m.Payload = c
		case 8:
			m.ID = r.ID + alt + "0"
		}
		if !utf8.ValidString(alt) && which%9 < 4 {
			return
		}
		h2, err := ComputeHash(&m)
		if err != nil {
			t.Fatal(err)
		}
		if h1 == h2 {
			t.Fatalf("field %d change did not change the hash (%q)", which%9, alt)
		}
	})
}

// FuzzVerify: VerifyRecords and the batched Verifier never panic and agree on every stream,
// and a valid chain verifies while any single mutation is detected.
func FuzzVerify(f *testing.F) {
	f.Add(uint8(5), uint8(2), uint8(0), []byte("x"), uint8(3))
	f.Add(uint8(1), uint8(0), uint8(9), []byte(`{"z":1}`), uint8(1))
	f.Fuzz(func(t *testing.T, n, at, kind uint8, data []byte, batch uint8) {
		recs := make([]Record, int(n%40))
		prev := ""
		for i := range recs {
			r, _ := fuzzRecord("c", "t", "", "", []byte(fmt.Sprintf(`{"i":%d}`, i)), int64(i+1), int64(i)*1e9)
			r.PrevHash = prev
			r.Hash, _ = ComputeHash(&r)
			prev = r.Hash
			recs[i] = r
		}
		if res := VerifyRecords("c", recs); !res.OK {
			t.Fatalf("valid chain rejected: %+v", res)
		}
		mutated := false
		if len(recs) > 0 {
			i := int(at) % len(recs)
			r := &recs[i]
			switch kind % 7 {
			case 0:
				r.Payload = json.RawMessage(data) // may be invalid JSON
			case 1:
				r.Seq += int64(kind) + 1
			case 2:
				if r.PrevHash == string(data) {
					return
				}
				r.PrevHash = string(data)
			case 3:
				if r.Hash == string(data) {
					return
				}
				r.Hash = string(data)
			case 4:
				r.ActorChain = json.RawMessage(data)
			case 5:
				recs = append(recs[:i], recs[i+1:]...)
			case 6:
				r.Type = string(data)
			}
			mutated = true
		}
		want := VerifyRecords("c", recs)
		v := NewVerifier("c")
		v.Workers = 1 + int(batch%4)
		b := 1 + int(batch%7)
		for i := 0; i < len(recs); i += b {
			j := min(i+b, len(recs))
			if !v.Feed(append([]Record(nil), recs[i:j]...)) {
				break
			}
		}
		got := v.Res
		got.Length = want.Length // Verifier counts examined records; VerifyRecords reports the total
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("verifier disagreement:\n batch %+v\n whole %+v", got, want)
		}
		if mutated && want.OK {
			// only mutations that leave the canonical content unchanged may pass
			if kind%7 == 0 || kind%7 == 4 || kind%7 == 6 {
				return
			}
			if kind%7 == 5 && int(at)%(len(recs)+1) == len(recs) {
				return // dropped the last record: head check is the store's job
			}
			t.Fatalf("mutation %d undetected", kind%7)
		}
	})
}

// FuzzAppendRequest: decoding + validation of arbitrary request bodies never panics and every
// accepted request canonicalises and hashes.
func FuzzAppendRequest(f *testing.F) {
	f.Add([]byte(`{"chain":"c","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{"x":1}}`))
	f.Add([]byte(`{"chain":"c","type":"t","actor_chain":[{"kind":"human","id":"a"}],"payload":{} }`))
	f.Add([]byte(`{"chain":"c\u0000","type":"t","actor_chain":[{"kind":"human","id":"a"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var req AppendRequest
		if json.Unmarshal(body, &req) != nil {
			return
		}
		if err := req.Validate(); err != nil {
			if _, ok := err.(*ValidationError); !ok {
				t.Fatalf("non-validation error %T", err)
			}
			return
		}
		for _, s := range []string{req.Chain, req.Type, req.GoalID, req.PolicyVersion, req.IdempotencyKey} {
			if strings.ContainsRune(s, 0) {
				t.Fatalf("NUL accepted in %q (Postgres text rejects it: 500 instead of 400)", s)
			}
		}
		for _, a := range req.ActorChain {
			if strings.ContainsRune(a.ID, 0) || strings.ContainsRune(a.Model, 0) || strings.ContainsRune(a.ModelVersion, 0) {
				t.Fatal("NUL accepted in actor")
			}
		}
		pl, err := canon.CanonicalBytes(req.Payload)
		if err != nil {
			t.Fatalf("validated payload does not canonicalise: %v", err)
		}
		if len(pl) == 0 || pl[0] != '{' {
			t.Fatalf("non-object payload accepted: %s", pl)
		}
	})
}
