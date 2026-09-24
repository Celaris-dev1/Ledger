package canon

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

var canonSeeds = []string{
	`{"b":1,"a":2}`, `{"n":1.0,"e":1E+2,"neg":-0,"big":123456789012345678901234567890}`,
	`{"s":"<script>&\u0000 \ud800"}`, `{"é":1,"😀":3,"￿":4}`, `[1,[2,[3]],{},null,true,false,"x"]`,
	`{"dup":1,"dup":2}`, `  12.50 `, `"str"`, `{"a":{"b":{"c":[1e-7,0.1]}}}`, `{} {}`, `{"a":1}x`,
}

// FuzzCanonical checks the canonical encoding: whole-input only (exactly the inputs
// encoding/json considers valid), idempotent, and semantically identical to the input with
// number literals preserved (compared as json.Number).
func FuzzCanonical(f *testing.F) {
	for _, s := range canonSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := CanonicalBytes(in)
		if !json.Valid(in) {
			if err == nil {
				t.Fatalf("accepted invalid JSON %q -> %q", in, c)
			}
			return
		}
		if err != nil {
			t.Fatalf("rejected valid JSON %q: %v", in, err)
		}
		c2, err := CanonicalBytes(c)
		if err != nil || !bytes.Equal(c, c2) {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", in, c, c2, err)
		}
		var a, b any
		d1 := json.NewDecoder(bytes.NewReader(in))
		d1.UseNumber()
		d2 := json.NewDecoder(bytes.NewReader(c))
		d2.UseNumber()
		if d1.Decode(&a) != nil || d2.Decode(&b) != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("semantics changed: %q -> %q", in, c)
		}
		// plain encoding/json view (float64) must agree too
		var pa, pb any
		if json.Unmarshal(in, &pa) == nil {
			if err := json.Unmarshal(c, &pb); err != nil || !reflect.DeepEqual(pa, pb) {
				t.Fatalf("json semantics changed: %q -> %q", in, c)
			}
		}
	})
}

// FuzzHashSensitivity: hashes are equal exactly when canonical bodies are equal, and prev is bound.
func FuzzHashSensitivity(f *testing.F) {
	f.Add("", `{"a":1}`, `{"a":2}`)
	f.Add("abc", `{"a":1.0}`, `{"a":1}`)
	f.Add("x", `{"a":"é"}`, `{"a":"é"}`)
	f.Fuzz(func(t *testing.T, prev, x, y string) {
		cx, err1 := CanonicalBytes([]byte(x))
		cy, err2 := CanonicalBytes([]byte(y))
		if err1 != nil || err2 != nil {
			return
		}
		vx, _ := Normalize(cx)
		vy, _ := Normalize(cy)
		hx, err := Hash(prev, vx)
		if err != nil {
			t.Fatal(err)
		}
		hy, err := Hash(prev, vy)
		if err != nil {
			t.Fatal(err)
		}
		if (hx == hy) != bytes.Equal(cx, cy) {
			t.Fatalf("hash equality %v but canonical equality %v: %q %q", hx == hy, bytes.Equal(cx, cy), cx, cy)
		}
		if hp, _ := Hash(prev+"0", vx); hp == hx {
			t.Fatal("prev not bound")
		}
	})
}
