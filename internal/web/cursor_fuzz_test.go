package web

import (
	"reflect"
	"testing"
)

// FuzzDecodeCursor: SSE cursors (Last-Event-ID / ?cursor=) are client input. Decoding never
// panics, never yields negative or empty-chain entries, and Encode/Decode round-trips.
func FuzzDecodeCursor(f *testing.F) {
	for _, s := range []string{"", "gate=12&harbour=3", "a=-1", "=5", "a=1&a=2", "t%2Facme%2Fx=9", "%zz", "a=9223372036854775808", "a=1;b=2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := DecodeCursor(s)
		if !ok {
			return
		}
		for k, v := range c {
			if k == "" || v < 0 {
				t.Fatalf("bad entry %q=%d from %q", k, v, s)
			}
		}
		enc := EncodeCursor(c)
		c2, ok := DecodeCursor(enc)
		if !ok {
			t.Fatalf("re-encoded cursor %q rejected", enc)
		}
		// zero entries are dropped by Encode (seq 0 == start of chain)
		for k, v := range c {
			if v == 0 {
				delete(c, k)
			}
		}
		if !reflect.DeepEqual(c, c2) {
			t.Fatalf("round trip: %v -> %q -> %v", c, enc, c2)
		}
	})
}
