package canon

import "testing"

func TestCanonicalSortsAndCompacts(t *testing.T) {
	got, err := CanonicalBytes([]byte(`{ "b": 1.50, "a": {"z": "<x>", "y": [3, 1e2]} }`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"y":[3,1e2],"z":"<x>"},"b":1.50}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestHashDeterministicAndChained(t *testing.T) {
	a, _ := Hash("", map[string]any{"x": 1, "y": "z"})
	b, _ := Hash("", map[string]any{"y": "z", "x": 1})
	if a != b || len(a) != 64 {
		t.Fatalf("not deterministic: %s %s", a, b)
	}
	c, _ := Hash(a, map[string]any{"x": 1, "y": "z"})
	if c == a {
		t.Fatal("prev hash not included")
	}
}

// Regression (hardening fuzz): trailing data after the JSON value was silently dropped.
func TestCanonicalRejectsTrailingData(t *testing.T) {
	for _, in := range []string{`{} {}`, `{"a":1}x`, `{"a":1}]`, `1 2`} {
		if c, err := CanonicalBytes([]byte(in)); err == nil {
			t.Errorf("%q accepted as %q", in, c)
		}
	}
	if _, err := CanonicalBytes([]byte(" {\"a\":1} \n")); err != nil {
		t.Fatalf("surrounding whitespace must be allowed: %v", err)
	}
}
