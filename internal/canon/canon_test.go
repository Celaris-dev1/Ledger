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
