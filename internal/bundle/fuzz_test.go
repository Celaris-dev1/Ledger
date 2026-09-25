package bundle

import (
	"bytes"
	"testing"
)

// FuzzRead feeds arbitrary bytes to Read: whatever cmd/ledger-verify does with attacker-controlled
// bundle files, it must never panic, only return an error or a (possibly Verify-failing) Bundle.
func FuzzRead(f *testing.F) {
	b, _ := buildFuzzSeedBundle()
	var buf bytes.Buffer
	_ = Write(&buf, b)
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add([]byte("not a tar file"))
	f.Add([]byte{0x1f, 0x8b, 0x00}) // gzip magic, truncated

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		// A parsed bundle must also survive Verify without panicking, whatever nonsense it holds.
		_, _ = Verify(got)
	})
}

func buildFuzzSeedBundle() (Bundle, error) {
	t := &testing.T{}
	b, _ := buildTestBundle(t)
	return b, nil
}
