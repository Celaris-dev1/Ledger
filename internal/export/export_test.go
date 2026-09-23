package export

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

func TestBuildAndRender(t *testing.T) {
	recs := []store.Record{{
		ID: "1", Chain: "warrant", Seq: 1, Type: "warrant.token.revoked", GoalID: "g1",
		ActorChain: json.RawMessage(`[{"id":"alice","kind":"human"},{"id":"bot","kind":"agent","model":"m","model_version":"1"}]`),
		Payload:    json.RawMessage(`{"x":"<script>"}`), PolicyVersion: "p1", CreatedAt: time.Now(),
	}}
	p := Build("g1", []ChainSection{{Verify: store.VerifyRecords("warrant", recs), Records: recs}})
	if p.Summary.TotalRecords != 1 || len(p.Summary.OversightRecords) != 1 || p.Summary.Humans[0] != "alice" {
		t.Fatalf("bad summary %+v", p.Summary)
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, p); err != nil {
		t.Fatal(err)
	}
	h := buf.String()
	for _, want := range []string{"Article 12", "Art. 12(2)(a)", "Article 14", "Art. 14(4)", "agent:bot (m@1)"} {
		if !strings.Contains(h, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(h, "<script>") {
		t.Error("payload not escaped")
	}
	if err := WriteZip(&bytes.Buffer{}, p); err != nil {
		t.Fatal(err)
	}
}
