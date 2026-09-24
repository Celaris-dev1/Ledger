package backup

import (
	"context"
	"encoding/json"

	"github.com/Celaris-dev1/Ledger/internal/store"
)

// RecordType marks a completed backup in the ledger system chain (evidence for SOC 2 CC7.5 /
// HIPAA 164.308(a)(7)).
const RecordType = "ledger.backup.created"

// Record appends a ledger.backup.created record describing m.
func Record(ctx context.Context, st *store.Store, m Manifest, location, operator string) (*store.Record, error) {
	if operator == "" {
		operator = "operator"
	}
	keyID := ""
	if m.Signature != nil {
		keyID = m.Signature.KeyID
	}
	pl, _ := json.Marshal(map[string]any{"format": m.Format, "snapshot_at": m.CreatedAt, "manifest_hash": m.ManifestHash,
		"signer_key_id": keyID, "chains": len(m.Chains), "records": m.Records, "anchor_receipts": m.Receipts, "location": location})
	return st.Append(ctx, store.AppendRequest{Chain: "ledger", Type: RecordType,
		ActorChain: []store.Actor{{Kind: "human", ID: operator}, {Kind: "service", ID: "ledger-backup"}}, Payload: pl})
}
