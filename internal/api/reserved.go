package api

import (
	"net/http"
	"strings"
)

// systemChain is Ledger's own chain (key rotations, retention policies, legal holds,
// erasures, backups). Its state is derived by folding these record types, so they must only
// be written by ledger's own operations (CLI / services), never through POST /v1/records:
// otherwise any appender could e.g. release a legal hold or fake a backup.
const systemChain = "ledger"

var reservedSystemTypes = map[string]bool{
	"ledger.key.rotated":          true,
	"ledger.retention.policy.set": true,
	"ledger.hold.created":         true,
	"ledger.hold.released":        true,
	"ledger.erasure":              true,
	"ledger.backup.created":       true,
}

// reservedAppend rejects API appends of system record types to the system chain (physical
// name, so the default tenant's bare "ledger" is covered too).
func reservedAppend(w http.ResponseWriter, be Backend, chain, typ string) bool {
	if !reservedSystemTypes[strings.TrimSpace(typ)] {
		return false
	}
	ph, ok := physical(w, be, chain)
	if !ok {
		return true
	}
	if ph == systemChain {
		writeErr(w, http.StatusForbidden, typ+" records on the ledger system chain are written only by ledger itself (CLI/services)")
		return true
	}
	return false
}
