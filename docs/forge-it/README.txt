This is the sample bundle for the Ledger "Forge It" challenge (see docs/forge-it.md).

It was generated deterministically by tools/forge-it-sample (run via scripts/forge-it-sample.sh)
and contains no private key material: the Ed25519 signing key was generated in memory, used once
to sign the chain root below, and discarded. Only its public key (embedded in the root) ships.

  chain:      forge-it-sample
  root seq:   5
  root head:  3a698fab512cfd3877f6d42ba94d1e4bd1542a3cb4492fe74f9a82a085aea4ec
  key id:     ed25519:d3702f782502e601
  public key: z+xJSnzIQtg0Dywzvl7VUzTLpj5VFajA8wZ3IRz6ztQ=

Verify it with:

  go run ./cmd/ledger-verify docs/forge-it/sample-bundle.tar

Then try to beat it: edit sample-bundle.tar (modify a record, reorder, delete, insert, truncate,
swap the root signature or the anchor receipt) and see if ledger-verify still says OK. See
docs/forge-it.md for the rules and what's out of scope.
