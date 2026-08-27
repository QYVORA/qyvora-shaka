# Evidence

Every meaningful finding in SHAKA is backed by evidence. The evidence system
makes reports reproducible and findings auditable: an evidence record captures
the raw observation behind a claim, hashed and deduplicated.

## Where this lives

- `internal/evidence` — the evidence store.
- `pkg/models/evidence.go` — the `Evidence` model and hashing.
- `pkg/models/session.go` — session-level evidence and finding deduplication.
- `pkg/models/finding.go` — `Finding.Fingerprint()` for finding dedup.

## Evidence model

One evidence record is one verifiable observation:

```go
type Evidence struct {
    ID        string    // "ev-…"
    Kind      string    // attribute | observation | configuration | service | relationship
    Source    string    // collection source, e.g. "LDAP://DC01/CN=…,…"
    Target    string
    Data      string
    Hash      string    // SHA-256 of Data
    State     State
    Timestamp time.Time
}
```

`Source` traces where the observation came from (LDAP path, enumerator),
keeping the chain finding → evidence → observed object → collection source.

## Hashing

- The content hash is the lowercase hex SHA-256 digest of `Data`
  (`models.HashContent`).
- Hashes are assigned at capture time and are reproducible: running the
  assessment again over the same data yields the same hashes.
- Hashes drive deduplication and let anyone re-verify an artifact by
  re-hashing.

## Deduplication

- The evidence store (`internal/evidence`) is safe for concurrent use and
  deduplicates by content hash — parallel enumeration can record evidence
  without creating dupes.
- The session deduplicates findings by fingerprint
  (`Session.AddFinding`: merges evidence into the existing finding) and
  evidence by hash (`Session.AddEvidence`).
- Edges in the graph carry `EvidenceIDs`, and an edge re-added with new
  evidence appends those IDs — the linkage is preserved without duplication.

## Viewing evidence

`shaka evidence` lists evidence collected in the **latest** session:

```sh
shaka evidence
```

This renders a table (`id`, `type`, `hash`, `source`). It is empty until
findings with evidence exist. The same records are serialized into every
session and appear in JSON/YAML reports.

## Storage

- Evidence lives in the session model and is persisted with it as JSON under
  `session.dir` (`./sessions/*.session.json`, written mode 0600).
- Findings reference their evidence inline; reporting renders the linkage
  without re-collecting anything.

## Integrity

- The session JSON records each evidence item's content hash.
- A report rendered from a session references the hash, so a tampered record
  is detectable by re-hashing.
- Evidence is captured locally from the directory service; the framework
  never writes anything to the assessed directory.