# Artifact catalog and downloads

Successful jobs bind each required artifact ID into `job_result_objects` before
the terminal transition. The runner service then verifies the immutable
artifact record and provenance and inserts the exact tenant-owned
`artifacts_catalog` row. If the response is lost between terminal completion
and catalog insertion, the runner's durable exact completion retry performs
the same idempotent catalog reconciliation; changed metadata conflicts.

Here `artifact ID` means the immutable `ArtifactRecord` digest. The catalog's
content/manifest digest is the record's file blob or directory-tree root, and
the provenance digest is the signed statement identity embedded in the record.
Downloads, scans, promotion, GC, and restore always reload the record by
artifact ID and verify those links; none attempts to deserialize a content or
provenance digest as an artifact record.

Metadata and provenance reads are tenant-filtered before artifact existence is
disclosed. Download tickets are random, stored only as domain-separated
SHA-256 hashes, bound to the requesting principal, tenant, classification and
manifest digest, expire after at most fifteen minutes, and are consumed once in
an immediate transaction. Downloads re-verify the immutable artifact and
provenance before opening a bounded four-frame attachment stream. Responses
use `no-store`, `nosniff`, a sanitized attachment filename, and
`application/octet-stream`; inline HTML is never served.

The initial download adapter streams single-file artifacts. Directory
artifacts remain cataloged and promotable but fail closed at download until a
deterministic bounded archive adapter is configured. A consumed ticket is not
restored when storage integrity fails.

Operators should alert on completion/catalog reconciliation errors, missing
CAS objects, provenance mismatch, download-ticket replays, ticket expiry,
classification denials, and sustained download concurrency. Migration 18 adds
the artifact catalog, one-use tickets, scan results, promotion journal, and
bounded report-summary roots. Database and data-root backups must be from the
same epoch; restore verification treats catalog roots as authoritative.

Scanner isolation, evidence-bound promotion, quotas, legal holds, backup pins,
and two-generation collection are covered by
[durable output lifecycle operations](output-lifecycle.md).
