# constitute-protocol

Shared non-UI protocol, crypto-envelope, service-access, broker, and record primitives for first-party Constitution services.

`constitute-protocol` owns reusable protocol machinery only. It does not own UI chrome, app controllers, native service policy, or service business logic.

## Current Scope

- Nostr event construction, signing, verification, and minimal routing tags
- CAAC v1 sealed envelopes for cryptography-assured access control
- Service-access capability/status/signal contract names and codecs
- Runtime broker message constants and validators
- CAAC Storage primitive records for encrypted objects, encrypted index shards, key grants, pin leases, availability refs, graph edges, and encrypted detail refs
- CAAC Logging primitive records for blind structured events, safe facts, redaction classes, correlation refs, and encrypted detail refs
- Shared record codecs where records are duplicated across repos
- Rust/JS fixtures proving the shared contract stays aligned

## Boundary

- `constitute-ui` owns UI primitives.
- `constitute-account` owns browser-side identity/session/runtime authority.
- `constitute-gateway` owns hosted-service admission and capability issuance policy.
- `constitute-nvr` owns camera/media service behavior and capability enforcement.
- `constitute-storage` owns the SQLite/files service implementation, pin/prune behavior, and local materialized search.
- `constitute-logging` owns event observation, dedupe, safe-fact indexing, hot query/watch projections, and storage archive submission.

Protocol code stays policy-neutral: it validates shapes and cryptographic envelopes, but downstream services decide whether a valid capability is sufficient for a specific operation.
