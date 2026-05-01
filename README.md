# constitute-protocol

Shared non-UI protocol, crypto-envelope, service-access, broker, and record primitives for first-party Constitution services.

`constitute-protocol` owns reusable protocol machinery only. It does not own UI chrome, app controllers, native service policy, or service business logic.

## Current Scope

- Nostr event construction, signing, verification, and minimal routing tags
- CAAC v1 sealed envelopes for cryptography-assured access control
- Service-access capability/status/signal contract names and codecs
- Runtime broker message constants and validators
- Shared record codecs where records are duplicated across repos
- Rust/JS fixtures proving the shared contract stays aligned

## Boundary

- `constitute-ui` owns UI primitives.
- `constitute-account` owns browser-side identity/session/runtime authority.
- `constitute-gateway` owns hosted-service admission and capability issuance policy.
- `constitute-nvr` owns camera/media service behavior and capability enforcement.

Protocol code stays policy-neutral: it validates shapes and cryptographic envelopes, but downstream services decide whether a valid capability is sufficient for a specific operation.
