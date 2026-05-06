# constitute-protocol Architecture

`constitute-protocol` is the shared non-UI primitive layer for Constitution first-party services.

## Owns

- canonical Nostr event primitives
- cryptographic helpers for service-access envelopes
- CAAC v1 envelope shape and validation helpers
- broker message names and payload validators
- service-access capability/status/request/signal contract shapes
- hosted-service descriptors, service exchange frames, service projection records, cursor/freshness, diagnostics, and transport-neutral control/observe contract shapes
- CAAC Storage primitive records for encrypted content-addressed objects, encrypted index shards, key grants, pins, availability refs, graph edges, and encrypted detail refs
- CAAC Logging primitive records for safe structured event envelopes, redaction classes, correlation refs, and encrypted detail references
- shared record codecs where multiple repos previously duplicated the same shape
- cross-language test vectors

## Does Not Own

- UI rendering, chrome, layout, slots, or first-party visual primitives
- account runtime worker implementation
- gateway admission policy
- NVR camera/media policy
- storage service implementation or object policy
- logging service observation, storage, query, or projection policy
- app controllers or domain navigation

## CAAC v1

CAAC v1 is encrypted, signed, scoped, and replay-resistant.

Outer envelope fields expose only routing-minimum information:

- `version`
- `kind`
- `envelopeId`
- `issuerPk`
- `issuedAt`
- `expiresAt`
- `alg`
- recipient hints
- per-recipient nonce/ciphertext
- `signature`

Sensitive service-access fields are encrypted:

- identity id
- subject device public key
- target service public key
- service slug
- capability scope
- source/control scopes
- display metadata
- request payloads

Signed data proves origin and integrity. Encrypted data protects confidentiality. CAAC service-access payloads must be sealed before they cross relay-facing or broker-facing boundaries that do not need plaintext.

## Service Access

The current first-party service-access vocabulary is:

- `serviceCapability`
- `ServiceAccessContext`
- `gateway.serviceAccess.request`
- `gateway.serviceAccess.response`
- `gateway.serviceSignal.request`
- `gateway.serviceSignal.response`
- `serviceAccessContext.get`
- `serviceAccessContext.put`
- `serviceAccessContext.delete`
- `gateway_service_access_request`
- `gateway_service_access_status`
- `gateway_service_signal_request`
- `gateway_service_signal_status`
- `gateway_service_signal`
- `service_access.invocation`
- `gateway.service_access`

The launch-token vocabulary is retired in consumers of this package.

## Service Control And Observation

Gateway is host/control-plane and route authority. Services own semantic validation and response shaping.

Protocol owns the shared frame and record shapes for:

- `HostedServiceDescriptor`
- `ServiceExchangeFrame`
- `ProjectionRecord`
- `DiagnosticEvent`

The service exchange frame families are:

- `service.describe.request`
- `service.describe.response`
- `service.projection.request`
- `service.projection.response`
- `service.control.request`
- `service.control.response`
- `service.invoke.request`
- `service.invoke.response`
- `service.watch.request`
- `service.watch.event`
- `service.close`

Service communication is protocol frames over transport adapters. HTTP is not an ecosystem contract. Temporary local transports may exist only below the protocol boundary and should carry generic service frames, not service-specific routes or query semantics.

## Runtime Projections

Runtime projections are retained, capability-scoped, app-consumable state channels.
Protocol owns the generic shape only:

- `ProjectionChannel`
- `ProjectionCursor`
- `ProjectionFreshness`
- `ProjectionPolicy`
- `ProjectionCoverage`
- `ProjectionSyncState`
- `ProjectionObserverUpdate`
- `ProjectionRecord`

Projection channels are explicit names, not arbitrary data pipes. The initial channels are:

- `logging.events`
- `logging.health`

Broker/control messages may establish access or repair stale projections through service-owned exchange. They are not the primary browser data surface. Browser apps consume retained/runtime-materialized projections first. Runtime synchronization, cursors, and chunks are below the projection boundary and must not become app table logic.

## CAAC Storage

CAAC Storage is the current storage access model. It is not a separate SCAAC architecture.

Protocol owns the reusable record shapes:

- `StorageContainer`
- `StorageObjectManifest`
- `StorageChunkRef`
- `StorageIndexShard`
- `StorageGraphEdge`
- `StorageKeyGrant`
- `StoragePinLease`
- `StorageAvailabilityRef`
- `EncryptedDetailRef`

Storage data and index payloads are encrypted with symmetric keys. Those keys are wrapped and granted through CAAC capabilities, while key-wallet authority stays outside the storage service. Storage hosts and intermediaries may pin, sync, and share ciphertext without learning plaintext metadata or long-lived account secrets.

## CAAC Logging

Protocol owns shared log/event record shapes and validation only. Logging is blind by default:

- producers create safe facts from their own plaintext context
- producers encrypt sensitive detail before it enters a logging surface
- log records carry searchable safe facts plus optional `EncryptedDetailRef`
- logging event projections remain generic: one event envelope contract, dynamic `safeFacts`, typed refs, tags, severity, category, and outcome
- logging projection policy/coverage records describe sync target, rolling scope, verbosity, retention target, materialized count, target count, and sync state
- `constitute-logging` must not receive or return decrypted detail
- client/device wallets or explicitly authorized analyzer services handle decrypt/view

Sensitive payloads, credentials, CAAC request bodies, service capability values, decrypted request bodies, raw secret material, and credential-bearing URLs are never valid safe facts.
