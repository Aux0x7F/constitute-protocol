# constitute-protocol

`constitute-protocol` is the shared primitive layer for Constitution services
and clients.

It contains reusable CAAC/security primitives, bootstrap-only Nostr fallback
carrier helpers, swarm frames, `swarm.edge` session records, channel and
capability directories, projection deltas, storage pin records, stream session
records, logging evidence envelopes, subscription/admission posture, and
validators that should not be duplicated by individual services or browser
apps.
