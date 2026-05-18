import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex as nobleBytesToHex, hexToBytes as nobleHexToBytes } from "@noble/hashes/utils";

export const CAAC_ALG_V1 = "caac-v1-secp256k1-hkdf-sha256-xchacha20poly1305";
export const CAAC_VERSION = 1;
export const DEFAULT_CAPABILITY_TTL_SECONDS = 15 * 60;
export const MAX_CAPABILITY_TTL_SECONDS = 30 * 60;
export const DEFAULT_REQUEST_TTL_SECONDS = 90;

export const BROKER = Object.freeze({
  PROJECTION_GET: "projection.get",
  PROJECTION_PUT: "projection.put",
  SERVICE_CATALOG_GET: "service.catalog.get",
  SERVICE_NODE_GET: "service.node.get",
  SERVICE_NODE_POLICY_PUT: "service.node.policy.put",
});

export const SERVICE_SURFACE = Object.freeze({
  SCHEMA_VERSION: 1,
  FIELD_CAPABILITY: Object.freeze({
    READ: "read",
    OBSERVE: "observe",
    SET: "set",
    ATTACH: "attach",
    INVOKE: "invoke",
  }),
});

export const SURFACE_APP = Object.freeze({
  SCHEMA_VERSION: 1,
  MODULE_ROLE: Object.freeze({
    RUNTIME_CLIENT: "runtimeClient",
    PROJECTION_MODEL: "projectionModel",
    PLATFORM_ADAPTER: "platformAdapter",
    SERVICE_SURFACE_ADAPTER: "serviceSurfaceAdapter",
    PRODUCT_VIEW: "productView",
    OPERATOR_HELPER: "operatorHelper",
    RELEASE_HELPER: "releaseHelper",
  }),
  PARTICIPANT_SIDE: Object.freeze({
    WINDOW: "window",
    RUNTIME: "runtime",
    SERVICE: "service",
    OPERATOR: "operator",
    NATIVE: "native",
    STORAGE: "storage",
  }),
  FULFILLMENT_MODE: Object.freeze({
    BUNDLED: "bundled",
    SWARM_PACKAGE: "swarmPackage",
    STORAGE_OBJECT: "storageObject",
    NATIVE_INSTALLED: "nativeInstalled",
    DEV_OVERLAY: "devOverlay",
  }),
  UPDATE_POSTURE: Object.freeze({
    STATIC: "static",
    COMPATIBLE: "compatible",
    UPDATE_AVAILABLE: "updateAvailable",
    BLOCKED: "blocked",
  }),
  MANIFEST_VERSION_STATE: Object.freeze({
    CURRENT: "current",
    COMPATIBLE: "compatible",
    UPDATE_AVAILABLE: "updateAvailable",
    BLOCKED: "blocked",
    SUPERSEDED: "superseded",
  }),
  BOOTSTRAP_POSTURE: Object.freeze({
    STATIC: "static",
    READY: "ready",
    DEGRADED: "degraded",
    BLOCKED: "blocked",
    UNAVAILABLE: "unavailable",
  }),
  SERVICE_MANAGER_POSTURE: Object.freeze({
    MANUAL: "manual",
    READY: "ready",
    DEGRADED: "degraded",
    BLOCKED: "blocked",
    UNAVAILABLE: "unavailable",
  }),
  SERVICE_MANAGER_OPERATION: Object.freeze({
    INSTALL: "install",
    UPDATE: "update",
    START: "start",
    STOP: "stop",
    RESTART: "restart",
    ROLLBACK: "rollback",
    HEALTH_CHECK: "healthCheck",
    PROMOTE: "promote",
  }),
  SERVICE_MANAGER_OPERATION_STATE: Object.freeze({
    REQUESTED: "requested",
    ACCEPTED: "accepted",
    RUNNING: "running",
    SUCCEEDED: "succeeded",
    FAILED: "failed",
    BLOCKED: "blocked",
    CANCELLED: "cancelled",
    SUPERSEDED: "superseded",
  }),
  SERVICE_MANAGER_PROOF_STATE: Object.freeze({
    PENDING: "pending",
    PROVED: "proved",
    FAILED: "failed",
    BLOCKED: "blocked",
    EXPIRED: "expired",
  }),
  SECRET_BOUNDARY: Object.freeze({
    NOT_REQUIRED: "notRequired",
    RESOLVED: "resolved",
    BLOCKED: "blocked",
    UNAVAILABLE: "unavailable",
  }),
  RELEASE_POSTURE: Object.freeze({
    STATIC: "static",
    BUILD_READY: "buildReady",
    RELEASE_READY: "releaseReady",
    ROLLBACK_READY: "rollbackReady",
    BLOCKED: "blocked",
    UNAVAILABLE: "unavailable",
  }),
  SERVICE_MANAGER_CONTRACT_STATE: Object.freeze({
    DRAFT: "draft",
    READY: "ready",
    BLOCKED: "blocked",
    SUPERSEDED: "superseded",
    EXPIRED: "expired",
  }),
  SERVICE_MANAGER_PROOF_PROFILE: Object.freeze({
    SURFACE_LANDSCAPE: "surfaceLandscape",
    NVR_LIVE_30S: "nvrLive30s",
    LONG_STREAM_10M: "longStream10m",
    LOGGING_PRESSURE: "loggingPressure",
    DIRECT_EDGE: "directEdge",
    NATIVE_CHECKS: "nativeChecks",
  }),
});

export const AGREEMENT = Object.freeze({
  PLANE: Object.freeze({
    ACTION_AUTHORITY: "actionAuthority",
    ACCESS_AUTHORITY: "accessAuthority",
    DELIVERY_WITNESS: "deliveryWitness",
    MATERIALIZATION: "materialization",
  }),
  ACTION_GRANT_STATE: Object.freeze({
    REQUESTED: "requested",
    ACCEPTED: "accepted",
    APPLIED: "applied",
    REJECTED: "rejected",
    BLOCKED: "blocked",
    EXPIRED: "expired",
    REVOKED: "revoked",
  }),
  AUTHORITY_PROOF_STATE: Object.freeze({
    PROVED: "proved",
    DEGRADED: "degraded",
    BLOCKED: "blocked",
    EXPIRED: "expired",
    REVOKED: "revoked",
  }),
  AUTHORITY_PROOF_CHECK: Object.freeze({
    SYNC: "sync",
    READ: "read",
    WRITE_REDUCE: "writeReduce",
    REVOKE_EXPIRE: "revokeExpire",
  }),
  ROOT_OPERATION: Object.freeze({
    ADD_ROOT: "addRoot",
    REFRESH_ROOT: "refreshRoot",
    ROTATE_ROOT: "rotateRoot",
    REVOKE_ROOT: "revokeRoot",
    ENROLL_DEVICE: "enrollDevice",
    REVOKE_DEVICE: "revokeDevice",
  }),
  ACCESS_EPOCH_CHANGE: Object.freeze({
    CREATE: "create",
    ADD_MEMBER: "addMember",
    REMOVE_MEMBER: "removeMember",
    ROTATE_KEY: "rotateKey",
    REVOKE_MEMBER: "revokeMember",
    PARTITION_SPLIT: "partitionSplit",
    PARTITION_MERGE: "partitionMerge",
    PURPOSE_KEY: "purposeKey",
  }),
  CONTENT_CLASS: Object.freeze({
    SAFE_FACTS: "safeFacts",
    SAFE_INDEX: "safeIndex",
    UI_PROJECTION: "uiProjection",
    ENCRYPTED_DETAIL: "encryptedDetail",
    ENCRYPTED_RAW: "encryptedRaw",
    MEDIA_REFERENCE: "mediaReference",
    DIAGNOSTIC_DETAIL: "diagnosticDetail",
  }),
  PRIVACY_TIER: Object.freeze({
    PUBLIC_SAFE: "publicSafe",
    DOMAIN_SAFE: "domainSafe",
    DOMAIN_ENCRYPTED: "domainEncrypted",
    PRIVATE_ENCRYPTED: "privateEncrypted",
  }),
  SAFE_FACT_POLICY: Object.freeze({
    NONE: "none",
    MINIMAL: "minimal",
    INDEX_ONLY: "indexOnly",
    PROJECTION_SAFE: "projectionSafe",
  }),
});

export const STORAGE = Object.freeze({
  OBJECT_HASH_ALG: "sha256-ciphertext-v1",
  CHUNK_HASH_ALG: "sha256-ciphertext-v1",
  ENCRYPTION_ALG_XCHACHA20POLY1305: "xchacha20poly1305",
  CAAC_KIND_KEY_GRANT: "storage.key_grant",
});

export const STORAGE_KEY_GRANULARITY = Object.freeze({
  CONTAINER: "container",
  SHARD: "shard",
  ENTRY: "entry",
  FIELD_FAMILY: "fieldFamily",
});

export const LOGGING = Object.freeze({
  SCHEMA_VERSION: 1,
  EVENT_ID_PREFIX: "constitute-log-event-v1",
  EVIDENCE_PROFILE_RECORD_KIND: "logging.evidence.profile",
  SEVERITY: Object.freeze({
    DEBUG: "debug",
    INFO: "info",
    NOTICE: "notice",
    WARNING: "warning",
    ERROR: "error",
    CRITICAL: "critical",
  }),
  CATEGORY: Object.freeze({
    SYSTEM: "system",
    CAPABILITY: "capability",
    SWARM_EDGE: "swarmEdge",
    HOSTED_SERVICE: "hostedService",
    GATEWAY_CONTROL: "gatewayControl",
    CAMERA_DEVICE: "cameraDevice",
    MEDIA_PROJECTION: "mediaProjection",
    RECORDING: "recording",
    WORKER: "worker",
    STORAGE: "storage",
    LOGGING: "logging",
  }),
  OUTCOME: Object.freeze({
    OBSERVED: "observed",
    SUCCEEDED: "succeeded",
    FAILED: "failed",
    DENIED: "denied",
    DEGRADED: "degraded",
    RECOVERED: "recovered",
  }),
  REDACTION: Object.freeze({
    SAFE: "safe",
    REDACTED: "redacted",
    ENCRYPTED_DETAIL: "encryptedDetail",
    SENSITIVE_OMITTED: "sensitiveOmitted",
  }),
  VERBOSITY_CLASS: Object.freeze({
    CRITICAL: "critical",
    NORMAL: "normal",
    VERBOSE: "verbose",
    NOISE: "noise",
  }),
  RETENTION_CLASS: Object.freeze({
    FOREVER: "forever",
    LONG: "long",
    ROLLING: "rolling",
    SHORT: "short",
    EPHEMERAL: "ephemeral",
  }),
  EVIDENCE_PROFILE_EVENT_CLASS: Object.freeze({
    SECURITY_AUDIT: "securityAudit",
    RUNTIME_DIAGNOSTIC: "runtimeDiagnostic",
    SERVICE_EVENT: "serviceEvent",
    STORAGE_ACCESS: "storageAccess",
    MEDIA_PATH: "mediaPath",
  }),
  EVIDENCE_DETAIL_CUSTODY: Object.freeze({
    SAFE_FACTS_ONLY: "safeFactsOnly",
    ENCRYPTED_DETAIL_REF: "encryptedDetailRef",
    ENCRYPTED_RAW_REF: "encryptedRawRef",
  }),
});

export const PROJECTION = Object.freeze({
  CHANNEL: Object.freeze({
    LOGGING_EVENTS: "logging.events",
    LOGGING_HEALTH: "logging.health",
    LOGGING_DASHBOARD: "logging.dashboard",
    DIAGNOSTICS_EVENTS: "diagnostics.events",
  }),
  FRESHNESS: Object.freeze({
    FRESH: "fresh",
    STALE: "stale",
    MISSING: "missing",
    ERROR: "error",
  }),
  SYNC_STATE: Object.freeze({
    IDLE: "idle",
    SYNCING: "syncing",
    DEGRADED: "degraded",
    STALE: "stale",
    BLOCKED: "blocked",
    COMPLETE_ENOUGH: "completeEnough",
  }),
});

export const DIAGNOSTICS = Object.freeze({
  SCHEMA_VERSION: 1,
  CHANNEL_EVENTS: "diagnostics.events",
  RUNTIME_CHANNEL: "runtime.diagnostics",
  LEVEL: Object.freeze({
    DEBUG: "debug",
    INFO: "info",
    WARN: "warn",
    ERROR: "error",
  }),
  RUNTIME_RECORD_KIND: Object.freeze({
    EVENT: "runtime.diagnostic.event",
    COMMAND: "runtime.diagnostic.command",
    COMMAND_RESULT: "runtime.diagnostic.command.result",
  }),
  RUNTIME_CAPABILITY: Object.freeze({
    OBSERVE: "runtime.diagnostics.observe",
    COMMAND: "runtime.diagnostics.command",
  }),
});

export function bytesToHex(bytes) {
  return nobleBytesToHex(bytes);
}

export function hexToBytes(hex) {
  return nobleHexToBytes(String(hex || "").trim());
}

export function utf8ToBytes(value) {
  return new TextEncoder().encode(String(value ?? ""));
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function canonicalJson(value) {
  return JSON.stringify(sortCanonical(value));
}

function sortCanonical(value) {
  if (Array.isArray(value)) return value.map(sortCanonical);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const key of Object.keys(value).sort()) {
    const next = value[key];
    if (next !== undefined) out[key] = sortCanonical(next);
  }
  return out;
}

export function sha256Hex(value) {
  const bytes = value instanceof Uint8Array ? value : utf8ToBytes(String(value ?? ""));
  return bytesToHex(sha256(bytes));
}

export function pubkeyFromSecretKey(secretKeyHex) {
  return bytesToHex(schnorr.getPublicKey(hexToBytes(secretKeyHex)));
}

export function compressedPublicKeyFromXOnly(xonlyHex) {
  return `02${String(xonlyHex || "").trim()}`;
}

export function buildBootstrapNostrUnsignedEvent({ pubkey, kind, tags = [], content = "", created_at }) {
  return {
    pubkey: String(pubkey || ""),
    created_at: Number(created_at || nowSeconds()),
    kind: Number(kind || 0),
    tags: Array.isArray(tags) ? tags : [],
    content: String(content ?? ""),
  };
}

export function bootstrapNostrEventIdHex(unsigned) {
  return sha256Hex(JSON.stringify([
    0,
    unsigned.pubkey,
    unsigned.created_at,
    unsigned.kind,
    unsigned.tags || [],
    unsigned.content || "",
  ]));
}

export function signBootstrapNostrEvent(unsigned, secretKeyHex) {
  const id = bootstrapNostrEventIdHex(unsigned);
  const sig = schnorr.sign(hexToBytes(id), hexToBytes(secretKeyHex));
  return {
    id,
    pubkey: unsigned.pubkey,
    created_at: unsigned.created_at,
    kind: unsigned.kind,
    tags: unsigned.tags || [],
    content: unsigned.content || "",
    sig: bytesToHex(sig),
  };
}

export function verifyBootstrapNostrEvent(event) {
  const unsigned = buildBootstrapNostrUnsignedEvent(event);
  if (bootstrapNostrEventIdHex(unsigned) !== event.id) return false;
  return schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey));
}

export function buildBootstrapNostrEvent({ secretKey, kind, tags = [], content = "", created_at = nowSeconds() }) {
  const pubkey = pubkeyFromSecretKey(secretKey);
  return signBootstrapNostrEvent(buildBootstrapNostrUnsignedEvent({ pubkey, kind, tags, content, created_at }), secretKey);
}

function deriveRecipientKey({ issuerSecretKey, recipientPk, kind, envelopeId }) {
  const recipientCompressed = hexToBytes(compressedPublicKeyFromXOnly(recipientPk));
  const shared = secp256k1.getSharedSecret(hexToBytes(issuerSecretKey), recipientCompressed, true).slice(1, 33);
  const info = utf8ToBytes(`constitute-caac-v1|${kind}|${envelopeId}|${pubkeyFromSecretKey(issuerSecretKey)}|${recipientPk}`);
  return hkdf(sha256, shared, utf8ToBytes("constitute-caac-v1"), info, 32);
}

function deriveOpenKey({ recipientSecretKey, issuerPk, recipientPk, kind, envelopeId }) {
  const issuerCompressed = hexToBytes(compressedPublicKeyFromXOnly(issuerPk));
  const shared = secp256k1.getSharedSecret(hexToBytes(recipientSecretKey), issuerCompressed, true).slice(1, 33);
  const info = utf8ToBytes(`constitute-caac-v1|${kind}|${envelopeId}|${issuerPk}|${recipientPk}`);
  return hkdf(sha256, shared, utf8ToBytes("constitute-caac-v1"), info, 32);
}

function recipientAad({ kind, envelopeId, issuerPk, recipientPk }) {
  return utf8ToBytes(`caac-v1|${kind}|${envelopeId}|${issuerPk}|${recipientPk}`);
}

export function unsignedEnvelope(envelope) {
  return {
    alg: envelope.alg,
    envelopeId: envelope.envelopeId,
    expiresAt: envelope.expiresAt,
    issuedAt: envelope.issuedAt,
    issuerPk: envelope.issuerPk,
    kind: envelope.kind,
    recipients: envelope.recipients || [],
    version: envelope.version,
  };
}

export function envelopeSigningDigest(envelope) {
  return sha256(utf8ToBytes(canonicalJson(unsignedEnvelope(envelope))));
}

export function signEnvelope(envelope, issuerSecretKey) {
  return bytesToHex(schnorr.sign(envelopeSigningDigest(envelope), hexToBytes(issuerSecretKey)));
}

export function verifyEnvelopeSignature(envelope) {
  if (!envelope?.signature) return false;
  return schnorr.verify(hexToBytes(envelope.signature), envelopeSigningDigest(envelope), hexToBytes(envelope.issuerPk));
}

export function sealEnvelope({
  kind,
  claims,
  issuerSecretKey,
  recipientPks,
  issuedAt = nowSeconds(),
  expiresAt = issuedAt + DEFAULT_REQUEST_TTL_SECONDS,
  envelopeId = bytesToHex(randomBytes(16)),
  nonces = [],
} = {}) {
  const issuerPk = pubkeyFromSecretKey(issuerSecretKey);
  const plaintext = utf8ToBytes(canonicalJson(claims || {}));
  const recipients = [];
  for (const [index, recipientPk] of Array.from(new Set(recipientPks || [])).entries()) {
    const nonce = nonces[index] ? hexToBytes(nonces[index]) : randomBytes(24);
    const key = deriveRecipientKey({ issuerSecretKey, recipientPk, kind, envelopeId });
    const cipher = xchacha20poly1305(key, nonce, recipientAad({ kind, envelopeId, issuerPk, recipientPk }));
    const ciphertext = cipher.encrypt(plaintext);
    recipients.push({
      recipientPk: String(recipientPk),
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ciphertext),
    });
  }
  const envelope = {
    version: CAAC_VERSION,
    kind: String(kind || ""),
    envelopeId,
    issuerPk,
    issuedAt,
    expiresAt,
    alg: CAAC_ALG_V1,
    recipients,
  };
  envelope.signature = signEnvelope(envelope, issuerSecretKey);
  return envelope;
}

export function openEnvelope(envelope, recipientSecretKey, { now = nowSeconds(), replayCache } = {}) {
  if (!envelope || envelope.version !== CAAC_VERSION) throw new Error("unsupported caac envelope version");
  if (envelope.alg !== CAAC_ALG_V1) throw new Error("unsupported caac envelope algorithm");
  if (Number(envelope.expiresAt || 0) <= now) throw new Error("caac envelope expired");
  if (!verifyEnvelopeSignature(envelope)) throw new Error("invalid caac envelope signature");
  if (replayCache) {
    if (replayCache.has(envelope.envelopeId)) throw new Error("caac envelope replayed");
    replayCache.add(envelope.envelopeId);
  }
  const recipientPk = pubkeyFromSecretKey(recipientSecretKey);
  const recipient = (envelope.recipients || []).find((entry) => entry.recipientPk === recipientPk);
  if (!recipient) throw new Error("caac envelope recipient mismatch");
  const key = deriveOpenKey({
    recipientSecretKey,
    issuerPk: envelope.issuerPk,
    recipientPk,
    kind: envelope.kind,
    envelopeId: envelope.envelopeId,
  });
  const cipher = xchacha20poly1305(
    key,
    hexToBytes(recipient.nonce),
    recipientAad({ kind: envelope.kind, envelopeId: envelope.envelopeId, issuerPk: envelope.issuerPk, recipientPk }),
  );
  const plaintext = cipher.decrypt(hexToBytes(recipient.ciphertext));
  return JSON.parse(bytesToUtf8(plaintext));
}

export class ReplayCache {
  constructor() {
    this.ids = new Set();
  }

  has(id) {
    return this.ids.has(String(id));
  }

  add(id) {
    this.ids.add(String(id));
  }
}

export function storageCiphertextHash(bytes) {
  return sha256Hex(bytes instanceof Uint8Array ? bytes : utf8ToBytes(String(bytes ?? "")));
}

export function storageObjectId({ containerId = "", contentHash = "" } = {}) {
  return sha256Hex(`constitute-storage-object-v1|${String(containerId).trim()}|${String(contentHash).trim()}`);
}

export function storageChunkId(hash) {
  return sha256Hex(`constitute-storage-chunk-v1|${String(hash || "").trim()}`);
}

export function makeStorageChunkRef({ ciphertext, chunkId } = {}) {
  const bytes = ciphertext instanceof Uint8Array ? ciphertext : utf8ToBytes(String(ciphertext ?? ""));
  const hash = storageCiphertextHash(bytes);
  return {
    chunkId: chunkId || storageChunkId(hash),
    hash,
    hashAlg: STORAGE.CHUNK_HASH_ALG,
    size: bytes.length,
  };
}

export function assertStorageChunkRef(chunk, ciphertext) {
  if (!chunk || typeof chunk !== "object") throw new Error("storage chunk ref must be an object");
  if (chunk.hashAlg !== STORAGE.CHUNK_HASH_ALG) throw new Error("unsupported storage chunk hash algorithm");
  const bytes = ciphertext instanceof Uint8Array ? ciphertext : utf8ToBytes(String(ciphertext ?? ""));
  if (Number(chunk.size) !== bytes.length) throw new Error("storage chunk size mismatch");
  if (chunk.hash !== storageCiphertextHash(bytes)) throw new Error("storage chunk hash mismatch");
  if (chunk.chunkId !== storageChunkId(chunk.hash)) throw new Error("storage chunk id mismatch");
  return chunk;
}

export function assertStorageObjectManifest(manifest) {
  if (!manifest || typeof manifest !== "object") throw new Error("storage manifest must be an object");
  if (!String(manifest.containerId || "").trim()) throw new Error("storage manifest missing container id");
  if (!String(manifest.contentHash || "").trim()) throw new Error("storage manifest missing content hash");
  if (manifest.hashAlg !== STORAGE.OBJECT_HASH_ALG) throw new Error("unsupported storage object hash algorithm");
  if (manifest.encryptionAlg !== STORAGE.ENCRYPTION_ALG_XCHACHA20POLY1305) {
    throw new Error("unsupported storage object encryption algorithm");
  }
  if (!String(manifest.keyRef || "").trim()) throw new Error("storage manifest missing key ref");
  if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
    throw new Error("storage manifest has no chunks");
  }
  if (manifest.objectId !== storageObjectId({ containerId: manifest.containerId, contentHash: manifest.contentHash })) {
    throw new Error("storage object id mismatch");
  }
  return manifest;
}

export function makeStorageObjectManifest({
  containerId,
  keyRef,
  chunks,
  createdAt = nowSeconds(),
  mediaType = "application/octet-stream",
  tags = [],
  encryptionAlg = STORAGE.ENCRYPTION_ALG_XCHACHA20POLY1305,
} = {}) {
  const chunkRefs = chunks || [];
  const contentHash = storageCiphertextHash(utf8ToBytes(canonicalJson(chunkRefs.map((chunk) => chunk.hash))));
  const manifest = {
    objectId: storageObjectId({ containerId, contentHash }),
    containerId,
    contentHash,
    hashAlg: STORAGE.OBJECT_HASH_ALG,
    encryptionAlg,
    keyRef,
    chunks: chunkRefs,
    createdAt,
    mediaType,
    tags,
  };
  return assertStorageObjectManifest(manifest);
}

export function assertStorageIndexShard(shard) {
  if (!shard || typeof shard !== "object") throw new Error("storage index shard must be an object");
  if (!String(shard.shardId || "").trim()) throw new Error("storage index shard missing id");
  if (!String(shard.containerId || "").trim()) throw new Error("storage index shard missing container id");
  if (!String(shard.keyRef || "").trim()) throw new Error("storage index shard missing key ref");
  if (shard.hashAlg !== STORAGE.OBJECT_HASH_ALG) throw new Error("unsupported storage index shard hash algorithm");
  if (!String(shard.ciphertextHash || "").trim()) throw new Error("storage index shard missing ciphertext hash");
  if (!Array.isArray(shard.chunks) || shard.chunks.length === 0) throw new Error("storage index shard has no chunks");
  return shard;
}

const SENSITIVE_SAFE_FACT_KEY_FRAGMENTS = [
  "argv",
  "body",
  "caac",
  "capabilitygrant",
  "credential",
  "decrypted",
  "password",
  "payload",
  "private",
  "raw",
  "rtsp",
  "secret",
  "servicecapability",
  "token",
];

function withoutLogComputedFields(event) {
  const clone = { ...(event || {}) };
  delete clone.eventId;
  delete clone.receivedAt;
  return clone;
}

export function logEventId(event) {
  return sha256Hex(`${LOGGING.EVENT_ID_PREFIX}|${canonicalJson(withoutLogComputedFields(event))}`);
}

export function rejectSensitiveSafeFacts(value) {
  if (Array.isArray(value)) {
    for (const item of value) rejectSensitiveSafeFacts(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, next] of Object.entries(value)) {
    const lowered = String(key).toLowerCase();
    if (SENSITIVE_SAFE_FACT_KEY_FRAGMENTS.some((fragment) => lowered.includes(fragment))) {
      throw new Error(`unsafe log safe fact key: ${key}`);
    }
    rejectSensitiveSafeFacts(next);
  }
}

export function assertEncryptedDetailRef(ref, context = "encrypted detail ref") {
  if (!ref || typeof ref !== "object" || Array.isArray(ref)) throw new Error(`${context} must be an object`);
  for (const field of ["objectId", "containerId", "keyRef", "manifestHash"]) {
    if (!String(ref[field] || "").trim()) throw new Error(`${context} missing ${field}`);
  }
  if (ref.summaryTags !== undefined) {
    if (!Array.isArray(ref.summaryTags)) throw new Error(`${context} summaryTags must be an array`);
    for (const tag of ref.summaryTags) {
      if (!String(tag || "").trim()) throw new Error(`${context} summaryTags must be non-empty strings`);
    }
  }
  return ref;
}

export function assertLogEventEnvelope(event) {
  if (!event || typeof event !== "object") throw new Error("log event must be an object");
  if (event.schemaVersion !== LOGGING.SCHEMA_VERSION) throw new Error("unsupported log schema version");
  if (!String(event.eventId || "").trim()) throw new Error("log event missing event id");
  if (!Number(event.occurredAt || 0)) throw new Error("log event missing occurred timestamp");
  if (!event.producer || typeof event.producer !== "object") throw new Error("log event missing producer");
  if (!String(event.producer.service || "").trim()) throw new Error("log event missing producer service");
  if (!String(event.producer.component || "").trim()) throw new Error("log event missing producer component");
  const severities = Object.values(LOGGING.SEVERITY);
  const categories = Object.values(LOGGING.CATEGORY);
  const outcomes = Object.values(LOGGING.OUTCOME);
  if (!severities.includes(event.severity)) throw new Error("invalid log severity");
  if (!categories.includes(event.category)) throw new Error("invalid log category");
  if (!outcomes.includes(event.outcome)) throw new Error("invalid log outcome");
  if (!event.safeFacts || typeof event.safeFacts !== "object" || Array.isArray(event.safeFacts)) {
    throw new Error("log safe facts must be an object");
  }
  rejectSensitiveSafeFacts(event.safeFacts);
  if (event.detailRef !== undefined) assertEncryptedDetailRef(event.detailRef, "log detailRef");
  if (event.encryptedDetailRefs !== undefined) {
    if (!Array.isArray(event.encryptedDetailRefs)) throw new Error("log encryptedDetailRefs must be an array");
    for (const ref of event.encryptedDetailRefs) assertEncryptedDetailRef(ref, "log encryptedDetailRefs entry");
  }
  if (event.eventId !== logEventId(event)) throw new Error("log event id mismatch");
  return event;
}

export function assertLogEvidenceProfile(profile) {
  if (!isObject(profile)) throw new Error("log evidence profile must be an object");
  assertRecordKind(profile, LOGGING.EVIDENCE_PROFILE_RECORD_KIND, "log evidence profile");
  requireString(profile.profileId, "log evidence profile profileId");
  requireString(profile.consumerRef, "log evidence profile consumerRef");
  const eventClasses = requireNonEmptyArray(profile.eventClasses, "log evidence profile eventClasses")
    .map((eventClass) => requireString(eventClass, "log evidence profile eventClass"));
  const allowedClasses = Object.values(LOGGING.EVIDENCE_PROFILE_EVENT_CLASS);
  for (const eventClass of eventClasses) {
    if (!allowedClasses.includes(eventClass)) throw new Error("invalid log evidence profile eventClass");
  }
  requireString(profile.retentionWindow, "log evidence profile retentionWindow");
  assertReferenceList(profile.safeIndexRefs, "log evidence profile safeIndexRefs");
  const detailCustody = requireString(profile.detailCustody, "log evidence profile detailCustody");
  if (!Object.values(LOGGING.EVIDENCE_DETAIL_CUSTODY).includes(detailCustody)) {
    throw new Error("invalid log evidence profile detailCustody");
  }
  if (typeof profile.encryptedDetailRequired !== "boolean") {
    throw new Error("log evidence profile encryptedDetailRequired must be boolean");
  }
  const accessGrantRefs = assertOptionalReferenceList(profile.accessGrantRefs, "log evidence profile accessGrantRefs");
  const storageContainerRefs = assertOptionalReferenceList(profile.storageContainerRefs, "log evidence profile storageContainerRefs");
  if (profile.encryptedDetailRequired && accessGrantRefs.length === 0) {
    throw new Error("encrypted log evidence profile requires accessGrantRefs");
  }
  if (profile.encryptedDetailRequired && storageContainerRefs.length === 0) {
    throw new Error("encrypted log evidence profile requires storageContainerRefs");
  }
  if (profile.materializationBudgetRef !== undefined) {
    requireString(profile.materializationBudgetRef, "log evidence profile materializationBudgetRef");
  }
  if (!Number(profile.issuedAt || 0)) throw new Error("log evidence profile missing issuedAt");
  if (profile.expiresAt !== undefined && Number(profile.expiresAt) <= Number(profile.issuedAt)) {
    throw new Error("log evidence profile expiresAt must be after issuedAt");
  }
  rejectForbiddenKeys(profile, new Set([
    "secret",
    "password",
    "token",
    "privateKey",
    "secretKey",
    "value",
    "contents",
    "rawPayload",
    "rawEvent",
    "payloadBytes",
    "body",
  ]), "log evidence profile");
  rejectMediaByteFields(profile, "log evidence profile");
  return {
    ...profile,
    eventClasses,
    detailCustody,
    accessGrantRefs,
    storageContainerRefs,
  };
}

export function makeLogEventEnvelope({
  occurredAt = nowSeconds(),
  receivedAt,
  producer,
  category = LOGGING.CATEGORY.SYSTEM,
  severity = LOGGING.SEVERITY.INFO,
  outcome = LOGGING.OUTCOME.OBSERVED,
  subject,
  resource,
  correlation,
  tags = [],
  safeFacts = {},
  detailRef,
  encryptedDetailRefs = [],
  redaction = [LOGGING.REDACTION.SAFE],
} = {}) {
  const event = {
    schemaVersion: LOGGING.SCHEMA_VERSION,
    eventId: "",
    occurredAt,
    producer,
    category,
    severity,
    outcome,
    tags,
    safeFacts,
    redaction,
  };
  if (receivedAt !== undefined) event.receivedAt = receivedAt;
  if (subject) event.subject = subject;
  if (resource) event.resource = resource;
  if (correlation) event.correlation = correlation;
  if (detailRef) event.detailRef = detailRef;
  if (encryptedDetailRefs?.length) event.encryptedDetailRefs = encryptedDetailRefs;
  event.eventId = logEventId(event);
  return assertLogEventEnvelope(event);
}

const UNSAFE_SAFE_FACT_KEY_RE = /(password|credential|secret|token|capabilitygrant|servicecapability|privatekey|secretkey|sdp|rtspurl|cameraurl|serviceprivateurl|authorization|rawpayload|requestbody)/i;
const UNSAFE_SAFE_FACT_VALUE_RE = /(rtsp:\/\/|authorization:|servicecapability|-----begin)/i;

export function rejectUnsafeSafeFacts(value, path = "") {
  if (value == null) return;
  if (Array.isArray(value)) {
    for (const item of value) rejectUnsafeSafeFacts(item, path);
    return;
  }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (UNSAFE_SAFE_FACT_KEY_RE.test(key)) throw new Error(`unsafe safe fact key: ${path}${key}`);
      rejectUnsafeSafeFacts(child, `${path}${key}.`);
    }
    return;
  }
  if (typeof value === "string" && UNSAFE_SAFE_FACT_VALUE_RE.test(value)) {
    throw new Error("unsafe safe fact value");
  }
}

export function assertHostedServiceDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== "object") throw new Error("service descriptor must be an object");
  if (!String(descriptor.service || "").trim()) throw new Error("service descriptor missing service");
  if (!String(descriptor.servicePk || "").trim()) throw new Error("service descriptor missing servicePk");
  if (!String(descriptor.hostGatewayPk || "").trim()) throw new Error("service descriptor missing hostGatewayPk");
  if (!String(descriptor.surfaceChannel || "").trim()) throw new Error("service descriptor missing surfaceChannel");
  if (descriptor.location !== undefined) assertServiceLocationRef(descriptor.location);
  if (descriptor.aliases !== undefined && !Array.isArray(descriptor.aliases)) throw new Error("service descriptor aliases must be an array");
  if (descriptor.nodes !== undefined && !Array.isArray(descriptor.nodes)) throw new Error("service descriptor nodes must be an array");
  return descriptor;
}

export function assertServiceLocationRef(location) {
  if (!location || typeof location !== "object") throw new Error("service location must be an object");
  if (!String(location.locationId || "").trim()) throw new Error("service location missing locationId");
  if (!String(location.label || "").trim()) throw new Error("service location missing label");
  if (!String(location.gatewayPk || "").trim()) throw new Error("service location missing gatewayPk");
  return location;
}

export function assertServiceNodeFieldDescriptor(field) {
  if (!field || typeof field !== "object") throw new Error("service node field must be an object");
  if (!String(field.fieldId || "").trim()) throw new Error("service node field missing fieldId");
  if (!String(field.label || "").trim()) throw new Error("service node field missing label");
  const capabilities = field.capabilities ?? [];
  if (!Array.isArray(capabilities) || capabilities.length === 0) throw new Error("service node field missing capabilities");
  for (const capability of capabilities) {
    if (!Object.values(SERVICE_SURFACE.FIELD_CAPABILITY).includes(capability)) {
      throw new Error("invalid service node field capability");
    }
  }
  const schema = field.schema ?? {};
  if (schema && (typeof schema !== "object" || Array.isArray(schema))) throw new Error("service node field schema must be an object");
  return field;
}

export function assertServiceNodeDescriptor(node) {
  if (!node || typeof node !== "object") throw new Error("service node must be an object");
  if (!String(node.nodeId || "").trim()) throw new Error("service node missing nodeId");
  if (!String(node.path || "").trim()) throw new Error("service node missing path");
  if (!String(node.label || "").trim()) throw new Error("service node missing label");
  if (node.aliases !== undefined && !Array.isArray(node.aliases)) throw new Error("service node aliases must be an array");
  if (node.children !== undefined && !Array.isArray(node.children)) throw new Error("service node children must be an array");
  for (const field of node.fields || []) assertServiceNodeFieldDescriptor(field);
  return node;
}

export function assertServiceSurfaceProjection(surface) {
  if (!surface || typeof surface !== "object") throw new Error("service surface must be an object");
  if (!String(surface.surfaceId || "").trim()) throw new Error("service surface missing surfaceId");
  if (!Number(surface.schemaVersion || 0)) throw new Error("service surface missing schemaVersion");
  if (!String(surface.service || "").trim()) throw new Error("service surface missing service");
  if (!String(surface.servicePk || "").trim()) throw new Error("service surface missing servicePk");
  if (!String(surface.hostGatewayPk || "").trim()) throw new Error("service surface missing hostGatewayPk");
  if (surface.location !== undefined) assertServiceLocationRef(surface.location);
  if (!String(surface.summary || "").trim()) throw new Error("service surface missing summary");
  if (!String(surface.healthNode || "").trim()) throw new Error("service surface missing healthNode");
  if (!Number(surface.updatedAt || 0)) throw new Error("service surface missing updatedAt");
  const nodes = surface.nodes ?? [];
  if (!Array.isArray(nodes) || nodes.length === 0) throw new Error("service surface must describe at least one node");
  for (const node of nodes) assertServiceNodeDescriptor(node);
  if (!findServiceNode(surface, surface.healthNode)) throw new Error("service surface healthNode does not match a node");
  return surface;
}

export function findServiceNode(surface, nodePath) {
  const value = String(nodePath || "").trim();
  return (surface?.nodes || []).find((node) => String(node.path || "").trim() === value
    || (node.aliases || []).some((alias) => String(alias || "").trim() === value));
}

export function assertServiceAttachDescriptor(attach) {
  if (!attach || typeof attach !== "object") throw new Error("service attach descriptor must be an object");
  if (!String(attach.attachId || "").trim()) throw new Error("service attach descriptor missing attachId");
  if (!String(attach.label || "").trim()) throw new Error("service attach descriptor missing label");
  if (!String(attach.attachKind || "").trim()) throw new Error("service attach descriptor missing attachKind");
  return attach;
}

export function assertServiceNodeProjectionRecord(record, surface) {
  if (!record || typeof record !== "object") throw new Error("service node projection must be an object");
  assertServiceSurfaceProjection(surface);
  if (String(record.service || "").trim() !== String(surface.service || "").trim()) throw new Error("service node projection service mismatch");
  if (String(record.servicePk || "").trim() !== String(surface.servicePk || "").trim()) throw new Error("service node projection servicePk mismatch");
  if (!findServiceNode(surface, record.nodePath)) throw new Error("service node projection targets unknown node");
  assertProjectionFreshness(record.freshness);
  for (const field of ["payload", "fields", "desired", "status", "result", "safeFacts"]) {
    const value = record[field] ?? {};
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`service node projection ${field} must be an object`);
  }
  for (const attach of record.attaches || []) assertServiceAttachDescriptor(attach);
  rejectUnsafeSafeFacts(record.safeFacts ?? {});
  return record;
}

export function assertServiceNodeSetRequest(request, surface) {
  if (!request || typeof request !== "object") throw new Error("service node set request must be an object");
  assertServiceSurfaceProjection(surface);
  if (!String(request.requestId || "").trim()) throw new Error("service node set missing requestId");
  if (String(request.service || "").trim() !== String(surface.service || "").trim()) throw new Error("service node set service mismatch");
  const node = findServiceNode(surface, request.nodePath);
  if (!node) throw new Error("service node set targets unknown node");
  const desired = request.desired ?? {};
  if (!desired || typeof desired !== "object" || Array.isArray(desired)) throw new Error("service node set desired must be an object");
  for (const fieldId of Object.keys(desired)) {
    const field = (node.fields || []).find((candidate) => candidate.fieldId === fieldId);
    if (!field) throw new Error("service node set targets unknown field");
    if (!(field.capabilities || []).includes(SERVICE_SURFACE.FIELD_CAPABILITY.SET)) {
      throw new Error("service node field is not settable");
    }
  }
  return request;
}

export function assertProjectionChannelId(channelId, descriptor) {
  const value = String(channelId || "").trim();
  if (!value) throw new Error("projection missing channel id");
  const descriptorChannels = Array.isArray(descriptor?.allowedProjectionChannels) ? descriptor.allowedProjectionChannels : [];
  if (descriptorChannels.length > 0) {
    if (!descriptorChannels.includes(value)) throw new Error("unsupported projection channel");
    return value;
  }
  return value;
}

export function assertProjectionFreshness(freshness) {
  if (!freshness || typeof freshness !== "object") throw new Error("projection freshness must be an object");
  if (!Object.values(PROJECTION.FRESHNESS).includes(freshness.state)) throw new Error("invalid projection freshness state");
  if (!Number(freshness.updatedAt || 0)) throw new Error("projection freshness missing updatedAt");
  return freshness;
}

export function assertServiceProjectionRequest(request, descriptor) {
  if (!request || typeof request !== "object") throw new Error("service projection request must be an object");
  if (!String(request.requestId || "").trim()) throw new Error("service projection missing requestId");
  assertProjectionChannelId(request.channelId, descriptor);
  if (!String(request.service || "").trim()) throw new Error("service projection missing service");
  const filters = request.filters ?? {};
  if (!filters || typeof filters !== "object" || Array.isArray(filters)) {
    throw new Error("service projection filters must be an object");
  }
  if (request.policy !== undefined) {
    assertProjectionPolicy(request.policy, descriptor);
    if (request.policy.channelId !== request.channelId) throw new Error("projection policy channel mismatch");
    if (request.policy.service !== request.service) throw new Error("projection policy service mismatch");
  }
  return request;
}

export function assertProjectionPolicy(policy, descriptor) {
  if (!policy || typeof policy !== "object") throw new Error("projection policy must be an object");
  if (!String(policy.policyId || "").trim()) throw new Error("projection policy missing policyId");
  assertProjectionChannelId(policy.channelId, descriptor);
  if (!String(policy.service || "").trim()) throw new Error("projection policy missing service");
  const scope = policy.scope ?? {};
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) throw new Error("projection policy scope must be an object");
  if (policy.rollingWindowHours !== undefined && Number(policy.rollingWindowHours) <= 0) {
    throw new Error("projection policy rolling window must be positive");
  }
  if (policy.maxVerbosityClass !== undefined && !Object.values(LOGGING.VERBOSITY_CLASS).includes(policy.maxVerbosityClass)) {
    throw new Error("invalid projection policy verbosity class");
  }
  if (policy.minSeverity !== undefined && !Object.values(LOGGING.SEVERITY).includes(policy.minSeverity)) {
    throw new Error("invalid projection policy severity");
  }
  const excluded = policy.excludedVerbosityClasses ?? [];
  if (!Array.isArray(excluded)) throw new Error("projection policy excluded verbosity classes must be an array");
  for (const value of excluded) {
    if (!Object.values(LOGGING.VERBOSITY_CLASS).includes(value)) throw new Error("invalid projection policy excluded verbosity class");
  }
  for (const [field, value] of Object.entries({
    syncDepthTarget: policy.syncDepthTarget ?? {},
    retentionTarget: policy.retentionTarget ?? {},
  })) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`projection policy ${field} must be an object`);
    }
  }
  return policy;
}

export function makeProjectionPolicy({
  policyId,
  channelId,
  service,
  scope = {},
  rollingWindowHours,
  maxVerbosityClass,
  minSeverity,
  excludedVerbosityClasses = [],
  syncDepthTarget = {},
  retentionTarget = {},
} = {}) {
  return assertProjectionPolicy({
    policyId,
    channelId,
    service,
    scope,
    ...(rollingWindowHours !== undefined ? { rollingWindowHours: Number(rollingWindowHours) } : {}),
    ...(maxVerbosityClass ? { maxVerbosityClass } : {}),
    ...(minSeverity ? { minSeverity } : {}),
    excludedVerbosityClasses,
    syncDepthTarget,
    retentionTarget,
  });
}

export function assertProjectionCoverage(coverage) {
  if (!coverage || typeof coverage !== "object") throw new Error("projection coverage must be an object");
  if (!Number.isFinite(Number(coverage.materializedCount)) || Number(coverage.materializedCount) < 0) {
    throw new Error("projection coverage invalid materialized count");
  }
  if (coverage.targetCount !== undefined && (!Number.isFinite(Number(coverage.targetCount)) || Number(coverage.targetCount) < 0)) {
    throw new Error("projection coverage invalid target count");
  }
  const ratio = Number(coverage.completionRatio);
  if (!Number.isFinite(ratio) || ratio < 0 || ratio > 1) {
    throw new Error("projection coverage completion ratio must be 0..1");
  }
  if (!Object.values(PROJECTION.SYNC_STATE).includes(coverage.syncState)) {
    throw new Error("invalid projection sync state");
  }
  if (coverage.completeSeverityBands !== undefined && !Array.isArray(coverage.completeSeverityBands)) {
    throw new Error("projection coverage severity bands must be an array");
  }
  return coverage;
}

export function makeProjectionCoverage({
  materializedCount = 0,
  targetCount,
  completionRatio = 0,
  completeSeverityBands = [],
  oldestObservedAt,
  newestObservedAt,
  syncState = PROJECTION.SYNC_STATE.IDLE,
} = {}) {
  return assertProjectionCoverage({
    materializedCount: Number(materializedCount),
    ...(targetCount !== undefined ? { targetCount: Number(targetCount) } : {}),
    completionRatio: Number(completionRatio),
    completeSeverityBands,
    ...(oldestObservedAt !== undefined ? { oldestObservedAt: Number(oldestObservedAt) } : {}),
    ...(newestObservedAt !== undefined ? { newestObservedAt: Number(newestObservedAt) } : {}),
    syncState,
  });
}

export function assertProjectionObserverUpdate(update) {
  if (!update || typeof update !== "object") throw new Error("projection observer update must be an object");
  if (!String(update.projectionKey || "").trim()) throw new Error("projection observer update missing projection key");
  if (!Number.isFinite(Number(update.changedCount)) || Number(update.changedCount) < 0) {
    throw new Error("projection observer update invalid changed count");
  }
  assertProjectionCoverage(update.coverage);
  assertProjectionFreshness(update.freshness);
  if (update.diagnostics !== undefined && !Array.isArray(update.diagnostics)) {
    throw new Error("projection observer diagnostics must be an array");
  }
  return update;
}

export function makeProjectionObserverUpdate({
  projectionKey,
  changedCount = 0,
  coverage,
  freshness,
  diagnostics = [],
} = {}) {
  return assertProjectionObserverUpdate({
    projectionKey,
    changedCount: Number(changedCount),
    coverage,
    freshness,
    diagnostics,
  });
}

export function assertProjectionRecord(result, descriptor) {
  if (!result || typeof result !== "object") throw new Error("projection record must be an object");
  assertProjectionChannelId(result.channelId, descriptor);
  if (!String(result.service || "").trim()) throw new Error("projection record missing service");
  if (!String(result.servicePk || "").trim()) throw new Error("projection record missing servicePk");
  assertProjectionFreshness(result.freshness);
  const payload = result.payload ?? {};
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("projection record payload must be an object");
  }
  rejectUnsafeSafeFacts(result.safeFacts ?? {});
  return result;
}

export function makeProjectionRecord({
  channelId,
  service,
  servicePk,
  producer = {},
  cursor,
  freshness,
  scope = {},
  payloadSchema,
  payload = {},
  safeFacts = {},
  encryptedDetailRefs = [],
  diagnostics = [],
} = {}) {
  return assertProjectionRecord({
    channelId,
    service,
    servicePk,
    producer,
    ...(cursor ? { cursor } : {}),
    freshness,
    scope,
    ...(payloadSchema ? { payloadSchema } : {}),
    payload,
    safeFacts,
    encryptedDetailRefs,
    diagnostics,
  });
}

export function assertDiagnosticEvent(event) {
  if (!event || typeof event !== "object") throw new Error("diagnostic event must be an object");
  if (!String(event.diagnosticId || "").trim()) throw new Error("diagnostic missing diagnosticId");
  if (!Number(event.schemaVersion || 0)) throw new Error("diagnostic missing schemaVersion");
  if (!Number(event.occurredAt || 0)) throw new Error("diagnostic missing occurredAt");
  if (!Object.values(DIAGNOSTICS.LEVEL).includes(String(event.level || "").trim())) throw new Error("invalid diagnostic level");
  if (!String(event.operation || "").trim()) throw new Error("diagnostic missing operation");
  rejectUnsafeSafeFacts(event.safeFacts ?? {});
  return event;
}

export const SWARM = Object.freeze({
  FRAME_VERSION: 1,
  WIRE_KIND: Object.freeze({
    FRAME: "swarm.frame",
    EDGE_HELLO: "swarm.edge.hello",
    EDGE_RESUME: "swarm.edge.resume",
    EDGE_ACCEPT: "swarm.edge.accept",
    EDGE_CLOSE: "swarm.edge.close",
  }),
  BODY_ENCODING: Object.freeze({
    CAAC: "caac",
    PUBLIC: "public",
  }),
  FRAME_KIND: Object.freeze({
    RECORD_PUBLISH: "record.publish",
    RECORD_RETRACT: "record.retract",
    CHANNEL_OBSERVE: "channel.observe",
    CHANNEL_UNOBSERVE: "channel.unobserve",
    PROJECTION_SNAPSHOT: "projection.snapshot",
    PROJECTION_DELTA: "projection.delta",
    PROJECTION_REPAIR_REQUEST: "projection.repair.request",
    SERVICE_INTENT: "service.intent",
    SERVICE_RESPONSE: "service.response",
    STREAM_INTENT: "stream.intent",
    STREAM_CONTROL: "stream.control",
    STREAM_STATUS: "stream.status",
    STORAGE_PIN_INTENT: "storage.pin.intent",
    STORAGE_PIN_ATTESTATION: "storage.pin.attestation",
    NODE_CAPABILITY: "node.capability",
    RUNTIME_ACTIVATION_REQUEST: "runtime.activation.request",
    ROUTE_PROMISE: "route.promise",
    ROUTE_OBSERVATION: "route.observation",
    STREAM_ROUTE_PLAN: "stream.routePlan",
    RUNTIME_DIAGNOSTIC_EVENT: "runtime.diagnostic.event",
    RUNTIME_DIAGNOSTIC_COMMAND: "runtime.diagnostic.command",
    RUNTIME_DIAGNOSTIC_COMMAND_RESULT: "runtime.diagnostic.command.result",
    ACK: "ack",
    REJECT: "reject",
    SWARM_IDENTITY: "swarm.identity",
    SWARM_DEVICE: "swarm.device",
    SWARM_GATEWAY: "swarm.gateway",
    SWARM_SERVICE: "swarm.service",
    SWARM_MEMBER: "swarm.member",
    SWARM_GRANT: "swarm.grant",
    SWARM_ROLE: "swarm.role",
    SWARM_INTERACTION: "swarm.interaction",
    SWARM_ACTIVATION: "swarm.activation",
    SWARM_RELEASE: "swarm.release",
    SWARM_REVOCATION: "swarm.revocation",
    AUTHORITY_ROOT_OPERATION: "authority.root.operation",
    AUTHORITY_ACTION_GRANT: "authority.action.grant",
    AUTHORITY_ACTION_EXERCISE: "authority.action.exercise",
    AUTHORITY_GRANT_REVOCATION_POSTURE: "authority.grant.revocationPosture",
    AUTHORITY_MULTI_IDENTITY_PROOF: "authority.multiIdentity.proof",
    ACCESS_GROUP: "access.group",
    ACCESS_EPOCH: "access.epoch",
    PRIVATE_CONTENT_ENVELOPE: "private.content.envelope",
    EVENT_FABRIC_ACCESS_CLASS: "event.fabric.accessClass",
    PARTICIPANT_RUNLEVEL: "participant.runlevel",
    PARTICIPANT_SELF_CAPABILITY: "participant.selfCapability",
    INGRESS_LANE_POSTURE: "ingress.lane.posture",
    EVENT_ADMISSION: "event.admission",
    SUBSCRIPTION_CONTRACT: "subscription.contract",
    MATERIALIZATION_BUDGET: "materialization.budget",
    CONSUMER_FLOOR: "consumer.floor",
    PROJECTION_REPAIR_POSTURE: "projection.repair.posture",
    RESOURCE_PROFILE: "resource.profile",
    RESOURCE_POSTURE: "resource.posture",
    RETENTION_RELEASE: "retention.release",
    CONTRIBUTION_LIFECYCLE: "contribution.lifecycle",
    MEDIA_FULFILLMENT_EVIDENCE: "media.fulfillment.evidence",
    MEDIA_TRANSPORT_PATH: "media.transport.path",
    MEDIA_TRANSPORT_OBSERVATION: "media.transport.observation",
    SERVICE_REGISTRY_CLAIM: "service.registry.claim",
    SERVICE_REGISTRY_MATERIALIZATION: "service.registry.materialization",
    SERVICE_MANAGER_POSTURE: "service.manager.posture",
    SERVICE_MANAGER_OPERATION_POSTURE: "service.manager.operation.posture",
    SERVICE_MANAGER_PROOF_DIGEST: "service.manager.proof.digest",
    SERVICE_MANAGER_RELEASE_CONTRACT: "service.manager.release.contract",
    SERVICE_MANAGER_SECRET_BOUNDARY: "service.manager.secretBoundary",
    SERVICE_MANAGER_TRAIN_DIGEST: "service.manager.train.digest",
    SERVICE_MANAGER_LAB_PROOF: "service.manager.labProof",
    SURFACE_APP_MANIFEST: "surface.app.manifest",
    SURFACE_APP_BOOTSTRAP_CONTRACT: "surface.app.bootstrap.contract",
    SURFACE_APP_BOOTSTRAP_POSTURE: "surface.app.bootstrap.posture",
  }),
  RECORD_KIND: Object.freeze({
    NODE_CAPABILITY: "node.capability",
    RUNTIME_ACTIVATION_REQUEST: "runtime.activation.request",
    ROUTE_PROMISE: "route.promise",
    ROUTE_OBSERVATION: "route.observation",
    STREAM_ROUTE_PLAN: "stream.routePlan",
    RUNTIME_DIAGNOSTIC_EVENT: "runtime.diagnostic.event",
    RUNTIME_DIAGNOSTIC_COMMAND: "runtime.diagnostic.command",
    RUNTIME_DIAGNOSTIC_COMMAND_RESULT: "runtime.diagnostic.command.result",
    MEMBER_PRESENCE: "member.presence",
    DIRECTORY_ENTRY: "directory.entry",
    BOOTSTRAP_CARRIER: "bootstrap.carrier",
    SWARM_IDENTITY: "swarm.identity",
    SWARM_DEVICE: "swarm.device",
    SWARM_GATEWAY: "swarm.gateway",
    SWARM_SERVICE: "swarm.service",
    SWARM_MEMBER: "swarm.member",
    SWARM_GRANT: "swarm.grant",
    SWARM_ROLE: "swarm.role",
    SWARM_INTERACTION: "swarm.interaction",
    SWARM_ACTIVATION: "swarm.activation",
    SWARM_RELEASE: "swarm.release",
    SWARM_REVOCATION: "swarm.revocation",
    AUTHORITY_ROOT_OPERATION: "authority.root.operation",
    AUTHORITY_ACTION_GRANT: "authority.action.grant",
    AUTHORITY_ACTION_EXERCISE: "authority.action.exercise",
    AUTHORITY_GRANT_REVOCATION_POSTURE: "authority.grant.revocationPosture",
    AUTHORITY_MULTI_IDENTITY_PROOF: "authority.multiIdentity.proof",
    ACCESS_GROUP: "access.group",
    ACCESS_EPOCH: "access.epoch",
    PRIVATE_CONTENT_ENVELOPE: "private.content.envelope",
    EVENT_FABRIC_ACCESS_CLASS: "event.fabric.accessClass",
    PARTICIPANT_RUNLEVEL: "participant.runlevel",
    PARTICIPANT_SELF_CAPABILITY: "participant.selfCapability",
    INGRESS_LANE_POSTURE: "ingress.lane.posture",
    EVENT_ADMISSION: "event.admission",
    SUBSCRIPTION_CONTRACT: "subscription.contract",
    MATERIALIZATION_BUDGET: "materialization.budget",
    CONSUMER_FLOOR: "consumer.floor",
    PROJECTION_REPAIR_POSTURE: "projection.repair.posture",
    RESOURCE_PROFILE: "resource.profile",
    RESOURCE_POSTURE: "resource.posture",
    RETENTION_RELEASE: "retention.release",
    CONTRIBUTION_LIFECYCLE: "contribution.lifecycle",
    MEDIA_FULFILLMENT_EVIDENCE: "media.fulfillment.evidence",
    MEDIA_TRANSPORT_PATH: "media.transport.path",
    MEDIA_TRANSPORT_OBSERVATION: "media.transport.observation",
    SERVICE_REGISTRY_CLAIM: "service.registry.claim",
    SERVICE_REGISTRY_MATERIALIZATION: "service.registry.materialization",
    SERVICE_MANAGER_POSTURE: "service.manager.posture",
    SERVICE_MANAGER_OPERATION_POSTURE: "service.manager.operation.posture",
    SERVICE_MANAGER_PROOF_DIGEST: "service.manager.proof.digest",
    SERVICE_MANAGER_RELEASE_CONTRACT: "service.manager.release.contract",
    SERVICE_MANAGER_SECRET_BOUNDARY: "service.manager.secretBoundary",
    SERVICE_MANAGER_TRAIN_DIGEST: "service.manager.train.digest",
    SERVICE_MANAGER_LAB_PROOF: "service.manager.labProof",
    SURFACE_APP_MANIFEST: "surface.app.manifest",
    SURFACE_APP_BOOTSTRAP_CONTRACT: "surface.app.bootstrap.contract",
    SURFACE_APP_BOOTSTRAP_POSTURE: "surface.app.bootstrap.posture",
  }),
  AUTHORITY_DOMAIN: Object.freeze({
    IDENTITY: "identity",
    GATEWAY: "gateway",
    SERVICE: "service",
    DEVICE: "device",
    RUNTIME: "runtime",
  }),
  INTERACTION_ROLE: Object.freeze({
    REQUESTER: "requester",
    COORDINATOR: "coordinator",
    ROUTER: "router",
    EXECUTOR: "executor",
    ADAPTER: "adapter",
    STORAGE: "storage",
    OBSERVER: "observer",
    OWNER: "owner",
  }),
  INTERACTION_STATE: Object.freeze({
    PREPARED: "prepared",
    ACCEPTED: "accepted",
    ROUTED: "routed",
    SERVICE_ACCEPTED: "serviceAccepted",
    ACTIVE: "active",
    REJECTED: "rejected",
    RELEASED: "released",
    EXPIRED: "expired",
  }),
  ROUTING_SCOPE_KIND: Object.freeze({
    LOCAL: "local",
    SWARM_ZONE: "swarmZone",
    EXPLICIT_AUDIENCE: "explicitAudience",
    EXPLICIT_MEMBER: "explicitMember",
    BOOTSTRAP: "bootstrap",
  }),
  ROUTING_SCOPE_STATE: Object.freeze({
    NOT_REQUIRED: "notRequired",
    READY: "ready",
    SYNCING: "syncing",
    STALE: "stale",
    MISSING: "missing",
    UNAVAILABLE: "unavailable",
  }),
  ROUTING_BLOCKED_REASON: Object.freeze({
    MISSING_ZONE_BASELINE: "missingZoneBaseline",
    NO_MEMBER_IN_ZONE: "noMemberInZone",
    ZERO_PROPAGATION: "zeroPropagation",
    ZONE_MISMATCH: "zoneMismatch",
    AUDIENCE_MISMATCH: "audienceMismatch",
    EDGE_NOT_ACCEPTED: "edgeNotAccepted",
  }),
  PARTICIPANT_RUNLEVEL: Object.freeze({
    LOCAL_CACHE: "localCache",
    AUTHORITY_READY: "authorityReady",
    EDGE_ATTACHED: "edgeAttached",
    DIRECTORY_READY: "directoryReady",
    ROUTE_READY: "routeReady",
    INTERACTIVE: "interactive",
    FULFILLING: "fulfilling",
    DEGRADED: "degraded",
    BLOCKED: "blocked",
    UNAVAILABLE: "unavailable",
  }),
  SELF_CAPABILITY_ACTION: Object.freeze({
    OBSERVE: "observe",
    REQUEST: "request",
    ROUTE: "route",
    FULFILL: "fulfill",
    RETAIN: "retain",
    RELEASE: "release",
    ADMINISTER: "administer",
  }),
  SELF_CAPABILITY_STATUS: Object.freeze({
    AVAILABLE: "available",
    DEGRADED: "degraded",
    BLOCKED: "blocked",
    DISABLED: "disabled",
    UNKNOWN: "unknown",
  }),
  POSTURE_FACET_STATE: Object.freeze({
    READY: "ready",
    NOT_REQUIRED: "notRequired",
    MISSING: "missing",
    BLOCKED: "blocked",
    DEGRADED: "degraded",
    UNKNOWN: "unknown",
  }),
  RESOURCE_PROFILE_CLASS: Object.freeze({
    THIN_CLIENT: "thinClient",
    BALANCED: "balanced",
    OFFLINE_FIRST: "offlineFirst",
    ARCHIVE_NODE: "archiveNode",
    OPERATOR_DEV: "operatorDev",
    CUSTOM: "custom",
  }),
  RESOURCE_POSTURE_STATE: Object.freeze({
    WITHIN_BUDGET: "withinBudget",
    PRESSURE: "pressure",
    OVER_BUDGET: "overBudget",
    SWEEPING: "sweeping",
    BLOCKED: "blocked",
    UNAVAILABLE: "unavailable",
  }),
  EVENT_PLANE: Object.freeze({
    AUTHORITY: "authority",
    ROUTE: "route",
    ACTIVATION: "activation",
    PROJECTION: "projection",
    PROJECTION_REPAIR: "projectionRepair",
    CONTRIBUTION: "contribution",
    RETENTION: "retention",
    DIAGNOSTIC: "diagnostic",
    DEV_BRIDGE: "devBridge",
    LOGGING_REPLAY: "loggingReplay",
    BULK_RETAINED_DATA: "bulkRetainedData",
  }),
  EVENT_ADMISSION_DECISION: Object.freeze({
    FORWARD: "forward",
    DROP: "drop",
    DEFER: "defer",
    SUMMARIZE: "summarize",
    REJECT: "reject",
  }),
  EVENT_PROOF_REQUIREMENT: Object.freeze({
    NONE: "none",
    SIGNATURE: "signature",
    AUTHORITY: "authority",
    SEALED: "sealed",
    EXECUTION: "execution",
  }),
  EVENT_PROOF_STATE: Object.freeze({
    NOT_REQUIRED: "notRequired",
    PENDING: "pending",
    VERIFIED: "verified",
    FAILED: "failed",
  }),
  EVENT_DELIVERY_MODE: Object.freeze({
    PUSH: "push",
    PULL: "pull",
    OBSERVE: "observe",
    REPLAY: "replay",
    DELTA: "delta",
    SUMMARY: "summary",
  }),
  EVENT_BACKPRESSURE_BEHAVIOR: Object.freeze({
    DROP: "drop",
    DEFER: "defer",
    SUMMARIZE: "summarize",
    REJECT: "reject",
    FORWARD: "forward",
  }),
  MATERIALIZATION_PAYLOAD_CLASS: Object.freeze({
    CONTROL: "control",
    EVIDENCE: "evidence",
    PROJECTION: "projection",
    RETAINED_RAW: "retainedRaw",
    MEDIA: "media",
    BULK: "bulk",
  }),
  MATERIALIZATION_COPY_ROLE: Object.freeze({
    TRANSPORT: "transport",
    PROJECTION: "projection",
    CACHE: "cache",
    BUFFER: "buffer",
    RETENTION: "retention",
    DEBUG: "debug",
    EVIDENCE: "evidence",
    REFERENCE_ONLY: "referenceOnly",
  }),
  MATERIALIZATION_TRANSFER_MODE: Object.freeze({
    CLONE: "clone",
    TRANSFERABLE: "transferable",
    SHARED: "shared",
    NATIVE: "native",
    REFERENCE_ONLY: "referenceOnly",
  }),
  MATERIALIZATION_LAG_STATE: Object.freeze({
    CAUGHT_UP: "caughtUp",
    LAGGING: "lagging",
    STALE: "stale",
    BLOCKED: "blocked",
    UNKNOWN: "unknown",
  }),
  MATERIALIZATION_SCHEMA_STATE: Object.freeze({
    CURRENT: "current",
    COMPATIBLE: "compatible",
    MIGRATING: "migrating",
    IGNORE: "ignore",
    QUARANTINED: "quarantined",
    BLOCKED: "blocked",
  }),
  MATERIALIZATION_PRIVACY_TIER: Object.freeze({
    ENCRYPTED_RAW: "encryptedRaw",
    ENCRYPTED_DETAIL: "encryptedDetail",
    SAFE_FACTS: "safeFacts",
    SAFE_INDEX: "safeIndex",
    SAFE_PROJECTION: "safeProjection",
    UI_PROJECTION: "uiProjection",
  }),
  PROJECTION_REPAIR_STATE: Object.freeze({
    PENDING: "pending",
    OBSERVING: "observing",
    BLOCKED: "blocked",
    SATISFIED: "satisfied",
    EXPIRED: "expired",
  }),
  RETENTION_RELEASE_STATE: Object.freeze({
    FREEABLE: "freeable",
    RELEASE_BLOCKED: "releaseBlocked",
  }),
  CONTRIBUTION_TYPE: Object.freeze({
    CLAIM: "claim",
    PROMISE: "promise",
    FULFILLMENT: "fulfillment",
    WITNESS: "witness",
    RETRACTION: "retraction",
    RELEASE: "release",
    EXPIRY: "expiry",
    OBSERVATION: "observation",
  }),
  CONTRIBUTION_STATE: Object.freeze({
    ACTIVE: "active",
    WITNESSED: "witnessed",
    RETRACTED: "retracted",
    RELEASED: "released",
    EXPIRED: "expired",
    BLOCKED: "blocked",
  }),
  MEDIA_FULFILLMENT_EVIDENCE_KIND: Object.freeze({
    TRANSPORT_STATE: "transportState",
    SELECTED_CANDIDATE_PAIR: "selectedCandidatePair",
    INBOUND_STATS: "inboundStats",
    TRACK_STATE: "trackState",
    RENDER_STATE: "renderState",
    RELEASE: "release",
  }),
  MEDIA_FULFILLMENT_STATE: Object.freeze({
    PENDING: "pending",
    USABLE: "usable",
    BLOCKED: "blocked",
    RELEASED: "released",
  }),
  MEDIA_TRANSPORT_PATH_STATE: Object.freeze({
    PENDING: "pending",
    ACTIONABLE: "actionable",
    BLOCKED: "blocked",
    RELEASED: "released",
  }),
  MEDIA_TRANSPORT_SELECTED_PAIR_STATE: Object.freeze({
    PENDING: "pending",
    SELECTED: "selected",
    FAILED: "failed",
    NONE: "none",
  }),
  MEDIA_TRANSPORT_RTP_STATE: Object.freeze({
    PENDING: "pending",
    FLOWING: "flowing",
    STALLED: "stalled",
    BLOCKED: "blocked",
    RELEASED: "released",
  }),
  MEDIA_TRANSPORT_RENDER_STATE: Object.freeze({
    PENDING: "pending",
    VISIBLE: "visible",
    BLOCKED: "blocked",
    RELEASED: "released",
  }),
  MEDIA_TRANSPORT_PARTICIPANT_ROLE: Object.freeze({
    BROWSER: "browser",
    SERVICE: "service",
    GATEWAY: "gateway",
    RELAY: "relay",
    TURN: "turn",
    RUNTIME: "runtime",
  }),
  MEDIA_TRANSPORT_OBSERVATION_STATE: Object.freeze({
    PENDING: "pending",
    CONNECTING: "connecting",
    CONNECTED: "connected",
    DISCONNECTED: "disconnected",
    RECOVERING: "recovering",
    FAILED: "failed",
    CLOSED: "closed",
    RELEASED: "released",
    BLOCKED: "blocked",
  }),
  RECOVERY_REF_KIND: Object.freeze({
    ROOT: "recovery.root",
    ROUTE: "recovery.route",
  }),
  STORAGE_MEMBER_KIND: Object.freeze({
    BROWSER_INDEXEDDB_CACHE: "browserIndexedDbCache",
    SERVICE_STORAGE_MEMBER: "serviceStorageMember",
  }),
  CHANNEL_RECORD_KIND: Object.freeze({
    DESCRIPTOR: "channel.descriptor",
    POLICY: "channel.policy",
    MEMBERSHIP: "channel.membership",
    MEMBER_ROLE: "channel.memberRole",
    RECOMMENDATION: "channel.recommendation",
  }),
  CAPABILITY_RECORD_KIND: Object.freeze({
    DEFINITION: "capability.definition",
    ADVERTISEMENT: "capability.advertisement",
    DIRECTORY_ENTRY: "capability.directoryEntry",
    POLICY: "capability.policy",
  }),
  CORE_CAPABILITY: Object.freeze({
    SWARM_EDGE_ATTACH: "swarm.edge.attach",
    PROJECTION_OBSERVE: "projection.observe",
    PROJECTION_DELTA_APPLY: "projection.delta.apply",
    SERVICE_SURFACE_OBSERVE: "service.surface.observe",
    SERVICE_INTENT_INVOKE: "service.intent.invoke",
    STORAGE_OBJECT_PUT: "storage.object.put",
    STORAGE_OBJECT_GET: "storage.object.get",
    STORAGE_PIN: "storage.pin",
    STORAGE_AVAILABILITY_ATTEST: "storage.availability.attest",
    LOGGING_EVENTS_OBSERVE: "logging.events.observe",
    STREAM_SESSION_OFFER: "stream.session.offer",
    STREAM_SESSION_CONTROL: "stream.session.control",
    MEDIA_STREAM_PREVIEW: "media.stream.preview",
    NODE_CAPABILITY_ACTIVATE: "node.capability.activate",
    ROUTE_PROMISE_RESOLVE: "route.promise.resolve",
    ROUTE_OBSERVATION_PUBLISH: "route.observation.publish",
    STREAM_ROUTE_PLAN_OBSERVE: "stream.routePlan.observe",
    RUNTIME_DIAGNOSTICS_OBSERVE: "runtime.diagnostics.observe",
    RUNTIME_DIAGNOSTICS_COMMAND: "runtime.diagnostics.command",
    APP_RUNNER_PIN: "app.runner.pin",
  }),
  ACTIVATION_FORBIDDEN_FIELDS: Object.freeze([
    "frameKind",
    "recordKind",
    "channelId",
    "routeZone",
    "zoneId",
    "zoneScope",
    "ttl",
    "maxHops",
    "capability",
    "wireCapability",
    "servicePk",
    "gatewayPk",
    "audience",
    "audienceRefs",
    "recipientPks",
    "caacRecipients",
    "serviceUrl",
    "routeUrl",
  ]),
  ROUTE_OBSERVATION_STATE: Object.freeze({
    DELIVERED: "delivered",
    MEMBER_WRITTEN: "memberWritten",
    MEMBER_READ: "memberRead",
    OBSERVING_UNREACHABLE: "observingUnreachable",
    UNREACHABLE_FOR: "unreachableFor",
    REJECTED: "rejected",
    ACCEPTED: "accepted",
    DEGRADED: "degraded",
    RELEASED: "released",
    CLOSED: "closed",
    EXPIRED: "expired",
  }),
  ROUTE_FAILED_PREDICATE: Object.freeze({
    ZONE: "zone",
    CHANNEL: "channel",
    CAPABILITY: "capability",
    AUDIENCE: "audience",
    TTL_OR_HOP_BUDGET: "ttlOrHopBudget",
    STALE_ROUTE_LEASE: "staleRouteLease",
    DETACHED_MEMBER: "detachedMember",
    SERVICE_POLICY: "servicePolicy",
    PARTICIPANT_RELEASE: "participantRelease",
  }),
  STREAM_PATH_KIND: Object.freeze({
    DIRECT: "direct",
    BROWSER_WEBRTC: "browserWebRtc",
    NATIVE_SWARM: "nativeSwarm",
    GATEWAY_RELAY: "gatewayRelay",
    MULTI_GATEWAY_RELAY: "multiGatewayRelay",
    DEGRADED_PROJECTION_ONLY: "degradedProjectionOnly",
    UNAVAILABLE: "unavailable",
  }),
  STREAM_PATH_STATE: Object.freeze({
    CANDIDATE: "candidate",
    SELECTED: "selected",
    UNAVAILABLE: "unavailable",
    FAILED: "failed",
    RELEASED: "released",
  }),
  REACHABILITY_STATE: Object.freeze({
    UNKNOWN: "unknown",
    REACHABLE: "reachable",
    OBSERVING_UNREACHABLE: "observingUnreachable",
    UNREACHABLE_FOR: "unreachableFor",
    DEGRADED: "degraded",
    CLOSED: "closed",
    EXPIRED: "expired",
  }),
  CAAC_VALIDATION_MODE: Object.freeze({
    STRUCTURAL: "structural",
    FIXTURE: "fixture",
    PRODUCT: "product",
  }),
  FIXTURE_CAAC_PLACEHOLDERS: Object.freeze([
    "sealed-frame-placeholder",
    "service-stream-placeholder",
    "edge-hello-claims",
    "edge-accept-claims",
    "edge-resume-claims",
    "edge-close-claims",
  ]),
  PROJECTION_OP: Object.freeze({
    SET: "set",
    REMOVE: "remove",
    APPEND_UNIQUE: "appendUnique",
    REPLACE: "replace",
  }),
  EDGE_KIND: Object.freeze({
    HELLO: "swarm.edge.hello",
    ACCEPT: "swarm.edge.accept",
    RESUME: "swarm.edge.resume",
    CLOSE: "swarm.edge.close",
  }),
  STREAM_RECORD_KIND: Object.freeze({
    INTENT: "stream.session.intent",
    ADMISSION: "stream.session.admission",
    REJECT: "stream.session.reject",
    OFFER: "stream.session.offer",
    ANSWER: "stream.session.answer",
    CANDIDATE: "stream.session.candidate",
    CONTROL: "stream.session.control",
    HEALTH: "stream.session.health",
    CLOSE: "stream.session.close",
  }),
  STREAM_CANDIDATE_ROLE: Object.freeze({
    BROWSER: "browser",
    SERVICE: "service",
  }),
  STREAM_CANDIDATE_ACTIONABILITY: Object.freeze({
    USABLE: "usable",
    BLOCKED: "blocked",
  }),
});

export const SERVICE_REGISTRY = Object.freeze({
  SCHEMA_VERSION: 1,
  CLAIM_KIND: Object.freeze({
    SERVICE: "service",
    MEMBER: "member",
    CAPABILITY: "capability",
    CHANNEL: "channel",
    SURFACE: "surface",
  }),
  CLAIM_STATE: Object.freeze({
    CLAIMED: "claimed",
    RETRACTED: "retracted",
    EXPIRED: "expired",
    BLOCKED: "blocked",
  }),
  MATERIALIZATION_STATE: Object.freeze({
    READY: "ready",
    PARTIAL: "partial",
    STALE: "stale",
    BLOCKED: "blocked",
  }),
});

export const STREAM_SESSION_LIFECYCLE_PHASE = Object.freeze({
  INTENT: "intent",
  ADMISSION: "admission",
  REJECT: "reject",
  OFFER: "offer",
  ANSWER: "answer",
  CANDIDATE: "candidate",
  CONTROL: "control",
  HEALTH: "health",
  CLOSE: "close",
  UNKNOWN: "",
});

const STREAM_SESSION_PHASE_BY_RECORD_KIND = Object.freeze({
  [SWARM.STREAM_RECORD_KIND.INTENT]: STREAM_SESSION_LIFECYCLE_PHASE.INTENT,
  [SWARM.STREAM_RECORD_KIND.ADMISSION]: STREAM_SESSION_LIFECYCLE_PHASE.ADMISSION,
  [SWARM.STREAM_RECORD_KIND.REJECT]: STREAM_SESSION_LIFECYCLE_PHASE.REJECT,
  [SWARM.STREAM_RECORD_KIND.OFFER]: STREAM_SESSION_LIFECYCLE_PHASE.OFFER,
  [SWARM.STREAM_RECORD_KIND.ANSWER]: STREAM_SESSION_LIFECYCLE_PHASE.ANSWER,
  [SWARM.STREAM_RECORD_KIND.CANDIDATE]: STREAM_SESSION_LIFECYCLE_PHASE.CANDIDATE,
  [SWARM.STREAM_RECORD_KIND.CONTROL]: STREAM_SESSION_LIFECYCLE_PHASE.CONTROL,
  [SWARM.STREAM_RECORD_KIND.HEALTH]: STREAM_SESSION_LIFECYCLE_PHASE.HEALTH,
  [SWARM.STREAM_RECORD_KIND.CLOSE]: STREAM_SESSION_LIFECYCLE_PHASE.CLOSE,
});

function carrierPayload(frame) {
  const body = isObject(frame?.body) ? frame.body : {};
  return isObject(body.payload) ? body.payload : {};
}

export function streamSessionLifecycleRecordKind(source) {
  if (typeof source === "string") return source.trim();
  const frame = isObject(source) ? source : {};
  const payload = carrierPayload(frame);
  const recordRef = isObject(frame.recordRef) ? frame.recordRef : isObject(frame.record_ref) ? frame.record_ref : {};
  return String(payload.recordKind || payload.record_kind || payload.kind || recordRef.kind || "").trim();
}

export function streamSessionLifecyclePhase(source) {
  const recordKind = streamSessionLifecycleRecordKind(source);
  return STREAM_SESSION_PHASE_BY_RECORD_KIND[recordKind] || STREAM_SESSION_LIFECYCLE_PHASE.UNKNOWN;
}

export function streamSessionLifecycleRecordFromCarrier(frame) {
  const payload = carrierPayload(frame);
  const recordKind = streamSessionLifecycleRecordKind(frame);
  const phase = streamSessionLifecyclePhase(recordKind);
  if (!phase) return null;
  const record = isObject(payload.record) ? payload.record : payload;
  return { recordKind, record, phase };
}

const PROPAGATING_FRAME_KINDS = new Set([
  SWARM.FRAME_KIND.RECORD_PUBLISH,
  SWARM.FRAME_KIND.RECORD_RETRACT,
  SWARM.FRAME_KIND.CHANNEL_OBSERVE,
  SWARM.FRAME_KIND.CHANNEL_UNOBSERVE,
  SWARM.FRAME_KIND.PROJECTION_SNAPSHOT,
  SWARM.FRAME_KIND.PROJECTION_DELTA,
  SWARM.FRAME_KIND.PROJECTION_REPAIR_REQUEST,
  SWARM.FRAME_KIND.SERVICE_INTENT,
  SWARM.FRAME_KIND.SERVICE_RESPONSE,
  SWARM.FRAME_KIND.STREAM_INTENT,
  SWARM.FRAME_KIND.STREAM_CONTROL,
  SWARM.FRAME_KIND.STREAM_STATUS,
  SWARM.FRAME_KIND.STORAGE_PIN_INTENT,
  SWARM.FRAME_KIND.STORAGE_PIN_ATTESTATION,
  SWARM.FRAME_KIND.NODE_CAPABILITY,
  SWARM.FRAME_KIND.RUNTIME_ACTIVATION_REQUEST,
  SWARM.FRAME_KIND.ROUTE_PROMISE,
  SWARM.FRAME_KIND.ROUTE_OBSERVATION,
  SWARM.FRAME_KIND.STREAM_ROUTE_PLAN,
  SWARM.FRAME_KIND.RUNTIME_DIAGNOSTIC_EVENT,
  SWARM.FRAME_KIND.RUNTIME_DIAGNOSTIC_COMMAND,
  SWARM.FRAME_KIND.RUNTIME_DIAGNOSTIC_COMMAND_RESULT,
  SWARM.FRAME_KIND.SWARM_IDENTITY,
  SWARM.FRAME_KIND.SWARM_DEVICE,
  SWARM.FRAME_KIND.SWARM_GATEWAY,
  SWARM.FRAME_KIND.SWARM_SERVICE,
  SWARM.FRAME_KIND.SWARM_MEMBER,
  SWARM.FRAME_KIND.SWARM_GRANT,
  SWARM.FRAME_KIND.SWARM_ROLE,
  SWARM.FRAME_KIND.SWARM_INTERACTION,
  SWARM.FRAME_KIND.SWARM_ACTIVATION,
  SWARM.FRAME_KIND.SWARM_RELEASE,
  SWARM.FRAME_KIND.SWARM_REVOCATION,
]);

const PUBLIC_BOOTSTRAP_FRAME_KINDS = new Set([
  "bootstrap.discovery",
  "bootstrap.gatewayHint",
]);

function requireString(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${name} is required`);
  return text;
}

export function assertResolvedMemberRef(value, name = "resolved memberRef") {
  const text = requireString(value, name);
  if (!/^[0-9a-f]{64}$/i.test(text)) {
    throw new Error(`${name} must be a resolved public key`);
  }
  return text.toLowerCase();
}

function requireArray(value, name) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  return value;
}

function requireNonEmptyArray(value, name) {
  const array = requireArray(value, name);
  if (array.length === 0) throw new Error(`${name} must not be empty`);
  return array;
}

function isObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function assertCapabilityName(name) {
  const text = requireString(name, "capability name");
  if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/.test(text)) {
    throw new Error("invalid capability namespace");
  }
  return text;
}

export function assertZoneScope(scope) {
  if (!isObject(scope)) throw new Error("zone scope must be an object");
  const zoneId = requireString(scope.zoneId, "zone scope zoneId");
  const out = {
    zoneId,
    ...(scope.privacy ? { privacy: String(scope.privacy) } : {}),
    ...(scope.ttl !== undefined ? { ttl: Number(scope.ttl) } : {}),
    ...(scope.maxHops !== undefined ? { maxHops: Number(scope.maxHops) } : {}),
  };
  if (out.ttl !== undefined && (!Number.isFinite(out.ttl) || out.ttl <= 0)) throw new Error("zone scope ttl must be positive");
  if (out.maxHops !== undefined && (!Number.isInteger(out.maxHops) || out.maxHops < 0)) throw new Error("zone scope maxHops must be non-negative");
  return out;
}

export function assertSwarmFrameBody(body, frameKind) {
  if (!isObject(body)) throw new Error("swarm frame body must be an object");
  const encoding = requireString(body.encoding, "swarm frame body encoding");
  if (encoding === SWARM.BODY_ENCODING.CAAC) {
    if (!isObject(body.envelope)) throw new Error("swarm frame CAAC body missing envelope");
    return body;
  }
  if (encoding === SWARM.BODY_ENCODING.PUBLIC) {
    if (!PUBLIC_BOOTSTRAP_FRAME_KINDS.has(String(frameKind || "")) || body.publicBootstrap !== true) {
      throw new Error("public swarm frame body is only allowed for explicit bootstrap metadata");
    }
    return body;
  }
  throw new Error("unsupported swarm frame body encoding");
}

function normalizedSwarmFrameBodyForHash(body) {
  const out = { ...(body || {}) };
  if (out.publicBootstrap === false || out.publicBootstrap === null || out.publicBootstrap === undefined) delete out.publicBootstrap;
  if (out.payload === null || out.payload === undefined) delete out.payload;
  if (out.signature === null || out.signature === undefined) delete out.signature;
  return out;
}

export function swarmFrameId(frame) {
  const material = {
    version: frame.version,
    kind: frame.kind,
    issuer: frame.issuer,
    audience: frame.audience ?? null,
    zoneScope: frame.zoneScope ?? null,
    issuedAt: frame.issuedAt,
    expiresAt: frame.expiresAt ?? null,
    nonce: frame.nonce,
    correlationId: frame.correlationId ?? null,
    channelId: frame.channelId ?? null,
    recordRef: frame.recordRef ?? null,
    capability: frame.capability ?? null,
    body: normalizedSwarmFrameBodyForHash(frame.body),
  };
  return sha256Hex(`constitute-swarm-frame-v1|${canonicalJson(material)}`);
}

export function assertSwarmFrame(frame, { now = nowSeconds() * 1000 } = {}) {
  if (!isObject(frame)) throw new Error("swarm frame must be an object");
  if (Number(frame.version) !== SWARM.FRAME_VERSION) throw new Error("unsupported swarm frame version");
  const kind = requireString(frame.kind, "swarm frame kind");
  if (!Object.values(SWARM.FRAME_KIND).includes(kind) && !PUBLIC_BOOTSTRAP_FRAME_KINDS.has(kind)) {
    throw new Error("unsupported swarm frame kind");
  }
  requireString(frame.issuer, "swarm frame issuer");
  if (!Number.isFinite(Number(frame.issuedAt)) || Number(frame.issuedAt) <= 0) throw new Error("swarm frame issuedAt is required");
  if (frame.expiresAt !== undefined && Number(frame.expiresAt) <= now) throw new Error("swarm frame expired");
  requireString(frame.nonce, "swarm frame nonce");
  if (PROPAGATING_FRAME_KINDS.has(kind)) assertZoneScope(frame.zoneScope);
  if (frame.capability) assertCapabilityName(frame.capability);
  assertSwarmFrameBody(frame.body, kind);
  if ((kind === SWARM.FRAME_KIND.ACK || kind === SWARM.FRAME_KIND.REJECT) && !String(frame.correlationId || "").trim()) {
    throw new Error("ack/reject frame missing correlationId");
  }
  if (frame.frameId && frame.frameId !== swarmFrameId(frame)) throw new Error("swarm frame id mismatch");
  return frame;
}

export function makeSwarmFrame(input = {}) {
  const frame = {
    version: SWARM.FRAME_VERSION,
    kind: input.kind,
    issuer: input.issuer,
    ...(input.audience !== undefined ? { audience: input.audience } : {}),
    ...(input.zoneScope !== undefined ? { zoneScope: input.zoneScope } : {}),
    issuedAt: Number(input.issuedAt || nowSeconds() * 1000),
    ...(input.expiresAt !== undefined ? { expiresAt: Number(input.expiresAt) } : {}),
    nonce: input.nonce || bytesToHex(randomBytes(16)),
    ...(input.correlationId ? { correlationId: input.correlationId } : {}),
    ...(input.channelId ? { channelId: input.channelId } : {}),
    ...(input.recordRef ? { recordRef: input.recordRef } : {}),
    ...(input.capability ? { capability: input.capability } : {}),
    body: normalizedSwarmFrameBodyForHash(input.body),
    ...(input.ack ? { ack: input.ack } : {}),
  };
  frame.frameId = swarmFrameId(frame);
  return assertSwarmFrame(frame, { now: input.now });
}

export function assertChannelDescriptor(record) {
  if (!isObject(record)) throw new Error("channel descriptor must be an object");
  requireString(record.channelId, "channel descriptor channelId");
  requireString(record.kind, "channel descriptor kind");
  requireString(record.displayName, "channel descriptor displayName");
  requireArray(record.capabilities, "channel descriptor capabilities").forEach(assertCapabilityName);
  requireArray(record.recordKinds, "channel descriptor recordKinds").forEach((kind) => requireString(kind, "channel descriptor record kind"));
  requireArray(record.ownerRefs, "channel descriptor ownerRefs").forEach((owner) => requireString(owner, "channel descriptor owner ref"));
  requireString(record.policyRef, "channel descriptor policyRef");
  if (!Number(record.createdAt || 0)) throw new Error("channel descriptor missing createdAt");
  return record;
}

export function assertChannelMembership(record) {
  if (!isObject(record)) throw new Error("channel membership must be an object");
  requireString(record.channelId, "channel membership channelId");
  assertResolvedMemberRef(record.memberRef, "channel membership memberRef");
  const roles = requireArray(record.roles, "channel membership roles");
  if (roles.length === 0) throw new Error("channel membership must include at least one role");
  for (const role of roles) {
    const text = requireString(role, "channel membership role");
    if (!/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/.test(text)) throw new Error("invalid channel membership role");
  }
  if (!record.authorityEnvelope) throw new Error("channel membership missing authority envelope");
  return record;
}

export function assertCapabilityDefinition(record) {
  if (!isObject(record)) throw new Error("capability definition must be an object");
  assertCapabilityName(record.capability);
  requireString(record.definitionId, "capability definition id");
  requireString(record.namespace, "capability namespace");
  if (!String(record.capability).startsWith(`${record.namespace}.`)) throw new Error("capability namespace mismatch");
  if (record.schemaRef !== undefined) requireString(record.schemaRef, "capability schemaRef");
  if (!Number(record.createdAt || 0)) throw new Error("capability definition missing createdAt");
  return record;
}

export function assertCapabilityAdvertisement(record, { now = nowSeconds() * 1000 } = {}) {
  if (!isObject(record)) throw new Error("capability advertisement must be an object");
  assertCapabilityName(record.capability);
  requireString(record.advertisementId, "capability advertisement id");
  requireString(record.memberRef || record.serviceRef, "capability advertisement member/service ref");
  if (record.memberRef !== undefined && record.memberRef !== null && String(record.memberRef).trim()) {
    assertResolvedMemberRef(record.memberRef, "capability advertisement memberRef");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("capability advertisement missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= now) throw new Error("capability advertisement expired");
  return record;
}

function assertCapabilityDirectoryEntry(record) {
  if (!isObject(record)) throw new Error("capability directory entry must be an object");
  assertCapabilityName(record.capability);
  requireString(record.channelId, "capability directory entry channelId");
  if (record.memberRef !== undefined && record.memberRef !== null && String(record.memberRef).trim()) {
    assertResolvedMemberRef(record.memberRef, "capability directory entry memberRef");
  }
  if (!String(record.memberRef || record.serviceRef || "").trim()) {
    throw new Error("capability directory entry missing memberRef or serviceRef");
  }
  return record;
}

export function buildCapabilityDirectoryProjection({ definitions = [], advertisements = [], entries = [], now = nowSeconds() * 1000 } = {}) {
  const validDefinitions = definitions.map(assertCapabilityDefinition);
  const definitionNames = new Set(validDefinitions.map((definition) => definition.capability));
  const activeAdvertisements = advertisements
    .filter((ad) => ad.expiresAt === undefined || Number(ad.expiresAt) > now)
    .map((ad) => assertCapabilityAdvertisement(ad, { now }));
  const validEntries = entries
    .filter((entry) => definitionNames.has(entry.capability) || activeAdvertisements.some((ad) => ad.capability === entry.capability))
    .map(assertCapabilityDirectoryEntry);
  validEntries.sort((a, b) => String(a.capability).localeCompare(String(b.capability)) || String(a.channelId || "").localeCompare(String(b.channelId || "")));
  return { definitions: validDefinitions, advertisements: activeAdvertisements, entries: validEntries };
}

export function assertProjectionSnapshot(snapshot) {
  if (!isObject(snapshot)) throw new Error("projection snapshot must be an object");
  requireString(snapshot.projectionId, "projection snapshot projectionId");
  requireString(snapshot.policyId, "projection snapshot policyId");
  if (!Number.isInteger(Number(snapshot.revision)) || Number(snapshot.revision) < 0) throw new Error("projection snapshot invalid revision");
  if (!isObject(snapshot.state)) throw new Error("projection snapshot state must be an object");
  assertProjectionCoverage(snapshot.coverage);
  assertProjectionFreshness(snapshot.freshness);
  requireArray(snapshot.sourceRefs || [], "projection snapshot sourceRefs");
  if (!Number(snapshot.issuedAt || 0)) throw new Error("projection snapshot missing issuedAt");
  return snapshot;
}

export function assertProjectionDelta(delta) {
  if (!isObject(delta)) throw new Error("projection delta must be an object");
  requireString(delta.projectionId, "projection delta projectionId");
  requireString(delta.policyId, "projection delta policyId");
  if (!Number.isInteger(Number(delta.baseRevision)) || Number(delta.baseRevision) < 0) throw new Error("projection delta invalid baseRevision");
  if (!Number.isInteger(Number(delta.revision)) || Number(delta.revision) <= Number(delta.baseRevision)) throw new Error("projection delta invalid revision");
  const ops = requireArray(delta.ops, "projection delta ops");
  for (const op of ops) assertProjectionDeltaOp(op);
  requireArray(delta.affectedRecords || [], "projection delta affectedRecords");
  assertProjectionCoverage(delta.coverage);
  assertProjectionFreshness(delta.freshness);
  requireArray(delta.sourceRefs || [], "projection delta sourceRefs");
  if (!Number(delta.issuedAt || 0)) throw new Error("projection delta missing issuedAt");
  return delta;
}

export function assertProjectionDeltaOp(op) {
  if (!isObject(op)) throw new Error("projection delta op must be an object");
  if (!Object.values(SWARM.PROJECTION_OP).includes(String(op.op || ""))) throw new Error("unsupported projection delta op");
  const path = requireArray(op.path, "projection delta op path");
  if (path.length === 0) throw new Error("projection delta op path cannot be empty");
  for (const part of path) {
    if (!(typeof part === "string" || typeof part === "number")) throw new Error("projection delta op path parts must be strings or numbers");
  }
  if (op.op !== SWARM.PROJECTION_OP.REMOVE && op.value === undefined) throw new Error("projection delta op missing value");
  return op;
}

export function makeProjectionRepairRequest({ projectionId, policyId, currentRevision, requiredRevision } = {}) {
  return {
    projectionId: requireString(projectionId, "repair projectionId"),
    policyId: requireString(policyId, "repair policyId"),
    currentRevision: Number(currentRevision ?? 0),
    requiredRevision: Number(requiredRevision ?? 0),
    reason: "revisionGap",
  };
}

function valueAtPath(root, pathParts, create = false) {
  let cursor = root;
  for (let i = 0; i < pathParts.length - 1; i += 1) {
    const key = pathParts[i];
    if (cursor[key] === undefined) {
      if (!create) return [undefined, pathParts[pathParts.length - 1]];
      cursor[key] = typeof pathParts[i + 1] === "number" ? [] : {};
    }
    cursor = cursor[key];
    if (!isObject(cursor) && !Array.isArray(cursor)) throw new Error("projection delta path crosses non-container value");
  }
  return [cursor, pathParts[pathParts.length - 1]];
}

function cloneProjectionValue(value) {
  if (Array.isArray(value)) return value.map((item) => cloneProjectionValue(item));
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, child] of Object.entries(value)) out[key] = cloneProjectionValue(child);
  return out;
}

export function applyProjectionDelta({ state = {}, revision = 0, delta } = {}) {
  assertProjectionDelta(delta);
  if (Number(delta.baseRevision) !== Number(revision)) {
    return {
      state,
      revision,
      changed: false,
      repairRequest: makeProjectionRepairRequest({
        projectionId: delta.projectionId,
        policyId: delta.policyId,
        currentRevision: revision,
        requiredRevision: delta.baseRevision,
      }),
    };
  }
  const next = cloneProjectionValue(state || {});
  const before = canonicalJson(next);
  for (const op of delta.ops) {
    const [parent, key] = valueAtPath(next, op.path, op.op !== SWARM.PROJECTION_OP.REMOVE);
    if (op.op === SWARM.PROJECTION_OP.REMOVE) {
      if (Array.isArray(parent)) parent.splice(Number(key), 1);
      else if (parent && Object.prototype.hasOwnProperty.call(parent, key)) delete parent[key];
    } else if (op.op === SWARM.PROJECTION_OP.APPEND_UNIQUE) {
      if (!Array.isArray(parent[key])) parent[key] = [];
      if (!parent[key].some((entry) => canonicalJson(entry) === canonicalJson(op.value))) parent[key].push(op.value);
    } else {
      parent[key] = cloneProjectionValue(op.value);
    }
  }
  const after = canonicalJson(next);
  return { state: next, revision: Number(delta.revision), changed: before !== after };
}

function assertProjectionRevisionMap(value, name) {
  if (!isObject(value)) throw new Error(`${name} must be an object`);
  for (const [projectionId, revision] of Object.entries(value)) {
    requireString(projectionId, `${name} projectionId`);
    if (!Number.isInteger(Number(revision)) || Number(revision) < 0) throw new Error(`${name} revision must be non-negative`);
  }
  return value;
}

function assertSealedClaims(body, context) {
  if (!isObject(body)) throw new Error(`${context} missing sealedClaims`);
  if (body.encoding !== SWARM.BODY_ENCODING.CAAC || !isObject(body.envelope)) {
    throw new Error(`${context} sealedClaims must be sealed`);
  }
  return body;
}

function assertSwarmEdgeCommon(record, context) {
  requireString(record.memberKind, `${context} memberKind`);
  assertResolvedMemberRef(record.memberRef, `${context} memberRef`);
  assertZoneScope(record.zoneScope);
  for (const capability of requireArray(record.capabilityRefs, `${context} capabilityRefs`)) assertCapabilityName(capability);
  for (const channelRef of requireArray(record.channelRefs, `${context} channelRefs`)) requireString(channelRef, `${context} channelRef`);
  for (const promiseRef of requireArray(record.promiseRefs || [], `${context} promiseRefs`)) requireString(promiseRef, `${context} promiseRef`);
  if (record.lastAckedFrameId !== undefined) requireString(record.lastAckedFrameId, `${context} lastAckedFrameId`);
  assertProjectionRevisionMap(record.lastProjectionRevisions, `${context} lastProjectionRevisions`);
  requireString(record.nonce, `${context} nonce`);
  if (!Number(record.issuedAt || 0)) throw new Error(`${context} missing issuedAt`);
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error(`${context} expiresAt must be after issuedAt`);
  }
  assertSealedClaims(record.sealedClaims, context);
  return record;
}

export function assertSwarmEdgeHello(record) {
  if (!isObject(record)) throw new Error("swarm edge hello must be an object");
  const versions = requireArray(record.supportedVersions, "swarm edge hello supportedVersions");
  if (!versions.includes(SWARM.FRAME_VERSION)) throw new Error("swarm edge hello missing supported swarm version");
  return assertSwarmEdgeCommon(record, "swarm edge hello");
}

export function assertSwarmEdgeAccept(record) {
  if (!isObject(record)) throw new Error("swarm edge accept must be an object");
  requireString(record.sessionId, "swarm edge accept sessionId");
  if (Number(record.acceptedVersion) !== SWARM.FRAME_VERSION) throw new Error("swarm edge accept unsupported version");
  return assertSwarmEdgeCommon(record, "swarm edge accept");
}

export function assertSwarmEdgeResume(record) {
  if (!isObject(record)) throw new Error("swarm edge resume must be an object");
  requireString(record.sessionId, "swarm edge resume sessionId");
  return assertSwarmEdgeCommon(record, "swarm edge resume");
}

export function assertSwarmEdgeClose(record) {
  if (!isObject(record)) throw new Error("swarm edge close must be an object");
  requireString(record.sessionId, "swarm edge close sessionId");
  requireString(record.reasonCode, "swarm edge close reasonCode");
  return assertSwarmEdgeCommon(record, "swarm edge close");
}

export function assertStoragePinIntent(record) {
  if (!isObject(record)) throw new Error("storage pin intent must be an object");
  requireString(record.intentId, "storage pin intent id");
  requireArray(record.objectRefs, "storage pin intent objectRefs");
  requireString(record.manifestHash, "storage pin intent manifestHash");
  if (!Number.isInteger(Number(record.desiredReplicas)) || Number(record.desiredReplicas) < 1) throw new Error("storage pin intent desiredReplicas must be positive");
  requireString(record.retention, "storage pin intent retention");
  requireArray(record.authorityRefs, "storage pin intent authorityRefs");
  return record;
}

export function assertStoragePinAttestation(record) {
  if (!isObject(record)) throw new Error("storage pin attestation must be an object");
  requireString(record.attestationId, "storage pin attestation id");
  requireString(record.intentId, "storage pin attestation intentId");
  requireString(record.storageMemberRef, "storage pin attestation storageMemberRef");
  requireArray(record.acceptedRefs, "storage pin attestation acceptedRefs");
  requireArray(record.availabilityRefs, "storage pin attestation availabilityRefs");
  requireString(record.status, "storage pin attestation status");
  if (!Number(record.issuedAt || 0)) throw new Error("storage pin attestation missing issuedAt");
  return record;
}

export function deriveStoragePinProjection({ intent, attestations = [], now = nowSeconds() * 1000 } = {}) {
  assertStoragePinIntent(intent);
  const active = attestations
    .map(assertStoragePinAttestation)
    .filter((attestation) => attestation.intentId === intent.intentId)
    .filter((attestation) => attestation.expiresAt === undefined || Number(attestation.expiresAt) > now)
    .filter((attestation) => attestation.status === "accepted" || attestation.status === "pinned");
  const members = [...new Set(active.map((attestation) => attestation.storageMemberRef))].sort();
  return {
    intentId: intent.intentId,
    pinnedCount: members.length,
    members,
    availability: active.flatMap((attestation) => attestation.availabilityRefs),
    missingReplicas: Math.max(0, Number(intent.desiredReplicas) - members.length),
    expiresAt: intent.expiresAt,
    status: members.length >= Number(intent.desiredReplicas) ? "satisfied" : "pending",
  };
}

export function assertStreamSessionRecord(record) {
  if (!isObject(record)) throw new Error("stream session record must be an object");
  const kind = requireString(record.kind, "stream session kind");
  if (!Object.values(SWARM.STREAM_RECORD_KIND).includes(kind)) throw new Error("unsupported stream session kind");
  requireString(record.sessionId, "stream session id");
  requireString(record.issuer, "stream session issuer");
  if (!Number(record.issuedAt || 0)) throw new Error("stream session missing issuedAt");
  rejectMediaByteFields(record, "stream session record");
  return record;
}

export function assertStreamSessionIntent(record) {
  if (!isObject(record)) throw new Error("stream session intent must be an object");
  requireString(record.sessionId, "stream session intent sessionId");
  assertCapabilityName(record.capabilityRef);
  assertResolvedMemberRef(record.requesterRef, "stream session intent requesterRef");
  requireString(record.channelId, "stream session intent channelId");
  requireString(record.transport, "stream session intent transport");
  if (!Number(record.issuedAt || 0)) throw new Error("stream session intent missing issuedAt");
  rejectMediaByteFields(record, "stream session intent");
  return record;
}

export function assertStreamSessionAdmission(record) {
  if (!isObject(record)) throw new Error("stream session admission must be an object");
  requireString(record.admissionId, "stream session admission id");
  requireString(record.sessionId, "stream session admission sessionId");
  assertCapabilityName(record.capabilityRef);
  assertResolvedMemberRef(record.admittedBy, "stream session admission admittedBy");
  if (record.constraints !== undefined && record.constraints !== null && !isObject(record.constraints)) {
    throw new Error("stream session admission constraints must be an object");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("stream session admission missing issuedAt");
  rejectMediaByteFields(record, "stream session admission");
  return record;
}

export function assertStreamSessionReject(record) {
  if (!isObject(record)) throw new Error("stream session reject must be an object");
  requireString(record.rejectId, "stream session reject id");
  requireString(record.sessionId, "stream session reject sessionId");
  if (record.capabilityRef !== undefined) assertCapabilityName(record.capabilityRef);
  assertResolvedMemberRef(record.rejectedBy, "stream session reject rejectedBy");
  requireString(record.reasonCode || record.reason, "stream session reject reason");
  if (record.constraints !== undefined && record.constraints !== null && !isObject(record.constraints)) {
    throw new Error("stream session reject constraints must be an object");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("stream session reject missing issuedAt");
  rejectMediaByteFields(record, "stream session reject");
  return record;
}

export function assertStreamSessionOffer(record) {
  if (!isObject(record)) throw new Error("stream session offer must be an object");
  requireString(record.offerId, "stream session offer id");
  requireString(record.sessionId, "stream session offer sessionId");
  requireString(record.transport, "stream session offer transport");
  if (!isObject(record.payload)) throw new Error("stream session offer payload must be an object");
  if (!Number(record.issuedAt || 0)) throw new Error("stream session offer missing issuedAt");
  rejectMediaByteFields(record, "stream session offer");
  return record;
}

export function assertStreamSessionAnswer(record) {
  if (!isObject(record)) throw new Error("stream session answer must be an object");
  requireString(record.answerId, "stream session answer id");
  requireString(record.sessionId, "stream session answer sessionId");
  requireString(record.transport, "stream session answer transport");
  if (!isObject(record.payload)) throw new Error("stream session answer payload must be an object");
  if (!Number(record.issuedAt || 0)) throw new Error("stream session answer missing issuedAt");
  rejectMediaByteFields(record, "stream session answer");
  return record;
}

export function assertStreamSessionCandidate(record) {
  if (!isObject(record)) throw new Error("stream session candidate must be an object");
  requireString(record.candidateId, "stream session candidate id");
  requireString(record.sessionId, "stream session candidate sessionId");
  requireString(record.transport, "stream session candidate transport");
  requireString(record.candidateRole, "stream session candidate role");
  if (!Object.values(SWARM.STREAM_CANDIDATE_ROLE).includes(record.candidateRole)) {
    throw new Error("stream session candidate role is unsupported");
  }
  requireString(record.actionability, "stream session candidate actionability");
  if (!Object.values(SWARM.STREAM_CANDIDATE_ACTIONABILITY).includes(record.actionability)) {
    throw new Error("stream session candidate actionability is unsupported");
  }
  if (record.actionability === SWARM.STREAM_CANDIDATE_ACTIONABILITY.BLOCKED) {
    requireString(record.blockedReason, "stream session candidate blocked reason");
  }
  if (record.endpoint !== undefined && record.endpoint !== null) {
    assertStreamCandidateEndpoint(record.endpoint);
  }
  if (!isObject(record.payload)) throw new Error("stream session candidate payload must be an object");
  if (!Number(record.issuedAt || 0)) throw new Error("stream session candidate missing issuedAt");
  rejectMediaByteFields(record, "stream session candidate");
  return record;
}

function assertStreamCandidateEndpoint(endpoint) {
  if (!isObject(endpoint)) throw new Error("stream session candidate endpoint must be an object");
  if (endpoint.protocol !== undefined) requireString(endpoint.protocol, "stream session candidate endpoint protocol");
  if (endpoint.address !== undefined) requireString(endpoint.address, "stream session candidate endpoint address");
  if (endpoint.candidateType !== undefined) requireString(endpoint.candidateType, "stream session candidate endpoint type");
  if (endpoint.port !== undefined) {
    if (!Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) {
      throw new Error("stream session candidate endpoint port is invalid");
    }
  }
}

export function assertStreamSessionControl(record) {
  if (!isObject(record)) throw new Error("stream session control must be an object");
  requireString(record.controlId, "stream session control id");
  requireString(record.sessionId, "stream session control sessionId");
  requireString(record.command, "stream session control command");
  if (record.params !== undefined && record.params !== null && !isObject(record.params)) {
    throw new Error("stream session control params must be an object");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("stream session control missing issuedAt");
  rejectMediaByteFields(record, "stream session control");
  return record;
}

export function assertStreamSessionHealth(record) {
  if (!isObject(record)) throw new Error("stream session health must be an object");
  requireString(record.healthId, "stream session health id");
  requireString(record.sessionId, "stream session health sessionId");
  requireString(record.status, "stream session health status");
  if (record.recovery !== undefined && record.recovery !== null && !isObject(record.recovery)) {
    throw new Error("stream session health recovery must be an object");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("stream session health missing issuedAt");
  rejectMediaByteFields(record, "stream session health");
  return record;
}

export function assertStreamSessionClose(record) {
  if (!isObject(record)) throw new Error("stream session close must be an object");
  requireString(record.closeId, "stream session close id");
  requireString(record.sessionId, "stream session close sessionId");
  requireString(record.reasonCode, "stream session close reasonCode");
  if (!Number(record.issuedAt || 0)) throw new Error("stream session close missing issuedAt");
  rejectMediaByteFields(record, "stream session close");
  return record;
}

function rejectMediaByteFields(value, context) {
  if (containsMediaByteField(value)) throw new Error(`${context} must not carry media bytes`);
}

function containsMediaByteField(value) {
  if (Array.isArray(value)) return value.some(containsMediaByteField);
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(([key, next]) => isMediaByteKey(key) || containsMediaByteField(next));
}

function isMediaByteKey(key) {
  return [
    "mediaBytes",
    "payloadBytes",
    "mediaData",
    "mediaChunk",
    "encodedMediaBytes",
    "blobBytes",
    "payloadBlobBytes",
    "blobData",
    "blobChunk",
    "encodedBlobBytes",
    "binaryBytes",
    "rawBytes",
  ].includes(String(key || ""));
}

function rejectForbiddenKeys(value, forbidden, context, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectForbiddenKeys(item, forbidden, context, `${path}${index}.`));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, next] of Object.entries(value)) {
    if (forbidden.has(key)) throw new Error(`${context} contains forbidden protocol field: ${path}${key}`);
    rejectForbiddenKeys(next, forbidden, context, `${path}${key}.`);
  }
}

function rejectRouteControlByteFields(record, context) {
  rejectMediaByteFields(record, context);
}

function assertRecordKind(record, expected, context) {
  if (record.kind !== undefined && String(record.kind) !== expected) {
    throw new Error(`${context} kind must be ${expected}`);
  }
}

function assertReferenceList(value, name) {
  return requireNonEmptyArray(value, name).map((entry) => requireString(entry, `${name} entry`));
}

function assertOptionalObject(value, name) {
  if (value === undefined || value === null) return {};
  if (!isObject(value)) throw new Error(`${name} must be an object`);
  return value;
}

export function assertNodeCapability(record, { now = nowSeconds() * 1000 } = {}) {
  if (!isObject(record)) throw new Error("node capability must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.NODE_CAPABILITY, "node capability");
  requireString(record.nodeCapabilityId, "node capability id");
  requireString(record.nodeRef, "node capability nodeRef");
  assertCapabilityName(record.capabilityRef);
  requireString(record.serviceRef, "node capability serviceRef");
  assertResolvedMemberRef(record.serviceMemberRef, "node capability serviceMemberRef");
  assertReferenceList(record.backingChannelRefs, "node capability backingChannelRefs");
  assertOptionalObject(record.activationPolicy, "node capability activationPolicy");
  const freshness = assertOptionalObject(record.freshness, "node capability freshness");
  requireString(freshness.state, "node capability freshness state");
  if (!Number(freshness.updatedAt || 0)) throw new Error("node capability freshness missing updatedAt");
  if (freshness.expiresAt !== undefined && Number(freshness.expiresAt) <= now) throw new Error("node capability expired");
  assertOptionalObject(record.safeFacts, "node capability safeFacts");
  rejectRouteControlByteFields(record.safeFacts || {}, "node capability safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("node capability missing issuedAt");
  return record;
}

export function assertRuntimeActivationRequest(record) {
  if (!isObject(record)) throw new Error("runtime activation request must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.RUNTIME_ACTIVATION_REQUEST, "runtime activation request");
  rejectForbiddenKeys(record, new Set(SWARM.ACTIVATION_FORBIDDEN_FIELDS), "runtime activation request");
  requireString(record.activationId, "runtime activation activationId");
  requireString(record.nodeRef, "runtime activation nodeRef");
  assertCapabilityName(record.capabilityRef);
  assertOptionalObject(record.params, "runtime activation params");
  assertResolvedMemberRef(record.requesterRef, "runtime activation requesterRef");
  if (!Number(record.issuedAt || 0)) throw new Error("runtime activation missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("runtime activation expiresAt must be after issuedAt");
  }
  rejectRouteControlByteFields(record.params || {}, "runtime activation params");
  return record;
}

export function assertRoutePromise(record) {
  if (!isObject(record)) throw new Error("route promise must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.ROUTE_PROMISE, "route promise");
  requireString(record.promiseId, "route promise promiseId");
  requireString(record.activationId, "route promise activationId");
  requireString(record.nodeRef, "route promise nodeRef");
  assertCapabilityName(record.capabilityRef);
  assertResolvedMemberRef(record.requesterRef, "route promise requesterRef");
  assertResolvedMemberRef(record.servicePk, "route promise servicePk");
  requireString(record.channelId, "route promise channelId");
  assertZoneScope(record.zoneScope);
  if (record.returnZoneScope !== undefined && record.returnZoneScope !== null) {
    assertZoneScope(record.returnZoneScope);
  }
  assertReferenceList(record.audienceRefs, "route promise audienceRefs");
  if (record.serviceMemberRef !== undefined && record.serviceMemberRef !== null) {
    assertResolvedMemberRef(record.serviceMemberRef, "route promise serviceMemberRef");
  }
  assertReferenceList(record.authorityRefs, "route promise authorityRefs");
  assertOptionalObject(record.routePolicy, "route promise routePolicy");
  assertReferenceList(record.pathRefs, "route promise pathRefs");
  assertOptionalObject(record.releasePolicy, "route promise releasePolicy");
  if (!Number(record.issuedAt || 0)) throw new Error("route promise missing issuedAt");
  if (!Number(record.expiresAt || 0)) throw new Error("route promise missing expiresAt");
  if (Number(record.expiresAt) <= Number(record.issuedAt)) throw new Error("route promise expiresAt must be after issuedAt");
  rejectRouteControlByteFields(record, "route promise");
  return record;
}

export function assertLocalRouteBinding(record) {
  if (!isObject(record)) throw new Error("route binding must be an object");
  requireString(record.bindingId, "route binding bindingId");
  requireString(record.promiseId, "route binding promiseId");
  requireString(record.participantRef, "route binding participantRef");
  requireString(record.bindingKind, "route binding bindingKind");
  assertOptionalObject(record.localRefs, "route binding localRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("route binding missing issuedAt");
  return record;
}

const FAILURE_OBSERVATION_STATES = new Set([
  SWARM.ROUTE_OBSERVATION_STATE.OBSERVING_UNREACHABLE,
  SWARM.ROUTE_OBSERVATION_STATE.UNREACHABLE_FOR,
  SWARM.ROUTE_OBSERVATION_STATE.REJECTED,
]);

export function assertRouteObservation(record) {
  if (!isObject(record)) throw new Error("route observation must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.ROUTE_OBSERVATION, "route observation");
  requireString(record.observationId, "route observation observationId");
  const state = requireString(record.state, "route observation state");
  if (!Object.values(SWARM.ROUTE_OBSERVATION_STATE).includes(state)) throw new Error("unsupported route observation state");
  if (!String(record.frameId || record.promiseId || record.activationId || "").trim()) {
    throw new Error("route observation missing frameId, promiseId, or activationId");
  }
  const deliveredTo = requireArray(record.deliveredTo || [], "route observation deliveredTo");
  for (const memberRef of deliveredTo) {
    assertResolvedMemberRef(memberRef, "route observation deliveredTo");
  }
  const failedPredicates = requireArray(record.failedPredicates || [], "route observation failedPredicates");
  for (const predicate of failedPredicates) {
    const text = requireString(predicate, "route observation failedPredicate");
    if (!Object.values(SWARM.ROUTE_FAILED_PREDICATE).includes(text)) throw new Error("unsupported route failed predicate");
  }
  if (FAILURE_OBSERVATION_STATES.has(state) && failedPredicates.length === 0 && !String(record.releaseReason || "").trim()) {
    throw new Error("route observation failure state requires failed predicates or release reason");
  }
  assertOptionalObject(record.diagnostics, "route observation diagnostics");
  if (!Number(record.issuedAt || 0)) throw new Error("route observation missing issuedAt");
  rejectRouteControlByteFields(record.diagnostics || {}, "route observation diagnostics");
  return record;
}

function assertStreamRoutePath(path, context) {
  if (!isObject(path)) throw new Error(`${context} must be an object`);
  requireString(path.pathId, `${context} pathId`);
  const kind = requireString(path.kind, `${context} kind`);
  if (!Object.values(SWARM.STREAM_PATH_KIND).includes(kind)) throw new Error("unsupported stream path kind");
  if (path.state !== undefined && !Object.values(SWARM.STREAM_PATH_STATE).includes(String(path.state))) {
    throw new Error("unsupported stream path state");
  }
  if (path.refs !== undefined) requireArray(path.refs, `${context} refs`).forEach((entry) => requireString(entry, `${context} ref`));
  rejectRouteControlByteFields(path, context);
  return path;
}

export function assertStreamRoutePlan(record) {
  if (!isObject(record)) throw new Error("stream route plan must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.STREAM_ROUTE_PLAN, "stream route plan");
  requireString(record.sessionId, "stream route plan sessionId");
  assertReferenceList(record.sourceRefs, "stream route plan sourceRefs");
  assertResolvedMemberRef(record.requesterRef, "stream route plan requesterRef");
  assertResolvedMemberRef(record.serviceMemberRef, "stream route plan serviceMemberRef");
  assertCapabilityName(record.capabilityRef);
  assertOptionalObject(record.routeLease, "stream route plan routeLease");
  const candidates = requireNonEmptyArray(record.candidatePaths, "stream route plan candidatePaths").map((path) => assertStreamRoutePath(path, "stream route plan candidatePath"));
  const fallbackPaths = requireNonEmptyArray(record.fallbackPaths, "stream route plan fallbackPaths").map((path) => assertStreamRoutePath(path, "stream route plan fallbackPath"));
  assertStreamRoutePath(record.preferredPath, "stream route plan preferredPath");
  assertStreamRoutePath(record.selectedPath, "stream route plan selectedPath");
  const pathState = requireString(record.pathState, "stream route plan pathState");
  if (!Object.values(SWARM.STREAM_PATH_STATE).includes(pathState)) throw new Error("unsupported stream route path state");
  const reachabilityState = requireString(record.reachabilityState, "stream route plan reachabilityState");
  if (!Object.values(SWARM.REACHABILITY_STATE).includes(reachabilityState)) throw new Error("unsupported stream route reachability state");
  assertOptionalObject(record.releasePolicy, "stream route plan releasePolicy");
  assertOptionalObject(record.diagnostics, "stream route plan diagnostics");
  if (!Number(record.expiresAt || 0)) throw new Error("stream route plan missing expiresAt");
  if (!candidates.some((path) => path.pathId === record.preferredPath.pathId)) throw new Error("stream route plan preferredPath must be a candidate");
  if (!candidates.some((path) => path.pathId === record.selectedPath.pathId)) throw new Error("stream route plan selectedPath must be a candidate");
  if (fallbackPaths.length === 0) throw new Error("stream route plan fallbackPaths must not be empty");
  rejectRouteControlByteFields(record, "stream route plan");
  return record;
}

export function assertMemberPresence(record, { now = nowSeconds() * 1000 } = {}) {
  if (!isObject(record)) throw new Error("member presence must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.MEMBER_PRESENCE, "member presence");
  assertResolvedMemberRef(record.memberRef, "member presence memberRef");
  requireString(record.memberKind, "member presence memberKind");
  requireArray(record.capabilityRefs || [], "member presence capabilityRefs").forEach(assertCapabilityName);
  requireArray(record.channelRefs || [], "member presence channelRefs").forEach((entry) => requireString(entry, "member presence channelRef"));
  if (!Number(record.issuedAt || 0)) throw new Error("member presence missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= now) throw new Error("member presence expired");
  return record;
}

export function assertDirectoryEntry(record) {
  if (!isObject(record)) throw new Error("directory entry must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.DIRECTORY_ENTRY, "directory entry");
  requireString(record.entryId, "directory entry entryId");
  requireString(record.subjectRef, "directory entry subjectRef");
  requireString(record.source, "directory entry source");
  if (!["channelRecord", "capabilityRecord", "memberRecord", "projection", "observation", "bootstrap"].includes(String(record.source))) {
    throw new Error("unsupported directory entry source");
  }
  if (record.capabilityRef !== undefined) assertCapabilityName(record.capabilityRef);
  if (record.channelId !== undefined) requireString(record.channelId, "directory entry channelId");
  if (!Number(record.issuedAt || 0)) throw new Error("directory entry missing issuedAt");
  return record;
}

export function assertServiceRegistryClaim(record) {
  if (!isObject(record)) throw new Error("service registry claim must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_REGISTRY_CLAIM, "service registry claim");
  requireString(record.claimId, "service registry claim claimId");
  if (Number(record.schemaVersion || 0) !== SERVICE_REGISTRY.SCHEMA_VERSION) throw new Error("unsupported service registry claim schemaVersion");
  requireString(record.claimKind, "service registry claim claimKind");
  if (!Object.values(SERVICE_REGISTRY.CLAIM_KIND).includes(record.claimKind)) throw new Error("invalid service registry claim kind");
  requireString(record.state, "service registry claim state");
  if (!Object.values(SERVICE_REGISTRY.CLAIM_STATE).includes(record.state)) throw new Error("invalid service registry claim state");
  requireString(record.ownerRef, "service registry claim ownerRef");
  requireString(record.writerRef, "service registry claim writerRef");
  requireString(record.subjectRef, "service registry claim subjectRef");
  requireString(record.scopeRef, "service registry claim scopeRef");
  if (record.service !== undefined) requireString(record.service, "service registry claim service");
  if (record.servicePk !== undefined) requireString(record.servicePk, "service registry claim servicePk");
  if (record.serviceRef !== undefined) requireString(record.serviceRef, "service registry claim serviceRef");
  if (record.memberRef !== undefined) requireString(record.memberRef, "service registry claim memberRef");
  if (record.hostGatewayPk !== undefined) requireString(record.hostGatewayPk, "service registry claim hostGatewayPk");
  requireArray(record.capabilityRefs || [], "service registry claim capabilityRefs").forEach(assertCapabilityName);
  requireArray(record.channelRefs || [], "service registry claim channelRefs").forEach((entry) => requireString(entry, "service registry claim channelRef"));
  requireArray(record.nodeRefs || [], "service registry claim nodeRefs").forEach((entry) => requireString(entry, "service registry claim nodeRef"));
  requireArray(record.surfaceRefs || [], "service registry claim surfaceRefs").forEach((entry) => requireString(entry, "service registry claim surfaceRef"));
  requireArray(record.evidenceRefs || [], "service registry claim evidenceRefs").forEach((entry) => requireString(entry, "service registry claim evidenceRef"));
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service registry claim safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("service registry claim missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) throw new Error("service registry claim expires before issuedAt");
  if (record.retractedAt !== undefined && Number(record.retractedAt || 0) <= Number(record.issuedAt || 0)) throw new Error("service registry claim retracted before issuedAt");
  return record;
}

export function assertServiceRegistryMaterialization(record) {
  if (!isObject(record)) throw new Error("service registry materialization must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_REGISTRY_MATERIALIZATION, "service registry materialization");
  requireString(record.registryId, "service registry materialization registryId");
  if (Number(record.schemaVersion || 0) !== SERVICE_REGISTRY.SCHEMA_VERSION) throw new Error("unsupported service registry materialization schemaVersion");
  requireString(record.scopeRef, "service registry materialization scopeRef");
  requireString(record.state, "service registry materialization state");
  if (!Object.values(SERVICE_REGISTRY.MATERIALIZATION_STATE).includes(record.state)) throw new Error("invalid service registry materialization state");
  if (!Number.isFinite(Number(record.revision))) throw new Error("service registry materialization missing revision");
  requireArray(record.claimRefs || [], "service registry materialization claimRefs").forEach((entry) => requireString(entry, "service registry materialization claimRef"));
  requireArray(record.participantRefs || [], "service registry materialization participantRefs").forEach((entry) => requireString(entry, "service registry materialization participantRef"));
  requireArray(record.serviceRefs || [], "service registry materialization serviceRefs").forEach((entry) => requireString(entry, "service registry materialization serviceRef"));
  requireArray(record.services || [], "service registry materialization services").forEach(assertHostedServiceDescriptor);
  requireArray(record.entries || [], "service registry materialization entries").forEach(assertDirectoryEntry);
  if (record.coverage !== undefined) assertProjectionCoverage(record.coverage);
  if (record.freshness !== undefined) assertProjectionFreshness(record.freshness);
  requireArray(record.blockedReasons || [], "service registry materialization blockedReasons").forEach((entry) => requireString(entry, "service registry materialization blockedReason"));
  if (!Number(record.issuedAt || 0)) throw new Error("service registry materialization missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) throw new Error("service registry materialization expires before issuedAt");
  return record;
}

export function assertBootstrapCarrierRecord(record) {
  if (!isObject(record)) throw new Error("bootstrap carrier must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.BOOTSTRAP_CARRIER, "bootstrap carrier");
  requireString(record.carrierId, "bootstrap carrier carrierId");
  requireString(record.carrierKind, "bootstrap carrier carrierKind");
  requireString(record.boundary, "bootstrap carrier boundary");
  if (record.boundary !== "bootstrap" && record.boundary !== "fallback") throw new Error("bootstrap carrier boundary must be bootstrap or fallback");
  if (record.payloadRef !== undefined) requireString(record.payloadRef, "bootstrap carrier payloadRef");
  if (!Number(record.issuedAt || 0)) throw new Error("bootstrap carrier missing issuedAt");
  return record;
}

function assertAuthorityDomain(value, name = "authority domain") {
  const domain = requireString(value, name);
  if (!Object.values(SWARM.AUTHORITY_DOMAIN).includes(domain)) throw new Error(`unsupported ${name}`);
  return domain;
}

function assertInteractionRoleName(value, name = "interaction role") {
  const role = requireString(value, name);
  if (!Object.values(SWARM.INTERACTION_ROLE).includes(role)) throw new Error(`unsupported ${name}`);
  return role;
}

function assertInteractionStateName(value, name = "interaction state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.INTERACTION_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertRoutingScopeKind(value, name = "routing scope kind") {
  const kind = requireString(value, name);
  if (!Object.values(SWARM.ROUTING_SCOPE_KIND).includes(kind)) throw new Error(`unsupported ${name}`);
  return kind;
}

function assertRoutingScopeState(value, name = "routing scope state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.ROUTING_SCOPE_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertRoutingBlockedReason(value, name = "routing blocked reason") {
  const reason = requireString(value, name);
  if (!Object.values(SWARM.ROUTING_BLOCKED_REASON).includes(reason)) throw new Error(`unsupported ${name}`);
  return reason;
}

function assertParticipantRunlevelName(value, name = "participant runlevel") {
  const runlevel = requireString(value, name);
  if (!Object.values(SWARM.PARTICIPANT_RUNLEVEL).includes(runlevel)) throw new Error(`unsupported ${name}`);
  return runlevel;
}

function assertSelfCapabilityActionName(value, name = "self capability action") {
  const action = requireString(value, name);
  if (!Object.values(SWARM.SELF_CAPABILITY_ACTION).includes(action)) throw new Error(`unsupported ${name}`);
  return action;
}

function assertSelfCapabilityStatusName(value, name = "self capability status") {
  const status = requireString(value, name);
  if (!Object.values(SWARM.SELF_CAPABILITY_STATUS).includes(status)) throw new Error(`unsupported ${name}`);
  return status;
}

function assertPostureFacetState(value, name = "posture facet state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.POSTURE_FACET_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertResourceProfileClass(value, name = "resource profile class") {
  const profileClass = requireString(value, name);
  if (!Object.values(SWARM.RESOURCE_PROFILE_CLASS).includes(profileClass)) throw new Error(`unsupported ${name}`);
  return profileClass;
}

function assertResourcePostureState(value, name = "resource posture state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.RESOURCE_POSTURE_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertEventPlane(value, name = "event plane") {
  const plane = requireString(value, name);
  if (!Object.values(SWARM.EVENT_PLANE).includes(plane)) throw new Error(`unsupported ${name}`);
  return plane;
}

const EVENT_PLANE_KIND_RULES = Object.freeze([
  [SWARM.EVENT_PLANE.AUTHORITY, /^runtime\.authority\./],
  [SWARM.EVENT_PLANE.PROJECTION_REPAIR, /^projection\.repair/],
  [SWARM.EVENT_PLANE.PROJECTION, /^projection\./],
  [SWARM.EVENT_PLANE.CONTRIBUTION, /^contribution\./],
  [SWARM.EVENT_PLANE.ACTIVATION, /^(service|stream|interaction|media)\./],
  [SWARM.EVENT_PLANE.ROUTE, /^(route|frame|adapter\.edge|runtime\.directory)\./],
  [SWARM.EVENT_PLANE.RETENTION, /^(retention|runtime\.retention)\./],
]);

export function eventPlaneForRecordKind(kind, context = {}) {
  const value = String(kind || context.kind || context.recordKind || "").trim();
  for (const [plane, pattern] of EVENT_PLANE_KIND_RULES) {
    if (pattern.test(value)) return plane;
  }
  const channel = String(context.channelRef || context.channelId || "").trim();
  const capability = String(context.capabilityRef || context.capability || "").trim();
  if (channel === "logging.events" || capability === "logging.events.ingest") return SWARM.EVENT_PLANE.LOGGING_REPLAY;
  return SWARM.EVENT_PLANE.DIAGNOSTIC;
}

function assertEventAdmissionDecision(value, name = "event admission decision") {
  const decision = requireString(value, name);
  if (!Object.values(SWARM.EVENT_ADMISSION_DECISION).includes(decision)) throw new Error(`unsupported ${name}`);
  return decision;
}

function assertEventProofRequirement(value, name = "event proof requirement") {
  const requirement = requireString(value, name);
  if (!Object.values(SWARM.EVENT_PROOF_REQUIREMENT).includes(requirement)) throw new Error(`unsupported ${name}`);
  return requirement;
}

function assertEventProofState(value, name = "event proof state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.EVENT_PROOF_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertEventDeliveryMode(value, name = "event delivery mode") {
  const mode = requireString(value, name);
  if (!Object.values(SWARM.EVENT_DELIVERY_MODE).includes(mode)) throw new Error(`unsupported ${name}`);
  return mode;
}

function assertEventBackpressureBehavior(value, name = "event backpressure behavior") {
  const behavior = requireString(value, name);
  if (!Object.values(SWARM.EVENT_BACKPRESSURE_BEHAVIOR).includes(behavior)) throw new Error(`unsupported ${name}`);
  return behavior;
}

function assertMaterializationPayloadClass(value, name = "materialization payload class") {
  const payloadClass = requireString(value, name);
  if (!Object.values(SWARM.MATERIALIZATION_PAYLOAD_CLASS).includes(payloadClass)) throw new Error(`unsupported ${name}`);
  return payloadClass;
}

function assertMaterializationCopyRole(value, name = "materialization copy role") {
  const copyRole = requireString(value, name);
  if (!Object.values(SWARM.MATERIALIZATION_COPY_ROLE).includes(copyRole)) throw new Error(`unsupported ${name}`);
  return copyRole;
}

function assertMaterializationTransferMode(value, name = "materialization transfer mode") {
  const transferMode = requireString(value, name);
  if (!Object.values(SWARM.MATERIALIZATION_TRANSFER_MODE).includes(transferMode)) throw new Error(`unsupported ${name}`);
  return transferMode;
}

function assertMaterializationLagState(value, name = "materialization lag state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MATERIALIZATION_LAG_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMaterializationSchemaState(value, name = "materialization schema state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MATERIALIZATION_SCHEMA_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMaterializationPrivacyTier(value, name = "materialization privacy tier") {
  const tier = requireString(value, name);
  if (!Object.values(SWARM.MATERIALIZATION_PRIVACY_TIER).includes(tier)) throw new Error(`unsupported ${name}`);
  return tier;
}

function assertProjectionRepairState(value, name = "projection repair state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.PROJECTION_REPAIR_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertRetentionReleaseState(value, name = "retention release state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.RETENTION_RELEASE_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertContributionType(value, name = "contribution type") {
  const type = requireString(value, name);
  if (!Object.values(SWARM.CONTRIBUTION_TYPE).includes(type)) throw new Error(`unsupported ${name}`);
  return type;
}

function assertContributionState(value, name = "contribution state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.CONTRIBUTION_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMediaFulfillmentEvidenceKind(value, name = "media fulfillment evidence kind") {
  const kind = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND).includes(kind)) throw new Error(`unsupported ${name}`);
  return kind;
}

function assertMediaFulfillmentState(value, name = "media fulfillment state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_FULFILLMENT_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMediaTransportPathState(value, name = "media transport path state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_TRANSPORT_PATH_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMediaTransportSelectedPairState(value, name = "media transport selected pair state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_TRANSPORT_SELECTED_PAIR_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMediaTransportRtpState(value, name = "media transport rtp state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_TRANSPORT_RTP_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMediaTransportRenderState(value, name = "media transport render state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_TRANSPORT_RENDER_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertMediaTransportParticipantRole(value, name = "media transport participant role") {
  const role = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_TRANSPORT_PARTICIPANT_ROLE).includes(role)) throw new Error(`unsupported ${name}`);
  return role;
}

function assertMediaTransportObservationState(value, name = "media transport observation state") {
  const state = requireString(value, name);
  if (!Object.values(SWARM.MEDIA_TRANSPORT_OBSERVATION_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

export function assertRoutingScopePosture(posture, name = "routing scope") {
  if (!isObject(posture)) throw new Error(`${name} must be an object`);
  const kind = assertRoutingScopeKind(posture.kind, `${name} kind`);
  const state = assertRoutingScopeState(posture.state, `${name} state`);
  const required = posture.required === undefined ? kind !== SWARM.ROUTING_SCOPE_KIND.LOCAL : Boolean(posture.required);
  const zoneScope = posture.zoneScope === undefined || posture.zoneScope === null
    ? null
    : assertZoneScope(posture.zoneScope);
  if (
    kind === SWARM.ROUTING_SCOPE_KIND.SWARM_ZONE
    && required
    && [SWARM.ROUTING_SCOPE_STATE.READY, SWARM.ROUTING_SCOPE_STATE.SYNCING, SWARM.ROUTING_SCOPE_STATE.STALE].includes(state)
    && !zoneScope
  ) {
    throw new Error(`${name} swarmZone posture requires zoneScope`);
  }
  if (state === SWARM.ROUTING_SCOPE_STATE.NOT_REQUIRED && required) {
    throw new Error(`${name} notRequired state cannot be required`);
  }
  const blockedReason = String(posture.blockedReason || "").trim();
  if (blockedReason) assertRoutingBlockedReason(blockedReason, `${name} blockedReason`);
  const updatedAt = posture.updatedAt === undefined ? undefined : Number(posture.updatedAt);
  if (updatedAt !== undefined && (!Number.isFinite(updatedAt) || updatedAt < 0)) {
    throw new Error(`${name} updatedAt must be non-negative`);
  }
  return {
    kind,
    required,
    state,
    ...(zoneScope ? { zoneScope } : {}),
    ...(posture.source ? { source: String(posture.source) } : {}),
    ...(posture.baselineRef ? { baselineRef: String(posture.baselineRef) } : {}),
    ...(blockedReason ? { blockedReason } : {}),
    ...(updatedAt !== undefined ? { updatedAt } : {}),
  };
}

function assertPostureFacet(facet, name = "posture facet") {
  if (!isObject(facet)) throw new Error(`${name} must be an object`);
  const state = assertPostureFacetState(facet.state, `${name} state`);
  const reason = String(facet.reason || "").trim();
  const evidenceRefs = assertOptionalReferenceList(facet.evidenceRefs, `${name} evidenceRefs`);
  const authorityRefs = assertOptionalReferenceList(facet.authorityRefs, `${name} authorityRefs`);
  const policyRefs = assertOptionalReferenceList(facet.policyRefs, `${name} policyRefs`);
  if ([SWARM.POSTURE_FACET_STATE.MISSING, SWARM.POSTURE_FACET_STATE.BLOCKED, SWARM.POSTURE_FACET_STATE.DEGRADED].includes(state) && !reason) {
    throw new Error(`${name} ${state} state requires reason`);
  }
  if (facet.updatedAt !== undefined && (!Number.isFinite(Number(facet.updatedAt)) || Number(facet.updatedAt) < 0)) {
    throw new Error(`${name} updatedAt must be non-negative`);
  }
  return {
    state,
    ...(reason ? { reason } : {}),
    ...(evidenceRefs.length ? { evidenceRefs } : {}),
    ...(authorityRefs.length ? { authorityRefs } : {}),
    ...(policyRefs.length ? { policyRefs } : {}),
    ...(facet.updatedAt !== undefined ? { updatedAt: Number(facet.updatedAt) } : {}),
  };
}

const REQUIRED_SELF_CAPABILITY_FACETS = Object.freeze([
  "authority",
  "resource",
  "policy",
  "directory",
  "route",
  "adapter",
  "retention",
  "domain",
]);

function assertPostureFacetMap(value, name = "posture facets", required = []) {
  if (!isObject(value)) throw new Error(`${name} must be an object`);
  for (const key of required) {
    if (value[key] === undefined) throw new Error(`${name} missing ${key} facet`);
  }
  const facets = {};
  for (const [key, facet] of Object.entries(value)) {
    if (!/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/.test(key)) throw new Error(`${name} invalid facet ${key}`);
    facets[key] = assertPostureFacet(facet, `${name}.${key}`);
  }
  return facets;
}

function blockedFacetReasons(facets) {
  const reasons = [];
  for (const [facetName, facet] of Object.entries(facets || {})) {
    if ([SWARM.POSTURE_FACET_STATE.MISSING, SWARM.POSTURE_FACET_STATE.BLOCKED].includes(facet.state)) {
      reasons.push(facet.reason || `${facetName} ${facet.state}`);
    }
  }
  return reasons;
}

function degradedFacetReasons(facets) {
  const reasons = [];
  for (const [facetName, facet] of Object.entries(facets || {})) {
    if (facet.state === SWARM.POSTURE_FACET_STATE.DEGRADED) {
      reasons.push(facet.reason || `${facetName} degraded`);
    }
  }
  return reasons;
}

export function assertParticipantRunlevelPosture(record) {
  if (!isObject(record)) throw new Error("participant runlevel posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.PARTICIPANT_RUNLEVEL, "participant runlevel posture");
  requireString(record.runlevelId, "participant runlevel id");
  assertResolvedMemberRef(record.participantRef, "participant runlevel participantRef");
  requireString(record.participantKind, "participant runlevel participantKind");
  assertParticipantRunlevelName(record.runlevel);
  if (record.facets !== undefined) assertPostureFacetMap(record.facets, "participant runlevel facets");
  assertOptionalReferenceList(record.evidenceRefs, "participant runlevel evidenceRefs");
  assertOptionalReferenceList(record.authorityRefs, "participant runlevel authorityRefs");
  if (record.reason !== undefined) requireString(record.reason, "participant runlevel reason");
  if (!Number(record.updatedAt || 0)) throw new Error("participant runlevel missing updatedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.updatedAt)) {
    throw new Error("participant runlevel expiresAt must be after updatedAt");
  }
  return record;
}

export function assertSelfCapabilityAssessment(record) {
  if (!isObject(record)) throw new Error("self capability assessment must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.PARTICIPANT_SELF_CAPABILITY, "self capability assessment");
  requireString(record.assessmentId, "self capability assessment id");
  assertResolvedMemberRef(record.participantRef, "self capability participantRef");
  if (record.serviceMemberRef !== undefined && record.serviceMemberRef !== null) {
    assertResolvedMemberRef(record.serviceMemberRef, "self capability serviceMemberRef");
  }
  if (record.serviceRef !== undefined) requireString(record.serviceRef, "self capability serviceRef");
  if (record.subjectRef !== undefined) requireString(record.subjectRef, "self capability subjectRef");
  assertCapabilityName(record.capabilityRef);
  const actions = requireNonEmptyArray(record.actions, "self capability actions").map((action) => assertSelfCapabilityActionName(action));
  const status = assertSelfCapabilityStatusName(record.status);
  assertParticipantRunlevelName(record.runlevel);
  const facets = assertPostureFacetMap(record.facets, "self capability facets", REQUIRED_SELF_CAPABILITY_FACETS);
  const explicitBlockedReasons = assertOptionalReferenceList(record.blockedReasons, "self capability blockedReasons");
  const blockingReasons = blockedFacetReasons(facets);
  const degradingReasons = degradedFacetReasons(facets);
  if (status === SWARM.SELF_CAPABILITY_STATUS.AVAILABLE && (blockingReasons.length || degradingReasons.length || explicitBlockedReasons.length)) {
    throw new Error("available self capability cannot carry blocked or degraded posture");
  }
  if ([SWARM.SELF_CAPABILITY_STATUS.BLOCKED, SWARM.SELF_CAPABILITY_STATUS.DISABLED].includes(status) && blockingReasons.length === 0 && explicitBlockedReasons.length === 0) {
    throw new Error(`${status} self capability requires blocked reason`);
  }
  if (status === SWARM.SELF_CAPABILITY_STATUS.DEGRADED && blockingReasons.length) {
    throw new Error("degraded self capability cannot carry blocking posture");
  }
  if (actions.length !== new Set(actions).size) throw new Error("self capability actions must be unique");
  assertOptionalReferenceList(record.evidenceRefs, "self capability evidenceRefs");
  assertOptionalReferenceList(record.authorityRefs, "self capability authorityRefs");
  assertOptionalReferenceList(record.policyRefs, "self capability policyRefs");
  if (!Number(record.updatedAt || 0)) throw new Error("self capability missing updatedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.updatedAt)) {
    throw new Error("self capability expiresAt must be after updatedAt");
  }
  return record;
}

export function assertResourceProfile(record) {
  if (!isObject(record)) throw new Error("resource profile must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.RESOURCE_PROFILE, "resource profile");
  requireString(record.profileId, "resource profile profileId");
  assertResourceProfileClass(record.profileClass);
  assertSafeObject(record.budgets, "resource profile budgets");
  assertSafeObject(record.caps, "resource profile caps");
  if (record.ownerRef !== undefined) requireString(record.ownerRef, "resource profile ownerRef");
  if (!Number(record.issuedAt || 0)) throw new Error("resource profile missing issuedAt");
  return record;
}

export function assertResourcePosture(record) {
  if (!isObject(record)) throw new Error("resource posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.RESOURCE_POSTURE, "resource posture");
  requireString(record.postureId, "resource posture postureId");
  requireString(record.profileId, "resource posture profileId");
  const state = assertResourcePostureState(record.state);
  assertSafeObject(record.counts, "resource posture counts");
  assertSafeObject(record.budgets, "resource posture budgets");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "resource posture blockedReasons");
  if ([SWARM.RESOURCE_POSTURE_STATE.PRESSURE, SWARM.RESOURCE_POSTURE_STATE.OVER_BUDGET, SWARM.RESOURCE_POSTURE_STATE.BLOCKED].includes(state) && blockedReasons.length === 0) {
    throw new Error("resource posture pressure states require blockedReasons");
  }
  if (record.lanes !== undefined) {
    requireArray(record.lanes, "resource posture lanes").forEach((lane, index) => {
      assertIngressLanePosture(lane, `resource posture lanes[${index}]`);
    });
  }
  if (!Number(record.sampledAt || 0)) throw new Error("resource posture missing sampledAt");
  return record;
}

export function assertIngressLanePosture(record, context = "ingress lane posture") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  assertRecordKind(record, SWARM.RECORD_KIND.INGRESS_LANE_POSTURE, context);
  requireString(record.laneId, `${context} laneId`);
  requireString(record.laneKind, `${context} laneKind`);
  const priority = Number(record.priority);
  if (!Number.isFinite(priority) || priority < 0) throw new Error(`${context} priority must be non-negative`);
  const state = assertResourcePostureState(record.state, `${context} state`);
  assertSafeObject(record.counts, `${context} counts`);
  assertSafeObject(record.limits, `${context} limits`);
  assertOptionalReferenceList(record.relevanceRefs, `${context} relevanceRefs`);
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, `${context} blockedReasons`);
  if ([SWARM.RESOURCE_POSTURE_STATE.PRESSURE, SWARM.RESOURCE_POSTURE_STATE.OVER_BUDGET, SWARM.RESOURCE_POSTURE_STATE.BLOCKED].includes(state) && blockedReasons.length === 0) {
    throw new Error(`${context} pressure states require blockedReasons`);
  }
  if (!Number(record.sampledAt || 0)) throw new Error(`${context} missing sampledAt`);
  return record;
}

export function assertEventAdmissionEnvelope(record, context = "event admission envelope") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  assertRecordKind(record, SWARM.RECORD_KIND.EVENT_ADMISSION, context);
  requireString(record.admissionId, `${context} admissionId`);
  const plane = assertEventPlane(record.plane, `${context} plane`);
  if (record.laneId !== undefined) requireString(record.laneId, `${context} laneId`);
  if (record.subscriptionId !== undefined) requireString(record.subscriptionId, `${context} subscriptionId`);
  if (record.publisherRef !== undefined) requireString(record.publisherRef, `${context} publisherRef`);
  if (record.subscriberRef !== undefined) requireString(record.subscriberRef, `${context} subscriberRef`);
  assertSafeObject(record.subject, `${context} subject`);
  assertSafeObject(record.audience, `${context} audience`);
  const claimedSeverity = String(record.claimedSeverity || "").trim();
  if (claimedSeverity && !Object.values(LOGGING.SEVERITY).includes(claimedSeverity)) {
    throw new Error(`${context} claimedSeverity is unsupported`);
  }
  const effectivePriority = Number(record.effectivePriority);
  if (!Number.isFinite(effectivePriority) || effectivePriority < 0) {
    throw new Error(`${context} effectivePriority must be non-negative`);
  }
  const decision = assertEventAdmissionDecision(record.decision, `${context} decision`);
  const proofRequirement = assertEventProofRequirement(record.proofRequirement, `${context} proofRequirement`);
  const proofState = assertEventProofState(record.proofState, `${context} proofState`);
  const reason = String(record.reason || "").trim();
  if ([SWARM.EVENT_ADMISSION_DECISION.DROP, SWARM.EVENT_ADMISSION_DECISION.DEFER, SWARM.EVENT_ADMISSION_DECISION.SUMMARIZE, SWARM.EVENT_ADMISSION_DECISION.REJECT].includes(decision) && !reason) {
    throw new Error(`${context} ${decision} decision requires reason`);
  }
  if (proofRequirement === SWARM.EVENT_PROOF_REQUIREMENT.NONE && proofState !== SWARM.EVENT_PROOF_STATE.NOT_REQUIRED) {
    throw new Error(`${context} proofState must be notRequired when proofRequirement is none`);
  }
  if (proofRequirement !== SWARM.EVENT_PROOF_REQUIREMENT.NONE && proofState === SWARM.EVENT_PROOF_STATE.NOT_REQUIRED) {
    throw new Error(`${context} proofState cannot be notRequired when proof is required`);
  }
  if (decision === SWARM.EVENT_ADMISSION_DECISION.FORWARD && proofState === SWARM.EVENT_PROOF_STATE.FAILED) {
    throw new Error(`${context} cannot forward failed proof`);
  }
  if (record.cost !== undefined) assertSafeObject(record.cost, `${context} cost`);
  assertOptionalReferenceList(record.evidenceRefs, `${context} evidenceRefs`);
  if (!Number(record.observedAt || 0)) throw new Error(`${context} missing observedAt`);
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.observedAt)) {
    throw new Error(`${context} expiresAt must be after observedAt`);
  }
  if (plane === SWARM.EVENT_PLANE.BULK_RETAINED_DATA && decision === SWARM.EVENT_ADMISSION_DECISION.FORWARD && !record.subscriptionId) {
    throw new Error(`${context} bulk retained data forward requires subscriptionId`);
  }
  return record;
}

export function assertSubscriptionContract(record, context = "subscription contract") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  assertRecordKind(record, SWARM.RECORD_KIND.SUBSCRIPTION_CONTRACT, context);
  requireString(record.subscriptionId, `${context} subscriptionId`);
  requireString(record.subscriberRef, `${context} subscriberRef`);
  if (record.publisherRef !== undefined) requireString(record.publisherRef, `${context} publisherRef`);
  if (record.publisherClass !== undefined) requireString(record.publisherClass, `${context} publisherClass`);
  const planes = requireNonEmptyArray(record.planes, `${context} planes`).map((plane) => assertEventPlane(plane, `${context} plane`));
  if (planes.length !== new Set(planes).size) throw new Error(`${context} planes must be unique`);
  if (!isObject(record.subjectSelector)) throw new Error(`${context} subjectSelector must be an object`);
  assertSafeObject(record.subjectSelector, `${context} subjectSelector`);
  assertSafeObject(record.audience, `${context} audience`);
  const delivery = assertSafeObject(record.delivery, `${context} delivery`);
  assertEventDeliveryMode(delivery.mode, `${context} delivery mode`);
  const proof = assertSafeObject(record.proof, `${context} proof`);
  assertEventProofRequirement(proof.requirement, `${context} proof requirement`);
  const backpressure = assertSafeObject(record.backpressure, `${context} backpressure`);
  assertEventBackpressureBehavior(backpressure.behavior, `${context} backpressure behavior`);
  if (record.window !== undefined) assertSafeObject(record.window, `${context} window`);
  if (record.cost !== undefined) assertSafeObject(record.cost, `${context} cost`);
  assertOptionalCapabilityList(record.capabilityRefs, `${context} capabilityRefs`);
  assertOptionalReferenceList(record.authorityRefs, `${context} authorityRefs`);
  if (!Number(record.issuedAt || 0)) throw new Error(`${context} missing issuedAt`);
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error(`${context} expiresAt must be after issuedAt`);
  }
  return record;
}

function assertOptionalTimeField(value, name) {
  if (value === undefined || value === null || value === "") return undefined;
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) throw new Error(`${name} must be non-negative`);
  return number;
}

function assertMaterializationSchemaPosture(value, context) {
  if (value === undefined || value === null) return undefined;
  if (!isObject(value)) throw new Error(`${context} schema must be an object`);
  const state = assertMaterializationSchemaState(value.state, `${context} schema state`);
  const version = String(value.version || "").trim();
  const reason = String(value.reason || "").trim();
  if ([SWARM.MATERIALIZATION_SCHEMA_STATE.IGNORE, SWARM.MATERIALIZATION_SCHEMA_STATE.QUARANTINED, SWARM.MATERIALIZATION_SCHEMA_STATE.BLOCKED].includes(state) && !reason) {
    throw new Error(`${context} schema ${state} state requires reason`);
  }
  const migrationRefs = assertOptionalReferenceList(value.migrationRefs, `${context} schema migrationRefs`);
  return {
    state,
    ...(version ? { version } : {}),
    ...(reason ? { reason } : {}),
    ...(migrationRefs.length ? { migrationRefs } : {}),
  };
}

export function assertConsumerFloor(record, context = "consumer floor") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  assertRecordKind(record, SWARM.RECORD_KIND.CONSUMER_FLOOR, context);
  requireString(record.floorId, `${context} floorId`);
  requireString(record.consumerRef, `${context} consumerRef`);
  if (record.subscriptionId !== undefined) requireString(record.subscriptionId, `${context} subscriptionId`);
  if (record.materializationId !== undefined) requireString(record.materializationId, `${context} materializationId`);
  if (record.subjectRef !== undefined) requireString(record.subjectRef, `${context} subjectRef`);
  const lagState = assertMaterializationLagState(record.lagState || SWARM.MATERIALIZATION_LAG_STATE.UNKNOWN, `${context} lagState`);
  const cursor = String(record.cursor || "").trim();
  const ackFloor = String(record.ackFloor || "").trim();
  const witnessFloor = String(record.witnessFloor || "").trim();
  const compactionFloor = String(record.compactionFloor || "").trim();
  const eventTimeFloor = assertOptionalTimeField(record.eventTimeFloor, `${context} eventTimeFloor`);
  const observedTimeFloor = assertOptionalTimeField(record.observedTimeFloor, `${context} observedTimeFloor`);
  if (eventTimeFloor !== undefined && observedTimeFloor !== undefined && observedTimeFloor < eventTimeFloor) {
    throw new Error(`${context} observedTimeFloor must not be before eventTimeFloor`);
  }
  if ([SWARM.MATERIALIZATION_LAG_STATE.LAGGING, SWARM.MATERIALIZATION_LAG_STATE.STALE, SWARM.MATERIALIZATION_LAG_STATE.BLOCKED].includes(lagState) && !String(record.reason || "").trim()) {
    throw new Error(`${context} ${lagState} state requires reason`);
  }
  if (record.redelivery !== undefined) assertSafeObject(record.redelivery, `${context} redelivery`);
  if (record.replay !== undefined) assertSafeObject(record.replay, `${context} replay`);
  assertOptionalReferenceList(record.evidenceRefs, `${context} evidenceRefs`);
  if (!Number(record.sampledAt || 0)) throw new Error(`${context} missing sampledAt`);
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.sampledAt)) {
    throw new Error(`${context} expiresAt must be after sampledAt`);
  }
  return {
    ...record,
    lagState,
    ...(cursor ? { cursor } : {}),
    ...(ackFloor ? { ackFloor } : {}),
    ...(witnessFloor ? { witnessFloor } : {}),
    ...(compactionFloor ? { compactionFloor } : {}),
    ...(eventTimeFloor !== undefined ? { eventTimeFloor } : {}),
    ...(observedTimeFloor !== undefined ? { observedTimeFloor } : {}),
  };
}

export function assertMaterializationBudget(record, context = "materialization budget") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  assertRecordKind(record, SWARM.RECORD_KIND.MATERIALIZATION_BUDGET, context);
  requireString(record.budgetId, `${context} budgetId`);
  requireString(record.sourceAuthority, `${context} sourceAuthority`);
  requireString(record.consumerRef, `${context} consumerRef`);
  const payloadClass = assertMaterializationPayloadClass(record.payloadClass, `${context} payloadClass`);
  const copyRole = assertMaterializationCopyRole(record.copyRole, `${context} copyRole`);
  const transferMode = assertMaterializationTransferMode(record.transferMode, `${context} transferMode`);
  const privacyTier = record.privacyTier === undefined
    ? undefined
    : assertMaterializationPrivacyTier(record.privacyTier, `${context} privacyTier`);
  const state = assertResourcePostureState(record.state || SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET, `${context} state`);
  assertSafeObject(record.limits, `${context} limits`);
  if (record.snapshotPolicy !== undefined) assertSafeObject(record.snapshotPolicy, `${context} snapshotPolicy`);
  if (record.deltaPolicy !== undefined) assertSafeObject(record.deltaPolicy, `${context} deltaPolicy`);
  if (record.coalescing !== undefined) assertSafeObject(record.coalescing, `${context} coalescing`);
  if (record.cardinality !== undefined) assertSafeObject(record.cardinality, `${context} cardinality`);
  const schemaPosture = assertMaterializationSchemaPosture(record.schema, context);
  const consumerFloor = record.consumerFloor === undefined || record.consumerFloor === null
    ? undefined
    : assertConsumerFloor(record.consumerFloor, `${context} consumerFloor`);
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, `${context} blockedReasons`);
  if ([SWARM.RESOURCE_POSTURE_STATE.PRESSURE, SWARM.RESOURCE_POSTURE_STATE.OVER_BUDGET, SWARM.RESOURCE_POSTURE_STATE.BLOCKED].includes(state) && blockedReasons.length === 0) {
    throw new Error(`${context} pressure states require blockedReasons`);
  }
  if (payloadClass === SWARM.MATERIALIZATION_PAYLOAD_CLASS.MEDIA && transferMode === SWARM.MATERIALIZATION_TRANSFER_MODE.CLONE) {
    throw new Error(`${context} media payload must not use clone transfer`);
  }
  if (payloadClass === SWARM.MATERIALIZATION_PAYLOAD_CLASS.RETAINED_RAW && privacyTier && ![
    SWARM.MATERIALIZATION_PRIVACY_TIER.ENCRYPTED_RAW,
    SWARM.MATERIALIZATION_PRIVACY_TIER.ENCRYPTED_DETAIL,
  ].includes(privacyTier)) {
    throw new Error(`${context} retained raw payload requires encrypted privacy tier`);
  }
  if (transferMode === SWARM.MATERIALIZATION_TRANSFER_MODE.REFERENCE_ONLY) {
    const refs = assertOptionalReferenceList(record.referenceRefs, `${context} referenceRefs`);
    if (refs.length === 0) throw new Error(`${context} referenceOnly transfer requires referenceRefs`);
  } else {
    assertOptionalReferenceList(record.referenceRefs, `${context} referenceRefs`);
  }
  assertOptionalReferenceList(record.evidenceRefs, `${context} evidenceRefs`);
  if (record.retentionClass !== undefined) requireString(record.retentionClass, `${context} retentionClass`);
  if (!Number(record.issuedAt || 0)) throw new Error(`${context} missing issuedAt`);
  if (record.releaseAfter !== undefined && Number(record.releaseAfter) < Number(record.issuedAt)) {
    throw new Error(`${context} releaseAfter must not be before issuedAt`);
  }
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error(`${context} expiresAt must be after issuedAt`);
  }
  rejectMediaByteFields(record, context);
  return {
    ...record,
    state,
    payloadClass,
    copyRole,
    transferMode,
    ...(privacyTier ? { privacyTier } : {}),
    ...(schemaPosture ? { schema: schemaPosture } : {}),
    ...(consumerFloor ? { consumerFloor } : {}),
  };
}

export function assertProjectionRepairPosture(record) {
  if (!isObject(record)) throw new Error("projection repair posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.PROJECTION_REPAIR_POSTURE, "projection repair posture");
  requireString(record.repairId, "projection repair repairId");
  requireString(record.projectionId, "projection repair projectionId");
  requireString(record.policyId, "projection repair policyId");
  const state = assertProjectionRepairState(record.state);
  const currentRevision = Number(record.currentRevision);
  const requiredRevision = Number(record.requiredRevision ?? record.targetRevision);
  if (!Number.isInteger(currentRevision) || currentRevision < 0) throw new Error("projection repair currentRevision must be non-negative integer");
  if (!Number.isInteger(requiredRevision) || requiredRevision <= currentRevision) throw new Error("projection repair requiredRevision must be after currentRevision");
  requireString(record.reason, "projection repair reason");
  if (record.coverage !== undefined) assertProjectionCoverage(record.coverage);
  if (record.observerRef !== undefined) requireString(record.observerRef, "projection repair observerRef");
  if (record.routePromiseId !== undefined) requireString(record.routePromiseId, "projection repair routePromiseId");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "projection repair blockedReasons");
  if (state === SWARM.PROJECTION_REPAIR_STATE.BLOCKED && blockedReasons.length === 0) {
    throw new Error("blocked projection repair requires blockedReasons");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("projection repair missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("projection repair expiresAt must be after issuedAt");
  }
  rejectMediaByteFields(record, "projection repair posture");
  return record;
}

export function assertRetentionReleasePosture(record) {
  if (!isObject(record)) throw new Error("retention release posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.RETENTION_RELEASE, "retention release posture");
  requireString(record.evaluationId, "retention release evaluationId");
  requireString(record.subjectRef, "retention release subjectRef");
  requireString(record.effectiveRetention, "retention release effectiveRetention");
  const state = assertRetentionReleaseState(record.state);
  assertOptionalReferenceList(record.policyRefs, "retention release policyRefs");
  assertOptionalReferenceList(record.overlayRefs, "retention release overlayRefs");
  assertReferenceList(record.ownerRefs, "retention release ownerRefs");
  assertOptionalReferenceList(record.holderRefs, "retention release holderRefs");
  assertOptionalReferenceList(record.fulfillmentRefs, "retention release fulfillmentRefs");
  const residencyLayers = requireNonEmptyArray(record.residencyLayers, "retention release residencyLayers").map((entry) => requireString(entry, "retention release residencyLayer"));
  assertOptionalReferenceList(record.witnessRefs, "retention release witnessRefs");
  assertOptionalReferenceList(record.supersessionRefs, "retention release supersessionRefs");
  assertOptionalReferenceList(record.retractionRefs, "retention release retractionRefs");
  assertOptionalReferenceList(record.revocationRefs, "retention release revocationRefs");
  const blockers = requireArray(record.blockers || [], "retention release blockers");
  for (const blocker of blockers) {
    if (typeof blocker === "string") requireString(blocker, "retention release blocker");
    else if (isObject(blocker)) {
      requireString(blocker.code || blocker.reason, "retention release blocker code");
      if (blocker.ownerRef !== undefined) requireString(blocker.ownerRef, "retention release blocker ownerRef");
    } else {
      throw new Error("retention release blocker must be string or object");
    }
  }
  if (state === SWARM.RETENTION_RELEASE_STATE.RELEASE_BLOCKED && blockers.length === 0) {
    throw new Error("releaseBlocked retention posture requires blockers");
  }
  if (state === SWARM.RETENTION_RELEASE_STATE.FREEABLE && blockers.length !== 0) {
    throw new Error("freeable retention posture cannot carry blockers");
  }
  if (!residencyLayers.length) throw new Error("retention release residencyLayers must not be empty");
  const validUntil = assertOptionalTimeField(record.validUntil, "retention release validUntil");
  const releaseAfter = assertOptionalTimeField(record.releaseAfter, "retention release releaseAfter");
  if (validUntil !== undefined && releaseAfter !== undefined && releaseAfter < validUntil) {
    throw new Error("retention release releaseAfter must not be before validUntil");
  }
  if (!Number(record.evaluatedAt || 0)) throw new Error("retention release missing evaluatedAt");
  return record;
}

export function assertContributionLifecycle(record, context = "contribution lifecycle") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  assertRecordKind(record, SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE, context);
  requireString(record.contributionId, `${context} contributionId`);
  requireString(record.parentRef, `${context} parentRef`);
  requireString(record.subjectRef, `${context} subjectRef`);
  requireString(record.writerRef, `${context} writerRef`);
  const contributionType = assertContributionType(record.contributionType, `${context} contributionType`);
  const state = assertContributionState(record.state || SWARM.CONTRIBUTION_STATE.ACTIVE, `${context} state`);
  requireString(record.role, `${context} role`);
  assertReferenceList(record.authorityRefs, `${context} authorityRefs`);
  if (record.scope !== undefined) assertSafeObject(record.scope, `${context} scope`);
  const supersedes = assertOptionalReferenceList(record.supersedes, `${context} supersedes`);
  const witnessRefs = assertOptionalReferenceList(record.witnessRefs, `${context} witnessRefs`);
  const evidenceRefs = assertOptionalReferenceList(record.evidenceRefs, `${context} evidenceRefs`);
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, `${context} blockedReasons`);
  const targetContributionRef = String(record.targetContributionRef || "").trim();
  if (!Number(record.issuedAt || 0)) throw new Error(`${context} missing issuedAt`);
  const validUntil = assertOptionalTimeField(record.validUntil, `${context} validUntil`);
  if (validUntil !== undefined && validUntil <= Number(record.issuedAt)) {
    throw new Error(`${context} validUntil must be after issuedAt`);
  }
  const releaseAfter = assertOptionalTimeField(record.releaseAfter, `${context} releaseAfter`);
  if (releaseAfter !== undefined && releaseAfter < Number(record.issuedAt)) {
    throw new Error(`${context} releaseAfter must not be before issuedAt`);
  }
  const retractedAt = assertOptionalTimeField(record.retractedAt, `${context} retractedAt`);
  if (retractedAt !== undefined && retractedAt < Number(record.issuedAt)) {
    throw new Error(`${context} retractedAt must not be before issuedAt`);
  }
  if ([SWARM.CONTRIBUTION_TYPE.WITNESS, SWARM.CONTRIBUTION_TYPE.RETRACTION, SWARM.CONTRIBUTION_TYPE.RELEASE].includes(contributionType) && !targetContributionRef) {
    throw new Error(`${context} ${contributionType} requires targetContributionRef`);
  }
  if (contributionType === SWARM.CONTRIBUTION_TYPE.WITNESS && !Number(record.observedAt || 0)) {
    throw new Error(`${context} witness requires observedAt`);
  }
  if (state === SWARM.CONTRIBUTION_STATE.WITNESSED && witnessRefs.length === 0) {
    throw new Error(`${context} witnessed state requires witnessRefs`);
  }
  if (state === SWARM.CONTRIBUTION_STATE.RETRACTED && retractedAt === undefined) {
    throw new Error(`${context} retracted state requires retractedAt`);
  }
  if (state === SWARM.CONTRIBUTION_STATE.BLOCKED && blockedReasons.length === 0) {
    throw new Error(`${context} blocked state requires blockedReasons`);
  }
  rejectMediaByteFields(record, context);
  return {
    ...record,
    contributionType,
    state,
    supersedes,
    witnessRefs,
    evidenceRefs,
    blockedReasons,
    ...(targetContributionRef ? { targetContributionRef } : {}),
    ...(validUntil !== undefined ? { validUntil } : {}),
    ...(releaseAfter !== undefined ? { releaseAfter } : {}),
    ...(retractedAt !== undefined ? { retractedAt } : {}),
  };
}

export function assertMediaFulfillmentEvidence(record) {
  if (!isObject(record)) throw new Error("media fulfillment evidence must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.MEDIA_FULFILLMENT_EVIDENCE, "media fulfillment evidence");
  requireString(record.evidenceId, "media fulfillment evidence evidenceId");
  const evidenceKind = assertMediaFulfillmentEvidenceKind(record.evidenceKind);
  const state = assertMediaFulfillmentState(record.state);
  if (record.sessionId !== undefined) requireString(record.sessionId, "media fulfillment evidence sessionId");
  if (record.activationId !== undefined) requireString(record.activationId, "media fulfillment evidence activationId");
  if (record.interactionId !== undefined) requireString(record.interactionId, "media fulfillment evidence interactionId");
  if (record.correlationId !== undefined) requireString(record.correlationId, "media fulfillment evidence correlationId");
  if (record.routePromiseId !== undefined) requireString(record.routePromiseId, "media fulfillment evidence routePromiseId");
  if (!record.sessionId && !record.activationId && !record.interactionId && !record.correlationId) {
    throw new Error("media fulfillment evidence requires sessionId, activationId, interactionId, or correlationId");
  }
  if (record.participantRef !== undefined) requireString(record.participantRef, "media fulfillment evidence participantRef");
  if (record.adapterRef !== undefined) requireString(record.adapterRef, "media fulfillment evidence adapterRef");
  if (record.serviceRef !== undefined) requireString(record.serviceRef, "media fulfillment evidence serviceRef");
  if (record.sourceRef !== undefined) requireString(record.sourceRef, "media fulfillment evidence sourceRef");
  const blockedReason = String(record.blockedReason || "").trim();
  if (state === SWARM.MEDIA_FULFILLMENT_STATE.BLOCKED && !blockedReason) {
    throw new Error("blocked media fulfillment evidence requires blockedReason");
  }
  if (state === SWARM.MEDIA_FULFILLMENT_STATE.RELEASED && evidenceKind !== SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND.RELEASE) {
    throw new Error("released media fulfillment evidence must use release evidence kind");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "media fulfillment evidence safeFacts");
  assertOptionalReferenceList(record.evidenceRefs, "media fulfillment evidence evidenceRefs");
  if (!Number(record.observedAt || 0)) throw new Error("media fulfillment evidence missing observedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.observedAt)) {
    throw new Error("media fulfillment evidence expiresAt must be after observedAt");
  }
  rejectMediaByteFields(record, "media fulfillment evidence");
  return record;
}

export function assertMediaTransportPath(record) {
  if (!isObject(record)) throw new Error("media transport path must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.MEDIA_TRANSPORT_PATH, "media transport path");
  requireString(record.pathId, "media transport path pathId");
  requireString(record.sessionId, "media transport path sessionId");
  if (record.activationId !== undefined) requireString(record.activationId, "media transport path activationId");
  if (record.routePromiseId !== undefined) requireString(record.routePromiseId, "media transport path routePromiseId");
  requireString(record.transportProfileRef, "media transport path transportProfileRef");
  assertMediaTransportPathState(record.state);
  assertMediaTransportSelectedPairState(record.selectedPairState);
  assertMediaTransportRtpState(record.inboundRtpState);
  assertMediaTransportRenderState(record.renderState);
  assertOptionalReferenceList(record.browserCandidateRefs, "media transport path browserCandidateRefs");
  assertOptionalReferenceList(record.serviceCandidateRefs, "media transport path serviceCandidateRefs");
  assertOptionalReferenceList(record.relayParticipantRefs, "media transport path relayParticipantRefs");
  assertOptionalReferenceList(record.turnParticipantRefs, "media transport path turnParticipantRefs");
  assertOptionalReferenceList(record.evidenceRefs, "media transport path evidenceRefs");
  const blockedReason = String(record.blockedReason || "").trim();
  if (record.state === SWARM.MEDIA_TRANSPORT_PATH_STATE.BLOCKED && !blockedReason) {
    throw new Error("blocked media transport path requires blockedReason");
  }
  if (record.safeFacts !== undefined) {
    if (!isObject(record.safeFacts)) throw new Error("media transport path safeFacts must be an object");
    rejectUnsafeSafeFacts(record.safeFacts);
    rejectMediaByteFields(record.safeFacts, "media transport path safeFacts");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("media transport path missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("media transport path expiresAt must be after issuedAt");
  }
  rejectMediaByteFields(record, "media transport path");
  return record;
}

export function assertMediaTransportObservation(record) {
  if (!isObject(record)) throw new Error("media transport observation must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.MEDIA_TRANSPORT_OBSERVATION, "media transport observation");
  requireString(record.observationId, "media transport observation observationId");
  requireString(record.pathId, "media transport observation pathId");
  requireString(record.sessionId, "media transport observation sessionId");
  if (record.activationId !== undefined) requireString(record.activationId, "media transport observation activationId");
  if (record.routePromiseId !== undefined) requireString(record.routePromiseId, "media transport observation routePromiseId");
  requireString(record.participantRef, "media transport observation participantRef");
  assertMediaTransportParticipantRole(record.participantRole);
  assertMediaTransportObservationState(record.state);
  if (record.selectedPairState !== undefined) assertMediaTransportSelectedPairState(record.selectedPairState);
  if (record.inboundRtpState !== undefined) assertMediaTransportRtpState(record.inboundRtpState);
  if (record.renderState !== undefined) assertMediaTransportRenderState(record.renderState);
  const blockedReason = String(record.blockedReason || "").trim();
  if (record.state === SWARM.MEDIA_TRANSPORT_OBSERVATION_STATE.BLOCKED && !blockedReason) {
    throw new Error("blocked media transport observation requires blockedReason");
  }
  if (record.evidenceRefs !== undefined) assertOptionalReferenceList(record.evidenceRefs, "media transport observation evidenceRefs");
  if (record.safeFacts !== undefined) {
    if (!isObject(record.safeFacts)) throw new Error("media transport observation safeFacts must be an object");
    rejectUnsafeSafeFacts(record.safeFacts);
    rejectMediaByteFields(record.safeFacts, "media transport observation safeFacts");
  }
  if (!Number(record.observedAt || 0)) throw new Error("media transport observation missing observedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.observedAt)) {
    throw new Error("media transport observation expiresAt must be after observedAt");
  }
  rejectMediaByteFields(record, "media transport observation");
  return record;
}

function assertOptionalReferenceList(value, name) {
  if (value === undefined || value === null) return [];
  return requireArray(value, name).map((entry) => requireString(entry, `${name} entry`));
}

function assertOptionalCapabilityList(value, name) {
  return assertOptionalReferenceList(value, name).map(assertCapabilityName);
}

function assertSafeObject(value, name) {
  const object = assertOptionalObject(value, name);
  rejectRouteControlByteFields(object, name);
  rejectUnsafeSafeFacts(object);
  return object;
}

function assertPrivateRefList(value, name = "privateRefs") {
  if (value === undefined || value === null) return [];
  const refs = requireArray(value, name);
  for (const ref of refs) {
    if (!isObject(ref)) throw new Error(`${name} entry must be an object`);
    requireString(ref.ref, `${name} ref`);
    if (ref.kind !== undefined) requireString(ref.kind, `${name} kind`);
  }
  return refs;
}

function assertParticipantView(value, context) {
  if (!isObject(value)) throw new Error(`${context} must be an object`);
  assertInteractionRoleName(value.role, `${context} role`);
  assertResolvedMemberRef(value.memberRef, `${context} memberRef`);
  assertOptionalCapabilityList(value.capabilityRefs, `${context} capabilityRefs`);
  assertOptionalReferenceList(value.channelRefs, `${context} channelRefs`);
  assertOptionalReferenceList(value.authorityRefs, `${context} authorityRefs`);
  if (value.contractView !== undefined) assertOptionalObject(value.contractView, `${context} contractView`);
  if (value.safeFacts !== undefined) assertSafeObject(value.safeFacts, `${context} safeFacts`);
  return value;
}

export function assertSwarmIdentity(record) {
  if (!isObject(record)) throw new Error("swarm identity must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_IDENTITY, "swarm identity");
  requireString(record.identityId, "swarm identity identityId");
  assertReferenceList(record.rootRefs, "swarm identity rootRefs");
  const recoveryRootRefs = assertOptionalReferenceList(record.recoveryRootRefs, "swarm identity recoveryRootRefs");
  const recoveryRouteRefs = assertOptionalReferenceList(record.recoveryRouteRefs, "swarm identity recoveryRouteRefs");
  if (recoveryRouteRefs.some((ref) => recoveryRootRefs.includes(ref))) {
    throw new Error("swarm identity recovery route must not be promoted as recovery root");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm identity safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm identity missing issuedAt");
  return record;
}

export function assertSwarmDevice(record) {
  if (!isObject(record)) throw new Error("swarm device must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_DEVICE, "swarm device");
  requireString(record.deviceId, "swarm device deviceId");
  requireString(record.deviceRef, "swarm device deviceRef");
  requireString(record.identityRef, "swarm device identityRef");
  assertOptionalCapabilityList(record.capabilityRefs, "swarm device capabilityRefs");
  assertReferenceList(record.authorityRefs, "swarm device authorityRefs");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm device safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm device missing issuedAt");
  return record;
}

export function assertSwarmGateway(record) {
  if (!isObject(record)) throw new Error("swarm gateway must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_GATEWAY, "swarm gateway");
  requireString(record.gatewayId, "swarm gateway gatewayId");
  requireString(record.gatewayRef, "swarm gateway gatewayRef");
  assertReferenceList(record.ownerRefs, "swarm gateway ownerRefs");
  assertReferenceList(record.authorityRefs, "swarm gateway authorityRefs");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm gateway safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm gateway missing issuedAt");
  return record;
}

export function assertSwarmService(record) {
  if (!isObject(record)) throw new Error("swarm service must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_SERVICE, "swarm service");
  requireString(record.serviceId, "swarm service serviceId");
  requireString(record.serviceRef, "swarm service serviceRef");
  requireString(record.service, "swarm service service");
  requireString(record.contractRef, "swarm service contractRef");
  assertOptionalCapabilityList(record.capabilityRefs, "swarm service capabilityRefs");
  assertOptionalReferenceList(record.channelRefs, "swarm service channelRefs");
  assertReferenceList(record.authorityRefs, "swarm service authorityRefs");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm service safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm service missing issuedAt");
  return record;
}

export function assertSwarmMember(record) {
  if (!isObject(record)) throw new Error("swarm member must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_MEMBER, "swarm member");
  requireString(record.memberId, "swarm member memberId");
  assertResolvedMemberRef(record.memberRef, "swarm member memberRef");
  requireString(record.memberKind, "swarm member memberKind");
  assertOptionalCapabilityList(record.capabilityRefs, "swarm member capabilityRefs");
  assertOptionalReferenceList(record.channelRefs, "swarm member channelRefs");
  assertReferenceList(record.authorityRefs, "swarm member authorityRefs");
  if (record.storage !== undefined) {
    const storage = assertOptionalObject(record.storage, "swarm member storage");
    if (storage.memberKind !== undefined && !Object.values(SWARM.STORAGE_MEMBER_KIND).includes(String(storage.memberKind))) {
      throw new Error("unsupported swarm member storage kind");
    }
    if (storage.authorityDomain === SWARM.AUTHORITY_DOMAIN.IDENTITY) {
      throw new Error("storage member must not claim identity authority");
    }
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm member safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm member missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("swarm member expiresAt must be after issuedAt");
  }
  return record;
}

export function assertSwarmGrant(record) {
  if (!isObject(record)) throw new Error("swarm grant must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_GRANT, "swarm grant");
  requireString(record.grantId, "swarm grant grantId");
  requireString(record.issuerRef, "swarm grant issuerRef");
  requireString(record.subjectRef, "swarm grant subjectRef");
  assertReferenceList(record.audienceRefs, "swarm grant audienceRefs");
  assertAuthorityDomain(record.authorityDomain, "swarm grant authorityDomain");
  assertOptionalCapabilityList(record.capabilityRefs, "swarm grant capabilityRefs");
  assertOptionalReferenceList(record.roleRefs, "swarm grant roleRefs");
  if (record.elevated === true && !assertOptionalReferenceList(record.rootRefs, "swarm grant rootRefs").length) {
    throw new Error("elevated swarm grant requires rootRefs");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm grant safeFacts");
  assertPrivateRefList(record.privateRefs, "swarm grant privateRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm grant missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("swarm grant expiresAt must be after issuedAt");
  }
  return record;
}

export function assertSwarmRole(record) {
  if (!isObject(record)) throw new Error("swarm role must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_ROLE, "swarm role");
  requireString(record.roleId, "swarm role roleId");
  assertInteractionRoleName(record.role, "swarm role role");
  assertResolvedMemberRef(record.memberRef, "swarm role memberRef");
  assertOptionalCapabilityList(record.capabilityRefs, "swarm role capabilityRefs");
  assertReferenceList(record.authorityRefs, "swarm role authorityRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm role missing issuedAt");
  return record;
}

export function assertSwarmInteraction(record) {
  if (!isObject(record)) throw new Error("swarm interaction must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_INTERACTION, "swarm interaction");
  requireString(record.interactionId, "swarm interaction interactionId");
  requireString(record.contractRef, "swarm interaction contractRef");
  requireString(record.interactionKind || record.kindName || record.interactionType, "swarm interaction interactionKind");
  const participants = requireNonEmptyArray(record.participants, "swarm interaction participants");
  participants.forEach((entry, index) => assertParticipantView(entry, `swarm interaction participant ${index}`));
  const participantRoles = new Set(participants.map((entry) => String(entry.role)));
  for (const required of [SWARM.INTERACTION_ROLE.REQUESTER, SWARM.INTERACTION_ROLE.COORDINATOR]) {
    if (!participantRoles.has(required)) throw new Error(`swarm interaction missing ${required} participant`);
  }
  assertInteractionStateName(record.state, "swarm interaction state");
  assertOptionalCapabilityList(record.capabilityRefs, "swarm interaction capabilityRefs");
  assertOptionalReferenceList(record.channelRefs, "swarm interaction channelRefs");
  const authority = assertOptionalObject(record.authority, "swarm interaction authority");
  if (authority.domains !== undefined) requireArray(authority.domains, "swarm interaction authority domains").forEach((domain) => assertAuthorityDomain(domain));
  if (authority.grantRefs !== undefined) assertOptionalReferenceList(authority.grantRefs, "swarm interaction authority grantRefs");
  if (record.routingScope !== undefined) assertRoutingScopePosture(record.routingScope, "swarm interaction routingScope");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm interaction safeFacts");
  assertPrivateRefList(record.privateRefs, "swarm interaction privateRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm interaction missing issuedAt");
  return record;
}

export function assertSwarmActivation(record) {
  if (!isObject(record)) throw new Error("swarm activation must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_ACTIVATION, "swarm activation");
  requireString(record.activationId, "swarm activation activationId");
  requireString(record.interactionId, "swarm activation interactionId");
  requireString(record.nodeRef, "swarm activation nodeRef");
  assertCapabilityName(record.capabilityRef);
  assertResolvedMemberRef(record.requesterRef, "swarm activation requesterRef");
  assertResolvedMemberRef(record.runtimeMemberRef, "swarm activation runtimeMemberRef");
  assertInteractionStateName(record.state, "swarm activation state");
  const summary = assertOptionalObject(record.authoritySummary, "swarm activation authoritySummary");
  for (const domain of ["requester", "runtime", "gateway", "service"]) {
    const entry = summary[domain];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`swarm activation authoritySummary missing ${domain}`);
    }
    if (!String(entry.state || "").trim()) throw new Error(`swarm activation authoritySummary ${domain} missing state`);
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "swarm activation safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm activation missing issuedAt");
  return record;
}

export function assertSwarmRelease(record) {
  if (!isObject(record)) throw new Error("swarm release must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_RELEASE, "swarm release");
  requireString(record.releaseId, "swarm release releaseId");
  requireString(record.interactionId, "swarm release interactionId");
  requireString(record.releasedBy, "swarm release releasedBy");
  requireString(record.reasonCode, "swarm release reasonCode");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm release missing issuedAt");
  return record;
}

export function assertSwarmRevocation(record) {
  if (!isObject(record)) throw new Error("swarm revocation must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SWARM_REVOCATION, "swarm revocation");
  requireString(record.revocationId, "swarm revocation revocationId");
  requireString(record.targetRef, "swarm revocation targetRef");
  requireString(record.issuerRef, "swarm revocation issuerRef");
  assertAuthorityDomain(record.authorityDomain, "swarm revocation authorityDomain");
  requireString(record.reasonCode, "swarm revocation reasonCode");
  if (!Number(record.issuedAt || 0)) throw new Error("swarm revocation missing issuedAt");
  return record;
}

const PRIVATE_CONTENT_FORBIDDEN_FIELDS = new Set([
  "plaintext",
  "cleartext",
  "body",
  "payload",
  "contents",
  "content",
  "value",
  "ciphertext",
  "sealedPayload",
  "wrappedKey",
  "key",
  "secret",
  "password",
  "token",
  "privateKey",
  "secretKey",
]);

function assertAgreementPlaneName(value, name = "agreement plane") {
  const plane = requireString(value, name);
  if (!Object.values(AGREEMENT.PLANE).includes(plane)) throw new Error(`unsupported ${name}`);
  return plane;
}

function assertActionGrantStateName(value, name = "action grant state") {
  const state = requireString(value, name);
  if (!Object.values(AGREEMENT.ACTION_GRANT_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertAuthorityProofStateName(value, name = "authority proof state") {
  const state = requireString(value, name);
  if (!Object.values(AGREEMENT.AUTHORITY_PROOF_STATE).includes(state)) throw new Error(`unsupported ${name}`);
  return state;
}

function assertAuthorityProofCheckName(value, name = "authority proof check") {
  const check = requireString(value, name);
  if (!Object.values(AGREEMENT.AUTHORITY_PROOF_CHECK).includes(check)) throw new Error(`unsupported ${name}`);
  return check;
}

function assertRootOperationName(value, name = "root operation") {
  const operation = requireString(value, name);
  if (!Object.values(AGREEMENT.ROOT_OPERATION).includes(operation)) throw new Error(`unsupported ${name}`);
  return operation;
}

function assertAccessEpochChangeName(value, name = "access epoch change") {
  const change = requireString(value, name);
  if (!Object.values(AGREEMENT.ACCESS_EPOCH_CHANGE).includes(change)) throw new Error(`unsupported ${name}`);
  return change;
}

function assertContentClassName(value, name = "content class") {
  const contentClass = requireString(value, name);
  if (!Object.values(AGREEMENT.CONTENT_CLASS).includes(contentClass)) throw new Error(`unsupported ${name}`);
  return contentClass;
}

function assertAgreementPrivacyTier(value, name = "privacy tier") {
  const privacyTier = requireString(value, name);
  if (!Object.values(AGREEMENT.PRIVACY_TIER).includes(privacyTier)) throw new Error(`unsupported ${name}`);
  return privacyTier;
}

function assertSafeFactPolicyName(value, name = "safe fact policy") {
  const policy = requireString(value, name);
  if (!Object.values(AGREEMENT.SAFE_FACT_POLICY).includes(policy)) throw new Error(`unsupported ${name}`);
  return policy;
}

function assertNoPrivateContentFields(record, context) {
  rejectForbiddenKeys(record, PRIVATE_CONTENT_FORBIDDEN_FIELDS, context);
  rejectMediaByteFields(record, context);
}

export function assertAuthorityRootOperation(record) {
  if (!isObject(record)) throw new Error("authority root operation must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.AUTHORITY_ROOT_OPERATION, "authority root operation");
  requireString(record.operationId, "authority root operation operationId");
  assertRootOperationName(record.operation);
  requireString(record.identityRef, "authority root operation identityRef");
  requireString(record.actorRef, "authority root operation actorRef");
  requireString(record.targetRef, "authority root operation targetRef");
  const adminGrantRefs = assertReferenceList(record.adminGrantRefs, "authority root operation adminGrantRefs");
  const rootRefs = assertOptionalReferenceList(record.rootRefs, "authority root operation rootRefs");
  assertOptionalReferenceList(record.deviceRefs, "authority root operation deviceRefs");
  assertOptionalReferenceList(record.notificationRefs, "authority root operation notificationRefs");
  assertOptionalReferenceList(record.evidenceRefs, "authority root operation evidenceRefs");
  const state = assertActionGrantStateName(record.state, "authority root operation state");
  const blockedReason = String(record.blockedReason || "").trim();
  if ([AGREEMENT.ACTION_GRANT_STATE.BLOCKED, AGREEMENT.ACTION_GRANT_STATE.REJECTED].includes(state) && !blockedReason) {
    throw new Error("blocked or rejected authority root operation requires blockedReason");
  }
  if (adminGrantRefs.length === 0) throw new Error("authority root operation requires adminGrantRefs");
  if ([AGREEMENT.ROOT_OPERATION.ROTATE_ROOT, AGREEMENT.ROOT_OPERATION.REVOKE_ROOT, AGREEMENT.ROOT_OPERATION.ADD_ROOT].includes(record.operation) && rootRefs.length === 0) {
    throw new Error("root-changing authority operation requires rootRefs");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "authority root operation safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("authority root operation missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("authority root operation expiresAt must be after issuedAt");
  }
  return { ...record, plane: AGREEMENT.PLANE.ACTION_AUTHORITY, state };
}

export function assertActionAuthorityGrant(record) {
  if (!isObject(record)) throw new Error("action authority grant must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.AUTHORITY_ACTION_GRANT, "action authority grant");
  requireString(record.grantId, "action authority grant grantId");
  const plane = assertAgreementPlaneName(record.plane || AGREEMENT.PLANE.ACTION_AUTHORITY, "action authority grant plane");
  if (plane !== AGREEMENT.PLANE.ACTION_AUTHORITY) throw new Error("action authority grant plane must be actionAuthority");
  requireString(record.issuerRef, "action authority grant issuerRef");
  requireString(record.subjectRef, "action authority grant subjectRef");
  assertReferenceList(record.audienceRefs, "action authority grant audienceRefs");
  assertAuthorityDomain(record.authorityDomain, "action authority grant authorityDomain");
  requireString(record.resourceRef, "action authority grant resourceRef");
  requireString(record.action, "action authority grant action");
  const state = assertActionGrantStateName(record.state || AGREEMENT.ACTION_GRANT_STATE.ACCEPTED, "action authority grant state");
  if (record.scope !== undefined) assertSafeObject(record.scope, "action authority grant scope");
  assertOptionalCapabilityList(record.capabilityRefs, "action authority grant capabilityRefs");
  assertOptionalReferenceList(record.parentGrantRefs, "action authority grant parentGrantRefs");
  assertOptionalReferenceList(record.revocationRefs, "action authority grant revocationRefs");
  assertOptionalReferenceList(record.evidenceRefs, "action authority grant evidenceRefs");
  const rootRefs = assertOptionalReferenceList(record.rootRefs, "action authority grant rootRefs");
  if (record.elevated === true && rootRefs.length === 0) throw new Error("elevated action authority grant requires rootRefs");
  if (record.delegation !== undefined) {
    const delegation = assertOptionalObject(record.delegation, "action authority grant delegation");
    if (delegation.allowed !== undefined && typeof delegation.allowed !== "boolean") throw new Error("action authority grant delegation.allowed must be boolean");
    if (delegation.maxDepth !== undefined && (!Number.isInteger(Number(delegation.maxDepth)) || Number(delegation.maxDepth) < 0)) {
      throw new Error("action authority grant delegation.maxDepth must be non-negative integer");
    }
    assertOptionalReferenceList(delegation.inheritedFrom, "action authority grant delegation inheritedFrom");
  }
  const blockedReason = String(record.blockedReason || "").trim();
  if ([AGREEMENT.ACTION_GRANT_STATE.BLOCKED, AGREEMENT.ACTION_GRANT_STATE.REJECTED].includes(state) && !blockedReason) {
    throw new Error("blocked or rejected action authority grant requires blockedReason");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "action authority grant safeFacts");
  assertPrivateRefList(record.privateRefs, "action authority grant privateRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("action authority grant missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("action authority grant expiresAt must be after issuedAt");
  }
  return { ...record, plane, state };
}

export function assertActionAuthorityExercise(record) {
  if (!isObject(record)) throw new Error("action authority exercise must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.AUTHORITY_ACTION_EXERCISE, "action authority exercise");
  requireString(record.exerciseId, "action authority exercise exerciseId");
  requireString(record.grantId, "action authority exercise grantId");
  requireString(record.actorRef, "action authority exercise actorRef");
  requireString(record.subjectRef, "action authority exercise subjectRef");
  requireString(record.resourceRef, "action authority exercise resourceRef");
  requireString(record.action, "action authority exercise action");
  const state = assertActionGrantStateName(record.state, "action authority exercise state");
  assertOptionalReferenceList(record.evidenceRefs, "action authority exercise evidenceRefs");
  assertOptionalReferenceList(record.resultRefs, "action authority exercise resultRefs");
  const blockedReason = String(record.blockedReason || "").trim();
  if ([AGREEMENT.ACTION_GRANT_STATE.BLOCKED, AGREEMENT.ACTION_GRANT_STATE.REJECTED, AGREEMENT.ACTION_GRANT_STATE.EXPIRED, AGREEMENT.ACTION_GRANT_STATE.REVOKED].includes(state) && !blockedReason) {
    throw new Error("blocked/rejected/expired/revoked action authority exercise requires blockedReason");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "action authority exercise safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("action authority exercise missing issuedAt");
  if (record.observedAt !== undefined && Number(record.observedAt) < Number(record.issuedAt)) {
    throw new Error("action authority exercise observedAt must not be before issuedAt");
  }
  return { ...record, plane: AGREEMENT.PLANE.ACTION_AUTHORITY, state };
}

export function assertAuthorityGrantRevocationPosture(record) {
  if (!isObject(record)) throw new Error("authority grant revocation posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.AUTHORITY_GRANT_REVOCATION_POSTURE, "authority grant revocation posture");
  requireString(record.revocationId, "authority grant revocation posture revocationId");
  requireString(record.targetGrantRef, "authority grant revocation posture targetGrantRef");
  requireString(record.issuerRef, "authority grant revocation posture issuerRef");
  assertAuthorityDomain(record.authorityDomain, "authority grant revocation posture authorityDomain");
  assertReferenceList(record.affectedGrantRefs, "authority grant revocation posture affectedGrantRefs");
  assertOptionalReferenceList(record.affectedAccessGroupRefs, "authority grant revocation posture affectedAccessGroupRefs");
  assertOptionalReferenceList(record.inheritedScopeRefs, "authority grant revocation posture inheritedScopeRefs");
  const state = assertActionGrantStateName(record.state, "authority grant revocation posture state");
  requireString(record.reasonCode, "authority grant revocation posture reasonCode");
  assertOptionalReferenceList(record.evidenceRefs, "authority grant revocation posture evidenceRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("authority grant revocation posture missing issuedAt");
  if (record.effectiveAt !== undefined && Number(record.effectiveAt) < Number(record.issuedAt)) {
    throw new Error("authority grant revocation posture effectiveAt must not be before issuedAt");
  }
  return { ...record, plane: AGREEMENT.PLANE.ACTION_AUTHORITY, state };
}

function assertAuthorityProofCheck(record) {
  if (!isObject(record)) throw new Error("authority proof check must be an object");
  const check = assertAuthorityProofCheckName(record.check, "authority proof check check");
  const plane = assertAgreementPlaneName(record.plane, "authority proof check plane");
  const state = assertAuthorityProofStateName(record.state, "authority proof check state");
  requireString(record.targetRef, "authority proof check targetRef");
  assertOptionalReferenceList(record.grantRefs, "authority proof check grantRefs");
  assertOptionalReferenceList(record.accessGroupRefs, "authority proof check accessGroupRefs");
  assertOptionalReferenceList(record.accessEpochRefs, "authority proof check accessEpochRefs");
  assertOptionalReferenceList(record.exerciseRefs, "authority proof check exerciseRefs");
  assertOptionalReferenceList(record.evidenceRefs, "authority proof check evidenceRefs");
  const blockedReason = String(record.blockedReason || "").trim();
  if ([AGREEMENT.AUTHORITY_PROOF_STATE.BLOCKED, AGREEMENT.AUTHORITY_PROOF_STATE.DEGRADED, AGREEMENT.AUTHORITY_PROOF_STATE.EXPIRED, AGREEMENT.AUTHORITY_PROOF_STATE.REVOKED].includes(state) && !blockedReason) {
    throw new Error("non-proved authority proof check requires blockedReason");
  }
  if (record.expiresAt !== undefined) assertOptionalTimeField(record.expiresAt, "authority proof check expiresAt");
  if (check === AGREEMENT.AUTHORITY_PROOF_CHECK.SYNC && plane !== AGREEMENT.PLANE.DELIVERY_WITNESS) {
    throw new Error("sync authority proof check must use deliveryWitness plane");
  }
  if (check === AGREEMENT.AUTHORITY_PROOF_CHECK.READ && plane !== AGREEMENT.PLANE.ACCESS_AUTHORITY) {
    throw new Error("read authority proof check must use accessAuthority plane");
  }
  if ([AGREEMENT.AUTHORITY_PROOF_CHECK.WRITE_REDUCE, AGREEMENT.AUTHORITY_PROOF_CHECK.REVOKE_EXPIRE].includes(check) && plane !== AGREEMENT.PLANE.ACTION_AUTHORITY) {
    throw new Error("write/revoke authority proof checks must use actionAuthority plane");
  }
  return { ...record, check, plane, state };
}

export function assertAuthorityMultiIdentityProof(record) {
  if (!isObject(record)) throw new Error("authority multi-identity proof must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.AUTHORITY_MULTI_IDENTITY_PROOF, "authority multi-identity proof");
  requireString(record.proofId, "authority multi-identity proof proofId");
  requireString(record.ownerIdentityRef, "authority multi-identity proof ownerIdentityRef");
  requireString(record.granteeIdentityRef, "authority multi-identity proof granteeIdentityRef");
  requireString(record.granteeMemberRef, "authority multi-identity proof granteeMemberRef");
  assertReferenceList(record.subjectRefs, "authority multi-identity proof subjectRefs");
  assertReferenceList(record.actionGrantRefs, "authority multi-identity proof actionGrantRefs");
  assertReferenceList(record.accessGroupRefs, "authority multi-identity proof accessGroupRefs");
  assertOptionalReferenceList(record.accessEpochRefs, "authority multi-identity proof accessEpochRefs");
  assertOptionalReferenceList(record.privateEnvelopeRefs, "authority multi-identity proof privateEnvelopeRefs");
  assertOptionalReferenceList(record.revocationRefs, "authority multi-identity proof revocationRefs");
  assertOptionalReferenceList(record.evidenceRefs, "authority multi-identity proof evidenceRefs");
  const state = assertAuthorityProofStateName(record.state || AGREEMENT.AUTHORITY_PROOF_STATE.PROVED, "authority multi-identity proof state");
  const checks = requireNonEmptyArray(record.checks, "authority multi-identity proof checks").map(assertAuthorityProofCheck);
  const checkKinds = new Set(checks.map((check) => check.check));
  for (const required of Object.values(AGREEMENT.AUTHORITY_PROOF_CHECK)) {
    if (!checkKinds.has(required)) throw new Error(`authority multi-identity proof missing ${required} check`);
  }
  if (!checks.some((check) => check.plane === AGREEMENT.PLANE.ACCESS_AUTHORITY)) {
    throw new Error("authority multi-identity proof requires accessAuthority check");
  }
  if (!checks.some((check) => check.plane === AGREEMENT.PLANE.ACTION_AUTHORITY)) {
    throw new Error("authority multi-identity proof requires actionAuthority check");
  }
  if (!checks.some((check) => check.plane === AGREEMENT.PLANE.DELIVERY_WITNESS)) {
    throw new Error("authority multi-identity proof requires deliveryWitness check");
  }
  const readCheck = checks.find((check) => check.check === AGREEMENT.AUTHORITY_PROOF_CHECK.READ);
  if (!readCheck || !assertOptionalReferenceList(readCheck.accessGroupRefs, "read authority proof check accessGroupRefs").length) {
    throw new Error("read authority proof check requires accessGroupRefs");
  }
  const revokeCheck = checks.find((check) => check.check === AGREEMENT.AUTHORITY_PROOF_CHECK.REVOKE_EXPIRE);
  if (!revokeCheck || (!assertOptionalReferenceList(record.revocationRefs, "authority multi-identity proof revocationRefs").length && !revokeCheck.expiresAt)) {
    throw new Error("revoke/expire authority proof requires revocationRefs or expiresAt");
  }
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "authority multi-identity proof blockedReasons");
  if ([AGREEMENT.AUTHORITY_PROOF_STATE.BLOCKED, AGREEMENT.AUTHORITY_PROOF_STATE.DEGRADED].includes(state) && blockedReasons.length === 0) {
    throw new Error("blocked or degraded authority multi-identity proof requires blockedReasons");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "authority multi-identity proof safeFacts");
  assertNoPrivateContentFields(record.safeFacts || {}, "authority multi-identity proof safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("authority multi-identity proof missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("authority multi-identity proof expiresAt must be after issuedAt");
  }
  return { ...record, state, checks };
}

export function assertAccessGroup(record) {
  if (!isObject(record)) throw new Error("access group must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.ACCESS_GROUP, "access group");
  requireString(record.groupId, "access group groupId");
  requireString(record.ownerRef, "access group ownerRef");
  requireString(record.subjectRef, "access group subjectRef");
  const contentClasses = requireNonEmptyArray(record.contentClasses, "access group contentClasses").map((entry) => assertContentClassName(entry, "access group contentClass"));
  assertReferenceList(record.memberRefs, "access group memberRefs");
  assertReferenceList(record.adminRefs, "access group adminRefs");
  requireString(record.currentEpochId, "access group currentEpochId");
  assertOptionalReferenceList(record.partitionRefs, "access group partitionRefs");
  assertOptionalReferenceList(record.policyRefs, "access group policyRefs");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "access group safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("access group missing issuedAt");
  return { ...record, plane: AGREEMENT.PLANE.ACCESS_AUTHORITY, contentClasses };
}

export function assertAccessEpoch(record) {
  if (!isObject(record)) throw new Error("access epoch must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.ACCESS_EPOCH, "access epoch");
  requireString(record.epochId, "access epoch epochId");
  requireString(record.groupId, "access epoch groupId");
  const sequence = Number(record.sequence);
  if (!Number.isInteger(sequence) || sequence < 1) throw new Error("access epoch sequence must be positive integer");
  const changeKind = assertAccessEpochChangeName(record.changeKind, "access epoch changeKind");
  if (record.previousEpochId !== undefined) requireString(record.previousEpochId, "access epoch previousEpochId");
  assertReferenceList(record.memberRefs, "access epoch memberRefs");
  const addedMemberRefs = assertOptionalReferenceList(record.addedMemberRefs, "access epoch addedMemberRefs");
  const removedMemberRefs = assertOptionalReferenceList(record.removedMemberRefs, "access epoch removedMemberRefs");
  assertOptionalReferenceList(record.partitionRefs, "access epoch partitionRefs");
  requireString(record.keyRef, "access epoch keyRef");
  const proofRefs = assertReferenceList(record.proofRefs, "access epoch proofRefs");
  if ([AGREEMENT.ACCESS_EPOCH_CHANGE.REMOVE_MEMBER, AGREEMENT.ACCESS_EPOCH_CHANGE.REVOKE_MEMBER, AGREEMENT.ACCESS_EPOCH_CHANGE.ROTATE_KEY].includes(changeKind) && !String(record.previousEpochId || "").trim()) {
    throw new Error("revoking or rotating access epoch requires previousEpochId");
  }
  if ([AGREEMENT.ACCESS_EPOCH_CHANGE.REMOVE_MEMBER, AGREEMENT.ACCESS_EPOCH_CHANGE.REVOKE_MEMBER].includes(changeKind) && removedMemberRefs.length === 0) {
    throw new Error("member removal access epoch requires removedMemberRefs");
  }
  if (changeKind === AGREEMENT.ACCESS_EPOCH_CHANGE.ADD_MEMBER && addedMemberRefs.length === 0) {
    throw new Error("member addition access epoch requires addedMemberRefs");
  }
  if (proofRefs.length === 0) throw new Error("access epoch requires proofRefs");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "access epoch safeFacts");
  assertNoPrivateContentFields(record.safeFacts || {}, "access epoch safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("access epoch missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("access epoch expiresAt must be after issuedAt");
  }
  return { ...record, plane: AGREEMENT.PLANE.ACCESS_AUTHORITY, sequence, changeKind, addedMemberRefs, removedMemberRefs };
}

export function assertPrivateContentEnvelope(record) {
  if (!isObject(record)) throw new Error("private content envelope must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.PRIVATE_CONTENT_ENVELOPE, "private content envelope");
  assertNoPrivateContentFields(record, "private content envelope");
  requireString(record.envelopeId, "private content envelope envelopeId");
  const contentClass = assertContentClassName(record.contentClass, "private content envelope contentClass");
  if (![AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL, AGREEMENT.CONTENT_CLASS.ENCRYPTED_RAW, AGREEMENT.CONTENT_CLASS.MEDIA_REFERENCE, AGREEMENT.CONTENT_CLASS.DIAGNOSTIC_DETAIL].includes(contentClass)) {
    throw new Error("private content envelope requires encrypted/detail/media content class");
  }
  requireString(record.accessGroupRef, "private content envelope accessGroupRef");
  requireString(record.epochId, "private content envelope epochId");
  requireString(record.subjectRef, "private content envelope subjectRef");
  requireString(record.issuerRef, "private content envelope issuerRef");
  const bodyRefs = [
    record.ciphertextRef,
    record.storageObjectRef,
    record.detailRef,
    record.mediaObjectRef,
    record.caacEnvelopeRef,
  ].map((value) => String(value || "").trim()).filter(Boolean);
  if (bodyRefs.length === 0) throw new Error("private content envelope requires a content reference");
  assertOptionalReferenceList(record.recipientRefs, "private content envelope recipientRefs");
  if (record.keyRef !== undefined) requireString(record.keyRef, "private content envelope keyRef");
  if (record.summarySafeFacts !== undefined) {
    assertSafeObject(record.summarySafeFacts, "private content envelope summarySafeFacts");
    assertNoPrivateContentFields(record.summarySafeFacts, "private content envelope summarySafeFacts");
  }
  assertOptionalReferenceList(record.evidenceRefs, "private content envelope evidenceRefs");
  if (!Number(record.issuedAt || 0)) throw new Error("private content envelope missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt) <= Number(record.issuedAt)) {
    throw new Error("private content envelope expiresAt must be after issuedAt");
  }
  return { ...record, plane: AGREEMENT.PLANE.ACCESS_AUTHORITY, contentClass };
}

export function assertEventFabricAccessClass(record) {
  if (!isObject(record)) throw new Error("event fabric access class must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.EVENT_FABRIC_ACCESS_CLASS, "event fabric access class");
  requireString(record.classId, "event fabric access class classId");
  const contentClass = assertContentClassName(record.contentClass, "event fabric access class contentClass");
  const privacyTier = assertAgreementPrivacyTier(record.privacyTier, "event fabric access class privacyTier");
  requireNonEmptyArray(record.eventClasses, "event fabric access class eventClasses").forEach((entry) => requireString(entry, "event fabric access class eventClass"));
  assertReferenceList(record.accessGroupRefs, "event fabric access class accessGroupRefs");
  assertOptionalReferenceList(record.processorRoleRefs, "event fabric access class processorRoleRefs");
  requireString(record.storageClass, "event fabric access class storageClass");
  requireString(record.retentionClass, "event fabric access class retentionClass");
  assertSafeFactPolicyName(record.safeFactPolicy, "event fabric access class safeFactPolicy");
  if (record.indexPolicy !== undefined) assertSafeObject(record.indexPolicy, "event fabric access class indexPolicy");
  if ([AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL, AGREEMENT.CONTENT_CLASS.ENCRYPTED_RAW, AGREEMENT.CONTENT_CLASS.DIAGNOSTIC_DETAIL].includes(contentClass) && privacyTier === AGREEMENT.PRIVACY_TIER.PUBLIC_SAFE) {
    throw new Error("encrypted event fabric access class must not use publicSafe privacy tier");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "event fabric access class safeFacts");
  if (!Number(record.issuedAt || 0)) throw new Error("event fabric access class missing issuedAt");
  return { ...record, plane: AGREEMENT.PLANE.MATERIALIZATION, contentClass, privacyTier };
}

export function assertSwarmIdentityGraph(records) {
  const graphRecords = requireArray(records, "swarm identity graph");
  const liveKinds = new Set([
    SWARM.RECORD_KIND.SWARM_INTERACTION,
    SWARM.RECORD_KIND.SWARM_ACTIVATION,
    SWARM.RECORD_KIND.ROUTE_PROMISE,
    SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE,
    SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
    SWARM.RECORD_KIND.CONSUMER_FLOOR,
    SWARM.RECORD_KIND.MEDIA_TRANSPORT_PATH,
    SWARM.RECORD_KIND.MEDIA_TRANSPORT_OBSERVATION,
    "stream.session.offer",
    "stream.session.answer",
    "stream.session.candidate",
    "stream.session.control",
    "stream.session.health",
    "stream.session.close",
  ]);
  for (const record of graphRecords) {
    if (!isObject(record)) throw new Error("swarm identity graph record must be an object");
    const kind = String(record.kind || record.recordKind || "").trim();
    if (liveKinds.has(kind)) throw new Error("swarm identity graph must not contain live lease or activation state");
    if (record.lease || record.routePromise || record.activeSession || record.streamSession) {
      throw new Error("swarm identity graph must not contain live lease or activation state");
    }
  }
  return graphRecords;
}

function isFixturePlaceholderEnvelope(envelope) {
  if (!isObject(envelope)) return false;
  const values = [
    envelope.envelopeId,
    envelope.signature,
    envelope.sealedPayload,
    envelope.placeholder,
    envelope.ciphertext,
  ].map((value) => String(value || ""));
  if (values.some((value) => value && SWARM.FIXTURE_CAAC_PLACEHOLDERS.includes(value))) return true;
  if (envelope.envelopeId && !envelope.alg && !envelope.recipients && !envelope.signature) return true;
  return false;
}

export function assertCaacEnvelopeForMode(envelope, {
  mode = SWARM.CAAC_VALIDATION_MODE.PRODUCT,
  now = nowSeconds(),
} = {}) {
  if (!isObject(envelope)) throw new Error("caac envelope must be an object");
  const validationMode = requireString(mode, "caac validation mode");
  if (!Object.values(SWARM.CAAC_VALIDATION_MODE).includes(validationMode)) throw new Error("unsupported caac validation mode");
  if (validationMode === SWARM.CAAC_VALIDATION_MODE.FIXTURE) {
    if (isFixturePlaceholderEnvelope(envelope)) return envelope;
  }
  if (validationMode === SWARM.CAAC_VALIDATION_MODE.STRUCTURAL) {
    requireString(envelope.envelopeId, "caac envelope envelopeId");
    return envelope;
  }
  if (isFixturePlaceholderEnvelope(envelope)) throw new Error("fixture caac placeholder rejected in product mode");
  if (Number(envelope.version) !== CAAC_VERSION) throw new Error("unsupported caac envelope version");
  if (envelope.alg !== CAAC_ALG_V1) throw new Error("unsupported caac envelope algorithm");
  requireString(envelope.kind, "caac envelope kind");
  requireString(envelope.envelopeId, "caac envelope envelopeId");
  requireString(envelope.issuerPk, "caac envelope issuerPk");
  if (!Number(envelope.issuedAt || 0)) throw new Error("caac envelope missing issuedAt");
  if (!Number(envelope.expiresAt || 0)) throw new Error("caac envelope missing expiresAt");
  if (Number(envelope.expiresAt) <= now) throw new Error("caac envelope expired");
  requireString(envelope.signature, "caac envelope signature");
  const recipients = requireNonEmptyArray(envelope.recipients, "caac envelope recipients");
  for (const recipient of recipients) {
    if (!isObject(recipient)) throw new Error("caac envelope recipient must be an object");
    requireString(recipient.recipientPk, "caac envelope recipientPk");
    requireString(recipient.nonce, "caac envelope recipient nonce");
    requireString(recipient.ciphertext, "caac envelope recipient ciphertext");
  }
  if (!verifyEnvelopeSignature(envelope)) throw new Error("invalid caac envelope signature");
  return envelope;
}

export function assertAppRecipe(record) {
  if (!isObject(record)) throw new Error("app recipe must be an object");
  requireString(record.recipeId, "app recipe id");
  requireString(record.name, "app recipe name");
  requireArray(record.requiredCapabilities, "app recipe requiredCapabilities").forEach(assertCapabilityName);
  requireArray(record.requiredChannels, "app recipe requiredChannels");
  requireArray(record.roles, "app recipe roles");
  return record;
}

export function assertSurfaceModuleClaim(record) {
  if (!isObject(record)) throw new Error("surface module claim must be an object");
  requireString(record.moduleRef, "surface module claim moduleRef");
  requireString(record.role, "surface module claim role");
  if (!Object.values(SURFACE_APP.MODULE_ROLE).includes(record.role)) throw new Error("invalid surface module role");
  requireString(record.participantSide, "surface module claim participantSide");
  if (!Object.values(SURFACE_APP.PARTICIPANT_SIDE).includes(record.participantSide)) throw new Error("invalid surface module participantSide");
  requireString(record.fulfillmentMode, "surface module claim fulfillmentMode");
  if (!Object.values(SURFACE_APP.FULFILLMENT_MODE).includes(record.fulfillmentMode)) throw new Error("invalid surface module fulfillmentMode");
  requireString(record.version, "surface module claim version");
  requireArray(record.primitiveRefs || [], "surface module claim primitiveRefs");
  requireArray(record.requiredCapabilities || [], "surface module claim requiredCapabilities");
  requireArray(record.inputs || [], "surface module claim inputs");
  requireArray(record.outputs || [], "surface module claim outputs");
  requireArray(record.fallbackRefs || [], "surface module claim fallbackRefs");
  if (record.sandbox !== undefined && !isObject(record.sandbox)) throw new Error("surface module claim sandbox must be an object");
  if (record.evidenceContract !== undefined && !isObject(record.evidenceContract)) throw new Error("surface module claim evidenceContract must be an object");
  if (record.lifecycle !== undefined && !isObject(record.lifecycle)) throw new Error("surface module claim lifecycle must be an object");
  if (record.materializationBudgetRef !== undefined) requireString(record.materializationBudgetRef, "surface module claim materializationBudgetRef");
  if (!Number(record.issuedAt || 0)) throw new Error("surface module claim missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) throw new Error("surface module claim expires before issuedAt");
  return record;
}

function assertSurfaceSecretBoundary(record, name = "surface secret boundary") {
  const boundary = assertOptionalObject(record, name);
  if (!Object.keys(boundary).length) return boundary;
  const state = requireString(boundary.state, `${name} state`);
  if (!Object.values(SURFACE_APP.SECRET_BOUNDARY).includes(state)) throw new Error(`invalid ${name} state`);
  assertOptionalReferenceList(boundary.secretRefs, `${name} secretRefs`);
  assertOptionalReferenceList(boundary.authorityRefs, `${name} authorityRefs`);
  assertOptionalReferenceList(boundary.evidenceRefs, `${name} evidenceRefs`);
  const blockedReasons = assertOptionalReferenceList(boundary.blockedReasons, `${name} blockedReasons`);
  if (state === SURFACE_APP.SECRET_BOUNDARY.BLOCKED && blockedReasons.length === 0) {
    throw new Error(`${name} blocked state requires blockedReasons`);
  }
  rejectForbiddenKeys(boundary, new Set(["secret", "password", "token", "privateKey", "secretKey", "value", "contents"]), name);
  return boundary;
}

function assertSurfaceReleasePosture(record, name = "surface release posture") {
  const posture = assertOptionalObject(record, name);
  if (!Object.keys(posture).length) return posture;
  const state = requireString(posture.state, `${name} state`);
  if (!Object.values(SURFACE_APP.RELEASE_POSTURE).includes(state)) throw new Error(`invalid ${name} state`);
  if (posture.buildRef !== undefined) requireString(posture.buildRef, `${name} buildRef`);
  if (posture.releaseRef !== undefined) requireString(posture.releaseRef, `${name} releaseRef`);
  if (posture.rollbackRef !== undefined) requireString(posture.rollbackRef, `${name} rollbackRef`);
  assertOptionalReferenceList(posture.evidenceRefs, `${name} evidenceRefs`);
  const blockedReasons = assertOptionalReferenceList(posture.blockedReasons, `${name} blockedReasons`);
  if (state === SURFACE_APP.RELEASE_POSTURE.BLOCKED && blockedReasons.length === 0) {
    throw new Error(`${name} blocked state requires blockedReasons`);
  }
  if (state === SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY && !String(posture.rollbackRef || "").trim()) {
    throw new Error(`${name} rollbackReady state requires rollbackRef`);
  }
  return posture;
}

export function assertServiceManagerPosture(record) {
  if (!isObject(record)) throw new Error("service manager posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_POSTURE, "service manager posture");
  requireString(record.managerId, "service manager posture managerId");
  requireString(record.subjectRef, "service manager posture subjectRef");
  requireString(record.managerRef, "service manager posture managerRef");
  const state = requireString(record.state, "service manager posture state");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_POSTURE).includes(state)) throw new Error("invalid service manager posture state");
  assertOptionalReferenceList(record.serviceRefs, "service manager posture serviceRefs");
  assertOptionalCapabilityList(record.capabilityRefs, "service manager posture capabilityRefs");
  assertOptionalReferenceList(record.operationRefs, "service manager posture operationRefs");
  assertOptionalReferenceList(record.proofDigestRefs, "service manager posture proofDigestRefs");
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "service manager secretBoundary");
  if (record.releasePosture !== undefined) assertSurfaceReleasePosture(record.releasePosture, "service manager releasePosture");
  if (record.rollbackPosture !== undefined) assertSurfaceReleasePosture(record.rollbackPosture, "service manager rollbackPosture");
  assertOptionalReferenceList(record.evidenceRefs, "service manager posture evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager posture blockedReasons");
  if (state === SURFACE_APP.SERVICE_MANAGER_POSTURE.BLOCKED && blockedReasons.length === 0) {
    throw new Error("service manager blocked state requires blockedReasons");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("service manager posture missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) throw new Error("service manager posture expires before issuedAt");
  return record;
}

function assertSurfaceOperationTimeline(record, context, baseField = "requestedAt") {
  const base = Number(record[baseField] || 0);
  if (!base) throw new Error(`${context} missing ${baseField}`);
  for (const field of ["acceptedAt", "startedAt", "completedAt", "observedAt", "expiresAt"]) {
    if (record[field] === undefined) continue;
    const value = Number(record[field] || 0);
    if (!value) throw new Error(`${context} invalid ${field}`);
    if (value <= base && field === "expiresAt") throw new Error(`${context} expires before ${baseField}`);
    if (value < base && field !== "expiresAt") throw new Error(`${context} ${field} before ${baseField}`);
  }
  if (record.startedAt !== undefined && record.completedAt !== undefined && Number(record.completedAt || 0) < Number(record.startedAt || 0)) {
    throw new Error(`${context} completedAt before startedAt`);
  }
}

function assertSurfaceManagerSensitiveBoundary(record, context) {
  rejectForbiddenKeys(record, new Set(["secret", "password", "token", "privateKey", "secretKey", "value", "contents", "plaintext", "ciphertext"]), context);
  rejectRouteControlByteFields(record, context);
}

function assertServiceManagerContractState(value, context) {
  const state = requireString(value, `${context} state`);
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE).includes(state)) {
    throw new Error(`invalid ${context} state`);
  }
  return state;
}

export function assertServiceManagerSecretBoundary(record) {
  if (!isObject(record)) throw new Error("service manager secret boundary must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_SECRET_BOUNDARY, "service manager secret boundary");
  requireString(record.boundaryId, "service manager secret boundary boundaryId");
  requireString(record.managerId, "service manager secret boundary managerId");
  requireString(record.subjectRef, "service manager secret boundary subjectRef");
  const state = requireString(record.state, "service manager secret boundary state");
  if (!Object.values(SURFACE_APP.SECRET_BOUNDARY).includes(state)) throw new Error("invalid service manager secret boundary state");
  assertOptionalReferenceList(record.secretRefs, "service manager secret boundary secretRefs");
  assertOptionalReferenceList(record.accessGroupRefs, "service manager secret boundary accessGroupRefs");
  assertOptionalReferenceList(record.authorityRefs, "service manager secret boundary authorityRefs");
  assertOptionalReferenceList(record.evidenceRefs, "service manager secret boundary evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager secret boundary blockedReasons");
  if (state === SURFACE_APP.SECRET_BOUNDARY.RESOLVED) {
    const secretRefs = assertOptionalReferenceList(record.secretRefs, "service manager secret boundary secretRefs");
    const accessGroupRefs = assertOptionalReferenceList(record.accessGroupRefs, "service manager secret boundary accessGroupRefs");
    if (secretRefs.length === 0 && accessGroupRefs.length === 0) {
      throw new Error("service manager resolved secret boundary requires secretRefs or accessGroupRefs");
    }
  }
  if (state === SURFACE_APP.SECRET_BOUNDARY.BLOCKED && blockedReasons.length === 0) {
    throw new Error("service manager blocked secret boundary requires blockedReasons");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service manager secret boundary safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "service manager secret boundary");
  if (!Number(record.issuedAt || 0)) throw new Error("service manager secret boundary missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) {
    throw new Error("service manager secret boundary expires before issuedAt");
  }
  return record;
}

export function assertServiceManagerReleaseContract(record) {
  if (!isObject(record)) throw new Error("service manager release contract must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_RELEASE_CONTRACT, "service manager release contract");
  requireString(record.contractId, "service manager release contract contractId");
  requireString(record.managerId, "service manager release contract managerId");
  requireString(record.subjectRef, "service manager release contract subjectRef");
  requireString(record.managerRef, "service manager release contract managerRef");
  const state = assertServiceManagerContractState(record.state, "service manager release contract");
  if (record.appContractRef !== undefined) requireString(record.appContractRef, "service manager release contract appContractRef");
  if (record.version !== undefined) requireString(record.version, "service manager release contract version");
  if (record.buildRef !== undefined) requireString(record.buildRef, "service manager release contract buildRef");
  if (record.releaseRef !== undefined) requireString(record.releaseRef, "service manager release contract releaseRef");
  if (record.rollbackRef !== undefined) requireString(record.rollbackRef, "service manager release contract rollbackRef");
  assertOptionalReferenceList(record.compatibilityRefs, "service manager release contract compatibilityRefs");
  assertOptionalReferenceList(record.authorityRefs, "service manager release contract authorityRefs");
  assertOptionalReferenceList(record.secretBoundaryRefs, "service manager release contract secretBoundaryRefs");
  assertOptionalReferenceList(record.proofDigestRefs, "service manager release contract proofDigestRefs");
  assertOptionalReferenceList(record.labProofRefs, "service manager release contract labProofRefs");
  assertOptionalReferenceList(record.evidenceRefs, "service manager release contract evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager release contract blockedReasons");
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "service manager release contract secretBoundary");
  if (record.releasePosture !== undefined) assertSurfaceReleasePosture(record.releasePosture, "service manager release contract releasePosture");
  if (record.rollbackPosture !== undefined) assertSurfaceReleasePosture(record.rollbackPosture, "service manager release contract rollbackPosture");
  if (state === SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY) {
    if (!String(record.buildRef || "").trim()) throw new Error("service manager ready release contract requires buildRef");
    if (!String(record.releaseRef || "").trim()) throw new Error("service manager ready release contract requires releaseRef");
    if (record.rollbackRequired !== false && !String(record.rollbackRef || "").trim()) {
      throw new Error("service manager ready release contract requires rollbackRef unless rollbackRequired is false");
    }
  }
  if (state === SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.BLOCKED && blockedReasons.length === 0) {
    throw new Error("service manager blocked release contract requires blockedReasons");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service manager release contract safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "service manager release contract");
  if (!Number(record.issuedAt || 0)) throw new Error("service manager release contract missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) {
    throw new Error("service manager release contract expires before issuedAt");
  }
  return record;
}

export function assertServiceManagerLabProof(record) {
  if (!isObject(record)) throw new Error("service manager lab proof must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_LAB_PROOF, "service manager lab proof");
  requireString(record.proofId, "service manager lab proof proofId");
  requireString(record.managerId, "service manager lab proof managerId");
  requireString(record.subjectRef, "service manager lab proof subjectRef");
  const profile = requireString(record.profile, "service manager lab proof profile");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_PROOF_PROFILE).includes(profile)) throw new Error("invalid service manager lab proof profile");
  const state = requireString(record.state, "service manager lab proof state");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_PROOF_STATE).includes(state)) throw new Error("invalid service manager lab proof state");
  if (record.trainRef !== undefined) requireString(record.trainRef, "service manager lab proof trainRef");
  if (record.releaseContractRef !== undefined) requireString(record.releaseContractRef, "service manager lab proof releaseContractRef");
  if (record.appContractRef !== undefined) requireString(record.appContractRef, "service manager lab proof appContractRef");
  assertOptionalReferenceList(record.surfaceRefs, "service manager lab proof surfaceRefs");
  assertOptionalReferenceList(record.serviceRefs, "service manager lab proof serviceRefs");
  assertOptionalReferenceList(record.environmentRefs, "service manager lab proof environmentRefs");
  assertOptionalReferenceList(record.artifactRefs, "service manager lab proof artifactRefs");
  assertOptionalReferenceList(record.metricsRefs, "service manager lab proof metricsRefs");
  assertOptionalReferenceList(record.proofRefs, "service manager lab proof proofRefs");
  assertOptionalReferenceList(record.evidenceRefs, "service manager lab proof evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager lab proof blockedReasons");
  if ([SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.BLOCKED, SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.FAILED].includes(state) && blockedReasons.length === 0) {
    throw new Error("service manager blocked or failed lab proof requires blockedReasons");
  }
  if (state === SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED) {
    const artifactRefs = assertOptionalReferenceList(record.artifactRefs, "service manager lab proof artifactRefs");
    const metricsRefs = assertOptionalReferenceList(record.metricsRefs, "service manager lab proof metricsRefs");
    const proofRefs = assertOptionalReferenceList(record.proofRefs, "service manager lab proof proofRefs");
    if (artifactRefs.length === 0 && metricsRefs.length === 0 && proofRefs.length === 0) {
      throw new Error("service manager proved lab proof requires artifactRefs, metricsRefs, or proofRefs");
    }
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service manager lab proof safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "service manager lab proof");
  assertSurfaceOperationTimeline(record, "service manager lab proof", "startedAt");
  return record;
}

export function assertServiceManagerTrainDigest(record) {
  if (!isObject(record)) throw new Error("service manager train digest must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_TRAIN_DIGEST, "service manager train digest");
  requireString(record.trainId, "service manager train digest trainId");
  requireString(record.managerId, "service manager train digest managerId");
  requireString(record.subjectRef, "service manager train digest subjectRef");
  const state = requireString(record.state, "service manager train digest state");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_PROOF_STATE).includes(state)) throw new Error("invalid service manager train digest state");
  assertOptionalReferenceList(record.repoRefs, "service manager train digest repoRefs");
  assertOptionalReferenceList(record.commitRefs, "service manager train digest commitRefs");
  assertOptionalReferenceList(record.appContractRefs, "service manager train digest appContractRefs");
  assertOptionalReferenceList(record.releaseContractRefs, "service manager train digest releaseContractRefs");
  assertOptionalReferenceList(record.operationRefs, "service manager train digest operationRefs");
  assertOptionalReferenceList(record.proofDigestRefs, "service manager train digest proofDigestRefs");
  assertOptionalReferenceList(record.labProofRefs, "service manager train digest labProofRefs");
  assertOptionalReferenceList(record.metricsRefs, "service manager train digest metricsRefs");
  assertOptionalReferenceList(record.evidenceRefs, "service manager train digest evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager train digest blockedReasons");
  if ([SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.BLOCKED, SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.FAILED].includes(state) && blockedReasons.length === 0) {
    throw new Error("service manager blocked or failed train digest requires blockedReasons");
  }
  if (state === SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED) {
    const releaseContractRefs = assertOptionalReferenceList(record.releaseContractRefs, "service manager train digest releaseContractRefs");
    const labProofRefs = assertOptionalReferenceList(record.labProofRefs, "service manager train digest labProofRefs");
    const proofDigestRefs = assertOptionalReferenceList(record.proofDigestRefs, "service manager train digest proofDigestRefs");
    if (releaseContractRefs.length === 0) throw new Error("service manager proved train digest requires releaseContractRefs");
    if (labProofRefs.length === 0 && proofDigestRefs.length === 0) {
      throw new Error("service manager proved train digest requires labProofRefs or proofDigestRefs");
    }
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service manager train digest safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "service manager train digest");
  if (!Number(record.observedAt || 0)) throw new Error("service manager train digest missing observedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.observedAt || 0)) {
    throw new Error("service manager train digest expires before observedAt");
  }
  return record;
}

export function assertSurfaceAppBootstrapContract(record) {
  if (!isObject(record)) throw new Error("surface app bootstrap contract must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_CONTRACT, "surface app bootstrap contract");
  requireString(record.bootstrapContractId, "surface app bootstrap contract bootstrapContractId");
  requireString(record.appContractRef, "surface app bootstrap contract appContractRef");
  requireString(record.appId, "surface app bootstrap contract appId");
  const state = assertServiceManagerContractState(record.state, "surface app bootstrap contract");
  const sourceMode = requireString(record.sourceMode, "surface app bootstrap contract sourceMode");
  if (!Object.values(SURFACE_APP.FULFILLMENT_MODE).includes(sourceMode)) throw new Error("invalid surface app bootstrap contract sourceMode");
  const moduleRefs = assertOptionalReferenceList(record.moduleRefs, "surface app bootstrap contract moduleRefs");
  if (record.serviceManagerRef !== undefined) requireString(record.serviceManagerRef, "surface app bootstrap contract serviceManagerRef");
  if (record.releaseContractRef !== undefined) requireString(record.releaseContractRef, "surface app bootstrap contract releaseContractRef");
  if (record.secretBoundaryRef !== undefined) requireString(record.secretBoundaryRef, "surface app bootstrap contract secretBoundaryRef");
  if (record.trainDigestRef !== undefined) requireString(record.trainDigestRef, "surface app bootstrap contract trainDigestRef");
  assertOptionalReferenceList(record.labProofProfileRefs, "surface app bootstrap contract labProofProfileRefs");
  assertOptionalReferenceList(record.authorityRefs, "surface app bootstrap contract authorityRefs");
  assertOptionalReferenceList(record.evidenceRefs, "surface app bootstrap contract evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "surface app bootstrap contract blockedReasons");
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "surface app bootstrap contract secretBoundary");
  if (record.releaseContract !== undefined) assertServiceManagerReleaseContract(record.releaseContract);
  if (state === SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY) {
    if (moduleRefs.length === 0) throw new Error("surface app ready bootstrap contract requires moduleRefs");
    if (
      [SURFACE_APP.FULFILLMENT_MODE.SWARM_PACKAGE, SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT, SURFACE_APP.FULFILLMENT_MODE.NATIVE_INSTALLED].includes(sourceMode)
      && !String(record.releaseContractRef || "").trim()
    ) {
      throw new Error("surface app non-bundled bootstrap contract requires releaseContractRef");
    }
  }
  if (state === SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.BLOCKED && blockedReasons.length === 0) {
    throw new Error("surface app blocked bootstrap contract requires blockedReasons");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "surface app bootstrap contract safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "surface app bootstrap contract");
  if (!Number(record.issuedAt || 0)) throw new Error("surface app bootstrap contract missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) {
    throw new Error("surface app bootstrap contract expires before issuedAt");
  }
  return record;
}

function assertSurfaceAppManifestVersion(record, context = "surface app manifest version") {
  if (!isObject(record)) throw new Error(`${context} must be an object`);
  requireString(record.appContractRef, `${context} appContractRef`);
  requireString(record.version, `${context} version`);
  const state = requireString(record.state, `${context} state`);
  if (!Object.values(SURFACE_APP.MANIFEST_VERSION_STATE).includes(state)) throw new Error(`invalid ${context} state`);
  if (record.sourceMode !== undefined && !Object.values(SURFACE_APP.FULFILLMENT_MODE).includes(record.sourceMode)) {
    throw new Error(`invalid ${context} sourceMode`);
  }
  assertOptionalReferenceList(record.compatibilityRefs, `${context} compatibilityRefs`);
  assertOptionalReferenceList(record.moduleRefs, `${context} moduleRefs`);
  if (record.bootstrapContractRef !== undefined) requireString(record.bootstrapContractRef, `${context} bootstrapContractRef`);
  if (record.releaseContractRef !== undefined) requireString(record.releaseContractRef, `${context} releaseContractRef`);
  assertOptionalReferenceList(record.authorityRefs, `${context} authorityRefs`);
  assertOptionalReferenceList(record.evidenceRefs, `${context} evidenceRefs`);
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, `${context} blockedReasons`);
  if (state === SURFACE_APP.MANIFEST_VERSION_STATE.BLOCKED && blockedReasons.length === 0) {
    throw new Error(`${context} blocked state requires blockedReasons`);
  }
  if (
    [SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT, SURFACE_APP.MANIFEST_VERSION_STATE.COMPATIBLE, SURFACE_APP.MANIFEST_VERSION_STATE.UPDATE_AVAILABLE].includes(state)
    && [SURFACE_APP.FULFILLMENT_MODE.SWARM_PACKAGE, SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT, SURFACE_APP.FULFILLMENT_MODE.NATIVE_INSTALLED].includes(record.sourceMode)
    && !String(record.releaseContractRef || "").trim()
  ) {
    throw new Error(`${context} non-bundled source requires releaseContractRef`);
  }
  return record;
}

export function assertSurfaceAppManifest(record) {
  if (!isObject(record)) throw new Error("surface app manifest must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SURFACE_APP_MANIFEST, "surface app manifest");
  requireString(record.manifestId, "surface app manifest manifestId");
  requireString(record.appId, "surface app manifest appId");
  requireString(record.currentAppContractRef, "surface app manifest currentAppContractRef");
  requireString(record.currentVersion, "surface app manifest currentVersion");
  const state = requireString(record.state || SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT, "surface app manifest state");
  if (!Object.values(SURFACE_APP.MANIFEST_VERSION_STATE).includes(state)) throw new Error("invalid surface app manifest state");
  if (record.defaultSourceMode !== undefined && !Object.values(SURFACE_APP.FULFILLMENT_MODE).includes(record.defaultSourceMode)) {
    throw new Error("invalid surface app manifest defaultSourceMode");
  }
  const versions = requireNonEmptyArray(record.versions, "surface app manifest versions")
    .map((entry, index) => assertSurfaceAppManifestVersion(entry, `surface app manifest versions[${index}]`));
  const current = versions.find((entry) => (
    String(entry.appContractRef) === String(record.currentAppContractRef)
    && String(entry.version) === String(record.currentVersion)
  ));
  if (!current) throw new Error("surface app manifest missing current version claim");
  assertOptionalReferenceList(record.appContractRefs, "surface app manifest appContractRefs");
  assertOptionalReferenceList(record.compatibilityRefs, "surface app manifest compatibilityRefs");
  assertOptionalReferenceList(record.bootstrapContractRefs, "surface app manifest bootstrapContractRefs");
  assertOptionalReferenceList(record.releaseContractRefs, "surface app manifest releaseContractRefs");
  assertOptionalReferenceList(record.authorityRefs, "surface app manifest authorityRefs");
  assertOptionalReferenceList(record.evidenceRefs, "surface app manifest evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "surface app manifest blockedReasons");
  if (state === SURFACE_APP.MANIFEST_VERSION_STATE.BLOCKED && blockedReasons.length === 0) {
    throw new Error("surface app manifest blocked state requires blockedReasons");
  }
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "surface app manifest secretBoundary");
  if (record.releasePosture !== undefined) assertSurfaceReleasePosture(record.releasePosture, "surface app manifest releasePosture");
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "surface app manifest safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "surface app manifest");
  if (!Number(record.issuedAt || 0)) throw new Error("surface app manifest missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) {
    throw new Error("surface app manifest expires before issuedAt");
  }
  return record;
}

export function assertServiceManagerOperationPosture(record) {
  if (!isObject(record)) throw new Error("service manager operation posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_OPERATION_POSTURE, "service manager operation posture");
  requireString(record.operationId, "service manager operation posture operationId");
  requireString(record.managerId, "service manager operation posture managerId");
  requireString(record.subjectRef, "service manager operation posture subjectRef");
  requireString(record.managerRef, "service manager operation posture managerRef");
  requireString(record.requesterRef, "service manager operation posture requesterRef");
  const operation = requireString(record.operation, "service manager operation posture operation");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_OPERATION).includes(operation)) throw new Error("invalid service manager operation");
  const state = requireString(record.state, "service manager operation posture state");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE).includes(state)) throw new Error("invalid service manager operation state");
  assertOptionalReferenceList(record.serviceRefs, "service manager operation posture serviceRefs");
  assertOptionalCapabilityList(record.capabilityRefs, "service manager operation posture capabilityRefs");
  assertOptionalReferenceList(record.authorityRefs, "service manager operation posture authorityRefs");
  assertOptionalReferenceList(record.evidenceRefs, "service manager operation posture evidenceRefs");
  assertOptionalReferenceList(record.proofRefs, "service manager operation posture proofRefs");
  if (record.releaseRef !== undefined) requireString(record.releaseRef, "service manager operation posture releaseRef");
  if (record.rollbackRef !== undefined) requireString(record.rollbackRef, "service manager operation posture rollbackRef");
  if (operation === SURFACE_APP.SERVICE_MANAGER_OPERATION.ROLLBACK && !String(record.rollbackRef || "").trim()) {
    throw new Error("service manager rollback operation requires rollbackRef");
  }
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "service manager operation secretBoundary");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager operation posture blockedReasons");
  if ([SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.BLOCKED, SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.FAILED].includes(state) && blockedReasons.length === 0) {
    throw new Error("service manager blocked or failed operation requires blockedReasons");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service manager operation posture safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "service manager operation posture");
  assertSurfaceOperationTimeline(record, "service manager operation posture", "requestedAt");
  return record;
}

export function assertServiceManagerProofDigest(record) {
  if (!isObject(record)) throw new Error("service manager proof digest must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SERVICE_MANAGER_PROOF_DIGEST, "service manager proof digest");
  requireString(record.digestId, "service manager proof digest digestId");
  requireString(record.operationId, "service manager proof digest operationId");
  requireString(record.managerId, "service manager proof digest managerId");
  requireString(record.subjectRef, "service manager proof digest subjectRef");
  const state = requireString(record.state, "service manager proof digest state");
  if (!Object.values(SURFACE_APP.SERVICE_MANAGER_PROOF_STATE).includes(state)) throw new Error("invalid service manager proof digest state");
  if (record.trainRef !== undefined) requireString(record.trainRef, "service manager proof digest trainRef");
  if (record.releaseRef !== undefined) requireString(record.releaseRef, "service manager proof digest releaseRef");
  if (record.rollbackRef !== undefined) requireString(record.rollbackRef, "service manager proof digest rollbackRef");
  assertOptionalReferenceList(record.commitRefs, "service manager proof digest commitRefs");
  assertOptionalReferenceList(record.artifactRefs, "service manager proof digest artifactRefs");
  assertOptionalReferenceList(record.proofRefs, "service manager proof digest proofRefs");
  assertOptionalReferenceList(record.metricsRefs, "service manager proof digest metricsRefs");
  assertOptionalReferenceList(record.environmentRefs, "service manager proof digest environmentRefs");
  assertOptionalReferenceList(record.serviceRefs, "service manager proof digest serviceRefs");
  assertOptionalReferenceList(record.evidenceRefs, "service manager proof digest evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "service manager proof digest blockedReasons");
  if ([SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.BLOCKED, SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.FAILED].includes(state) && blockedReasons.length === 0) {
    throw new Error("service manager blocked or failed proof digest requires blockedReasons");
  }
  const artifactRefs = assertOptionalReferenceList(record.artifactRefs, "service manager proof digest artifactRefs");
  const proofRefs = assertOptionalReferenceList(record.proofRefs, "service manager proof digest proofRefs");
  if (state === SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED && artifactRefs.length === 0 && proofRefs.length === 0) {
    throw new Error("service manager proved proof digest requires artifactRefs or proofRefs");
  }
  if (record.safeFacts !== undefined) assertSafeObject(record.safeFacts, "service manager proof digest safeFacts");
  assertSurfaceManagerSensitiveBoundary(record, "service manager proof digest");
  if (!Number(record.observedAt || 0)) throw new Error("service manager proof digest missing observedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.observedAt || 0)) throw new Error("service manager proof digest expires before observedAt");
  return record;
}

export function assertSurfaceAppBootstrapPosture(record) {
  if (!isObject(record)) throw new Error("surface app bootstrap posture must be an object");
  assertRecordKind(record, SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_POSTURE, "surface app bootstrap posture");
  requireString(record.bootstrapId, "surface app bootstrap posture bootstrapId");
  requireString(record.contractId, "surface app bootstrap posture contractId");
  requireString(record.appId, "surface app bootstrap posture appId");
  const state = requireString(record.state, "surface app bootstrap posture state");
  if (!Object.values(SURFACE_APP.BOOTSTRAP_POSTURE).includes(state)) throw new Error("invalid surface app bootstrap posture state");
  if (record.sourceMode !== undefined && !Object.values(SURFACE_APP.FULFILLMENT_MODE).includes(record.sourceMode)) {
    throw new Error("invalid surface app bootstrap sourceMode");
  }
  assertOptionalReferenceList(record.moduleRefs, "surface app bootstrap posture moduleRefs");
  if (record.serviceManagerRef !== undefined) requireString(record.serviceManagerRef, "surface app bootstrap posture serviceManagerRef");
  if (record.serviceManagerPosture !== undefined) assertServiceManagerPosture(record.serviceManagerPosture);
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "surface app bootstrap secretBoundary");
  if (record.releasePosture !== undefined) assertSurfaceReleasePosture(record.releasePosture, "surface app bootstrap releasePosture");
  if (record.rollbackPosture !== undefined) assertSurfaceReleasePosture(record.rollbackPosture, "surface app bootstrap rollbackPosture");
  assertOptionalReferenceList(record.evidenceRefs, "surface app bootstrap posture evidenceRefs");
  const blockedReasons = assertOptionalReferenceList(record.blockedReasons, "surface app bootstrap posture blockedReasons");
  if (state === SURFACE_APP.BOOTSTRAP_POSTURE.BLOCKED && blockedReasons.length === 0) {
    throw new Error("surface app bootstrap blocked state requires blockedReasons");
  }
  if (!Number(record.issuedAt || 0)) throw new Error("surface app bootstrap posture missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) throw new Error("surface app bootstrap posture expires before issuedAt");
  return record;
}

export function assertSurfaceAppContract(record) {
  if (!isObject(record)) throw new Error("surface app contract must be an object");
  requireString(record.contractId, "surface app contract contractId");
  if (Number(record.schemaVersion || 0) !== SURFACE_APP.SCHEMA_VERSION) throw new Error("unsupported surface app contract schemaVersion");
  requireString(record.appId, "surface app contract appId");
  requireString(record.version, "surface app contract version");
  requireString(record.displayName, "surface app contract displayName");
  requireArray(record.requiredPrimitives || [], "surface app contract requiredPrimitives");
  const requiredRoles = requireNonEmptyArray(record.requiredModuleRoles, "surface app contract requiredModuleRoles");
  for (const role of requiredRoles) {
    if (!Object.values(SURFACE_APP.MODULE_ROLE).includes(role)) throw new Error("invalid surface app required module role");
  }
  const modules = requireNonEmptyArray(record.modules, "surface app contract modules").map(assertSurfaceModuleClaim);
  const coveredRoles = new Set(modules.map((module) => module.role));
  for (const role of requiredRoles) {
    if (!coveredRoles.has(role)) throw new Error(`surface app contract missing module role ${role}`);
  }
  requireArray(record.projectionSubscriptions || [], "surface app contract projectionSubscriptions");
  requireArray(record.permissionRequirements || [], "surface app contract permissionRequirements");
  requireArray(record.capabilityRequirements || [], "surface app contract capabilityRequirements");
  requireArray(record.materializationBudgets || [], "surface app contract materializationBudgets")
    .map((budget) => assertMaterializationBudget(budget, "surface app contract materializationBudget"));
  if (record.fallbackPolicy !== undefined && !isObject(record.fallbackPolicy)) throw new Error("surface app contract fallbackPolicy must be an object");
  if (record.updatePosture !== undefined) {
    if (!isObject(record.updatePosture)) throw new Error("surface app contract updatePosture must be an object");
    if (record.updatePosture.state !== undefined && !Object.values(SURFACE_APP.UPDATE_POSTURE).includes(record.updatePosture.state)) {
      throw new Error("invalid surface app update posture state");
    }
  }
  if (record.secretBoundary !== undefined) assertSurfaceSecretBoundary(record.secretBoundary, "surface app contract secretBoundary");
  if (record.releasePosture !== undefined) assertSurfaceReleasePosture(record.releasePosture, "surface app contract releasePosture");
  if (record.rollbackPosture !== undefined) assertSurfaceReleasePosture(record.rollbackPosture, "surface app contract rollbackPosture");
  if (record.serviceManagerPosture !== undefined) assertServiceManagerPosture(record.serviceManagerPosture);
  if (record.bootstrapPosture !== undefined) assertSurfaceAppBootstrapPosture(record.bootstrapPosture);
  if (!Number(record.issuedAt || 0)) throw new Error("surface app contract missing issuedAt");
  if (record.expiresAt !== undefined && Number(record.expiresAt || 0) <= Number(record.issuedAt || 0)) throw new Error("surface app contract expires before issuedAt");
  return record;
}

export function assertAppRunnerAdvertisement(record) {
  if (!isObject(record)) throw new Error("app runner advertisement must be an object");
  requireString(record.runnerId, "app runner id");
  assertResolvedMemberRef(record.memberRef, "app runner memberRef");
  requireString(record.version, "app runner version");
  if (!isObject(record.capacity)) throw new Error("app runner capacity must be an object");
  if (!isObject(record.health)) throw new Error("app runner health must be an object");
  return record;
}
