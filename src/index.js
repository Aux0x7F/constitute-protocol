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
  SERVICE_ACCESS_REQUEST: "gateway.serviceAccess.request",
  SERVICE_ACCESS_RESPONSE: "gateway.serviceAccess.response",
  SERVICE_SIGNAL_REQUEST: "gateway.serviceSignal.request",
  SERVICE_SIGNAL_RESPONSE: "gateway.serviceSignal.response",
  SERVICE_ACCESS_CONTEXT_GET: "serviceAccessContext.get",
  SERVICE_ACCESS_CONTEXT_PUT: "serviceAccessContext.put",
  SERVICE_ACCESS_CONTEXT_DELETE: "serviceAccessContext.delete",
});

export const SERVICE_ACCESS_EVENTS = Object.freeze({
  REQUEST: "gateway_service_access_request",
  STATUS: "gateway_service_access_status",
  SIGNAL_REQUEST: "gateway_service_signal_request",
  SIGNAL_STATUS: "gateway_service_signal_status",
  SIGNAL: "gateway_service_signal",
  GRANT: "gateway.service_access",
});

export const SERVICE_ACCESS_KINDS = Object.freeze({
  CAPABILITY: "service_access.capability",
  STATUS: "service_access.status",
  REQUEST: "service_access.request",
  SIGNAL: "service_access.signal",
  INVOCATION: "service_access.invocation",
  ADMIN: "service_access.admin",
  CONTROL: "service_access.control",
  CLOSE: "service_access.close",
});

export const STORAGE = Object.freeze({
  OBJECT_HASH_ALG: "sha256-ciphertext-v1",
  CHUNK_HASH_ALG: "sha256-ciphertext-v1",
  ENCRYPTION_ALG_XCHACHA20POLY1305: "xchacha20poly1305",
  CAAC_KIND_KEY_GRANT: "storage.key_grant",
  CAAC_KIND_SERVICE_ACCESS: "storage.service_access",
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
    SERVICE_ACCESS: "serviceAccess",
    SERVICE_SIGNAL: "serviceSignal",
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

export function buildUnsignedEvent({ pubkey, kind, tags = [], content = "", created_at }) {
  return {
    pubkey: String(pubkey || ""),
    created_at: Number(created_at || nowSeconds()),
    kind: Number(kind || 0),
    tags: Array.isArray(tags) ? tags : [],
    content: String(content ?? ""),
  };
}

export function eventIdHex(unsigned) {
  return sha256Hex(JSON.stringify([
    0,
    unsigned.pubkey,
    unsigned.created_at,
    unsigned.kind,
    unsigned.tags || [],
    unsigned.content || "",
  ]));
}

export function signEvent(unsigned, secretKeyHex) {
  const id = eventIdHex(unsigned);
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

export function verifyEvent(event) {
  const unsigned = buildUnsignedEvent(event);
  if (eventIdHex(unsigned) !== event.id) return false;
  return schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey));
}

export function buildNostrEvent({ secretKey, kind, tags = [], content = "", created_at = nowSeconds() }) {
  const pubkey = pubkeyFromSecretKey(secretKey);
  return signEvent(buildUnsignedEvent({ pubkey, kind, tags, content, created_at }), secretKey);
}

export function serviceAccessRoutingTags({ gatewayPk = "", servicePk = "", service = "", envelopeKind = "" } = {}) {
  const tags = [["t", "constitute"], ["t", "service_access"]];
  if (gatewayPk) tags.push(["p", String(gatewayPk)]);
  if (servicePk) tags.push(["service_pk", String(servicePk)]);
  if (service) tags.push(["service", String(service)]);
  if (envelopeKind) tags.push(["caac_kind", String(envelopeKind)]);
  return tags;
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

export function serviceAccessContextId({ service = "", gatewayPk = "", servicePk = "", capabilityId = "" } = {}) {
  return sha256Hex(canonicalJson({ capabilityId, gatewayPk, service, servicePk })).slice(0, 32);
}

export function assertServiceAccessContext(value) {
  if (!value || typeof value !== "object") throw new Error("service access context must be an object");
  if (!String(value.contextId || "").trim()) throw new Error("service access context missing contextId");
  if (!String(value.service || "").trim()) throw new Error("service access context missing service");
  if (!String(value.gatewayPk || "").trim()) throw new Error("service access context missing gatewayPk");
  if (!String(value.servicePk || "").trim()) throw new Error("service access context missing servicePk");
  if (!value.serviceCapability) throw new Error("service access context missing serviceCapability");
  return value;
}

export function makeServiceAccessContext({
  contextId,
  service,
  gatewayPk,
  servicePk,
  identityId = "",
  devicePk = "",
  display = {},
  serviceCapability,
  issuedAt = nowSeconds(),
  expiresAt = issuedAt + DEFAULT_CAPABILITY_TTL_SECONDS,
} = {}) {
  const context = {
    contextId: contextId || serviceAccessContextId({ service, gatewayPk, servicePk, capabilityId: serviceCapability?.envelopeId || "" }),
    service,
    gatewayPk,
    servicePk,
    identityId,
    devicePk,
    display: display || {},
    serviceCapability,
    issuedAt,
    expiresAt,
  };
  return assertServiceAccessContext(context);
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
  "capability",
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
  const clone = structuredClone(event || {});
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
  if (event.eventId !== logEventId(event)) throw new Error("log event id mismatch");
  return event;
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
  event.eventId = logEventId(event);
  return assertLogEventEnvelope(event);
}
