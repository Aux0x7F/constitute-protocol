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
  PROJECTION_GET: "projection.get",
  PROJECTION_PUT: "projection.put",
  PROJECTION_POLICY_PUT: "projection.policy.put",
  SERVICE_PROJECTION_REQUEST: "service.projection.request",
  SERVICE_PROJECTION_RESPONSE: "service.projection.response",
});

export const SERVICE_EXCHANGE = Object.freeze({
  SCHEMA_VERSION: 1,
  KIND: Object.freeze({
    DESCRIBE_REQUEST: "service.describe.request",
    DESCRIBE_RESPONSE: "service.describe.response",
    PROJECTION_REQUEST: "service.projection.request",
    PROJECTION_RESPONSE: "service.projection.response",
    CONTROL_REQUEST: "service.control.request",
    CONTROL_RESPONSE: "service.control.response",
    INVOKE_REQUEST: "service.invoke.request",
    INVOKE_RESPONSE: "service.invoke.response",
    WATCH_REQUEST: "service.watch.request",
    WATCH_EVENT: "service.watch.event",
    CLOSE: "service.close",
  }),
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
  LEVEL: Object.freeze({
    DEBUG: "debug",
    INFO: "info",
    WARN: "warn",
    ERROR: "error",
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

const UNSAFE_SAFE_FACT_KEY_RE = /(password|credential|secret|token|capability|servicecapability|privatekey|secretkey|rtspurl|authorization|rawpayload|requestbody)/i;
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
  if (descriptor.projectionChannels !== undefined && !Array.isArray(descriptor.projectionChannels)) {
    throw new Error("service descriptor projectionChannels must be an array");
  }
  for (const channel of descriptor.projectionChannels || []) {
    if (!String(channel || "").trim()) throw new Error("service descriptor contains empty projection channel");
  }
  return descriptor;
}

export function assertServiceExchangeFrame(frame) {
  if (!frame || typeof frame !== "object") throw new Error("service exchange frame must be an object");
  if (!String(frame.frameId || "").trim()) throw new Error("service exchange missing frameId");
  if (!Number(frame.schemaVersion || 0)) throw new Error("service exchange missing schemaVersion");
  if (!Object.values(SERVICE_EXCHANGE.KIND).includes(String(frame.kind || "").trim())) {
    throw new Error("unsupported service exchange kind");
  }
  if (!String(frame.issuerPk || "").trim()) throw new Error("service exchange missing issuerPk");
  if (!String(frame.recipientServicePk || "").trim()) throw new Error("service exchange missing recipientServicePk");
  if (!String(frame.hostGatewayPk || "").trim()) throw new Error("service exchange missing hostGatewayPk");
  if (!Number(frame.issuedAt || 0) || !Number(frame.expiresAt || 0) || Number(frame.expiresAt) <= Number(frame.issuedAt)) {
    throw new Error("service exchange invalid time bounds");
  }
  if (!String(frame.signature || "").trim()) throw new Error("service exchange missing signature");
  return frame;
}

export function makeServiceExchangeFrame(input = {}) {
  const now = nowSeconds();
  return assertServiceExchangeFrame({
    frameId: String(input.frameId || `service-frame-${sha256Hex(`${now}:${Math.random()}`).slice(0, 24)}`),
    schemaVersion: Number(input.schemaVersion || SERVICE_EXCHANGE.SCHEMA_VERSION),
    kind: String(input.kind || ""),
    issuerPk: String(input.issuerPk || ""),
    recipientServicePk: String(input.recipientServicePk || ""),
    hostGatewayPk: String(input.hostGatewayPk || ""),
    issuedAt: Number(input.issuedAt || now),
    expiresAt: Number(input.expiresAt || now + DEFAULT_REQUEST_TTL_SECONDS),
    ...(input.traceId ? { traceId: String(input.traceId) } : {}),
    ...(input.requestId ? { requestId: String(input.requestId) } : {}),
    ...(input.correlationId ? { correlationId: String(input.correlationId) } : {}),
    routeHint: input.routeHint && typeof input.routeHint === "object" ? input.routeHint : {},
    sealedPayload: input.sealedPayload && typeof input.sealedPayload === "object" ? input.sealedPayload : {},
    signature: String(input.signature || "unsigned-local-frame"),
  });
}

export function assertProjectionChannelId(channelId, descriptor) {
  const value = String(channelId || "").trim();
  if (!value) throw new Error("projection missing channel id");
  const descriptorChannels = Array.isArray(descriptor?.projectionChannels) ? descriptor.projectionChannels : [];
  if (descriptorChannels.length > 0) {
    if (!descriptorChannels.includes(value)) throw new Error("unsupported projection channel");
    return value;
  }
  if (!Object.values(PROJECTION.CHANNEL).includes(value)) {
    throw new Error("unsupported projection channel");
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
