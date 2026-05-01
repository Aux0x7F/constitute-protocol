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
