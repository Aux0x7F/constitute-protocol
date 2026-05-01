import assert from "node:assert/strict";
import test from "node:test";
import {
  BROKER,
  ReplayCache,
  SERVICE_ACCESS_EVENTS,
  SERVICE_ACCESS_KINDS,
  buildUnsignedEvent,
  eventIdHex,
  openEnvelope,
  pubkeyFromSecretKey,
  sealEnvelope,
  signEvent,
  verifyEnvelopeSignature,
  verifyEvent,
} from "../src/index.js";

const ISSUER_SK = "0000000000000000000000000000000000000000000000000000000000000001";
const GATEWAY_SK = "0000000000000000000000000000000000000000000000000000000000000002";
const SERVICE_SK = "0000000000000000000000000000000000000000000000000000000000000003";
const BROWSER_SK = "0000000000000000000000000000000000000000000000000000000000000004";

test("nostr sign/verify roundtrip matches the shared id vector", () => {
  const pk = pubkeyFromSecretKey(ISSUER_SK);
  const unsigned = buildUnsignedEvent({
    pubkey: pk,
    kind: 1111,
    tags: [["t", "constitute"]],
    content: "{\"ok\":true}",
    created_at: 1700000000,
  });
  assert.equal(eventIdHex(unsigned), "79893099e8d1dae52109e57cd6fa2c4eef5257d6779dad8107c708a64ef0e9ad");
  const event = signEvent(unsigned, ISSUER_SK);
  assert.equal(verifyEvent(event), true);
});

test("sealed envelope opens for gateway and service but not browser", () => {
  const gatewayPk = pubkeyFromSecretKey(GATEWAY_SK);
  const servicePk = pubkeyFromSecretKey(SERVICE_SK);
  const claims = {
    identityId: "id-secret",
    service: "nvr",
    sourceIds: ["front-door"],
  };
  const envelope = sealEnvelope({
    kind: SERVICE_ACCESS_KINDS.CAPABILITY,
    claims,
    issuerSecretKey: ISSUER_SK,
    recipientPks: [gatewayPk, servicePk],
    issuedAt: 1700000000,
    expiresAt: 1700000900,
    envelopeId: "capability-001",
    nonces: [
      "000102030405060708090a0b0c0d0e0f1011121314151617",
      "17161514131211100f0e0d0c0b0a09080706050403020100",
    ],
  });
  assert.equal(verifyEnvelopeSignature(envelope), true);
  assert.deepEqual(openEnvelope(envelope, GATEWAY_SK, { now: 1700000001 }), claims);
  assert.deepEqual(openEnvelope(envelope, SERVICE_SK, { now: 1700000001 }), claims);
  assert.throws(() => openEnvelope(envelope, BROWSER_SK, { now: 1700000001 }), /recipient/);
});

test("sealed envelope rejects expiry, tamper, and replay", () => {
  const gatewayPk = pubkeyFromSecretKey(GATEWAY_SK);
  const envelope = sealEnvelope({
    kind: SERVICE_ACCESS_KINDS.REQUEST,
    claims: { requestId: "req-1" },
    issuerSecretKey: ISSUER_SK,
    recipientPks: [gatewayPk],
    issuedAt: 10,
    expiresAt: 20,
  });
  assert.throws(() => openEnvelope(envelope, GATEWAY_SK, { now: 21 }), /expired/);

  const tampered = structuredClone(envelope);
  tampered.recipients[0].ciphertext += "00";
  assert.throws(() => openEnvelope(tampered, GATEWAY_SK, { now: 11 }), /decrypt|signature|cipher/);

  const replayCache = new ReplayCache();
  assert.deepEqual(openEnvelope(envelope, GATEWAY_SK, { now: 11, replayCache }), { requestId: "req-1" });
  assert.throws(() => openEnvelope(envelope, GATEWAY_SK, { now: 11, replayCache }), /replayed/);
});

test("exports current service-access vocabulary only", () => {
  assert.equal(BROKER.SERVICE_ACCESS_REQUEST, "gateway.serviceAccess.request");
  assert.equal(BROKER.SERVICE_SIGNAL_REQUEST, "gateway.serviceSignal.request");
  assert.equal(SERVICE_ACCESS_EVENTS.REQUEST, "gateway_service_access_request");
  assert.equal(SERVICE_ACCESS_EVENTS.SIGNAL_REQUEST, "gateway_service_signal_request");
  assert.equal(SERVICE_ACCESS_EVENTS.SIGNAL_STATUS, "gateway_service_signal_status");
  assert.equal(SERVICE_ACCESS_EVENTS.SIGNAL, "gateway_service_signal");
  assert.equal(SERVICE_ACCESS_EVENTS.GRANT, "gateway.service_access");
  assert.equal(SERVICE_ACCESS_KINDS.INVOCATION, "service_access.invocation");
});
