export const CAAC_ALG_V1: string;
export const CAAC_VERSION: 1;
export const DEFAULT_CAPABILITY_TTL_SECONDS: number;
export const MAX_CAPABILITY_TTL_SECONDS: number;
export const DEFAULT_REQUEST_TTL_SECONDS: number;
export const BROKER: Readonly<Record<string, string>>;
export const SERVICE_ACCESS_EVENTS: Readonly<Record<string, string>>;
export const SERVICE_ACCESS_KINDS: Readonly<Record<string, string>>;

export type CaacRecipient = {
  recipientPk: string;
  nonce: string;
  ciphertext: string;
};

export type CaacEnvelope = {
  version: 1;
  kind: string;
  envelopeId: string;
  issuerPk: string;
  issuedAt: number;
  expiresAt: number;
  alg: string;
  recipients: CaacRecipient[];
  signature: string;
};

export type ServiceAccessContext = {
  contextId: string;
  service: string;
  gatewayPk: string;
  servicePk: string;
  identityId?: string;
  devicePk?: string;
  display?: Record<string, unknown>;
  serviceCapability: CaacEnvelope;
  issuedAt: number;
  expiresAt: number;
};

export function bytesToHex(bytes: Uint8Array): string;
export function hexToBytes(hex: string): Uint8Array;
export function utf8ToBytes(value: string): Uint8Array;
export function bytesToUtf8(bytes: Uint8Array): string;
export function randomBytes(length: number): Uint8Array;
export function nowSeconds(): number;
export function canonicalJson(value: unknown): string;
export function sha256Hex(value: string | Uint8Array): string;
export function pubkeyFromSecretKey(secretKeyHex: string): string;
export function compressedPublicKeyFromXOnly(xonlyHex: string): string;
export function buildUnsignedEvent(input: Record<string, unknown>): Record<string, unknown>;
export function eventIdHex(unsigned: Record<string, unknown>): string;
export function signEvent(unsigned: Record<string, unknown>, secretKeyHex: string): Record<string, unknown>;
export function verifyEvent(event: Record<string, unknown>): boolean;
export function buildNostrEvent(input: Record<string, unknown>): Record<string, unknown>;
export function serviceAccessRoutingTags(input?: Record<string, unknown>): string[][];
export function unsignedEnvelope(envelope: CaacEnvelope): Record<string, unknown>;
export function envelopeSigningDigest(envelope: CaacEnvelope): Uint8Array;
export function signEnvelope(envelope: CaacEnvelope, issuerSecretKey: string): string;
export function verifyEnvelopeSignature(envelope: CaacEnvelope): boolean;
export function sealEnvelope(input: {
  kind: string;
  claims: Record<string, unknown>;
  issuerSecretKey: string;
  recipientPks: string[];
  issuedAt?: number;
  expiresAt?: number;
  envelopeId?: string;
  nonces?: string[];
}): CaacEnvelope;
export function openEnvelope(envelope: CaacEnvelope, recipientSecretKey: string, opts?: { now?: number; replayCache?: ReplayCache }): Record<string, unknown>;
export class ReplayCache {
  has(id: string): boolean;
  add(id: string): void;
}
export function serviceAccessContextId(input?: Record<string, unknown>): string;
export function assertServiceAccessContext(value: unknown): ServiceAccessContext;
export function makeServiceAccessContext(input: Partial<ServiceAccessContext>): ServiceAccessContext;
