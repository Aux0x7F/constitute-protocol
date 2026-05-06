export const CAAC_ALG_V1: string;
export const CAAC_VERSION: 1;
export const DEFAULT_CAPABILITY_TTL_SECONDS: number;
export const MAX_CAPABILITY_TTL_SECONDS: number;
export const DEFAULT_REQUEST_TTL_SECONDS: number;
export const BROKER: Readonly<Record<string, string>>;
export const SERVICE_EXCHANGE: Readonly<Record<string, unknown>>;
export const SERVICE_ACCESS_EVENTS: Readonly<Record<string, string>>;
export const SERVICE_ACCESS_KINDS: Readonly<Record<string, string>>;
export const STORAGE: Readonly<Record<string, string>>;
export const STORAGE_KEY_GRANULARITY: Readonly<Record<string, string>>;
export const LOGGING: Readonly<Record<string, unknown>>;
export const PROJECTION: Readonly<Record<string, unknown>>;
export const DIAGNOSTICS: Readonly<Record<string, unknown>>;

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

export type StorageKeyGranularity = "container" | "shard" | "entry" | "fieldFamily";

export type StorageContainer = {
  containerId: string;
  ownerPk: string;
  createdAt: number;
  keyGranularity?: StorageKeyGranularity[];
  defaultRetentionClass?: string;
  labels?: string[];
};

export type StorageChunkRef = {
  chunkId: string;
  hash: string;
  hashAlg: string;
  size: number;
};

export type StorageObjectManifest = {
  objectId: string;
  containerId: string;
  contentHash: string;
  hashAlg: string;
  encryptionAlg: string;
  keyRef: string;
  chunks: StorageChunkRef[];
  createdAt: number;
  mediaType?: string;
  logicalDeletedAt?: number;
  tags?: string[];
};

export type EncryptedDetailRef = {
  objectId: string;
  containerId: string;
  keyRef: string;
  manifestHash: string;
  summaryTags?: string[];
};

export type StorageGraphEdge = {
  edgeId: string;
  containerId: string;
  fromRef: string;
  relation: string;
  toRef: string;
  detailRef?: EncryptedDetailRef;
  createdAt: number;
};

export type StorageIndexShard = {
  shardId: string;
  containerId: string;
  shardType: string;
  keyRef: string;
  ciphertextHash: string;
  hashAlg: string;
  chunks: StorageChunkRef[];
  objectRefs?: string[];
  graphEdges?: StorageGraphEdge[];
  createdAt: number;
};

export type StorageKeyGrant = {
  grantId: string;
  containerId: string;
  keyRef: string;
  scope: string;
  recipientPk: string;
  issuerPk: string;
  wrappingAlg: string;
  wrappedKey: string;
  issuedAt: number;
  expiresAt?: number;
};

export type StoragePinLease = {
  pinId: string;
  containerId: string;
  objectId?: string;
  chunkHash?: string;
  pinnedBy: string;
  retentionClass: string;
  createdAt: number;
  expiresAt?: number;
  lastAccessedAt?: number;
};

export type StorageAvailabilityRef = {
  availabilityId: string;
  storageHostId: string;
  retentionClass: string;
  objectId?: string;
  chunkHash?: string;
  exportedAt: number;
  expiresAt?: number;
};

export type LogSeverity = "debug" | "info" | "notice" | "warning" | "error" | "critical";
export type LogCategory =
  | "system"
  | "serviceAccess"
  | "serviceSignal"
  | "hostedService"
  | "gatewayControl"
  | "cameraDevice"
  | "mediaProjection"
  | "recording"
  | "worker"
  | "storage"
  | "logging";
export type LogOutcome = "observed" | "succeeded" | "failed" | "denied" | "degraded" | "recovered";
export type LogRedactionClass = "safe" | "redacted" | "encryptedDetail" | "sensitiveOmitted";
export type LogVerbosityClass = "critical" | "normal" | "verbose" | "noise";
export type LogRetentionClass = "forever" | "long" | "rolling" | "short" | "ephemeral";

export type LogProducerRef = {
  service: string;
  component: string;
  instanceId?: string;
  gatewayPk?: string;
  servicePk?: string;
};

export type LogSubjectRef = {
  kind: string;
  id?: string;
  display?: string;
};

export type LogResourceRef = {
  kind: string;
  id?: string;
  display?: string;
};

export type LogCorrelationRef = {
  correlationId: string;
  causationId?: string;
  traceId?: string;
};

export type LogEventEnvelope = {
  schemaVersion: 1;
  eventId: string;
  occurredAt: number;
  receivedAt?: number;
  producer: LogProducerRef;
  category: LogCategory;
  severity: LogSeverity;
  outcome: LogOutcome;
  subject?: LogSubjectRef;
  resource?: LogResourceRef;
  correlation?: LogCorrelationRef;
  tags?: string[];
  safeFacts: Record<string, unknown>;
  detailRef?: EncryptedDetailRef;
  redaction?: LogRedactionClass[];
};

export type ProjectionFreshnessState = "fresh" | "stale" | "missing" | "error";

export type ProjectionCursor = {
  value: string;
  updatedAt: number;
};

export type ProjectionFreshness = {
  state: ProjectionFreshnessState;
  updatedAt: number;
  staleAfter?: number;
  reason?: string;
};

export type ProjectionChannel = {
  channelId: string;
  service: string;
  projectionKind: string;
  capabilityScope: string;
};

export type ServiceProjectionRequest = {
  requestId: string;
  channelId: string;
  service: string;
  cursor?: string;
  limit?: number;
  filters?: Record<string, unknown>;
  policy?: ProjectionPolicy;
};

export type HostedServiceDescriptor = {
  service: string;
  servicePk: string;
  hostGatewayPk: string;
  display?: Record<string, unknown>;
  capabilities?: string[];
  projectionChannels?: string[];
  invocationKinds?: string[];
  transportHints?: Record<string, unknown>;
  healthSummary?: Record<string, unknown>;
};

export type ServiceExchangeFrame = {
  frameId: string;
  schemaVersion: number;
  kind: string;
  issuerPk: string;
  recipientServicePk: string;
  hostGatewayPk: string;
  issuedAt: number;
  expiresAt: number;
  traceId?: string;
  requestId?: string;
  correlationId?: string;
  routeHint?: Record<string, unknown>;
  sealedPayload?: Record<string, unknown>;
  signature: string;
};

export type ProjectionRecord = {
  channelId: string;
  service: string;
  servicePk: string;
  producer?: Record<string, unknown>;
  cursor?: ProjectionCursor;
  freshness: ProjectionFreshness;
  scope?: Record<string, unknown>;
  payloadSchema?: string;
  payload: Record<string, unknown>;
  safeFacts?: Record<string, unknown>;
  encryptedDetailRefs?: unknown[];
  diagnostics?: unknown[];
};

export type ProjectionSyncState = "idle" | "syncing" | "degraded" | "stale" | "blocked" | "completeEnough";

export type ProjectionPolicy = {
  policyId: string;
  channelId: string;
  service: string;
  scope?: Record<string, unknown>;
  rollingWindowHours?: number;
  maxVerbosityClass?: LogVerbosityClass;
  minSeverity?: LogSeverity;
  excludedVerbosityClasses?: LogVerbosityClass[];
  syncDepthTarget?: Record<string, unknown>;
  retentionTarget?: Record<string, unknown>;
};

export type ProjectionCoverage = {
  materializedCount: number;
  targetCount?: number;
  completionRatio: number;
  completeSeverityBands?: string[];
  oldestObservedAt?: number;
  newestObservedAt?: number;
  syncState: ProjectionSyncState;
};

export type ProjectionObserverUpdate = {
  projectionKey: string;
  changedCount: number;
  coverage: ProjectionCoverage;
  freshness: ProjectionFreshness;
  diagnostics?: unknown[];
};

export type DiagnosticEvent = {
  diagnosticId: string;
  schemaVersion: number;
  occurredAt: number;
  level: string;
  surface?: string;
  component?: string;
  operation: string;
  stage?: string;
  traceId?: string;
  requestId?: string;
  correlationId?: string;
  channelId?: string;
  service?: string;
  servicePk?: string;
  hostGatewayPk?: string;
  routeKind?: string;
  durationMs?: number;
  counts?: Record<string, number>;
  safeFacts?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
  encryptedDetailRefs?: unknown[];
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
export function storageCiphertextHash(bytes: string | Uint8Array): string;
export function storageObjectId(input?: { containerId?: string; contentHash?: string }): string;
export function storageChunkId(hash: string): string;
export function makeStorageChunkRef(input?: { ciphertext?: string | Uint8Array; chunkId?: string }): StorageChunkRef;
export function assertStorageChunkRef(chunk: unknown, ciphertext: string | Uint8Array): StorageChunkRef;
export function assertStorageObjectManifest(manifest: unknown): StorageObjectManifest;
export function makeStorageObjectManifest(input?: {
  containerId?: string;
  keyRef?: string;
  chunks?: StorageChunkRef[];
  createdAt?: number;
  mediaType?: string;
  tags?: string[];
  encryptionAlg?: string;
}): StorageObjectManifest;
export function assertStorageIndexShard(shard: unknown): StorageIndexShard;
export function logEventId(event: Partial<LogEventEnvelope>): string;
export function rejectSensitiveSafeFacts(value: unknown): void;
export function assertLogEventEnvelope(event: unknown): LogEventEnvelope;
export function makeLogEventEnvelope(input: Partial<LogEventEnvelope>): LogEventEnvelope;
export function rejectUnsafeSafeFacts(value: unknown): void;
export function assertHostedServiceDescriptor(descriptor: unknown): HostedServiceDescriptor;
export function assertServiceExchangeFrame(frame: unknown): ServiceExchangeFrame;
export function makeServiceExchangeFrame(input: Partial<ServiceExchangeFrame>): ServiceExchangeFrame;
export function assertProjectionChannelId(channelId: unknown, descriptor?: Partial<HostedServiceDescriptor>): string;
export function assertProjectionFreshness(freshness: unknown): ProjectionFreshness;
export function assertServiceProjectionRequest(request: unknown, descriptor?: Partial<HostedServiceDescriptor>): ServiceProjectionRequest;
export function assertProjectionPolicy(policy: unknown, descriptor?: Partial<HostedServiceDescriptor>): ProjectionPolicy;
export function makeProjectionPolicy(input: Partial<ProjectionPolicy>): ProjectionPolicy;
export function assertProjectionCoverage(coverage: unknown): ProjectionCoverage;
export function makeProjectionCoverage(input: Partial<ProjectionCoverage>): ProjectionCoverage;
export function assertProjectionObserverUpdate(update: unknown): ProjectionObserverUpdate;
export function makeProjectionObserverUpdate(input: Partial<ProjectionObserverUpdate>): ProjectionObserverUpdate;
export function assertProjectionRecord(result: unknown, descriptor?: Partial<HostedServiceDescriptor>): ProjectionRecord;
export function makeProjectionRecord(input: Partial<ProjectionRecord>): ProjectionRecord;
export function assertDiagnosticEvent(event: unknown): DiagnosticEvent;
