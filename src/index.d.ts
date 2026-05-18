export const CAAC_ALG_V1: string;
export const CAAC_VERSION: 1;
export const DEFAULT_CAPABILITY_TTL_SECONDS: number;
export const MAX_CAPABILITY_TTL_SECONDS: number;
export const DEFAULT_REQUEST_TTL_SECONDS: number;
export const BROKER: Readonly<Record<string, string>>;
export const SERVICE_SURFACE: Readonly<Record<string, unknown>>;
export const SURFACE_APP: Readonly<Record<string, unknown>>;
export const AGREEMENT: Readonly<Record<string, unknown>>;
export const SERVICE_REGISTRY: Readonly<Record<string, unknown>>;
export const STORAGE: Readonly<Record<string, string>>;
export const STORAGE_KEY_GRANULARITY: Readonly<Record<string, string>>;
export const LOGGING: Readonly<Record<string, unknown>>;
export const PROJECTION: Readonly<Record<string, unknown>>;
export const DIAGNOSTICS: Readonly<Record<string, unknown>>;
export const STREAM_SESSION_LIFECYCLE_PHASE: Readonly<Record<string, StreamSessionLifecyclePhase>>;

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

export type BootstrapNostrEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};

export type BootstrapNostrUnsignedEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

export type BootstrapNostrFilter = {
  kinds?: number[];
  "#t"?: string[];
  "#z"?: string[];
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
  | "capability"
  | "swarmEdge"
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
export type LogEvidenceProfileEventClass =
  | "securityAudit"
  | "runtimeDiagnostic"
  | "serviceEvent"
  | "storageAccess"
  | "mediaPath";
export type LogEvidenceDetailCustody = "safeFactsOnly" | "encryptedDetailRef" | "encryptedRawRef";

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
  encryptedDetailRefs?: EncryptedDetailRef[];
  redaction?: LogRedactionClass[];
};

export type LogEvidenceProfile = {
  kind?: "logging.evidence.profile";
  profileId: string;
  consumerRef: string;
  eventClasses: LogEvidenceProfileEventClass[];
  retentionWindow: string;
  safeIndexRefs: string[];
  detailCustody: LogEvidenceDetailCustody;
  encryptedDetailRequired: boolean;
  accessGrantRefs?: string[];
  storageContainerRefs?: string[];
  materializationBudgetRef?: string;
  issuedAt: number;
  expiresAt?: number;
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
  aliases?: string[];
  location?: ServiceLocationRef;
  surfaceChannel: string;
  display?: Record<string, unknown>;
  summary?: string;
  health?: Record<string, unknown>;
  nodes?: string[];
  retired?: Record<string, unknown>;
  transportHints?: Record<string, unknown>;
};

export type ServiceLocationRef = {
  locationId: string;
  label: string;
  gatewayPk: string;
};

export type ServiceNodeFieldCapability = "read" | "observe" | "set" | "attach" | "invoke";

export type ServiceNodeFieldDescriptor = {
  fieldId: string;
  label: string;
  description?: string;
  valueKind?: string;
  capabilities: ServiceNodeFieldCapability[];
  required?: boolean;
  schema?: Record<string, unknown>;
};

export type ServiceNodeDescriptor = {
  nodeId: string;
  path: string;
  label: string;
  description?: string;
  aliases?: string[];
  backingChannel?: string;
  children?: string[];
  fields?: ServiceNodeFieldDescriptor[];
  terminalOperation?: boolean;
  metadata?: Record<string, unknown>;
};

export type ServiceSurfaceProjection = {
  surfaceId: string;
  schemaVersion: number;
  service: string;
  servicePk: string;
  hostGatewayPk: string;
  location?: ServiceLocationRef;
  aliases?: string[];
  summary: string;
  healthNode: string;
  nodes: ServiceNodeDescriptor[];
  diagnostics?: unknown[];
  updatedAt: number;
};

export type ServiceAttachDescriptor = {
  attachId: string;
  label: string;
  description?: string;
  attachKind: string;
  protocol?: string;
  endpoint?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

export type ServiceNodeProjectionRecord = {
  requestId?: string;
  nodePath: string;
  service: string;
  servicePk: string;
  producer?: Record<string, unknown>;
  freshness: ProjectionFreshness;
  payloadSchema?: string;
  payload?: Record<string, unknown>;
  fields?: Record<string, unknown>;
  desired?: Record<string, unknown>;
  status?: Record<string, unknown>;
  result?: Record<string, unknown>;
  attaches?: ServiceAttachDescriptor[];
  safeFacts?: Record<string, unknown>;
  diagnostics?: unknown[];
};

export type ServiceNodeSetRequest = {
  requestId: string;
  service: string;
  nodePath: string;
  desired: Record<string, unknown>;
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

export type RuntimeDiagnosticEvent = {
  eventId: string;
  recordKind: "runtime.diagnostic.event";
  channelId: "runtime.diagnostics";
  kind: string;
  level: string;
  observedAt: number;
  buildId: string;
  runtimeSessionId: string;
  surface?: string;
  clientId?: string;
  frameId?: string;
  correlationId?: string;
  requestId?: string;
  activationId?: string;
  routePromiseId?: string;
  projectionKey?: string;
  channelRef?: string;
  capabilityRef?: string;
  safeFacts: Record<string, unknown>;
};

export type RuntimeDiagnosticCommand = {
  recordKind: "runtime.diagnostic.command";
  command: string;
  args?: Record<string, unknown>;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  audienceRuntimeSessionId: string;
};

export type RuntimeDiagnosticCommandResult = {
  recordKind: "runtime.diagnostic.command.result";
  command: string;
  ok: boolean;
  code?: string;
  result?: unknown;
  error?: string;
};

export const SWARM: Readonly<Record<string, unknown>>;

export type ZoneScope = {
  zoneId: string;
  privacy?: string;
  ttl?: number;
  maxHops?: number;
};

export type SwarmFrameBody = {
  encoding: "caac" | "public";
  envelope?: Record<string, unknown>;
  publicBootstrap?: boolean;
  payload?: Record<string, unknown>;
};

export type SwarmFrame = {
  version: 1;
  frameId: string;
  kind: string;
  issuer: string;
  audience?: unknown;
  zoneScope?: ZoneScope;
  issuedAt: number;
  expiresAt?: number;
  nonce: string;
  correlationId?: string;
  channelId?: string;
  recordRef?: Record<string, unknown>;
  capability?: string;
  body: SwarmFrameBody;
  ack?: Record<string, unknown>;
};

export type ChannelDescriptor = {
  channelId: string;
  kind: string;
  displayName: string;
  capabilities: string[];
  recordKinds: string[];
  ownerRefs: string[];
  policyRef: string;
  createdAt: number;
  expiresAt?: number;
};

export type ChannelMembership = {
  channelId: string;
  memberRef: string;
  roles: string[];
  authorityEnvelope: Record<string, unknown>;
};

export type CapabilityDefinition = {
  definitionId: string;
  capability: string;
  namespace: string;
  schemaRef?: string;
  createdAt: number;
};

export type CapabilityAdvertisement = {
  advertisementId: string;
  capability: string;
  memberRef?: string;
  serviceRef?: string;
  issuedAt: number;
  expiresAt?: number;
};

export type NodeCapability = {
  kind?: "node.capability";
  nodeCapabilityId: string;
  nodeRef: string;
  capabilityRef: string;
  serviceRef: string;
  serviceMemberRef: string;
  backingChannelRefs: string[];
  activationPolicy: Record<string, unknown>;
  freshness: { state: string; updatedAt: number; expiresAt?: number };
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type RuntimeActivationRequest = {
  kind?: "runtime.activation.request";
  activationId: string;
  nodeRef: string;
  capabilityRef: string;
  params: Record<string, unknown>;
  requesterRef: string;
  issuedAt: number;
  expiresAt?: number;
};

export type RoutePromise = {
  kind?: "route.promise";
  promiseId: string;
  activationId: string;
  nodeRef: string;
  capabilityRef: string;
  requesterRef: string;
  serviceMemberRef?: string;
  servicePk: string;
  channelId: string;
  zoneScope: ZoneScope;
  audienceRefs: string[];
  authorityRefs: string[];
  routePolicy: Record<string, unknown>;
  pathRefs: string[];
  issuedAt: number;
  expiresAt: number;
  releasePolicy: Record<string, unknown>;
};

export type LocalRouteBinding = {
  bindingId: string;
  promiseId: string;
  participantRef: string;
  bindingKind: string;
  localRefs?: Record<string, unknown>;
  issuedAt: number;
};

export type RouteObservationState =
  | "delivered"
  | "memberWritten"
  | "memberRead"
  | "observingUnreachable"
  | "unreachableFor"
  | "rejected"
  | "accepted"
  | "degraded"
  | "released"
  | "closed"
  | "expired";

export type RouteObservation = {
  kind?: "route.observation";
  observationId: string;
  state: RouteObservationState;
  frameId?: string;
  promiseId?: string;
  activationId?: string;
  deliveredTo?: string[];
  failedPredicates?: string[];
  releaseReason?: string;
  diagnostics?: Record<string, unknown>;
  issuedAt: number;
};

export type StreamRoutePath = {
  pathId: string;
  kind: string;
  state?: string;
  refs?: string[];
  diagnostics?: Record<string, unknown>;
};

export type StreamRoutePlan = {
  kind?: "stream.routePlan";
  sessionId: string;
  sourceRefs: string[];
  requesterRef: string;
  serviceMemberRef: string;
  capabilityRef: string;
  routeLease: Record<string, unknown>;
  candidatePaths: StreamRoutePath[];
  preferredPath: StreamRoutePath;
  fallbackPaths: StreamRoutePath[];
  selectedPath: StreamRoutePath;
  pathState: string;
  reachabilityState: string;
  releasePolicy: Record<string, unknown>;
  diagnostics?: Record<string, unknown>;
  expiresAt: number;
};

export type MemberPresence = {
  kind?: "member.presence";
  memberRef: string;
  memberKind: string;
  capabilityRefs?: string[];
  channelRefs?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type DirectoryEntry = {
  kind?: "directory.entry";
  entryId: string;
  subjectRef: string;
  source: string;
  capabilityRef?: string;
  channelId?: string;
  issuedAt: number;
};

export type ServiceRegistryClaimState = "claimed" | "retracted" | "expired" | "blocked";
export type ServiceRegistryClaimKind = "service" | "member" | "capability" | "channel" | "surface";
export type ServiceRegistryMaterializationState = "ready" | "partial" | "stale" | "blocked";

export type ServiceRegistryClaim = {
  kind?: "service.registry.claim";
  claimId: string;
  schemaVersion: 1;
  claimKind: ServiceRegistryClaimKind;
  state: ServiceRegistryClaimState;
  ownerRef: string;
  writerRef: string;
  subjectRef: string;
  scopeRef: string;
  service?: string;
  servicePk?: string;
  serviceRef?: string;
  memberRef?: string;
  hostGatewayPk?: string;
  capabilityRefs?: string[];
  channelRefs?: string[];
  nodeRefs?: string[];
  surfaceRefs?: string[];
  evidenceRefs?: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
  retractedAt?: number;
};

export type ServiceRegistryMaterialization = {
  kind?: "service.registry.materialization";
  registryId: string;
  schemaVersion: 1;
  scopeRef: string;
  state: ServiceRegistryMaterializationState;
  revision: number;
  claimRefs?: string[];
  participantRefs?: string[];
  serviceRefs?: string[];
  services?: unknown[];
  entries?: DirectoryEntry[];
  coverage?: ProjectionCoverage;
  freshness?: ProjectionFreshness;
  blockedReasons?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type BootstrapCarrierRecord = {
  kind?: "bootstrap.carrier";
  carrierId: string;
  carrierKind: string;
  boundary: "bootstrap" | "fallback";
  payloadRef?: string;
  issuedAt: number;
};

export type SwarmAuthorityDomain = "identity" | "gateway" | "service" | "device" | "runtime";
export type SwarmInteractionRoleName = "requester" | "coordinator" | "router" | "executor" | "adapter" | "storage" | "observer" | "owner";
export type SwarmInteractionState = "prepared" | "accepted" | "routed" | "serviceAccepted" | "active" | "rejected" | "released" | "expired";
export type RoutingScopeKind = "local" | "swarmZone" | "explicitAudience" | "explicitMember" | "bootstrap";
export type RoutingScopeState = "notRequired" | "ready" | "syncing" | "stale" | "missing" | "unavailable";
export type RoutingBlockedReason = "missingZoneBaseline" | "noMemberInZone" | "zeroPropagation" | "zoneMismatch" | "audienceMismatch" | "edgeNotAccepted";
export type ParticipantRunlevel =
  | "localCache"
  | "authorityReady"
  | "edgeAttached"
  | "directoryReady"
  | "routeReady"
  | "interactive"
  | "fulfilling"
  | "degraded"
  | "blocked"
  | "unavailable";
export type SelfCapabilityAction = "observe" | "request" | "route" | "fulfill" | "retain" | "release" | "administer";
export type SelfCapabilityStatus = "available" | "degraded" | "blocked" | "disabled" | "unknown";
export type PostureFacetState = "ready" | "notRequired" | "missing" | "blocked" | "degraded" | "unknown";
export type ResourceProfileClass = "thinClient" | "balanced" | "offlineFirst" | "archiveNode" | "operatorDev" | "custom";
export type ResourcePostureState = "withinBudget" | "pressure" | "overBudget" | "sweeping" | "blocked" | "unavailable";
export type EventPlane =
  | "authority"
  | "route"
  | "activation"
  | "projection"
  | "projectionRepair"
  | "contribution"
  | "retention"
  | "diagnostic"
  | "devBridge"
  | "loggingReplay"
  | "bulkRetainedData";
export type EventAdmissionDecision = "forward" | "drop" | "defer" | "summarize" | "reject";
export type EventProofRequirement = "none" | "signature" | "authority" | "sealed" | "execution";
export type EventProofState = "notRequired" | "pending" | "verified" | "failed";
export type EventDeliveryMode = "push" | "pull" | "observe" | "replay" | "delta" | "summary";
export type EventBackpressureBehavior = "drop" | "defer" | "summarize" | "reject" | "forward";
export type MaterializationPayloadClass = "control" | "evidence" | "projection" | "retainedRaw" | "media" | "bulk";
export type MaterializationCopyRole = "transport" | "projection" | "cache" | "buffer" | "retention" | "debug" | "evidence" | "referenceOnly";
export type MaterializationTransferMode = "clone" | "transferable" | "shared" | "native" | "referenceOnly";
export type MaterializationLagState = "caughtUp" | "lagging" | "stale" | "blocked" | "unknown";
export type MaterializationSchemaState = "current" | "compatible" | "migrating" | "ignore" | "quarantined" | "blocked";
export type MaterializationPrivacyTier = "encryptedRaw" | "encryptedDetail" | "safeFacts" | "safeIndex" | "safeProjection" | "uiProjection";
export type RetentionReleaseState = "freeable" | "releaseBlocked";
export type ContributionType = "claim" | "promise" | "fulfillment" | "witness" | "retraction" | "release" | "expiry" | "observation";
export type ContributionState = "active" | "witnessed" | "retracted" | "released" | "expired" | "blocked";

export type RoutingScopePosture = {
  kind: RoutingScopeKind;
  required: boolean;
  state: RoutingScopeState;
  zoneScope?: ZoneScope;
  source?: string;
  baselineRef?: string;
  blockedReason?: RoutingBlockedReason;
  updatedAt?: number;
};

export type PostureFacet = {
  state: PostureFacetState;
  reason?: string;
  evidenceRefs?: string[];
  authorityRefs?: string[];
  policyRefs?: string[];
  updatedAt?: number;
};

export type ParticipantRunlevelPosture = {
  kind?: "participant.runlevel";
  runlevelId: string;
  participantRef: string;
  participantKind: string;
  runlevel: ParticipantRunlevel;
  facets?: Record<string, PostureFacet>;
  evidenceRefs?: string[];
  authorityRefs?: string[];
  reason?: string;
  updatedAt: number;
  expiresAt?: number;
};

export type SelfCapabilityAssessment = {
  kind?: "participant.selfCapability";
  assessmentId: string;
  participantRef: string;
  participantKind?: string;
  serviceRef?: string;
  serviceMemberRef?: string;
  subjectRef?: string;
  capabilityRef: string;
  actions: SelfCapabilityAction[];
  status: SelfCapabilityStatus;
  runlevel: ParticipantRunlevel;
  facets: Record<"authority" | "resource" | "policy" | "directory" | "route" | "adapter" | "retention" | "domain", PostureFacet> & Record<string, PostureFacet>;
  blockedReasons?: string[];
  evidenceRefs?: string[];
  authorityRefs?: string[];
  policyRefs?: string[];
  updatedAt: number;
  expiresAt?: number;
};

export type ResourceProfile = {
  kind?: "resource.profile";
  profileId: string;
  profileClass: ResourceProfileClass;
  budgets?: Record<string, unknown>;
  caps?: Record<string, unknown>;
  ownerRef?: string;
  issuedAt: number;
};

export type ResourcePosture = {
  kind?: "resource.posture";
  postureId: string;
  profileId: string;
  state: ResourcePostureState;
  counts?: Record<string, unknown>;
  budgets?: Record<string, unknown>;
  lanes?: IngressLanePosture[];
  blockedReasons?: string[];
  sampledAt: number;
};

export type IngressLanePosture = {
  kind?: "ingress.lane.posture";
  laneId: string;
  laneKind: string;
  priority: number;
  state: ResourcePostureState;
  counts?: Record<string, unknown>;
  limits?: Record<string, unknown>;
  relevanceRefs?: string[];
  blockedReasons?: string[];
  sampledAt: number;
};

export type EventAdmissionEnvelope = {
  kind?: "event.admission";
  admissionId: string;
  plane: EventPlane;
  laneId?: string;
  subscriptionId?: string;
  publisherRef?: string;
  subscriberRef?: string;
  subject: Record<string, unknown>;
  audience: Record<string, unknown>;
  claimedSeverity?: LogSeverity;
  effectivePriority: number;
  decision: EventAdmissionDecision;
  proofRequirement: EventProofRequirement;
  proofState: EventProofState;
  reason?: string;
  cost?: Record<string, unknown>;
  evidenceRefs?: string[];
  observedAt: number;
  expiresAt?: number;
};

export type SubscriptionContract = {
  kind?: "subscription.contract";
  subscriptionId: string;
  subscriberRef: string;
  publisherRef?: string;
  publisherClass?: string;
  planes: EventPlane[];
  subjectSelector: Record<string, unknown>;
  audience: Record<string, unknown>;
  window?: Record<string, unknown>;
  cost?: Record<string, unknown>;
  proof: { requirement: EventProofRequirement } & Record<string, unknown>;
  delivery: { mode: EventDeliveryMode } & Record<string, unknown>;
  backpressure: { behavior: EventBackpressureBehavior } & Record<string, unknown>;
  capabilityRefs?: string[];
  authorityRefs?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type ConsumerFloor = {
  kind?: "consumer.floor";
  floorId: string;
  consumerRef: string;
  subscriptionId?: string;
  materializationId?: string;
  subjectRef?: string;
  cursor?: string;
  ackFloor?: string;
  witnessFloor?: string;
  compactionFloor?: string;
  eventTimeFloor?: number;
  observedTimeFloor?: number;
  lagState: MaterializationLagState;
  reason?: string;
  redelivery?: Record<string, unknown>;
  replay?: Record<string, unknown>;
  evidenceRefs?: string[];
  sampledAt: number;
  expiresAt?: number;
};

export type MaterializationBudget = {
  kind?: "materialization.budget";
  budgetId: string;
  sourceAuthority: string;
  consumerRef: string;
  subscriberRef?: string;
  payloadClass: MaterializationPayloadClass;
  copyRole: MaterializationCopyRole;
  transferMode: MaterializationTransferMode;
  privacyTier?: MaterializationPrivacyTier;
  state?: ResourcePostureState;
  limits?: Record<string, unknown>;
  snapshotPolicy?: Record<string, unknown>;
  deltaPolicy?: Record<string, unknown>;
  coalescing?: Record<string, unknown>;
  cardinality?: Record<string, unknown>;
  schema?: {
    state: MaterializationSchemaState;
    version?: string;
    reason?: string;
    migrationRefs?: string[];
  };
  consumerFloor?: ConsumerFloor;
  referenceRefs?: string[];
  blockedReasons?: string[];
  evidenceRefs?: string[];
  retentionClass?: string;
  issuedAt: number;
  releaseAfter?: number;
  expiresAt?: number;
};

export type RetentionReleasePosture = {
  kind?: "retention.release";
  evaluationId: string;
  subjectRef: string;
  effectiveRetention: string;
  state: RetentionReleaseState;
  policyRefs?: string[];
  overlayRefs?: string[];
  ownerRefs: string[];
  holderRefs?: string[];
  fulfillmentRefs?: string[];
  residencyLayers: string[];
  witnessRefs?: string[];
  supersessionRefs?: string[];
  retractionRefs?: string[];
  revocationRefs?: string[];
  blockers?: Array<string | Record<string, unknown>>;
  validUntil?: number;
  releaseAfter?: number;
  evaluatedAt: number;
};

export type ContributionLifecycle = {
  kind?: "contribution.lifecycle";
  contributionId: string;
  parentRef: string;
  subjectRef: string;
  writerRef: string;
  contributionType: ContributionType;
  state?: ContributionState;
  role: string;
  authorityRefs: string[];
  scope?: Record<string, unknown>;
  targetContributionRef?: string;
  supersedes?: string[];
  witnessRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  issuedAt: number;
  validUntil?: number;
  releaseAfter?: number;
  retractedAt?: number;
  observedAt?: number;
};

export type SwarmIdentityRecord = {
  kind?: "swarm.identity";
  identityId: string;
  rootRefs: string[];
  recoveryRootRefs?: string[];
  recoveryRouteRefs?: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type SwarmDeviceRecord = {
  kind?: "swarm.device";
  deviceId: string;
  deviceRef: string;
  identityRef: string;
  capabilityRefs?: string[];
  authorityRefs: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type SwarmGatewayRecord = {
  kind?: "swarm.gateway";
  gatewayId: string;
  gatewayRef: string;
  ownerRefs: string[];
  authorityRefs: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type SwarmServiceRecord = {
  kind?: "swarm.service";
  serviceId: string;
  serviceRef: string;
  service: string;
  contractRef: string;
  capabilityRefs?: string[];
  channelRefs?: string[];
  authorityRefs: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type SwarmMemberRecord = {
  kind?: "swarm.member";
  memberId: string;
  memberRef: string;
  memberKind: string;
  capabilityRefs?: string[];
  channelRefs?: string[];
  authorityRefs: string[];
  storage?: Record<string, unknown>;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type SwarmGrantRecord = {
  kind?: "swarm.grant";
  grantId: string;
  issuerRef: string;
  subjectRef: string;
  audienceRefs: string[];
  authorityDomain: SwarmAuthorityDomain;
  capabilityRefs?: string[];
  roleRefs?: string[];
  elevated?: boolean;
  rootRefs?: string[];
  safeFacts?: Record<string, unknown>;
  privateRefs?: Array<Record<string, unknown>>;
  issuedAt: number;
  expiresAt?: number;
};

export type SwarmRoleRecord = {
  kind?: "swarm.role";
  roleId: string;
  role: SwarmInteractionRoleName;
  memberRef: string;
  capabilityRefs?: string[];
  authorityRefs: string[];
  issuedAt: number;
};

export type SwarmInteractionParticipant = {
  role: SwarmInteractionRoleName;
  memberRef: string;
  capabilityRefs?: string[];
  channelRefs?: string[];
  authorityRefs?: string[];
  contractView?: Record<string, unknown>;
  safeFacts?: Record<string, unknown>;
};

export type SwarmInteractionRecord = {
  kind?: "swarm.interaction";
  interactionId: string;
  contractRef: string;
  interactionKind: string;
  participants: SwarmInteractionParticipant[];
  state: SwarmInteractionState;
  capabilityRefs?: string[];
  channelRefs?: string[];
  authority?: Record<string, unknown>;
  routingScope?: RoutingScopePosture;
  safeFacts?: Record<string, unknown>;
  privateRefs?: Array<Record<string, unknown>>;
  issuedAt: number;
  expiresAt?: number;
};

export type SwarmActivationRecord = {
  kind?: "swarm.activation";
  activationId: string;
  interactionId: string;
  nodeRef: string;
  capabilityRef: string;
  requesterRef: string;
  runtimeMemberRef: string;
  state: SwarmInteractionState;
  authoritySummary: Record<string, unknown>;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type SwarmReleaseRecord = {
  kind?: "swarm.release";
  releaseId: string;
  interactionId: string;
  releasedBy: string;
  reasonCode: string;
  issuedAt: number;
};

export type SwarmRevocationRecord = {
  kind?: "swarm.revocation";
  revocationId: string;
  targetRef: string;
  issuerRef: string;
  authorityDomain: SwarmAuthorityDomain;
  reasonCode: string;
  issuedAt: number;
};

export type AgreementPlane = "actionAuthority" | "accessAuthority" | "deliveryWitness" | "materialization";
export type ActionGrantState = "requested" | "accepted" | "applied" | "rejected" | "blocked" | "expired" | "revoked";
export type AuthorityProofState = "proved" | "degraded" | "blocked" | "expired" | "revoked";
export type AuthorityProofCheckKind = "sync" | "read" | "writeReduce" | "revokeExpire";
export type RootAuthorityOperation = "addRoot" | "refreshRoot" | "rotateRoot" | "revokeRoot" | "enrollDevice" | "revokeDevice";
export type AccessEpochChangeKind = "create" | "addMember" | "removeMember" | "rotateKey" | "revokeMember" | "partitionSplit" | "partitionMerge" | "purposeKey";
export type AgreementContentClass = "safeFacts" | "safeIndex" | "uiProjection" | "encryptedDetail" | "encryptedRaw" | "mediaReference" | "diagnosticDetail";
export type AgreementPrivacyTier = "publicSafe" | "domainSafe" | "domainEncrypted" | "privateEncrypted";
export type AgreementSafeFactPolicy = "none" | "minimal" | "indexOnly" | "projectionSafe";

export type AuthorityRootOperationRecord = {
  kind?: "authority.root.operation";
  operationId: string;
  operation: RootAuthorityOperation;
  identityRef: string;
  actorRef: string;
  targetRef: string;
  adminGrantRefs: string[];
  rootRefs?: string[];
  deviceRefs?: string[];
  notificationRefs?: string[];
  evidenceRefs?: string[];
  state: ActionGrantState;
  blockedReason?: string;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type ActionAuthorityGrantRecord = {
  kind?: "authority.action.grant";
  grantId: string;
  plane?: AgreementPlane;
  issuerRef: string;
  subjectRef: string;
  audienceRefs: string[];
  authorityDomain: SwarmAuthorityDomain;
  resourceRef: string;
  action: string;
  state?: ActionGrantState;
  scope?: Record<string, unknown>;
  capabilityRefs?: string[];
  parentGrantRefs?: string[];
  revocationRefs?: string[];
  evidenceRefs?: string[];
  elevated?: boolean;
  rootRefs?: string[];
  delegation?: Record<string, unknown>;
  blockedReason?: string;
  safeFacts?: Record<string, unknown>;
  privateRefs?: Array<Record<string, unknown>>;
  issuedAt: number;
  expiresAt?: number;
};

export type ActionAuthorityExerciseRecord = {
  kind?: "authority.action.exercise";
  exerciseId: string;
  grantId: string;
  actorRef: string;
  subjectRef: string;
  resourceRef: string;
  action: string;
  state: ActionGrantState;
  evidenceRefs?: string[];
  resultRefs?: string[];
  blockedReason?: string;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  observedAt?: number;
};

export type AuthorityGrantRevocationPostureRecord = {
  kind?: "authority.grant.revocationPosture";
  revocationId: string;
  targetGrantRef: string;
  issuerRef: string;
  authorityDomain: SwarmAuthorityDomain;
  affectedGrantRefs: string[];
  affectedAccessGroupRefs?: string[];
  inheritedScopeRefs?: string[];
  state: ActionGrantState;
  reasonCode: string;
  evidenceRefs?: string[];
  issuedAt: number;
  effectiveAt?: number;
};

export type AuthorityProofCheck = {
  check: AuthorityProofCheckKind;
  plane: AgreementPlane;
  state: AuthorityProofState;
  targetRef: string;
  grantRefs?: string[];
  accessGroupRefs?: string[];
  accessEpochRefs?: string[];
  exerciseRefs?: string[];
  evidenceRefs?: string[];
  blockedReason?: string;
  expiresAt?: number;
};

export type AuthorityMultiIdentityProofRecord = {
  kind?: "authority.multiIdentity.proof";
  proofId: string;
  ownerIdentityRef: string;
  granteeIdentityRef: string;
  granteeMemberRef: string;
  subjectRefs: string[];
  actionGrantRefs: string[];
  accessGroupRefs: string[];
  accessEpochRefs?: string[];
  privateEnvelopeRefs?: string[];
  revocationRefs?: string[];
  checks: AuthorityProofCheck[];
  state?: AuthorityProofState;
  blockedReasons?: string[];
  evidenceRefs?: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type AccessGroupRecord = {
  kind?: "access.group";
  groupId: string;
  ownerRef: string;
  subjectRef: string;
  contentClasses: AgreementContentClass[];
  memberRefs: string[];
  adminRefs: string[];
  currentEpochId: string;
  partitionRefs?: string[];
  policyRefs?: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type AccessEpochRecord = {
  kind?: "access.epoch";
  epochId: string;
  groupId: string;
  sequence: number;
  changeKind: AccessEpochChangeKind;
  previousEpochId?: string;
  memberRefs: string[];
  addedMemberRefs?: string[];
  removedMemberRefs?: string[];
  partitionRefs?: string[];
  keyRef: string;
  proofRefs: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type PrivateContentEnvelopeRecord = {
  kind?: "private.content.envelope";
  envelopeId: string;
  contentClass: AgreementContentClass;
  accessGroupRef: string;
  epochId: string;
  subjectRef: string;
  issuerRef: string;
  ciphertextRef?: string;
  storageObjectRef?: string;
  detailRef?: string;
  mediaObjectRef?: string;
  caacEnvelopeRef?: string;
  recipientRefs?: string[];
  keyRef?: string;
  summarySafeFacts?: Record<string, unknown>;
  evidenceRefs?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type EventFabricAccessClassRecord = {
  kind?: "event.fabric.accessClass";
  classId: string;
  contentClass: AgreementContentClass;
  privacyTier: AgreementPrivacyTier;
  eventClasses: string[];
  accessGroupRefs: string[];
  processorRoleRefs?: string[];
  storageClass: string;
  retentionClass: string;
  safeFactPolicy: AgreementSafeFactPolicy;
  indexPolicy?: Record<string, unknown>;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
};

export type EventFabricProcessorContractRecord = {
  kind?: "event.fabric.processor.contract";
  processorContractId: string;
  fabricRef: string;
  processorRef: string;
  processorRoleRef: string;
  state: "ready" | "degraded" | "blocked" | "pending" | "expired";
  inputAccessClassRefs: string[];
  inputEventClasses: string[];
  inputContentClasses: AgreementContentClass[];
  outputRefs?: string[];
  storageRefs?: string[];
  accessGroupRefs?: string[];
  consumerFloor?: ConsumerFloor;
  materializationBudget?: MaterializationBudget;
  bitemporalPolicy?: Record<string, unknown>;
  schemaPolicy?: Record<string, unknown>;
  compactionPolicy?: Record<string, unknown>;
  cardinalityPolicy?: Record<string, unknown>;
  encryptedDetailCustody?: Record<string, unknown>;
  samplingPolicy?: Record<string, unknown>;
  safeFacts?: Record<string, unknown>;
  evidenceRefs?: string[];
  blockedReasons?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type SecurityProcessorSeedRecord = {
  kind?: "security.processor.seed";
  seedId: string;
  fabricRef: string;
  processorRef: string;
  processorRoleRef: string;
  state: "ready" | "degraded" | "blocked" | "pending" | "expired";
  threatAnalysisRole: string;
  inputAccessClassRefs: string[];
  inputEventClasses: string[];
  inputContentClasses: AgreementContentClass[];
  accessGroupRefs?: string[];
  processorContractRefs?: string[];
  evidenceProfileRefs?: string[];
  materializationBudgetRefs?: string[];
  storageRefs?: string[];
  detailRefs?: string[];
  alertOutputRefs?: string[];
  evidenceHoldRefs?: string[];
  retentionHoldRefs?: string[];
  encryptedDetailCustody?: Record<string, unknown>;
  semanticBoundaries: {
    logging: string;
    storage: string;
    eventDomain: string;
    [key: string]: unknown;
  };
  safeFacts?: Record<string, unknown>;
  evidenceRefs?: string[];
  blockedReasons?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type ProjectionSnapshot = {
  projectionId: string;
  policyId: string;
  revision: number;
  state: Record<string, unknown>;
  coverage: ProjectionCoverage;
  freshness: ProjectionFreshness;
  sourceRefs?: unknown[];
  issuedAt: number;
};

export type ProjectionDeltaOp = {
  op: "set" | "remove" | "appendUnique" | "replace";
  path: Array<string | number>;
  value?: unknown;
};

export type ProjectionDelta = {
  projectionId: string;
  policyId: string;
  baseRevision: number;
  revision: number;
  ops: ProjectionDeltaOp[];
  affectedRecords?: unknown[];
  coverage: ProjectionCoverage;
  freshness: ProjectionFreshness;
  sourceRefs?: unknown[];
  issuedAt: number;
};

export type ProjectionRepairRequest = {
  projectionId: string;
  policyId: string;
  currentRevision: number;
  requiredRevision: number;
  reason: "revisionGap";
};

export type ProjectionRepairState = "pending" | "observing" | "blocked" | "satisfied" | "expired";

export type ProjectionRepairPosture = {
  kind?: "projection.repair.posture";
  repairId: string;
  projectionId: string;
  policyId: string;
  state: ProjectionRepairState;
  currentRevision: number;
  requiredRevision: number;
  reason: string;
  coverage?: ProjectionCoverage;
  observerRef?: string;
  routePromiseId?: string;
  blockedReasons?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type SwarmEdgeBase = {
  memberKind: string;
  memberRef: string;
  zoneScope: ZoneScope;
  capabilityRefs: string[];
  channelRefs: string[];
  promiseRefs: string[];
  lastAckedFrameId?: string;
  lastProjectionRevisions: Record<string, number>;
  nonce: string;
  issuedAt: number;
  expiresAt?: number;
  sealedClaims: SwarmFrameBody;
};

export type SwarmEdgeHello = SwarmEdgeBase & {
  supportedVersions: number[];
};

export type SwarmEdgeAccept = SwarmEdgeBase & {
  sessionId: string;
  acceptedVersion: number;
};

export type SwarmEdgeResume = SwarmEdgeBase & {
  sessionId: string;
};

export type SwarmEdgeClose = SwarmEdgeBase & {
  sessionId: string;
  reasonCode: string;
};

export type StoragePinIntent = {
  intentId: string;
  objectRefs: unknown[];
  manifestHash: string;
  desiredReplicas: number;
  retention: string;
  authorityRefs: unknown[];
  expiresAt?: number;
};

export type StoragePinAttestation = {
  attestationId: string;
  intentId: string;
  storageMemberRef: string;
  acceptedRefs: unknown[];
  availabilityRefs: unknown[];
  status: string;
  expiresAt?: number;
  issuedAt: number;
};

export type StreamSessionRecord = {
  kind: string;
  sessionId: string;
  issuer: string;
  issuedAt: number;
  [key: string]: unknown;
};

export type StreamSessionLifecyclePhase =
  | "intent"
  | "admission"
  | "reject"
  | "offer"
  | "answer"
  | "candidate"
  | "control"
  | "health"
  | "close"
  | "";

export type StreamSessionLifecycleCarrierRecord = {
  recordKind: string;
  phase: StreamSessionLifecyclePhase;
  record: Record<string, unknown>;
};

export type StreamSessionIntent = {
  sessionId: string;
  capabilityRef: string;
  requesterRef: string;
  channelId: string;
  transport: string;
  issuedAt: number;
  expiresAt?: number;
};

export type StreamSessionAdmission = {
  admissionId: string;
  sessionId: string;
  capabilityRef: string;
  admittedBy: string;
  constraints?: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionReject = {
  rejectId: string;
  sessionId: string;
  capabilityRef?: string;
  rejectedBy: string;
  reasonCode: string;
  constraints?: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionOffer = {
  offerId: string;
  sessionId: string;
  transport: string;
  payload: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionAnswer = {
  answerId: string;
  sessionId: string;
  transport: string;
  payload: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionCandidate = {
  candidateId: string;
  sessionId: string;
  transport: string;
  candidateRole: "browser" | "service";
  actionability: "usable" | "blocked";
  blockedReason?: string;
  endpoint?: {
    protocol?: string;
    address?: string;
    port?: number;
    candidateType?: string;
  };
  payload: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionControl = {
  controlId: string;
  sessionId: string;
  command: string;
  params?: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionHealth = {
  healthId: string;
  sessionId: string;
  status: string;
  recovery?: Record<string, unknown>;
  issuedAt: number;
};

export type StreamSessionClose = {
  closeId: string;
  sessionId: string;
  reasonCode: string;
  issuedAt: number;
};

export type MediaFulfillmentEvidenceKind =
  | "transportState"
  | "selectedCandidatePair"
  | "inboundStats"
  | "trackState"
  | "renderState"
  | "release";

export type MediaFulfillmentState = "pending" | "usable" | "blocked" | "released";

export type MediaFulfillmentEvidence = {
  kind?: "media.fulfillment.evidence";
  evidenceId: string;
  evidenceKind: MediaFulfillmentEvidenceKind;
  state: MediaFulfillmentState;
  sessionId?: string;
  activationId?: string;
  interactionId?: string;
  correlationId?: string;
  routePromiseId?: string;
  participantRef?: string;
  adapterRef?: string;
  serviceRef?: string;
  sourceRef?: string;
  blockedReason?: string;
  safeFacts?: Record<string, unknown>;
  evidenceRefs?: string[];
  observedAt: number;
  expiresAt?: number;
};

export type MediaTransportPathState = "pending" | "actionable" | "blocked" | "released";
export type MediaTransportSelectedPairState = "pending" | "selected" | "failed" | "none";
export type MediaTransportRtpState = "pending" | "flowing" | "stalled" | "blocked" | "released";
export type MediaTransportRenderState = "pending" | "visible" | "blocked" | "released";
export type MediaTransportParticipantRole = "browser" | "service" | "gateway" | "relay" | "turn" | "runtime";
export type MediaTransportObservationState =
  | "pending"
  | "connecting"
  | "connected"
  | "disconnected"
  | "recovering"
  | "failed"
  | "closed"
  | "released"
  | "blocked";

export type MediaTransportPath = {
  kind?: "media.transport.path";
  pathId: string;
  sessionId: string;
  activationId?: string;
  routePromiseId?: string;
  transportProfileRef: string;
  browserCandidateRefs?: string[];
  serviceCandidateRefs?: string[];
  relayParticipantRefs?: string[];
  turnParticipantRefs?: string[];
  state: MediaTransportPathState;
  selectedPairState: MediaTransportSelectedPairState;
  inboundRtpState: MediaTransportRtpState;
  renderState: MediaTransportRenderState;
  blockedReason?: string;
  safeFacts?: Record<string, unknown>;
  evidenceRefs?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type MediaTransportObservation = {
  kind?: "media.transport.observation";
  observationId: string;
  pathId: string;
  sessionId: string;
  activationId?: string;
  routePromiseId?: string;
  participantRef: string;
  participantRole: MediaTransportParticipantRole;
  state: MediaTransportObservationState;
  connectionState?: string;
  iceConnectionState?: string;
  selectedPairState?: MediaTransportSelectedPairState;
  inboundRtpState?: MediaTransportRtpState;
  renderState?: MediaTransportRenderState;
  blockedReason?: string;
  reason?: string;
  safeFacts?: Record<string, unknown>;
  evidenceRefs?: string[];
  observedAt: number;
  expiresAt?: number;
};

export type SurfaceModuleRole =
  | "runtimeClient"
  | "projectionModel"
  | "platformAdapter"
  | "serviceSurfaceAdapter"
  | "productView"
  | "operatorHelper"
  | "releaseHelper";

export type SurfaceModuleParticipantSide = "window" | "runtime" | "service" | "operator" | "native" | "storage";
export type SurfaceModuleFulfillmentMode = "bundled" | "swarmPackage" | "storageObject" | "nativeInstalled" | "devOverlay";
export type SurfaceAppUpdatePostureState = "static" | "compatible" | "updateAvailable" | "blocked";
export type SurfaceAppManifestVersionState = "current" | "compatible" | "updateAvailable" | "blocked" | "superseded";
export type SurfaceAppBootstrapPostureState = "static" | "ready" | "degraded" | "blocked" | "unavailable";
export type ServiceManagerPostureState = "manual" | "ready" | "degraded" | "blocked" | "unavailable";
export type ServiceManagerOperation =
  | "install"
  | "update"
  | "start"
  | "stop"
  | "restart"
  | "rollback"
  | "healthCheck"
  | "promote";
export type ServiceManagerOperationState =
  | "requested"
  | "accepted"
  | "running"
  | "succeeded"
  | "failed"
  | "blocked"
  | "cancelled"
  | "superseded";
export type ServiceManagerProofState = "pending" | "proved" | "failed" | "blocked" | "expired";
export type SurfaceSecretBoundaryState = "notRequired" | "resolved" | "blocked" | "unavailable";
export type SurfaceReleasePostureState = "static" | "buildReady" | "releaseReady" | "rollbackReady" | "blocked" | "unavailable";
export type ServiceManagerContractState = "draft" | "ready" | "blocked" | "superseded" | "expired";
export type ServiceManagerProofProfile =
  | "surfaceLandscape"
  | "nvrLive30s"
  | "longStream10m"
  | "loggingPressure"
  | "directEdge"
  | "nativeChecks";

export type SurfaceModuleClaim = {
  moduleRef: string;
  role: SurfaceModuleRole;
  participantSide: SurfaceModuleParticipantSide;
  fulfillmentMode: SurfaceModuleFulfillmentMode;
  primitiveRefs: string[];
  version: string;
  buildId?: string;
  requiredCapabilities?: string[];
  sandbox?: Record<string, unknown>;
  inputs?: string[];
  outputs?: string[];
  evidenceContract?: Record<string, unknown>;
  lifecycle?: Record<string, unknown>;
  materializationBudgetRef?: string;
  fallbackRefs?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type SurfaceAppContract = {
  contractId: string;
  schemaVersion: 1;
  appId: string;
  version: string;
  displayName: string;
  serviceRef?: string;
  appRef?: string;
  surfaceRef?: string;
  requiredPrimitives?: string[];
  requiredModuleRoles: SurfaceModuleRole[];
  modules: SurfaceModuleClaim[];
  projectionSubscriptions?: unknown[];
  permissionRequirements?: unknown[];
  capabilityRequirements?: unknown[];
  materializationBudgets?: MaterializationBudget[];
  fallbackPolicy?: Record<string, unknown>;
  updatePosture?: { state?: SurfaceAppUpdatePostureState; [key: string]: unknown };
  secretBoundary?: SurfaceSecretBoundary;
  releasePosture?: SurfaceReleasePosture;
  rollbackPosture?: SurfaceReleasePosture;
  serviceManagerPosture?: ServiceManagerPosture;
  bootstrapPosture?: SurfaceAppBootstrapPosture;
  issuedAt: number;
  expiresAt?: number;
};

export type SurfaceSecretBoundary = {
  state: SurfaceSecretBoundaryState;
  secretRefs?: string[];
  authorityRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  [key: string]: unknown;
};

export type SurfaceReleasePosture = {
  state: SurfaceReleasePostureState;
  buildRef?: string;
  releaseRef?: string;
  rollbackRef?: string;
  evidenceRefs?: string[];
  blockedReasons?: string[];
  [key: string]: unknown;
};

export type ServiceManagerSecretBoundary = {
  kind?: "service.manager.secretBoundary";
  boundaryId: string;
  managerId: string;
  subjectRef: string;
  state: SurfaceSecretBoundaryState;
  secretRefs?: string[];
  accessGroupRefs?: string[];
  authorityRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type ServiceManagerReleaseContract = {
  kind?: "service.manager.release.contract";
  contractId: string;
  managerId: string;
  subjectRef: string;
  managerRef: string;
  state: ServiceManagerContractState;
  appContractRef?: string;
  version?: string;
  buildRef?: string;
  releaseRef?: string;
  rollbackRef?: string;
  rollbackRequired?: boolean;
  compatibilityRefs?: string[];
  authorityRefs?: string[];
  secretBoundaryRefs?: string[];
  proofDigestRefs?: string[];
  labProofRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  secretBoundary?: SurfaceSecretBoundary;
  releasePosture?: SurfaceReleasePosture;
  rollbackPosture?: SurfaceReleasePosture;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type ServiceManagerLabProof = {
  kind?: "service.manager.labProof";
  proofId: string;
  managerId: string;
  subjectRef: string;
  profile: ServiceManagerProofProfile;
  state: ServiceManagerProofState;
  trainRef?: string;
  releaseContractRef?: string;
  appContractRef?: string;
  surfaceRefs?: string[];
  serviceRefs?: string[];
  environmentRefs?: string[];
  artifactRefs?: string[];
  metricsRefs?: string[];
  proofRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  safeFacts?: Record<string, unknown>;
  startedAt: number;
  acceptedAt?: number;
  completedAt?: number;
  observedAt?: number;
  expiresAt?: number;
};

export type ServiceManagerTrainDigest = {
  kind?: "service.manager.train.digest";
  trainId: string;
  managerId: string;
  subjectRef: string;
  state: ServiceManagerProofState;
  repoRefs?: string[];
  commitRefs?: string[];
  appContractRefs?: string[];
  releaseContractRefs?: string[];
  operationRefs?: string[];
  proofDigestRefs?: string[];
  labProofRefs?: string[];
  metricsRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  safeFacts?: Record<string, unknown>;
  observedAt: number;
  expiresAt?: number;
};

export type SurfaceAppBootstrapContract = {
  kind?: "surface.app.bootstrap.contract";
  bootstrapContractId: string;
  appContractRef: string;
  appId: string;
  state: ServiceManagerContractState;
  sourceMode: SurfaceModuleFulfillmentMode;
  moduleRefs?: string[];
  serviceManagerRef?: string;
  releaseContractRef?: string;
  secretBoundaryRef?: string;
  trainDigestRef?: string;
  labProofProfileRefs?: string[];
  authorityRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  secretBoundary?: SurfaceSecretBoundary;
  releaseContract?: ServiceManagerReleaseContract;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type SurfaceAppManifestVersion = {
  appContractRef: string;
  version: string;
  state: SurfaceAppManifestVersionState;
  sourceMode?: SurfaceModuleFulfillmentMode;
  moduleRefs?: string[];
  compatibilityRefs?: string[];
  bootstrapContractRef?: string;
  releaseContractRef?: string;
  authorityRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
};

export type SurfaceAppManifest = {
  kind?: "surface.app.manifest";
  manifestId: string;
  appId: string;
  state?: SurfaceAppManifestVersionState;
  currentAppContractRef: string;
  currentVersion: string;
  defaultSourceMode?: SurfaceModuleFulfillmentMode;
  versions: SurfaceAppManifestVersion[];
  appContractRefs?: string[];
  compatibilityRefs?: string[];
  bootstrapContractRefs?: string[];
  releaseContractRefs?: string[];
  authorityRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  secretBoundary?: SurfaceSecretBoundary;
  releasePosture?: SurfaceReleasePosture;
  safeFacts?: Record<string, unknown>;
  issuedAt: number;
  expiresAt?: number;
};

export type ServiceManagerPosture = {
  kind?: "service.manager.posture";
  managerId: string;
  subjectRef: string;
  managerRef: string;
  state: ServiceManagerPostureState;
  serviceRefs?: string[];
  capabilityRefs?: string[];
  operationRefs?: string[];
  proofDigestRefs?: string[];
  secretBoundary?: SurfaceSecretBoundary;
  releasePosture?: SurfaceReleasePosture;
  rollbackPosture?: SurfaceReleasePosture;
  evidenceRefs?: string[];
  blockedReasons?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type ServiceManagerOperationPosture = {
  kind?: "service.manager.operation.posture";
  operationId: string;
  managerId: string;
  subjectRef: string;
  managerRef: string;
  requesterRef: string;
  operation: ServiceManagerOperation;
  state: ServiceManagerOperationState;
  serviceRefs?: string[];
  capabilityRefs?: string[];
  authorityRefs?: string[];
  releaseRef?: string;
  rollbackRef?: string;
  secretBoundary?: SurfaceSecretBoundary;
  evidenceRefs?: string[];
  proofRefs?: string[];
  blockedReasons?: string[];
  safeFacts?: Record<string, unknown>;
  requestedAt: number;
  acceptedAt?: number;
  startedAt?: number;
  completedAt?: number;
  observedAt?: number;
  expiresAt?: number;
};

export type ServiceManagerProofDigest = {
  kind?: "service.manager.proof.digest";
  digestId: string;
  operationId: string;
  managerId: string;
  subjectRef: string;
  state: ServiceManagerProofState;
  trainRef?: string;
  releaseRef?: string;
  rollbackRef?: string;
  commitRefs?: string[];
  artifactRefs?: string[];
  proofRefs?: string[];
  metricsRefs?: string[];
  environmentRefs?: string[];
  serviceRefs?: string[];
  evidenceRefs?: string[];
  blockedReasons?: string[];
  safeFacts?: Record<string, unknown>;
  observedAt: number;
  expiresAt?: number;
};

export type SurfaceAppBootstrapPosture = {
  kind?: "surface.app.bootstrap.posture";
  bootstrapId: string;
  contractId: string;
  appId: string;
  state: SurfaceAppBootstrapPostureState;
  sourceMode?: SurfaceModuleFulfillmentMode;
  moduleRefs?: string[];
  serviceManagerRef?: string;
  serviceManagerPosture?: ServiceManagerPosture;
  secretBoundary?: SurfaceSecretBoundary;
  releasePosture?: SurfaceReleasePosture;
  rollbackPosture?: SurfaceReleasePosture;
  evidenceRefs?: string[];
  blockedReasons?: string[];
  issuedAt: number;
  expiresAt?: number;
};

export type AppRecipe = {
  recipeId: string;
  name: string;
  requiredCapabilities: string[];
  requiredChannels: unknown[];
  roles: unknown[];
};

export type AppRunnerAdvertisement = {
  runnerId: string;
  memberRef: string;
  version: string;
  capacity: Record<string, unknown>;
  health: Record<string, unknown>;
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
export function buildBootstrapNostrUnsignedEvent(input: Partial<BootstrapNostrUnsignedEvent>): BootstrapNostrUnsignedEvent;
export function bootstrapNostrEventIdHex(unsigned: BootstrapNostrUnsignedEvent): string;
export function signBootstrapNostrEvent(unsigned: BootstrapNostrUnsignedEvent, secretKeyHex: string): BootstrapNostrEvent;
export function verifyBootstrapNostrEvent(event: BootstrapNostrEvent): boolean;
export function buildBootstrapNostrEvent(input: Record<string, unknown>): BootstrapNostrEvent;
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
export function assertLogEvidenceProfile(profile: unknown): LogEvidenceProfile;
export function assertEncryptedDetailRef(ref: unknown, context?: string): EncryptedDetailRef;
export function makeLogEventEnvelope(input: Partial<LogEventEnvelope>): LogEventEnvelope;
export function rejectUnsafeSafeFacts(value: unknown): void;
export function assertHostedServiceDescriptor(descriptor: unknown): HostedServiceDescriptor;
export function assertServiceLocationRef(location: unknown): ServiceLocationRef;
export function assertServiceNodeFieldDescriptor(field: unknown): ServiceNodeFieldDescriptor;
export function assertServiceNodeDescriptor(node: unknown): ServiceNodeDescriptor;
export function assertServiceSurfaceProjection(surface: unknown): ServiceSurfaceProjection;
export function findServiceNode(surface: Partial<ServiceSurfaceProjection>, nodePath: string): ServiceNodeDescriptor | undefined;
export function assertServiceAttachDescriptor(attach: unknown): ServiceAttachDescriptor;
export function assertServiceNodeProjectionRecord(record: unknown, surface: ServiceSurfaceProjection): ServiceNodeProjectionRecord;
export function assertServiceNodeSetRequest(request: unknown, surface: ServiceSurfaceProjection): ServiceNodeSetRequest;
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
export function assertResolvedMemberRef(value: unknown, name?: string): string;
export function assertCapabilityName(name: unknown): string;
export function assertZoneScope(scope: unknown): ZoneScope;
export function assertRoutingScopePosture(posture: unknown, name?: string): RoutingScopePosture;
export function assertParticipantRunlevelPosture(record: unknown): ParticipantRunlevelPosture;
export function assertSelfCapabilityAssessment(record: unknown): SelfCapabilityAssessment;
export function assertResourceProfile(record: unknown): ResourceProfile;
export function assertResourcePosture(record: unknown): ResourcePosture;
export function assertIngressLanePosture(record: unknown): IngressLanePosture;
export function eventPlaneForRecordKind(kind: unknown, context?: { kind?: unknown; recordKind?: unknown; channelRef?: unknown; channelId?: unknown; capabilityRef?: unknown; capability?: unknown }): EventPlane;
export function assertEventAdmissionEnvelope(record: unknown): EventAdmissionEnvelope;
export function assertSubscriptionContract(record: unknown): SubscriptionContract;
export function assertConsumerFloor(record: unknown): ConsumerFloor;
export function assertMaterializationBudget(record: unknown): MaterializationBudget;
export function assertProjectionRepairPosture(record: unknown): ProjectionRepairPosture;
export function assertRetentionReleasePosture(record: unknown): RetentionReleasePosture;
export function assertContributionLifecycle(record: unknown, context?: string): ContributionLifecycle;
export function assertSwarmFrameBody(body: unknown, frameKind?: string): SwarmFrameBody;
export function swarmFrameId(frame: Partial<SwarmFrame>): string;
export function assertSwarmFrame(frame: unknown, opts?: { now?: number }): SwarmFrame;
export function makeSwarmFrame(input: Partial<SwarmFrame> & { now?: number }): SwarmFrame;
export function assertChannelDescriptor(record: unknown): ChannelDescriptor;
export function assertChannelMembership(record: unknown): ChannelMembership;
export function assertCapabilityDefinition(record: unknown): CapabilityDefinition;
export function assertCapabilityAdvertisement(record: unknown, opts?: { now?: number }): CapabilityAdvertisement;
export function assertNodeCapability(record: unknown, opts?: { now?: number }): NodeCapability;
export function assertRuntimeActivationRequest(record: unknown): RuntimeActivationRequest;
export function assertRoutePromise(record: unknown): RoutePromise;
export function assertLocalRouteBinding(record: unknown): LocalRouteBinding;
export function assertRouteObservation(record: unknown): RouteObservation;
export function assertStreamRoutePlan(record: unknown): StreamRoutePlan;
export function assertMemberPresence(record: unknown, opts?: { now?: number }): MemberPresence;
export function assertDirectoryEntry(record: unknown): DirectoryEntry;
export function assertServiceRegistryClaim(record: unknown): ServiceRegistryClaim;
export function assertServiceRegistryMaterialization(record: unknown): ServiceRegistryMaterialization;
export function assertBootstrapCarrierRecord(record: unknown): BootstrapCarrierRecord;
export function assertSwarmIdentity(record: unknown): SwarmIdentityRecord;
export function assertSwarmDevice(record: unknown): SwarmDeviceRecord;
export function assertSwarmGateway(record: unknown): SwarmGatewayRecord;
export function assertSwarmService(record: unknown): SwarmServiceRecord;
export function assertSwarmMember(record: unknown): SwarmMemberRecord;
export function assertSwarmGrant(record: unknown): SwarmGrantRecord;
export function assertSwarmRole(record: unknown): SwarmRoleRecord;
export function assertSwarmInteraction(record: unknown): SwarmInteractionRecord;
export function assertSwarmActivation(record: unknown): SwarmActivationRecord;
export function assertSwarmRelease(record: unknown): SwarmReleaseRecord;
export function assertSwarmRevocation(record: unknown): SwarmRevocationRecord;
export function assertAuthorityRootOperation(record: unknown): AuthorityRootOperationRecord;
export function assertActionAuthorityGrant(record: unknown): ActionAuthorityGrantRecord;
export function assertActionAuthorityExercise(record: unknown): ActionAuthorityExerciseRecord;
export function assertAuthorityGrantRevocationPosture(record: unknown): AuthorityGrantRevocationPostureRecord;
export function assertAuthorityMultiIdentityProof(record: unknown): AuthorityMultiIdentityProofRecord;
export function assertAccessGroup(record: unknown): AccessGroupRecord;
export function assertAccessEpoch(record: unknown): AccessEpochRecord;
export function assertPrivateContentEnvelope(record: unknown): PrivateContentEnvelopeRecord;
export function assertEventFabricAccessClass(record: unknown): EventFabricAccessClassRecord;
export function assertEventFabricProcessorContract(record: unknown): EventFabricProcessorContractRecord;
export function assertSecurityProcessorSeed(record: unknown): SecurityProcessorSeedRecord;
export function assertSwarmIdentityGraph(records: unknown): unknown[];
export function assertCaacEnvelopeForMode(envelope: unknown, opts?: { mode?: string; now?: number }): CaacEnvelope | Record<string, unknown>;
export function buildCapabilityDirectoryProjection(input?: {
  definitions?: CapabilityDefinition[];
  advertisements?: CapabilityAdvertisement[];
  entries?: Record<string, unknown>[];
  now?: number;
}): Record<string, unknown>;
export function assertProjectionSnapshot(snapshot: unknown): ProjectionSnapshot;
export function assertProjectionDelta(delta: unknown): ProjectionDelta;
export function assertProjectionDeltaOp(op: unknown): ProjectionDeltaOp;
export function makeProjectionRepairRequest(input?: Partial<ProjectionRepairRequest>): ProjectionRepairRequest;
export function applyProjectionDelta(input?: {
  state?: Record<string, unknown>;
  revision?: number;
  delta: ProjectionDelta;
}): { state: Record<string, unknown>; revision: number; changed: boolean; repairRequest?: ProjectionRepairRequest };
export function assertSwarmEdgeHello(record: unknown): SwarmEdgeHello;
export function assertSwarmEdgeAccept(record: unknown): SwarmEdgeAccept;
export function assertSwarmEdgeResume(record: unknown): SwarmEdgeResume;
export function assertSwarmEdgeClose(record: unknown): SwarmEdgeClose;
export function assertStoragePinIntent(record: unknown): StoragePinIntent;
export function assertStoragePinAttestation(record: unknown): StoragePinAttestation;
export function deriveStoragePinProjection(input?: {
  intent: StoragePinIntent;
  attestations?: StoragePinAttestation[];
  now?: number;
}): Record<string, unknown>;
export function assertStreamSessionRecord(record: unknown): StreamSessionRecord;
export function streamSessionLifecycleRecordKind(source: unknown): string;
export function streamSessionLifecyclePhase(source: unknown): StreamSessionLifecyclePhase;
export function streamSessionLifecycleRecordFromCarrier(source: unknown): StreamSessionLifecycleCarrierRecord | null;
export function assertStreamSessionIntent(record: unknown): StreamSessionIntent;
export function assertStreamSessionAdmission(record: unknown): StreamSessionAdmission;
export function assertStreamSessionReject(record: unknown): StreamSessionReject;
export function assertStreamSessionOffer(record: unknown): StreamSessionOffer;
export function assertStreamSessionAnswer(record: unknown): StreamSessionAnswer;
export function assertStreamSessionCandidate(record: unknown): StreamSessionCandidate;
export function assertStreamSessionControl(record: unknown): StreamSessionControl;
export function assertStreamSessionHealth(record: unknown): StreamSessionHealth;
export function assertStreamSessionClose(record: unknown): StreamSessionClose;
export function assertMediaFulfillmentEvidence(record: unknown): MediaFulfillmentEvidence;
export function assertMediaTransportPath(record: unknown): MediaTransportPath;
export function assertMediaTransportObservation(record: unknown): MediaTransportObservation;
export function assertSurfaceModuleClaim(record: unknown): SurfaceModuleClaim;
export function assertSurfaceAppContract(record: unknown): SurfaceAppContract;
export function assertSurfaceAppManifest(record: unknown): SurfaceAppManifest;
export function assertServiceManagerPosture(record: unknown): ServiceManagerPosture;
export function assertServiceManagerSecretBoundary(record: unknown): ServiceManagerSecretBoundary;
export function assertServiceManagerReleaseContract(record: unknown): ServiceManagerReleaseContract;
export function assertServiceManagerLabProof(record: unknown): ServiceManagerLabProof;
export function assertServiceManagerTrainDigest(record: unknown): ServiceManagerTrainDigest;
export function assertServiceManagerOperationPosture(record: unknown): ServiceManagerOperationPosture;
export function assertServiceManagerProofDigest(record: unknown): ServiceManagerProofDigest;
export function assertSurfaceAppBootstrapContract(record: unknown): SurfaceAppBootstrapContract;
export function assertSurfaceAppBootstrapPosture(record: unknown): SurfaceAppBootstrapPosture;
export function assertAppRecipe(record: unknown): AppRecipe;
export function assertAppRunnerAdvertisement(record: unknown): AppRunnerAdvertisement;
