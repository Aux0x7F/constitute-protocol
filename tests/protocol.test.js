import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  BROKER,
  DIAGNOSTICS,
  AGREEMENT,
  APP,
  LOGGING,
  FABRIC,
  PROJECTION,
  RUNNER,
  ReplayCache,
  SERVICE_SURFACE,
  SERVICE_REGISTRY,
  SURFACE_APP,
  STORAGE,
  STREAM_SESSION_LIFECYCLE_PHASE,
  SWARM,
  applyProjectionDelta,
  assertAppRecipe,
  assertAppRunnerAdvertisement,
  assertAppRunnerFulfillmentReport,
  assertAppRunnerFulfillmentLifecycle,
  assertContractTarget,
  assertContractTargetRegistryPosture,
  assertContentIndexRefPosture,
  assertContractIntentionPosture,
  assertAssociationBoundaryProof,
  assertHostFabricFulfillmentPlan,
  assertHostFabricMemberContribution,
  assertLifecyclePlanPosture,
  assertRunnerHostFulfillmentPosture,
  assertRunnerOperation,
  assertSubstrateAssociationHandoff,
  assertUniqueEdgeClassification,
  assertCapabilityAdvertisement,
  assertCapabilityDefinition,
  assertCapabilityName,
  assertBootstrapCarrierRecord,
  assertCaacEnvelopeForMode,
  assertChannelDescriptor,
  assertChannelMembership,
  assertDirectoryEntry,
  assertLocalRouteBinding,
  assertMaterializationBudget,
  assertMemberPresence,
  assertNodeCapability,
  assertParticipantRunlevelPosture,
  assertIngressLanePosture,
  assertEventAdmissionEnvelope,
  assertProjectionRepairPosture,
  assertResourcePosture,
  assertResourceProfile,
  assertRetentionReleasePosture,
  assertSubscriptionContract,
  assertStorageChunkRef,
  assertStorageObjectManifest,
  assertStorageIndexShard,
  assertStoragePinAttestation,
  assertStoragePinIntent,
  assertLogEventEnvelope,
  assertLogEvidenceProfile,
  assertDiagnosticEvent,
  assertHostedServiceDescriptor,
  assertProjectionDelta,
  assertProjectionSnapshot,
  assertProjectionCoverage,
  assertProjectionObserverUpdate,
  assertProjectionPolicy,
  assertProjectionRecord,
  assertResolvedMemberRef,
  assertRouteObservation,
  assertRoutePromise,
  assertServiceNodeProjectionRecord,
  assertServiceNodeSetRequest,
  assertServiceSurfaceProjection,
  assertServiceRegistryClaim,
  assertServiceRegistryMaterialization,
  assertServiceProjectionRequest,
  assertRuntimeActivationRequest,
  assertRoutingScopePosture,
  assertSelfCapabilityAssessment,
  assertStreamRoutePlan,
  assertStreamSessionAnswer,
  assertStreamSessionAdmission,
  assertStreamSessionCandidate,
  assertStreamSessionClose,
  assertStreamSessionControl,
  assertStreamSessionHealth,
  assertStreamSessionIntent,
  assertStreamSessionOffer,
  assertStreamSessionReject,
  assertStreamSessionRecord,
  streamSessionLifecycleRecordFromCarrier,
  streamSessionLifecyclePhase,
  streamSessionLifecycleRecordKind,
  assertMediaFulfillmentEvidence,
  assertMediaTransportPath,
  assertMediaTransportObservation,
  assertAppActivity,
  assertAppContract,
  assertAppModuleRole,
  assertAppRelease,
  assertAppReleaseResolution,
  assertAppActivityDependency,
  assertMessagingContract,
  assertCommunicationsModerationContract,
  assertServiceManagerPosture,
  assertServiceManagerSecretBoundary,
  assertServiceManagerReleaseContract,
  assertServiceManagerLabProof,
  assertServiceManagerTrainDigest,
  assertServiceManagerOperationPosture,
  assertServiceManagerProofDigest,
  assertSurfaceAppManifest,
  assertSurfaceAppManifestSelection,
  assertSurfaceAppSourceCandidatePosture,
  assertSurfaceAppManifestRunnerPlan,
  assertSurfaceAppRuntimeSelectionPosture,
  assertSurfaceAppServiceManagerActionability,
  assertSurfaceAppInstancePosture,
  assertSurfaceAdapterLifecyclePosture,
  assertSurfaceAppFulfillmentIdentityPosture,
  assertSurfaceAppAuthorityAccessPosture,
  assertSurfaceAppRunnerPlan,
  assertSurfaceAppDistributionPosture,
  assertSurfaceAppBootstrapContract,
  assertSurfaceAppBootstrapPosture,
  assertSurfaceModuleRolePosture,
  assertSurfaceAppModuleBindingPosture,
  assertServiceEdgeAdapterPosture,
  assertSurfaceAppContract,
  assertSurfaceModuleClaim,
  assertAccessEpoch,
  assertAccessGroup,
  assertActionAuthorityExercise,
  assertActionAuthorityGrant,
  assertAuthorityGrantRevocationPosture,
  assertAuthorityMultiIdentityProof,
  assertAuthorityRootOperation,
  assertConsumerFloor,
  assertContributionLifecycle,
  assertEventFabricAccessClass,
  assertEventFabricProcessorContract,
  assertEventFabricProcessorReport,
  assertCybersecProcessorSeed,
  assertCybersecFinding,
  assertCybersecEvidenceHold,
  assertCybersecMitigationRecommendation,
  assertCybersecMitigationConsumerPosture,
  assertHardeningSignalObservation,
  assertServiceHardeningPosture,
  assertNetworkExposurePosture,
  assertEvidenceRequestPosture,
  assertPrivateContentEnvelope,
  assertSwarmActivation,
  assertSwarmDevice,
  assertSwarmEdgeAccept,
  assertSwarmEdgeClose,
  assertSwarmEdgeHello,
  assertSwarmEdgeResume,
  assertSwarmFrame,
  assertSwarmGateway,
  assertSwarmGrant,
  assertSwarmIdentity,
  assertSwarmIdentityGraph,
  assertSwarmInteraction,
  assertSwarmMember,
  assertSwarmRelease,
  assertSwarmRevocation,
  assertSwarmRole,
  assertSwarmService,
  assertZoneScope,
  buildCapabilityDirectoryProjection,
  bootstrapNostrEventIdHex,
  buildBootstrapNostrUnsignedEvent,
  deriveStoragePinProjection,
  makeStorageChunkRef,
  makeStorageObjectManifest,
  makeLogEventEnvelope,
  makeProjectionCoverage,
  makeProjectionObserverUpdate,
  makeProjectionPolicy,
  makeSwarmFrame,
  makeProjectionRecord,
  openEnvelope,
  pubkeyFromSecretKey,
  sealEnvelope,
  storageCiphertextHash,
  storageObjectId,
  signBootstrapNostrEvent,
  verifyEnvelopeSignature,
  verifyBootstrapNostrEvent,
  eventPlaneForRecordKind,
} from "../src/index.js";

const ISSUER_SK = "0000000000000000000000000000000000000000000000000000000000000001";
const GATEWAY_SK = "0000000000000000000000000000000000000000000000000000000000000002";
const SERVICE_SK = "0000000000000000000000000000000000000000000000000000000000000003";
const BROWSER_SK = "0000000000000000000000000000000000000000000000000000000000000004";
const GATEWAY_PK = pubkeyFromSecretKey(GATEWAY_SK);
const SERVICE_PK = pubkeyFromSecretKey(SERVICE_SK);
const BROWSER_PK = pubkeyFromSecretKey(BROWSER_SK);

test("bootstrap nostr carrier sign/verify roundtrip matches the shared id vector", () => {
  const pk = pubkeyFromSecretKey(ISSUER_SK);
  const unsigned = buildBootstrapNostrUnsignedEvent({
    pubkey: pk,
    kind: 1111,
    tags: [["t", "constitute"]],
    content: "{\"ok\":true}",
    created_at: 1700000000,
  });
  assert.equal(bootstrapNostrEventIdHex(unsigned), "79893099e8d1dae52109e57cd6fa2c4eef5257d6779dad8107c708a64ef0e9ad");
  const event = signBootstrapNostrEvent(unsigned, ISSUER_SK);
  assert.equal(verifyBootstrapNostrEvent(event), true);
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
    kind: "capability.bootstrap",
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

test("event plane classifier separates primitive posture from local diagnostics", () => {
  assert.equal(eventPlaneForRecordKind("runtime.authority.device.ready"), SWARM.EVENT_PLANE.AUTHORITY);
  assert.equal(eventPlaneForRecordKind("projection.repair.request"), SWARM.EVENT_PLANE.PROJECTION_REPAIR);
  assert.equal(eventPlaneForRecordKind("projection.applied"), SWARM.EVENT_PLANE.PROJECTION);
  assert.equal(eventPlaneForRecordKind("stream.session.answer"), SWARM.EVENT_PLANE.ACTIVATION);
  assert.equal(eventPlaneForRecordKind("app.runner.fulfillment.report"), SWARM.EVENT_PLANE.ACTIVATION);
  assert.equal(eventPlaneForRecordKind("route.observation"), SWARM.EVENT_PLANE.ROUTE);
  assert.equal(eventPlaneForRecordKind("contribution.lifecycle.applied"), SWARM.EVENT_PLANE.CONTRIBUTION);
  assert.equal(eventPlaneForRecordKind("runtime.retention.release.blocked"), SWARM.EVENT_PLANE.RETENTION);
  assert.equal(eventPlaneForRecordKind("", { channelId: "logging.events" }), SWARM.EVENT_PLANE.LOGGING_REPLAY);
  assert.equal(eventPlaneForRecordKind("runtime.misc"), SWARM.EVENT_PLANE.DIAGNOSTIC);
});

test("sealed envelope rejects expiry, tamper, and replay", () => {
  const gatewayPk = pubkeyFromSecretKey(GATEWAY_SK);
  const envelope = sealEnvelope({
    kind: "capability.request",
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

test("exports projection and service-surface broker vocabulary without retired service route paths", () => {
  assert.equal(BROKER.SERVICE_CATALOG_GET, "service.catalog.get");
  assert.equal(BROKER.SERVICE_NODE_GET, "service.node.get");
  assert.equal(BROKER.SERVICE_NODE_POLICY_PUT, "service.node.policy.put");
  assert.equal(BROKER.PROJECTION_GET, "projection.get");
  assert.equal(BROKER.PROJECTION_PUT, "projection.put");
  assert.equal(BROKER[["SERVICE", "ACCESS", "REQUEST"].join("_")], undefined);
  assert.equal(BROKER[["SERVICE", "SIGNAL", "REQUEST"].join("_")], undefined);
  assert.equal(BROKER.SERVICE_PROJECTION_REQUEST, undefined);
});

test("service projection helpers validate retained logging projection records", () => {
  const descriptor = assertHostedServiceDescriptor({
    service: "logging",
    servicePk: pubkeyFromSecretKey(SERVICE_SK),
    hostGatewayPk: pubkeyFromSecretKey(GATEWAY_SK),
    aliases: ["Logging"],
    location: {
      locationId: "lab-gateway",
      label: "Lab Gateway",
      gatewayPk: pubkeyFromSecretKey(GATEWAY_SK),
    },
    surfaceChannel: "logging.surface",
    display: { name: "Constitute Logging" },
    summary: "Structured safe event observation.",
    health: { status: "ok" },
    nodes: ["events", "health", "dashboard", "settings"],
  });

  const policy = makeProjectionPolicy({
    policyId: "logging.default.72h.low",
    channelId: PROJECTION.CHANNEL.LOGGING_EVENTS,
    service: "logging",
    scope: { range: "rolling" },
    rollingWindowHours: 72,
    maxVerbosityClass: LOGGING.VERBOSITY_CLASS.NORMAL,
    minSeverity: LOGGING.SEVERITY.DEBUG,
    excludedVerbosityClasses: [LOGGING.VERBOSITY_CLASS.NOISE],
    syncDepthTarget: { mode: "policyComplete" },
    retentionTarget: { normalInfo: "48h" },
  });
  assertProjectionPolicy(policy, descriptor);

  const request = {
    requestId: "projection-1",
    channelId: PROJECTION.CHANNEL.LOGGING_EVENTS,
    service: "logging",
    limit: 100,
    filters: {
      severity: "error",
    },
    policy,
  };
  assertServiceProjectionRequest(request, descriptor);

  const result = makeProjectionRecord({
    channelId: request.channelId,
    service: "logging",
    servicePk: descriptor.servicePk,
    producer: { service: "logging" },
    cursor: {
      value: "cursor-1",
      updatedAt: 1700000000,
    },
    freshness: {
      state: PROJECTION.FRESHNESS.FRESH,
      updatedAt: 1700000000,
      staleAfter: 1700000030,
    },
    payload: {
      events: [],
      coverage: makeProjectionCoverage({
        materializedCount: 0,
        targetCount: 0,
        completionRatio: 1,
        syncState: PROJECTION.SYNC_STATE.COMPLETE_ENOUGH,
      }),
    },
    safeFacts: {
      count: 0,
    },
  });
  assertProjectionRecord(result, descriptor);

  const observerUpdate = makeProjectionObserverUpdate({
    projectionKey: "logging:service-pk:logging.events:logging.default.72h.low",
    changedCount: 0,
    coverage: result.payload.coverage,
    freshness: result.freshness,
  });
  assertProjectionCoverage(observerUpdate.coverage);
  assertProjectionObserverUpdate(observerUpdate);

  assert.doesNotThrow(() => assertServiceProjectionRequest({
    ...request,
    channelId: "logging.raw",
    policy: undefined,
  }, descriptor));
  assert.throws(() => assertServiceProjectionRequest({
    ...request,
    channelId: "logging.raw",
    policy: undefined,
  }, { allowedProjectionChannels: [PROJECTION.CHANNEL.LOGGING_HEALTH] }), /unsupported projection channel/);

  assert.throws(() => assertDiagnosticEvent({
    diagnosticId: "diag-1",
    schemaVersion: DIAGNOSTICS.SCHEMA_VERSION,
    occurredAt: 1700000000,
    level: DIAGNOSTICS.LEVEL.ERROR,
    operation: "logging-ui.projection.failed",
    safeFacts: { privateToken: "secret" },
  }), /unsafe safe fact key/);
});

test("service surface helpers validate node projections and settable fields", () => {
  const gatewayPk = pubkeyFromSecretKey(GATEWAY_SK);
  const servicePk = pubkeyFromSecretKey(SERVICE_SK);
  const surface = assertServiceSurfaceProjection({
    surfaceId: "logging.surface",
    schemaVersion: SERVICE_SURFACE.SCHEMA_VERSION,
    service: "logging",
    servicePk,
    hostGatewayPk: gatewayPk,
    location: {
      locationId: "lab-gateway",
      label: "Lab Gateway",
      gatewayPk,
    },
    aliases: ["Logging"],
    summary: "Structured safe event observation.",
    healthNode: "health",
    updatedAt: 1700000000,
    nodes: [
      {
        nodeId: "logging.health",
        path: "health",
        label: "Health",
        backingChannel: "logging.health",
        fields: [
          {
            fieldId: "status",
            label: "Status",
            valueKind: "string",
            capabilities: [
              SERVICE_SURFACE.FIELD_CAPABILITY.READ,
              SERVICE_SURFACE.FIELD_CAPABILITY.OBSERVE,
            ],
          },
        ],
      },
      {
        nodeId: "logging.settings",
        path: "settings",
        label: "Settings",
        backingChannel: "logging.settings",
        fields: [
          {
            fieldId: "verbosity",
            label: "Verbosity",
            valueKind: "string",
            capabilities: [
              SERVICE_SURFACE.FIELD_CAPABILITY.READ,
              SERVICE_SURFACE.FIELD_CAPABILITY.OBSERVE,
              SERVICE_SURFACE.FIELD_CAPABILITY.SET,
            ],
          },
        ],
      },
    ],
  });

  assertServiceNodeProjectionRecord({
    requestId: "node-1",
    nodePath: "health",
    service: "logging",
    servicePk,
    producer: { service: "logging" },
    freshness: { state: PROJECTION.FRESHNESS.FRESH, updatedAt: 1700000001 },
    payload: { status: "ok" },
    fields: { status: "ok" },
    desired: {},
    status: { state: "ok" },
    result: {},
    safeFacts: { status: "ok" },
  }, surface);

  assertServiceNodeSetRequest({
    requestId: "set-1",
    service: "logging",
    nodePath: "settings",
    desired: { verbosity: "verbose" },
  }, surface);
  assert.throws(() => assertServiceNodeSetRequest({
    requestId: "set-2",
    service: "logging",
    nodePath: "health",
    desired: { status: "ok" },
  }, surface), /not settable/);
});

test("service registry primitives validate participant claims and materialized directories", () => {
  const issuedAt = 1700000000;
  const servicePk = pubkeyFromSecretKey(SERVICE_SK);
  const gatewayPk = pubkeyFromSecretKey(GATEWAY_SK);
  const claim = assertServiceRegistryClaim({
    kind: SWARM.RECORD_KIND.SERVICE_REGISTRY_CLAIM,
    claimId: "service-registry-claim:nvr",
    schemaVersion: SERVICE_REGISTRY.SCHEMA_VERSION,
    claimKind: SERVICE_REGISTRY.CLAIM_KIND.SERVICE,
    state: SERVICE_REGISTRY.CLAIM_STATE.CLAIMED,
    ownerRef: `service:${servicePk}`,
    writerRef: `gateway:${gatewayPk}`,
    subjectRef: `service:${servicePk}`,
    scopeRef: "zone:lab",
    service: "nvr",
    servicePk,
    serviceRef: `service:nvr:${servicePk}`,
    memberRef: servicePk,
    hostGatewayPk: gatewayPk,
    capabilityRefs: ["media.stream.preview"],
    channelRefs: ["nvr.streams"],
    nodeRefs: ["nvr.streams.preview"],
    surfaceRefs: ["nvr.surface"],
    evidenceRefs: ["swarm.edge.session:service"],
    safeFacts: { service: "nvr" },
    issuedAt,
    expiresAt: issuedAt + 90_000,
  });
  assert.equal(claim.claimKind, SERVICE_REGISTRY.CLAIM_KIND.SERVICE);

  const materialized = assertServiceRegistryMaterialization({
    kind: SWARM.RECORD_KIND.SERVICE_REGISTRY_MATERIALIZATION,
    registryId: "service-registry:lab",
    schemaVersion: SERVICE_REGISTRY.SCHEMA_VERSION,
    scopeRef: "zone:lab",
    state: SERVICE_REGISTRY.MATERIALIZATION_STATE.READY,
    revision: 7,
    claimRefs: [claim.claimId],
    participantRefs: [claim.writerRef],
    serviceRefs: [claim.serviceRef],
    services: [
      {
        service: "nvr",
        servicePk,
        serviceRef: claim.serviceRef,
        hostGatewayPk: gatewayPk,
        surfaceChannel: "nvr.surface",
        nodes: [
          {
            path: "streams",
            nodeId: "nvr.streams.preview",
            label: "Streams",
            backingChannel: "nvr.streams",
            fields: [
              {
                fieldId: "sourceId",
                label: "Source",
                valueKind: "string",
                capabilities: [SERVICE_SURFACE.FIELD_CAPABILITY.READ],
              },
            ],
          },
        ],
      },
    ],
    entries: [
      {
        kind: SWARM.RECORD_KIND.DIRECTORY_ENTRY,
        entryId: "directory:nvr-streams",
        subjectRef: claim.subjectRef,
        source: "memberRecord",
        capabilityRef: "media.stream.preview",
        channelId: "nvr.streams",
        issuedAt,
      },
    ],
    coverage: {
      materializedCount: 1,
      targetCount: 1,
      completionRatio: 1,
      syncState: PROJECTION.SYNC_STATE.COMPLETE_ENOUGH,
    },
    freshness: { state: PROJECTION.FRESHNESS.FRESH, updatedAt: issuedAt },
    issuedAt,
  });
  assert.equal(materialized.services.length, 1);

  assert.throws(() => assertServiceRegistryClaim({
    ...claim,
    kind: SWARM.RECORD_KIND.SERVICE_REGISTRY_CLAIM,
    safeFacts: { servicePrivateUrl: "rtsp://camera" },
  }), /unsafe safe fact key/);
  assert.throws(() => assertServiceRegistryMaterialization({
    ...materialized,
    state: "complete",
  }), /invalid service registry materialization state/);
});

test("surface app contracts validate module roles and fulfillment boundaries", () => {
  const issuedAt = 1700000000;
  const runtimeClient = assertSurfaceModuleClaim({
    moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
    fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    version: "0.1.0",
    primitiveRefs: ["runtime.attach"],
    requiredCapabilities: ["runtime.snapshot.subscribe"],
    inputs: ["runtime.snapshot"],
    outputs: ["runtime.intent"],
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(runtimeClient.role, SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT);

  const contract = assertSurfaceAppContract({
    contractId: "surface-app:nvr-ui",
    schemaVersion: SURFACE_APP.SCHEMA_VERSION,
    appId: "constitute-nvr-ui",
    version: "0.1.0",
    displayName: "Security Cameras",
    requiredPrimitives: [
      "runtime.attach",
      "projection.materialization",
      "media.transport.path",
    ],
    requiredModuleRoles: [
      SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
      SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
      SURFACE_APP.MODULE_ROLE.PLATFORM_ADAPTER,
      SURFACE_APP.MODULE_ROLE.SERVICE_SURFACE_ADAPTER,
      SURFACE_APP.MODULE_ROLE.SERVICE_EDGE_ADAPTER,
      SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
    ],
    modules: [
      runtimeClient,
      {
        moduleRef: "constitute-nvr-ui/nvr-projection-model@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PROJECTION_MODEL,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["projection.materialization"],
        inputs: ["runtime.snapshot"],
        outputs: ["inventory.read-model"],
        issuedAt,
      },
      {
        moduleRef: "constitute-ui/media-webrtc-adapter@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PLATFORM_ADAPTER,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["media.transport.path"],
        inputs: ["stream.session.answer"],
        outputs: ["media.transport.observation"],
        issuedAt,
      },
      {
        moduleRef: "constitute-nvr-ui/service-surface-adapter@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.SERVICE_SURFACE_ADAPTER,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["stream.session.intent"],
        inputs: ["camera.selection"],
        outputs: ["runtime.intent"],
        issuedAt,
      },
      {
        moduleRef: "constitute-nvr/service-edge-adapter@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.SERVICE_EDGE_ADAPTER,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.SERVICE,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.NATIVE_INSTALLED,
        version: "0.1.0",
        primitiveRefs: ["service.admission", "stream.session.answer", "projection.delta"],
        inputs: ["runtime.intent"],
        outputs: ["service.accepted", "service.response.materialized", "projection.delta"],
        issuedAt,
      },
      {
        moduleRef: "constitute-nvr-ui/product-view@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.PRODUCT_VIEW,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        inputs: ["inventory.read-model", "media.render.posture"],
        outputs: ["user.intent"],
        issuedAt,
      },
    ],
    projectionSubscriptions: [
      { projectionId: "nvr.inventory", channelId: "nvr.inventory" },
    ],
    materializationBudgets: [
      {
        kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
        budgetId: "nvr.preview",
        sourceAuthority: "runtime.media.transport.path",
        consumerRef: "nvr-ui.preview",
        payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.MEDIA,
        copyRole: SWARM.MATERIALIZATION_COPY_ROLE.TRANSPORT,
        transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.NATIVE,
        privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.UI_PROJECTION,
        state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
        limits: { maxItems: 2, maxBytes: 1000000 },
        snapshotPolicy: { mode: "none" },
        deltaPolicy: { mode: "media-evidence" },
        coalescing: { key: "sourceId" },
        cardinality: { maxSourceIds: 2 },
        schema: { state: SWARM.MATERIALIZATION_SCHEMA_STATE.CURRENT, version: "nvr.preview.v1" },
        issuedAt,
      },
    ],
    updatePosture: {
      state: SURFACE_APP.UPDATE_POSTURE.STATIC,
      checkedAt: issuedAt,
    },
    issuedAt,
  });

  assert.equal(contract.modules.length, 6);
  assert.equal(contract.modules[4].role, SURFACE_APP.MODULE_ROLE.SERVICE_EDGE_ADAPTER);
  assert.throws(() => assertSurfaceAppContract({
    ...contract,
    modules: contract.modules.filter((module) => module.role !== SURFACE_APP.MODULE_ROLE.PLATFORM_ADAPTER),
  }), /missing module role platformAdapter/);
  assert.throws(() => assertSurfaceModuleClaim({
    ...runtimeClient,
    role: "runtimePolicy",
  }), /invalid surface module role/);
});

test("app contracts validate activity release and resolution records", () => {
  const contract = assertAppContract({
    kind: APP.RECORD_KIND.CONTRACT,
    appContractRef: "app:contract:community-launcher@0.1.0",
    appId: "community-launcher",
    version: "0.1.0",
    authorRef: "identity:community-root",
    state: APP.CONTRACT_STATE.READY,
    primitiveRefs: ["app.activity", "runtime.selection"],
    activityRefs: ["app:activity:community-launcher.channel"],
    moduleRoleRefs: [
      "app:module-role:community-launcher.runtime",
      "app:module-role:community-launcher.view",
    ],
    releaseRefs: ["app:release:community-launcher@0.1.0"],
    permissionRefs: ["permission:community-launcher:run"],
    accessGroupRefs: ["access-group:community-launcher:members"],
    compatibilityRefs: ["compat:surface-app:0.1"],
    evidenceRefs: ["evidence:app-contract:community-launcher"],
    issuedAt: 1_779_266_000,
    expiresAt: 1_779_269_600,
  });
  const runtimeRole = assertAppModuleRole({
    kind: APP.RECORD_KIND.MODULE_ROLE,
    moduleRoleRef: "app:module-role:community-launcher.runtime",
    appContractRef: contract.appContractRef,
    roleName: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    required: true,
    primitiveRefs: ["runtime.attach"],
    artifactRefs: ["build:artifact:community-launcher-runtime"],
    compatibilityRefs: ["compat:surface-app:0.1"],
    evidenceRefs: ["evidence:module-role:runtime"],
  });
  const activity = assertAppActivity({
    kind: APP.RECORD_KIND.ACTIVITY,
    activityRef: "app:activity:community-launcher.channel",
    appContractRef: contract.appContractRef,
    activityId: "channel",
    state: APP.ACTIVITY_STATE.READY,
    launchMode: APP.ACTIVITY_LAUNCH.EMBEDDED,
    embedPolicy: APP.EMBED_POLICY.RESTRICTED,
    primitiveRefs: ["messaging.thread.observe", "community.role.write"],
    moduleRoleRefs: [runtimeRole.moduleRoleRef, "app:module-role:community-launcher.view"],
    permissionRefs: ["permission:community-channel:write"],
    accessGroupRefs: ["access-group:community-launcher:members"],
    materializationRefs: ["materialization:community-channel:messages"],
    evidenceRefs: ["evidence:activity:community-channel"],
    issuedAt: 1_779_266_000,
    expiresAt: 1_779_269_600,
  });
  const release = assertAppRelease({
    kind: APP.RECORD_KIND.RELEASE,
    releaseRef: "app:release:community-launcher@0.1.0",
    appContractRef: contract.appContractRef,
    version: contract.version,
    sourceSnapshotRef: "source:snapshot:community-launcher:head",
    buildRunRef: "build:run:community-launcher@0.1.0",
    state: APP.RELEASE_STATE.PUBLISHED,
    artifactRefs: ["build:artifact:community-launcher-runtime", "build:artifact:community-launcher-view"],
    proofRefs: ["build:proof:community-launcher@0.1.0"],
    moduleRoleRefs: contract.moduleRoleRefs,
    storageRefs: ["storage:object:community-launcher@0.1.0"],
    compatibilityRefs: contract.compatibilityRefs,
    evidenceRefs: ["evidence:release:community-launcher"],
    issuedAt: 1_779_266_010,
    expiresAt: 1_779_269_600,
  });
  const resolution = assertAppReleaseResolution({
    kind: APP.RECORD_KIND.RELEASE_RESOLUTION,
    resolutionRef: "app:resolution:community-launcher@0.1.0",
    appIntentRef: "app:intent:community-launcher:channel",
    appContractRef: contract.appContractRef,
    requestedVersion: contract.version,
    state: APP.RESOLUTION_STATE.RESOLVED,
    selectedReleaseRef: release.releaseRef,
    selectedActivityRef: activity.activityRef,
    selectedArtifactRefs: release.artifactRefs,
    selectedModuleRoleRefs: release.moduleRoleRefs,
    selectedStorageRefs: release.storageRefs,
    sourceDigestRefs: ["source:digest:community-launcher@0.1.0"],
    sourceSnapshotRef: release.sourceSnapshotRef,
    buildProofRefs: release.proofRefs,
    compatibilityRefs: release.compatibilityRefs,
    permissionRefs: contract.permissionRefs,
    accessGroupRefs: contract.accessGroupRefs,
    evidenceRefs: ["evidence:resolution:community-launcher"],
    safeFacts: { activityId: activity.activityId, artifactCount: release.artifactRefs.length },
    resolvedAt: 1_779_266_020,
    expiresAt: 1_779_269_600,
  });

  assert.equal(contract.appContractRef, "app:contract:community-launcher@0.1.0");
  assert.equal(activity.launchMode, APP.ACTIVITY_LAUNCH.EMBEDDED);
  assert.deepEqual(resolution.selectedStorageRefs, ["storage:object:community-launcher@0.1.0"]);
  assert.throws(() => assertAppActivity({
    ...activity,
    moduleRoleRefs: [],
  }), /ready app activity requires primitiveRefs and moduleRoleRefs/);
  assert.throws(() => assertAppReleaseResolution({
    ...resolution,
    selectedStorageRefs: [],
  }), /resolved app release requires selected release/);
});

test("messaging and communications moderation remain app activity dependencies", () => {
  const issuedAt = 1_779_267_000;
  const messaging = assertMessagingContract({
    kind: APP.RECORD_KIND.MESSAGING_CONTRACT,
    messagingContractRef: "messaging:contract:truecost.web-team",
    scopeRef: "activity:scope:truecost.web-team.hosting",
    authorRef: "identity:truecost.root",
    state: APP.MESSAGING_STATE.READY,
    conversationRefs: ["messaging:thread:truecost.web-team.hosting"],
    participantRoleRefs: ["role:community.member", "role:webadmin"],
    activityRefs: ["app:activity:messaging.thread"],
    contentClassRefs: ["content:message.body", "content:message.safe-index"],
    accessGroupRefs: ["access-group:truecost.web-team"],
    witnessFloorRefs: ["witness:floor:messaging.thread"],
    retentionRefs: ["retention:message.thread.default"],
    moderationContractRefs: ["moderation:contract:truecost.web-team"],
    evidenceRefs: ["evidence:messaging.contract"],
    issuedAt,
    expiresAt: issuedAt + 3_600,
  });
  const moderation = assertCommunicationsModerationContract({
    kind: APP.RECORD_KIND.COMMUNICATIONS_MODERATION_CONTRACT,
    moderationContractRef: "moderation:contract:truecost.web-team",
    scopeRef: messaging.scopeRef,
    authorityRealmRef: "authority:realm:truecost.community",
    state: APP.COMMUNICATIONS_MODERATION_STATE.READY,
    actionRefs: ["moderation:action:report", "moderation:action:hide", "moderation:action:appeal"],
    targetRefs: messaging.conversationRefs,
    messagingContractRefs: [messaging.messagingContractRef],
    eventFabricRefs: ["event-fabric:logging.default"],
    permissionRefs: ["permission:moderation.web-team"],
    accessGroupRefs: ["access-group:truecost.moderators"],
    evidenceRefs: ["evidence:moderation.contract"],
    issuedAt,
    expiresAt: issuedAt + 3_600,
  });
  const messagingDependency = assertAppActivityDependency({
    kind: APP.RECORD_KIND.ACTIVITY_DEPENDENCY,
    dependencyRef: "app:dependency:community.channel.messaging",
    appContractRef: "app:contract:communities@0.1.0",
    activityRef: "app:activity:community.role-channel",
    dependencyType: APP.DEPENDENCY_TYPE.MESSAGING,
    required: true,
    state: APP.DEPENDENCY_STATE.READY,
    contractRefs: [messaging.messagingContractRef],
    primitiveRefs: ["primitive:messaging.thread"],
    permissionRefs: ["permission:message.write"],
    accessGroupRefs: messaging.accessGroupRefs,
    materializationRefs: ["materialization:thread.messages"],
    evidenceRefs: ["evidence:dependency.messaging"],
    issuedAt,
    expiresAt: issuedAt + 3_600,
  });
  const moderationDependency = assertAppActivityDependency({
    kind: APP.RECORD_KIND.ACTIVITY_DEPENDENCY,
    dependencyRef: "app:dependency:community.channel.moderation",
    appContractRef: "app:contract:communities@0.1.0",
    activityRef: "app:activity:community.role-channel",
    dependencyType: APP.DEPENDENCY_TYPE.COMMUNICATIONS_MODERATION,
    required: false,
    state: APP.DEPENDENCY_STATE.READY,
    contractRefs: [moderation.moderationContractRef],
    primitiveRefs: ["primitive:communications.moderation"],
    permissionRefs: moderation.permissionRefs,
    accessGroupRefs: moderation.accessGroupRefs,
    materializationRefs: ["materialization:moderation.posture"],
    evidenceRefs: ["evidence:dependency.moderation"],
    issuedAt,
    expiresAt: issuedAt + 3_600,
  });

  assert.equal(messagingDependency.dependencyType, "messaging");
  assert.equal(moderationDependency.dependencyType, "communicationsModeration");
  assert.throws(() => assertMessagingContract({
    ...messaging,
    contentClassRefs: [],
  }), /ready messaging contract requires participant roles/);
  assert.throws(() => assertAppActivityDependency({
    ...messagingDependency,
    state: APP.DEPENDENCY_STATE.BLOCKED,
    blockedReasons: [],
  }), /blocked app activity dependency requires blockedReasons/);
  assert.throws(() => assertCommunicationsModerationContract({
    ...moderation,
    actionRefs: [],
  }), /ready communications moderation contract requires actions/);
  assert.throws(() => assertAppActivityDependency({
    ...messagingDependency,
    payload: "message bodies stay behind CAAC access refs",
  }), /forbidden protocol field: payload/);
});

test("service edge adapter posture validates service-owned admission and backpressure evidence", () => {
  const observedAt = 1700000000;
  const posture = assertServiceEdgeAdapterPosture({
    kind: SWARM.RECORD_KIND.SERVICE_EDGE_ADAPTER_POSTURE,
    postureId: "service-edge:nvr:edge-session-1",
    moduleRef: "constitute-nvr/service-edge-adapter@0.1.0",
    serviceRef: `service:${SERVICE_PK}`,
    serviceMemberRef: SERVICE_PK,
    gatewayRef: `gateway:${GATEWAY_PK}`,
    edgeSessionRef: "edge-session-1",
    participantSide: SURFACE_APP.PARTICIPANT_SIDE.SERVICE,
    state: "ready",
    admissionState: "available",
    backpressureState: "clear",
    responseState: "available",
    projectionState: "available",
    releaseState: "held",
    capabilityRefs: [SWARM.CORE_CAPABILITY.SERVICE_EDGE_POSTURE_PUBLISH],
    inputRecordKinds: [SWARM.STREAM_RECORD_KIND.OFFER, SWARM.STREAM_RECORD_KIND.CONTROL],
    outputRecordKinds: [
      SWARM.STREAM_RECORD_KIND.ADMISSION,
      SWARM.STREAM_RECORD_KIND.ANSWER,
      SWARM.RECORD_KIND.MEDIA_TRANSPORT_PATH,
    ],
    evidenceChannels: ["service.admission", "service.response", "projection.delta"],
    queue: { pending: 0, capacity: 32, accepted: 1, rejected: 0, dropped: 0 },
    resourcePostureRef: "resource:nvr-edge",
    releaseRef: "release:nvr-edge",
    safeFacts: { edge: "nvr" },
    evidenceRefs: ["service.accepted:frame-1"],
    observedAt,
    expiresAt: observedAt + 90_000,
  });
  assert.equal(posture.state, "ready");
  assert.equal(posture.participantSide, SURFACE_APP.PARTICIPANT_SIDE.SERVICE);

  assert.throws(() => assertServiceEdgeAdapterPosture({
    ...posture,
    backpressureState: "blocked",
    blockedReasons: [],
  }), /blocked posture requires blockedReasons/);
  assert.throws(() => assertServiceEdgeAdapterPosture({
    ...posture,
    queue: { pending: -1 },
  }), /queue pending must be non-negative/);
});

test("surface app fulfillment identity posture separates contract, service, host, route, and runner identity", () => {
  const issuedAt = 1700000000;
  const posture = assertSurfaceAppFulfillmentIdentityPosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_FULFILLMENT_IDENTITY_POSTURE,
    identityId: "identity:surface-app:nvr-ui",
    state: "ready",
    appContractRef: "app:nvr-ui",
    appId: "constitute-nvr-ui",
    version: "0.2.0",
    surfaceRef: "surface:nvr-ui",
    serviceRequired: true,
    serviceContractRef: "service:nvr",
    serviceRef: "service:nvr",
    serviceRouteRefs: ["service:nvr", "route:service:nvr"],
    routeRefs: ["route:service:nvr"],
    hostRefs: ["host:lab-gateway"],
    managerRefs: ["manager:nvr-ui"],
    runnerRefs: [BROWSER_PK],
    memberRefs: [BROWSER_PK],
    capabilityRefs: ["service.manage"],
    grantRefs: ["grant:app:nvr-ui:run"],
    authorityRefs: ["authority:nvr-ui:local"],
    evidenceRefs: ["build:nvr-ui:local"],
    identityPosture: {
      app: "ready",
      service: "ready",
      route: "ready",
      host: "ready",
    },
    safeFacts: {
      serviceRequired: true,
      serviceRouteRefCount: 2,
      runnerRefCount: 1,
    },
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(posture.serviceContractRef, "service:nvr");
  assert.deepEqual(posture.runnerRefs, [BROWSER_PK]);

  assert.throws(() => assertSurfaceAppFulfillmentIdentityPosture({
    ...posture,
    identityId: "identity:surface-app:nvr-ui:bad-service",
    serviceRef: "service:nvr-route-only",
  }), /serviceRef must not differ from serviceContractRef/);

  assert.throws(() => assertSurfaceAppFulfillmentIdentityPosture({
    ...posture,
    identityId: "identity:surface-app:nvr-ui:bad-runner",
    runnerRefs: ["member:unresolved"],
  }), /must be a resolved public key/);
});

test("surface app authority access posture separates action grants from content access", () => {
  const issuedAt = 1700000000;
  const posture = assertSurfaceAppAuthorityAccessPosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_AUTHORITY_ACCESS_POSTURE,
    postureId: "authority-access:surface-app:nvr-ui",
    state: "ready",
    appContractRef: "app:nvr-ui",
    appId: "constitute-nvr-ui",
    actionRequired: true,
    accessRequired: true,
    syncRequired: true,
    rootRefs: ["root:aux"],
    deviceRefs: ["device:aux-browser"],
    grantRefs: ["grant:app:nvr-ui:run"],
    authorityRefs: ["authority:aux-browser"],
    accessGroupRefs: ["access-group:nvr-ui:media-preview"],
    accessEpochRefs: ["access-epoch:nvr-ui:media-preview:7"],
    privateEnvelopeRefs: ["private-envelope:nvr-ui:media-preview:latest"],
    syncRefs: ["witness:nvr-ui:manifest:observed"],
    requiredContentClasses: [AGREEMENT.CONTENT_CLASS.UI_PROJECTION, AGREEMENT.CONTENT_CLASS.MEDIA_REFERENCE],
    exerciseRefs: ["exercise:app:nvr-ui:run"],
    evidenceRefs: ["proof:nvr-ui:authority"],
    actionPosture: { state: "ready", grantRefCount: 1 },
    accessPosture: { state: "ready", accessGroupRefCount: 1, accessEpochRefCount: 1, privateEnvelopeRefCount: 1 },
    syncPosture: { state: "ready", syncRefCount: 1 },
    revocationPosture: { state: "clear" },
    expiryPosture: { state: "fresh" },
    safeFacts: { actionRequired: true, accessRequired: true, syncRequired: true },
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(posture.state, "ready");
  assert.deepEqual(posture.accessGroupRefs, ["access-group:nvr-ui:media-preview"]);
  assert.deepEqual(posture.accessEpochRefs, ["access-epoch:nvr-ui:media-preview:7"]);
  assert.deepEqual(posture.privateEnvelopeRefs, ["private-envelope:nvr-ui:media-preview:latest"]);
  assert.deepEqual(posture.syncRefs, ["witness:nvr-ui:manifest:observed"]);

  assert.throws(() => assertSurfaceAppAuthorityAccessPosture({
    ...posture,
    postureId: "authority-access:surface-app:nvr-ui:missing-grant",
    grantRefs: [],
  }), /action requires grantRefs/);

  assert.throws(() => assertSurfaceAppAuthorityAccessPosture({
    ...posture,
    postureId: "authority-access:surface-app:nvr-ui:missing-access",
    accessGroupRefs: [],
  }), /access requires accessGroupRefs/);

  assert.throws(() => assertSurfaceAppAuthorityAccessPosture({
    ...posture,
    postureId: "authority-access:surface-app:nvr-ui:missing-sync",
    syncRefs: [],
  }), /sync requires syncRefs/);

  assert.throws(() => assertSurfaceAppAuthorityAccessPosture({
    ...posture,
    postureId: "authority-access:surface-app:nvr-ui:revoked",
    state: "ready",
    revocationState: "revoked",
  }), /revoked state must be blocked/);
});

test("surface bootstrap contracts gate service manager release and secret posture", () => {
  const issuedAt = 1700000000;
  const serviceManager = assertServiceManagerPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_POSTURE,
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    state: SURFACE_APP.SERVICE_MANAGER_POSTURE.READY,
    serviceRefs: ["service:gateway"],
    capabilityRefs: ["service.manage"],
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.RESOLVED,
      secretRefs: ["secret:gateway-lab"],
      authorityRefs: ["identity:operator"],
    },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:gateway:2026-05-17",
      releaseRef: "release:gateway:2026-05-17",
      rollbackRef: "rollback:gateway:previous",
      evidenceRefs: ["ci:gateway:build"],
    },
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(serviceManager.state, SURFACE_APP.SERVICE_MANAGER_POSTURE.READY);

  const bootstrap = assertSurfaceAppBootstrapPosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_POSTURE,
    bootstrapId: "bootstrap:nvr-ui:lab",
    contractId: "surface-app:nvr-ui",
    appId: "constitute-nvr-ui",
    state: SURFACE_APP.BOOTSTRAP_POSTURE.READY,
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    moduleRefs: ["constitute-ui/runtime-surface-client@0.1.0"],
    serviceManagerRef: "manager:lab-gateway",
    serviceManagerPosture: serviceManager,
    secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.STATIC,
      evidenceRefs: ["build:nvr-ui:local"],
    },
    issuedAt,
  });
  assert.equal(bootstrap.state, SURFACE_APP.BOOTSTRAP_POSTURE.READY);

  const contract = assertSurfaceAppContract({
    contractId: "surface-app:nvr-ui",
    schemaVersion: SURFACE_APP.SCHEMA_VERSION,
    appId: "constitute-nvr-ui",
    version: "0.1.0",
    displayName: "Security Cameras",
    requiredModuleRoles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    modules: [
      {
        moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
        role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
        participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
        fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        version: "0.1.0",
        primitiveRefs: ["runtime.attach"],
        issuedAt,
      },
    ],
    serviceManagerPosture: serviceManager,
    bootstrapPosture: bootstrap,
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.STATIC,
    },
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED,
    },
    issuedAt,
  });
  assert.equal(contract.bootstrapPosture.state, SURFACE_APP.BOOTSTRAP_POSTURE.READY);

  assert.throws(() => assertServiceManagerPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_POSTURE,
    managerId: "manager:blocked",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    state: SURFACE_APP.SERVICE_MANAGER_POSTURE.BLOCKED,
    issuedAt,
  }), /blocked state requires blockedReasons/);
  assert.throws(() => assertSurfaceAppBootstrapPosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_POSTURE,
    bootstrapId: "bootstrap:bad",
    contractId: "surface-app:nvr-ui",
    appId: "constitute-nvr-ui",
    state: SURFACE_APP.BOOTSTRAP_POSTURE.READY,
    sourceMode: "httpEval",
    issuedAt,
  }), /invalid surface app bootstrap sourceMode/);
  assert.throws(() => assertServiceManagerPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_POSTURE,
    managerId: "manager:leaky",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    state: SURFACE_APP.SERVICE_MANAGER_POSTURE.READY,
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.RESOLVED,
      token: "inline-secret",
    },
    issuedAt,
  }), /forbidden protocol field/);
});

test("surface app manifests pin versioned app contracts and block unproven remote sources", () => {
  const issuedAt = 1700000000;
  const manifest = assertSurfaceAppManifest({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MANIFEST,
    manifestId: "surface-app-manifest:nvr-ui",
    appId: "constitute-nvr-ui",
    state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
    currentAppContractRef: "surface-app:nvr-ui@0.1.0",
    currentVersion: "0.1.0",
    defaultSourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    versions: [
      {
        appContractRef: "surface-app:nvr-ui@0.1.0",
        version: "0.1.0",
        state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
        sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
        requiredModuleRoles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
        compatibilityWindow: {
          minVersion: "0.1.0",
          maxVersion: "0.1.x",
          protocolRef: "protocol:surface-app:v1",
          schemaRefs: ["schema:surface-app-contract:v1"],
        },
        bundledSourceRefs: ["bundle:constitute-nvr-ui@0.1.0"],
        grantRefs: ["grant:app:nvr-ui:run"],
        runnerRequirementRefs: ["runner:req:nvr-ui"],
        serviceManagerRequirementRefs: ["service-manager:req:nvr-ui"],
        moduleRefs: ["constitute-ui/runtime-surface-client@0.1.0"],
        compatibilityRefs: ["protocol:surface-app:v1"],
      },
    ],
    appContractRefs: ["surface-app:nvr-ui@0.1.0"],
    requiredModuleRoles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    compatibilityWindow: {
      minVersion: "0.1.0",
      maxVersion: "0.1.x",
      protocolRef: "protocol:surface-app:v1",
      schemaRefs: ["schema:surface-app-contract:v1"],
    },
    bundledSourceRefs: ["bundle:constitute-nvr-ui@0.1.0"],
    grantRefs: ["grant:app:nvr-ui:run"],
    runnerRequirementRefs: ["runner:req:nvr-ui"],
    serviceManagerRequirementRefs: ["service-manager:req:nvr-ui"],
    compatibilityRefs: ["protocol:surface-app:v1"],
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(manifest.currentAppContractRef, "surface-app:nvr-ui@0.1.0");
  assert.deepEqual(manifest.requiredModuleRoles, [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT]);
  assert.equal(manifest.compatibilityWindow.protocolRef, "protocol:surface-app:v1");

  const distributionPosture = assertSurfaceAppDistributionPosture({
    state: SURFACE_APP.DISTRIBUTION_POSTURE.RETAINED,
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT,
    sourceRefs: ["surface-app-source:nvr-ui@0.2.0"],
    storageRefs: ["storage:object:surface-app:nvr-ui@0.2.0"],
    pinIntentRefs: ["storage.pin.intent:surface-app:nvr-ui@0.2.0"],
    pinProjectionRefs: ["storage.pin.projection:surface-app:nvr-ui@0.2.0"],
    releaseContractRefs: ["service.manager.release:nvr-ui@0.2.0"],
    retentionRefs: ["retention:surface-app:nvr-ui@0.2.0"],
    retentionClass: "app-release",
    schemaPosture: {
      state: SURFACE_APP.SCHEMA_POSTURE.COMPATIBLE,
      schemaRefs: ["schema:surface-app-contract:v1"],
    },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.RELEASE_READY,
      buildRef: "build:nvr-ui@0.2.0",
      releaseRef: "release:nvr-ui@0.2.0",
    },
    safeFacts: {
      retained: true,
      version: "0.2.0",
    },
  });
  assert.equal(distributionPosture.retentionClass, "app-release");

  const retainedManifest = assertSurfaceAppManifest({
    ...manifest,
    currentAppContractRef: "surface-app:nvr-ui@0.2.0",
    currentVersion: "0.2.0",
    defaultSourceMode: SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT,
    distributionPosture,
    versions: [
      {
        appContractRef: "surface-app:nvr-ui@0.2.0",
        version: "0.2.0",
        state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
        sourceMode: SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT,
        remoteSourceRefs: ["surface-app-source:nvr-ui@0.2.0"],
        releaseContractRef: "service.manager.release:nvr-ui@0.2.0",
        distributionPosture,
      },
    ],
    remoteSourceRefs: ["surface-app-source:nvr-ui@0.2.0"],
    releaseContractRefs: ["service.manager.release:nvr-ui@0.2.0"],
  });
  assert.equal(retainedManifest.distributionPosture.state, SURFACE_APP.DISTRIBUTION_POSTURE.RETAINED);

  assert.throws(() => assertSurfaceAppManifest({
    ...manifest,
    currentVersion: "0.2.0",
  }), /missing current version claim/);

  assert.throws(() => assertSurfaceAppManifest({
    ...manifest,
    versions: [
      {
        appContractRef: "surface-app:nvr-ui@0.2.0",
        version: "0.2.0",
        state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
        sourceMode: SURFACE_APP.FULFILLMENT_MODE.SWARM_PACKAGE,
        remoteSourceRefs: ["swarm-package:nvr-ui@0.2.0"],
      },
    ],
    currentAppContractRef: "surface-app:nvr-ui@0.2.0",
    currentVersion: "0.2.0",
  }), /non-bundled source requires releaseContractRef/);

  assert.throws(() => assertSurfaceAppDistributionPosture({
    ...distributionPosture,
    pinIntentRefs: [],
    pinProjectionRefs: [],
  }), /retained state requires pinIntentRefs or pinProjectionRefs/);

  assert.throws(() => assertSurfaceAppDistributionPosture({
    state: SURFACE_APP.DISTRIBUTION_POSTURE.DEGRADED,
    schemaPosture: {
      state: SURFACE_APP.SCHEMA_POSTURE.MIGRATION_REQUIRED,
    },
  }), /migrationRequired state requires migrationRefs or blockedReasons/);
});

test("surface app instance grammar validates clean selection and runner posture records", () => {
  const issuedAt = 1700000000;
  const moduleClaim = {
    moduleRef: "constitute-ui/runtime-surface-client@0.1.0",
    role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
    fulfillmentMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    version: "0.1.0",
    primitiveRefs: ["runtime.attach"],
    requiredCapabilities: ["runtime.snapshot.subscribe"],
    inputs: ["runtime.snapshot"],
    outputs: ["runtime.intent"],
    issuedAt,
  };
  const modulePosture = assertSurfaceModuleRolePosture({
    kind: SWARM.RECORD_KIND.SURFACE_MODULE_ROLE_POSTURE,
    state: "ready",
    blockedReason: "",
    role: SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT,
    moduleRef: "",
    primitiveRef: "",
    moduleCount: 1,
    modules: [moduleClaim],
  });
  const bootstrapContract = assertSurfaceAppBootstrapContract({
    kind: SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_CONTRACT,
    bootstrapContractId: "bootstrap:logging-ui@0.1.0",
    appContractRef: "surface-app:logging-ui@0.1.0",
    appId: "constitute-logging-ui",
    state: SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY,
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    moduleRefs: [moduleClaim.moduleRef],
    secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    issuedAt,
  });
  const runnerPlan = assertSurfaceAppRunnerPlan({
    kind: SWARM.RECORD_KIND.SURFACE_APP_RUNNER_PLAN,
    planId: "surface-runner:logging-ui",
    contractId: "surface-app:logging-ui@0.1.0",
    appId: "constitute-logging-ui",
    state: "ready",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    attachContext: {
      kind: "surface.app.attachContext",
      contractId: "surface-app:logging-ui@0.1.0",
      appId: "constitute-logging-ui",
    },
    modulePostures: [modulePosture],
    secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    bootstrapContract,
    blockedReasons: [],
    issuedAt,
  });
  const manifestSelection = assertSurfaceAppManifestSelection({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MANIFEST_SELECTION,
    manifestId: "surface-app-manifest:logging-ui",
    appId: "constitute-logging-ui",
    state: "ready",
    appContractRef: "surface-app:logging-ui@0.1.0",
    version: "0.1.0",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    claimState: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
    requiredModuleRoles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    bundledSourceRefs: ["bundle:logging-ui@0.1.0"],
    runnerRequirementRefs: ["runner:req:logging-ui"],
    compatibilityRefs: ["protocol:surface-app:v1"],
    bundledContractAvailable: true,
    claim: {
      appContractRef: "surface-app:logging-ui@0.1.0",
      version: "0.1.0",
      state: SURFACE_APP.MANIFEST_VERSION_STATE.CURRENT,
      sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
      bundledSourceRefs: ["bundle:logging-ui@0.1.0"],
    },
    issuedAt,
  });
  const sourceCandidatePosture = assertSurfaceAppSourceCandidatePosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_SOURCE_CANDIDATE_POSTURE,
    state: "ready",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    sourceClass: "bundled",
    candidateRefs: ["bundle:logging-ui@0.1.0"],
    bundledSourceRefs: ["bundle:logging-ui@0.1.0"],
    compatibilityRefs: ["protocol:surface-app:v1"],
    blockedReasons: [],
    issuedAt,
  });
  const blockedRemoteCandidate = assertSurfaceAppSourceCandidatePosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_SOURCE_CANDIDATE_POSTURE,
    state: "blocked",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT,
    sourceClass: "storagePinned",
    candidateRefs: ["storage-object:logging-ui@0.2.0"],
    storageObjectRefs: ["storage-object:logging-ui@0.2.0"],
    releaseContractRef: "release:logging-ui@0.2.0",
    compatibilityRefs: ["protocol:surface-app:v1"],
    proofDigestRefs: ["proof-digest:logging-ui@0.2.0"],
    rollbackRefs: ["rollback:logging-ui@0.1.0"],
    secretBoundaryRefs: [],
    blockedReasons: ["missingSecretBoundaryRef"],
    issuedAt,
  });
  assert.equal(blockedRemoteCandidate.state, "blocked");
  assert.throws(
    () => assertSurfaceAppSourceCandidatePosture({
      kind: SWARM.RECORD_KIND.SURFACE_APP_SOURCE_CANDIDATE_POSTURE,
      state: "ready",
      sourceMode: SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT,
      sourceClass: "storagePinned",
      candidateRefs: ["storage-object:logging-ui@0.2.0"],
      releaseContractRef: "release:logging-ui@0.2.0",
      digestRefs: ["sha256:logging-ui@0.2.0"],
      signatureRefs: ["sig:logging-ui@0.2.0"],
      proofDigestRefs: ["proof-digest:logging-ui@0.2.0"],
      rollbackRefs: ["rollback:logging-ui@0.1.0"],
      compatibilityRefs: ["protocol:surface-app:v1"],
      blockedReasons: [],
      issuedAt,
    }),
    /requires secretBoundaryRefs/
  );
  assert.throws(
    () => assertSurfaceAppSourceCandidatePosture({
      kind: SWARM.RECORD_KIND.SURFACE_APP_SOURCE_CANDIDATE_POSTURE,
      state: "ready",
      sourceMode: SURFACE_APP.FULFILLMENT_MODE.STORAGE_OBJECT,
      sourceClass: "storagePinned",
      candidateRefs: ["storage-object:logging-ui@0.2.0"],
      releaseContractRef: "release:logging-ui@0.2.0",
      signatureRefs: ["sig:logging-ui@0.2.0"],
      proofDigestRefs: ["proof-digest:logging-ui@0.2.0"],
      rollbackRefs: ["rollback:logging-ui@0.1.0"],
      secretBoundaryRefs: ["secret-boundary:logging-ui"],
      compatibilityRefs: ["protocol:surface-app:v1"],
      blockedReasons: [],
      issuedAt,
    }),
    /requires digestRefs/
  );
  const manifestRunnerPlan = assertSurfaceAppManifestRunnerPlan({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MANIFEST_RUNNER_PLAN,
    planId: "surface-runner:logging-ui",
    state: "ready",
    manifestSelection,
    runnerPlan,
    blockedReasons: [],
    issuedAt,
  });
  const serviceManagerActionability = assertSurfaceAppServiceManagerActionability({
    kind: SWARM.RECORD_KIND.SURFACE_APP_SERVICE_MANAGER_ACTIONABILITY,
    state: "ready",
    managerId: "manager:logging-ui",
    subjectRef: "surface-app:logging-ui@0.1.0",
    managerRef: "member:service-manager:logging-ui",
    serviceManagerRequirementRefs: ["service-manager:req:logging-ui"],
    operationRefs: ["operation:logging-ui:healthCheck"],
    healthState: "ready",
    serviceManagerPosture: {
      kind: SWARM.RECORD_KIND.SERVICE_MANAGER_POSTURE,
      managerId: "manager:logging-ui",
      subjectRef: "surface-app:logging-ui@0.1.0",
      managerRef: "member:service-manager:logging-ui",
      state: SURFACE_APP.SERVICE_MANAGER_POSTURE.READY,
      issuedAt,
    },
    operationPostures: [
      {
        kind: SWARM.RECORD_KIND.SERVICE_MANAGER_OPERATION_POSTURE,
        operationId: "operation:logging-ui:healthCheck",
        managerId: "manager:logging-ui",
        subjectRef: "surface-app:logging-ui@0.1.0",
        managerRef: "member:service-manager:logging-ui",
        requesterRef: "surface-app:logging-ui@0.1.0",
        operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.HEALTH_CHECK,
        state: SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.SUCCEEDED,
        blockedReasons: [],
        requestedAt: issuedAt,
        completedAt: issuedAt + 1,
      },
    ],
    blockedReasons: [],
    issuedAt,
  });
  const runtimeSelection = assertSurfaceAppRuntimeSelectionPosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_RUNTIME_SELECTION_POSTURE,
    selectionId: "runtime-selection:logging-ui",
    state: "ready",
    requestedAppRef: "surface-app:logging-ui@0.1.0",
    requestedVersion: "0.1.0",
    manifestId: "surface-app-manifest:logging-ui",
    appId: "constitute-logging-ui",
    pinnedAppContractRef: "surface-app:logging-ui@0.1.0",
    pinnedVersion: "0.1.0",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    requiredModuleRoles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    compatibilityResult: {
      kind: "surface.app.runtime.compatibility.result",
      state: "ready",
      blockedReasons: [],
    },
    sourceCandidatePosture,
    sourceTrustResult: {
      kind: "surface.app.runtime.source.trust.result",
      state: "ready",
      blockedReasons: [],
    },
    modulePostures: [modulePosture],
    runnerReadiness: {
      kind: "surface.app.runtime.runner.readiness",
      state: "ready",
      blockedReasons: [],
    },
    serviceManagerReadiness: {
      kind: "surface.app.runtime.service-manager.readiness",
      state: "unknown",
      blockedReasons: [],
    },
    serviceManagerActionability,
    manifestSelection,
    manifestRunnerPlan,
    runnerPlan,
    blockedReasons: [],
    issuedAt,
  });
  const moduleBindingPosture = assertSurfaceAppModuleBindingPosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_MODULE_BINDING_POSTURE,
    state: "ready",
    roles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    keys: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    moduleRefs: [moduleClaim.moduleRef],
    implementationRefs: [moduleClaim.moduleRef],
    blockedReasons: [],
  });
  const instance = assertSurfaceAppInstancePosture({
    kind: SWARM.RECORD_KIND.SURFACE_APP_INSTANCE_POSTURE,
    instanceId: "surface-instance:logging-ui",
    state: "ready",
    contractId: "surface-app:logging-ui@0.1.0",
    appId: "constitute-logging-ui",
    appRef: "surface-app:logging-ui@0.1.0",
    surfaceRef: "surface:logging-ui",
    displayName: "Logging",
    version: "0.1.0",
    manifestId: "surface-app-manifest:logging-ui",
    pinnedAppContractRef: "surface-app:logging-ui@0.1.0",
    pinnedVersion: "0.1.0",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    requiredModuleRoles: [SURFACE_APP.MODULE_ROLE.RUNTIME_CLIENT],
    moduleRefs: [moduleClaim.moduleRef],
    modulePostures: [modulePosture],
    moduleBindingPosture,
    materializationBudgetRefs: ["logging-ui.event-table"],
    runtimeSelectionPosture: runtimeSelection,
    runnerReadiness: runtimeSelection.runnerReadiness,
    serviceManagerReadiness: runtimeSelection.serviceManagerReadiness,
    runnerPlanRef: runnerPlan.planId,
    bootstrapContractRef: bootstrapContract.bootstrapContractId,
    blockedReasons: [],
    issuedAt,
  });
  assert.equal(instance.state, "ready");

  const leakySelection = {
    ...manifestSelection,
    surfaceApp: { contractId: "local-object" },
  };
  assert.throws(
    () => assertSurfaceAppManifestSelection(leakySelection),
    /must not expose enumerable surfaceApp/,
  );
});

test("service manager operations and proof digests validate release train evidence", () => {
  const requestedAt = 1700000000;
  const operation = assertServiceManagerOperationPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_OPERATION_POSTURE,
    operationId: "operation:gateway:promote:2026-05-17",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    requesterRef: "identity:operator",
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.PROMOTE,
    state: SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.SUCCEEDED,
    serviceRefs: ["service:gateway"],
    capabilityRefs: ["service.manage"],
    authorityRefs: ["identity:operator"],
    grantRefs: ["authority-grant:service-manager:gateway"],
    runnerOperationRef: "runner-operation:gateway:promote:2026-05-17",
    runnerRef: BROWSER_PK,
    hostRef: "host:lab-gateway",
    releaseRef: "release:gateway:2026-05-17",
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:gateway:2026-05-17",
      releaseRef: "release:gateway:2026-05-17",
      rollbackRef: "rollback:gateway:previous",
    },
    resourceBudget: {
      profileRef: "resource-profile:service-manager",
      maxMemoryMiB: 512,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:service-manager:gateway",
      profileId: "resource-profile:service-manager",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 120 },
      budgets: { memoryMiB: 512 },
      sampledAt: requestedAt + 30,
    },
    evidenceRefs: ["ci:gateway:linux", "ci:gateway:windows"],
    proofRefs: ["proof:gateway:smoke"],
    witnessRefs: ["witness:gateway-manager:observed"],
    retentionRefs: ["retention:gateway-release:90d"],
    releaseWitnessRefs: ["witness:operator:release-ready"],
    safeFacts: {
      ci: "passed",
      architecture: "surface-bootstrap",
    },
    requestedAt,
    acceptedAt: requestedAt + 10,
    startedAt: requestedAt + 20,
    completedAt: requestedAt + 60,
    expiresAt: requestedAt + 3600,
  });
  assert.equal(operation.operation, SURFACE_APP.SERVICE_MANAGER_OPERATION.PROMOTE);
  assert.deepEqual(operation.witnessRefs, ["witness:gateway-manager:observed"]);

  const releaseOperation = assertServiceManagerOperationPosture({
    ...operation,
    operationId: "operation:gateway:release:2026-05-17",
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.RELEASE,
    state: SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.SUCCEEDED,
    releaseWitnessRefs: ["witness:operator:released"],
  });
  assert.equal(releaseOperation.operation, SURFACE_APP.SERVICE_MANAGER_OPERATION.RELEASE);

  const digest = assertServiceManagerProofDigest({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_PROOF_DIGEST,
    digestId: "proof-digest:gateway:2026-05-17",
    operationId: operation.operationId,
    managerId: operation.managerId,
    subjectRef: operation.subjectRef,
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED,
    trainRef: "train:runtime-product:2026-05-17",
    releaseRef: "release:gateway:2026-05-17",
    commitRefs: ["git:gateway:4c9a49c"],
    artifactRefs: ["artifact:gateway:ci"],
    proofRefs: ["proof:gateway:linux", "proof:gateway:windows"],
    metricsRefs: ["metrics:spine:service-manager"],
    environmentRefs: ["env:github-actions"],
    serviceRefs: ["service:gateway"],
    safeFacts: {
      linux: "passed",
      windows: "passed",
    },
    observedAt: requestedAt + 80,
    expiresAt: requestedAt + 7200,
  });
  assert.equal(digest.state, SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED);

  const serviceManager = assertServiceManagerPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_POSTURE,
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    state: SURFACE_APP.SERVICE_MANAGER_POSTURE.READY,
    serviceRefs: ["service:gateway"],
    operationRefs: [operation.operationId],
    proofDigestRefs: [digest.digestId],
    issuedAt: requestedAt,
  });
  assert.deepEqual(serviceManager.operationRefs, [operation.operationId]);

  assert.throws(() => assertServiceManagerOperationPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_OPERATION_POSTURE,
    operationId: "operation:bad",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    requesterRef: "identity:operator",
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.ROLLBACK,
    state: SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.REQUESTED,
    requestedAt,
  }), /rollback operation requires rollbackRef/);
  assert.throws(() => assertServiceManagerOperationPosture({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_OPERATION_POSTURE,
    operationId: "operation:blocked",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    requesterRef: "identity:operator",
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.UPDATE,
    state: SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.BLOCKED,
    requestedAt,
  }), /blocked or failed operation requires blockedReasons/);
  assert.throws(() => assertServiceManagerOperationPosture({
    operationId: "operation:release-missing-ref",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    requesterRef: "identity:operator",
    operation: SURFACE_APP.SERVICE_MANAGER_OPERATION.RELEASE,
    state: SURFACE_APP.SERVICE_MANAGER_OPERATION_STATE.REQUESTED,
    requestedAt,
  }), /release operation requires releaseRef/);
  assert.throws(() => assertServiceManagerOperationPosture({
    ...operation,
    operationId: "operation:unresolved-runner",
    runnerRef: "member:gateway-manager",
  }), /resolved public key/);
  assert.throws(() => assertServiceManagerProofDigest({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_PROOF_DIGEST,
    digestId: "proof-digest:empty",
    operationId: operation.operationId,
    managerId: operation.managerId,
    subjectRef: operation.subjectRef,
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED,
    observedAt: requestedAt + 80,
  }), /proved proof digest requires artifactRefs or proofRefs/);
  assert.throws(() => assertServiceManagerProofDigest({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_PROOF_DIGEST,
    digestId: "proof-digest:leaky",
    operationId: operation.operationId,
    managerId: operation.managerId,
    subjectRef: operation.subjectRef,
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.BLOCKED,
    blockedReasons: ["secret-boundary"],
    safeFacts: {
      token: "inline-secret",
    },
    observedAt: requestedAt + 80,
  }), /unsafe safe fact key|forbidden protocol field/);
});

test("runner operations bind host fulfillment to grants, resources, secrets, release, and evidence", () => {
  const requestedAt = 1700000000;
  const operation = assertRunnerOperation({
    kind: SWARM.RECORD_KIND.RUNNER_OPERATION,
    operationId: "runner-operation:cybersec-bootstrap:execute:1",
    runnerId: "runner:lab-gateway:cybersec-bootstrap",
    runnerRef: BROWSER_PK,
    hostRef: "host:lab-gateway",
    requesterRef: "identity:aux",
    subjectRef: "cybersec-processor:dev",
    contractRef: "cybersec-processor:seed@0.1.0",
    operation: RUNNER.OPERATION.EXECUTE,
    state: RUNNER.OPERATION_STATE.SUCCEEDED,
    grantRefs: ["authority-grant:runner:cybersec-bootstrap"],
    capabilityRefs: ["app.runner.pin"],
    inputRefs: ["event-fabric:cybersec-audit"],
    outputRefs: ["alert-hold:cybersec-bootstrap:1"],
    evidenceRefs: ["evidence:runner:started", "evidence:runner:completed"],
    proofRefs: ["proof:runner:cybersec-bootstrap"],
    releaseRefs: ["release:runner:cybersec-bootstrap"],
    resourceBudget: {
      profileRef: "resource-profile:operator-dev",
      maxMemoryMiB: 512,
      maxCpuPct: 40,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:cybersec-bootstrap",
      profileId: "resource-profile:operator-dev",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 120, cpuPct: 8 },
      budgets: { memoryMiB: 512, cpuPct: 40 },
      sampledAt: requestedAt + 15,
    },
    secretBoundary: {
      state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED,
    },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:runner:cybersec-bootstrap",
      releaseRef: "release:runner:cybersec-bootstrap",
      rollbackRef: "rollback:runner:cybersec-bootstrap",
    },
    releaseRef: "release:runner:cybersec-bootstrap",
    rollbackRef: "rollback:runner:cybersec-bootstrap",
    safeFacts: {
      role: "cybersecProcessor",
      mode: "operatorDev",
    },
    requestedAt,
    acceptedAt: requestedAt + 1,
    startedAt: requestedAt + 2,
    completedAt: requestedAt + 12,
    observedAt: requestedAt + 15,
    expiresAt: requestedAt + 3600,
  });
  assert.equal(operation.operation, RUNNER.OPERATION.EXECUTE);
  assert.equal(operation.resourcePosture.state, SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET);

  const hostPosture = assertRunnerHostFulfillmentPosture({
    kind: SWARM.RECORD_KIND.RUNNER_HOST_FULFILLMENT_POSTURE,
    postureId: "runner-host:lab-gateway:cybersec-bootstrap:execute:1",
    runnerId: operation.runnerId,
    runnerRef: operation.runnerRef,
    hostRef: operation.hostRef,
    operationId: operation.operationId,
    operation: operation.operation,
    state: RUNNER.HOST_FULFILLMENT_STATE.SUCCEEDED,
    requesterRef: operation.requesterRef,
    subjectRef: operation.subjectRef,
    contractRef: operation.contractRef,
    serviceRefs: ["service:cybersec-bootstrap"],
    contractRefs: [operation.contractRef],
    grantRefs: operation.grantRefs,
    capabilityRefs: operation.capabilityRefs,
    inputRefs: operation.inputRefs,
    outputRefs: operation.outputRefs,
    evidenceRefs: ["evidence:runner-host:accepted", "evidence:runner-host:completed"],
    proofRefs: operation.proofRefs,
    releaseRefs: operation.releaseRefs,
    witnessRefs: ["witness:runner-host:observed"],
    resourceBudget: operation.resourceBudget,
    resourcePosture: operation.resourcePosture,
    secretBoundary: operation.secretBoundary,
    releasePosture: operation.releasePosture,
    releaseRef: operation.releaseRef,
    safeFacts: {
      hostRef: operation.hostRef,
      serviceHostIdentitySeparated: operation.hostRef !== operation.contractRef,
    },
    observedAt: requestedAt + 12,
    expiresAt: requestedAt + 3600,
  });
  assert.equal(hostPosture.hostRef, "host:lab-gateway");
  assert.notEqual(hostPosture.hostRef, hostPosture.contractRef);

  assert.throws(() => assertRunnerOperation({
    ...operation,
    operationId: "runner-operation:bad:grantless",
    grantRefs: [],
  }), /runner operation grantRefs must not be empty/);

  assert.throws(() => assertRunnerOperation({
    ...operation,
    operationId: "runner-operation:bad:rollback",
    operation: RUNNER.OPERATION.ROLLBACK,
    rollbackRef: "",
  }), /runner rollback operation requires rollbackRef/);

  assert.throws(() => assertRunnerOperation({
    ...operation,
    operationId: "runner-operation:bad:blocked",
    state: RUNNER.OPERATION_STATE.BLOCKED,
    blockedReasons: [],
  }), /blocked, failed, or rejected operation requires blockedReasons/);

  assert.throws(() => assertRunnerOperation({
    ...operation,
    operationId: "runner-operation:bad:secret",
    safeFacts: { token: "inline-secret" },
  }), /unsafe safe fact key|forbidden protocol field/);

  assert.throws(() => assertRunnerHostFulfillmentPosture({
    ...hostPosture,
    postureId: "runner-host:bad:secret",
    safeFacts: { token: "nope" },
  }), /unsafe.*token|runner host fulfillment posture/);

  assert.throws(() => assertRunnerHostFulfillmentPosture({
    ...hostPosture,
    postureId: "runner-host:bad:blocked",
    state: RUNNER.HOST_FULFILLMENT_STATE.BLOCKED,
    blockedReasons: [],
  }), /requires blockedReasons/);
});

test("host fabric records separate association, composition, lifecycle, source truth, and unique edges", () => {
  const observedAt = 1700000040;
  const handoff = assertSubstrateAssociationHandoff({
    kind: SWARM.RECORD_KIND.SUBSTRATE_ASSOCIATION_HANDOFF,
    handoffId: "handoff:lab-gateway:initial-owner",
    substrateRef: "substrate:first-trust:lab",
    hostRef: "host:lab-gateway",
    ownerRef: "identity:aux",
    fabricRef: "fabric:lab-gateway",
    state: FABRIC.ASSOCIATION_HANDOFF_STATE.HANDED_OFF,
    initialAssociationRefs: ["association:substrate:aux:lab-gateway"],
    gatewayAssociationRefs: ["association:gateway:lab-gateway:ongoing"],
    evidenceRefs: ["evidence:substrate:verified"],
    safeFacts: { handoff: "substrate-to-gateway-association" },
    issuedAt: observedAt - 10,
    handedOffAt: observedAt - 1,
    expiresAt: observedAt + 3600,
  });
  assert.equal(handoff.state, FABRIC.ASSOCIATION_HANDOFF_STATE.HANDED_OFF);

  const memberContribution = assertHostFabricMemberContribution({
    kind: SWARM.RECORD_KIND.HOST_FABRIC_MEMBER_CONTRIBUTION,
    contributionId: "fabric-contribution:gateway-association:1",
    fabricRef: "fabric:lab-gateway",
    hostRef: "host:lab-gateway",
    memberRef: BROWSER_PK,
    role: FABRIC.MEMBER_ROLE.GATEWAY_ASSOCIATION,
    state: FABRIC.MEMBER_CONTRIBUTION_STATE.RUNNING,
    contractRef: "contract:gateway-association@0.1.0",
    subjectRef: "association:gateway:lab-gateway:ongoing",
    capabilityRefs: ["gateway.association.fulfill"],
    grantRefs: ["grant:gateway-association:fulfill"],
    evidenceRefs: ["evidence:gateway-association:presence"],
    lifecyclePlanRefs: ["lifecycle-plan:gateway-association:1"],
    safeFacts: { role: "gatewayAssociation" },
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(memberContribution.role, FABRIC.MEMBER_ROLE.GATEWAY_ASSOCIATION);

  const lifecycle = assertLifecyclePlanPosture({
    kind: SWARM.RECORD_KIND.LIFECYCLE_PLAN_POSTURE,
    lifecyclePlanId: "lifecycle-plan:gateway-association:1",
    subjectRef: "association:gateway:lab-gateway:ongoing",
    contractRef: "contract:lifecycle.gateway-association@0.1.0",
    state: FABRIC.LIFECYCLE_PLAN_STATE.READY,
    lifecycleContractRefs: ["contract:lifecycle.gateway-association@0.1.0"],
    phasePostures: [
      { phase: FABRIC.LIFECYCLE_PHASE.SOURCE, state: FABRIC.LIFECYCLE_PHASE_STATE.READY, evidenceRefs: ["evidence:source:indexed"] },
      { phase: FABRIC.LIFECYCLE_PHASE.RUN, state: FABRIC.LIFECYCLE_PHASE_STATE.RUNNING, evidenceRefs: ["evidence:association:running"] },
      { phase: FABRIC.LIFECYCLE_PHASE.OBSERVE, state: FABRIC.LIFECYCLE_PHASE_STATE.READY, evidenceRefs: ["evidence:association:observed"] },
    ],
    memberContributionRefs: [memberContribution.contributionId],
    evidenceRefs: ["evidence:lifecycle:reduced"],
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(lifecycle.phasePostures.length, 3);

  const plan = assertHostFabricFulfillmentPlan({
    kind: SWARM.RECORD_KIND.HOST_FABRIC_FULFILLMENT_PLAN,
    planId: "fabric-plan:lab-gateway:association",
    fabricRef: "fabric:lab-gateway",
    hostRef: "host:lab-gateway",
    contractRef: "contract:gateway-association@0.1.0",
    state: FABRIC.FULFILLMENT_PLAN_STATE.READY,
    requiredRoleRefs: ["role:gatewayAssociation"],
    memberContributionRefs: [memberContribution.contributionId],
    lifecyclePlanRefs: [lifecycle.lifecyclePlanId],
    materializationBudgetRefs: ["materialization-budget:gateway-association"],
    associationHandoffRef: handoff.handoffId,
    evidenceRefs: ["evidence:fabric:plan-ready"],
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(plan.memberContributionRefs[0], memberContribution.contributionId);

  const associationBoundary = assertAssociationBoundaryProof({
    kind: SWARM.RECORD_KIND.ASSOCIATION_BOUNDARY_PROOF,
    proofId: "association-boundary-proof:lab-gateway",
    hostRef: "host:lab-gateway",
    ownerRef: "identity:aux",
    fabricRef: "fabric:lab-gateway",
    state: FABRIC.ASSOCIATION_BOUNDARY_PROOF_STATE.READY,
    substrateHandoffRef: handoff.handoffId,
    initialAssociationRefs: handoff.initialAssociationRefs,
    gatewayAssociationRefs: handoff.gatewayAssociationRefs,
    routeAssociationRefs: ["route-association:gateway:lab-gateway"],
    servicePresenceRefs: ["service-presence:nvr:lab-gateway"],
    membershipRefs: ["member-presence:service:nvr:lab-gateway"],
    fabricPlanRefs: [plan.planId],
    evidenceRefs: ["evidence:association-boundary:distinct"],
    safeFacts: { phaseSplit: "substrate-gateway-route-service-membership" },
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(associationBoundary.routeAssociationRefs[0], "route-association:gateway:lab-gateway");

  const contentIndex = assertContentIndexRefPosture({
    kind: SWARM.RECORD_KIND.CONTENT_INDEX_REF_POSTURE,
    postureId: "content-index-posture:gateway-association",
    contentIndexRef: "content-index:gateway-association@0.1.0",
    state: FABRIC.CONTENT_INDEX_STATE.READY,
    sourceRefs: ["source:gateway-association:contract"],
    materializedProjectionRefs: ["projection:gateway-association:hot"],
    storageRefs: ["storage:pin:gateway-association:contract"],
    schemaRefs: ["schema:content-index:v1"],
    evidenceRefs: ["evidence:content-index:materialized"],
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(contentIndex.sourceRefs[0], "source:gateway-association:contract");

  const intention = assertContractIntentionPosture({
    kind: SWARM.RECORD_KIND.CONTRACT_INTENTION_POSTURE,
    postureId: "contract-intention-posture:gateway-association",
    intentionRef: "contract-intention:gateway-association@0.1.0",
    state: FABRIC.CONTRACT_INTENTION_STATE.READY,
    canonicalHashRef: "hash:contract-intention:gateway-association",
    contentIndexRefs: [contentIndex.contentIndexRef],
    sourceGraphRefs: ["source:graph:gateway-association"],
    sourceSnapshotRefs: ["source:snapshot:gateway-association:head"],
    branchRefs: ["branch:main"],
    tagRefs: ["tag:gateway-association@0.1.0"],
    releaseRefs: ["release:gateway-association@0.1.0"],
    projectRefs: ["project:constituency"],
    workItemRefs: ["work-item:msa-transition"],
    buildTargetRefs: ["build-target:gateway-association"],
    buildProfileRefs: ["build-profile:rust-lib"],
    buildRefs: ["build:gateway-association:protocol-proof"],
    storageRefs: contentIndex.storageRefs,
    storagePinRefs: ["storage:pin:gateway-association:contract"],
    storageAvailabilityRefs: ["storage:availability:gateway-association:contract"],
    rollbackRefs: ["rollback:gateway-association@0.1.0"],
    cleanupRefs: ["cleanup:gateway-association:expired-builds"],
    compatibilityRefs: ["compat:protocol:0.1.0"],
    authoringSurfaceRefs: ["authoring:typed-library"],
    proofGateRefs: ["proof-gate:protocol-validated"],
    reducerRefs: ["reducer:gateway-association"],
    evidenceRefs: ["evidence:intention:signed"],
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(intention.contentIndexRefs[0], contentIndex.contentIndexRef);

  const uniqueEdge = assertUniqueEdgeClassification({
    kind: SWARM.RECORD_KIND.UNIQUE_EDGE_CLASSIFICATION,
    classificationId: "unique-edge:host-service-adapter:systemd",
    subjectRef: "adapter:host-service:systemd",
    state: FABRIC.UNIQUE_EDGE_CLASSIFICATION.UNIQUE_EDGE,
    externalRealityRef: "external:host-os:systemd",
    interactionRef: "interaction:service-lifecycle:systemd-unit",
    policyRefs: ["policy:host-service-adapter"],
    grantRefs: ["grant:host-service-adapter"],
    evidenceRefs: ["evidence:systemd:unit-state"],
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(uniqueEdge.state, FABRIC.UNIQUE_EDGE_CLASSIFICATION.UNIQUE_EDGE);

  const genericPrimitive = assertUniqueEdgeClassification({
    kind: SWARM.RECORD_KIND.UNIQUE_EDGE_CLASSIFICATION,
    classificationId: "unique-edge:runtime-client:generic",
    subjectRef: "module:runtime-client",
    state: FABRIC.UNIQUE_EDGE_CLASSIFICATION.GENERIC_PRIMITIVE,
    primitiveRef: "primitive:surface-runtime-client",
    evidenceRefs: ["evidence:runtime-client:generic"],
    observedAt,
    expiresAt: observedAt + 600,
  });
  assert.equal(genericPrimitive.primitiveRef, "primitive:surface-runtime-client");

  assert.throws(() => assertSubstrateAssociationHandoff({
    ...handoff,
    gatewayAssociationRefs: [],
  }), /gatewayAssociationRefs/);
  assert.throws(() => assertAssociationBoundaryProof({
    ...associationBoundary,
    membershipRefs: associationBoundary.gatewayAssociationRefs,
  }), /collapses phase ref/);
  assert.throws(() => assertAssociationBoundaryProof({
    ...associationBoundary,
    routeAssociationRefs: [],
  }), /routeAssociationRefs/);
  assert.throws(() => assertLifecyclePlanPosture({
    ...lifecycle,
    lifecyclePlanId: "lifecycle-plan:bad:blocked",
    state: FABRIC.LIFECYCLE_PLAN_STATE.BLOCKED,
    blockedReasons: [],
  }), /requires blockedReasons/);
  assert.throws(() => assertContentIndexRefPosture({
    ...contentIndex,
    postureId: "content-index-posture:bad:storage-only",
    sourceRefs: [],
  }), /requires sourceRefs/);
  assert.throws(() => assertContractIntentionPosture({
    ...intention,
    postureId: "contract-intention-posture:bad:no-hash",
    canonicalHashRef: "",
  }), /canonicalHashRef/);
  assert.throws(() => assertUniqueEdgeClassification({
    ...uniqueEdge,
    classificationId: "unique-edge:bad:no-external",
    externalRealityRef: "",
  }), /externalRealityRef/);
  assert.throws(() => assertHostFabricMemberContribution({
    ...memberContribution,
    contributionId: "fabric-contribution:bad:secret",
    safeFacts: { token: "nope" },
  }), /unsafe safe fact key|forbidden protocol field/);
});

test("contract targets declare platform branch adapter slots and proof posture", () => {
  const issuedAt = 1700000050;
  const target = assertContractTarget({
    kind: SWARM.RECORD_KIND.CONTRACT_TARGET,
    targetRef: "contract-target:desktop-dev:msa-transition",
    contractRef: "app:contract:nvr@0.1.0",
    profileRef: "host-profile:desktop",
    platformRef: "platform:windows",
    substrateRef: "substrate:desktop-dev",
    hostRef: "host:local-workstation",
    state: FABRIC.CONTRACT_TARGET_STATE.DEGRADED,
    compatibilityState: FABRIC.CONTRACT_TARGET_COMPATIBILITY_STATE.COMPATIBLE,
    modifierRefs: ["modifier:dev"],
    branchRefs: ["branch:0x/msa-transition"],
    subbranchRefs: ["subbranch:target-contract"],
    capabilitySlotRefs: [
      "slot:runtime",
      "slot:gateway",
      "slot:nvr-service",
      "slot:nvr-surface",
    ],
    adapterPackRef: "adapter-pack:desktop-dev",
    adapterRefs: ["adapter:webrtc:browser", "adapter:host-service:windows"],
    negativeSlotRefs: ["slot:native-client"],
    degradedSlotRefs: ["slot:operator-proof-focus"],
    proofProfileRefs: ["proof-profile:nvr-smoke-5s", "proof-profile:long-stream-10m"],
    proofRefs: ["proof:nvr-smoke-5s:20260522"],
    compatibilityRefs: ["compat:runtime-2.56"],
    evidenceRefs: ["evidence:target:selected"],
    targetAudience: "developer",
    safeFacts: { profile: "desktop-dev" },
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(target.negativeSlotRefs[0], "slot:native-client");
  assert.equal(target.compatibilityState, FABRIC.CONTRACT_TARGET_COMPATIBILITY_STATE.COMPATIBLE);

  assert.throws(() => assertContractTarget({
    ...target,
    targetRef: "contract-target:bad:ready-with-missing",
    state: FABRIC.CONTRACT_TARGET_STATE.READY,
    missingSlotRefs: ["slot:gateway"],
  }), /missingSlotRefs/);
  assert.throws(() => assertContractTarget({
    ...target,
    targetRef: "contract-target:bad:incompatible",
    compatibilityState: FABRIC.CONTRACT_TARGET_COMPATIBILITY_STATE.INCOMPATIBLE,
    blockedReasons: [],
  }), /blockedReasons/);
  assert.throws(() => assertContractTarget({
    ...target,
    targetRef: "contract-target:bad:secret",
    safeFacts: { token: "nope" },
  }), /unsafe safe fact key|forbidden protocol field/);
});

test("contract target registry posture maps slots to candidates and blockers", () => {
  const observedAt = 1700000060;
  const registry = assertContractTargetRegistryPosture({
    kind: SWARM.RECORD_KIND.CONTRACT_TARGET_REGISTRY_POSTURE,
    registryRef: "contract-target-registry:desktop-dev:msa-transition",
    targetRef: "contract-target:desktop-dev:msa-transition",
    contractRef: "app:contract:nvr@0.1.0",
    state: FABRIC.CONTRACT_TARGET_REGISTRY_STATE.DEGRADED,
    slotPostures: [
      {
        slotRef: "slot:runtime",
        state: FABRIC.CONTRACT_TARGET_SLOT_STATE.AVAILABLE,
        platformFitState: FABRIC.CONTRACT_TARGET_PLATFORM_FIT_STATE.COMPATIBLE,
        candidateFulfillmentRefs: ["fulfillment:runtime:browser"],
        selectedFulfillmentRef: "fulfillment:runtime:browser",
        sourceRefs: ["content-index:runtime-client"],
        buildRefs: ["build:runtime-client:local"],
        platformRefs: ["platform:browser"],
        adapterRefs: ["adapter:runtime-surface-client"],
        proofRequirementRefs: ["proof-requirement:surface-load"],
        proofRefs: ["proof:nvr-smoke-5s:20260522"],
        evidenceRefs: ["evidence:runtime:attached"],
      },
      {
        slotRef: "slot:native-client",
        state: FABRIC.CONTRACT_TARGET_SLOT_STATE.NOT_REQUIRED,
        platformFitState: FABRIC.CONTRACT_TARGET_PLATFORM_FIT_STATE.UNKNOWN,
      },
      {
        slotRef: "slot:operator-focus",
        state: FABRIC.CONTRACT_TARGET_SLOT_STATE.DEGRADED,
        platformFitState: FABRIC.CONTRACT_TARGET_PLATFORM_FIT_STATE.COMPATIBLE,
        candidateFulfillmentRefs: ["fulfillment:operator:aux-firefox"],
        evidenceRefs: ["evidence:operator:focus-repaired"],
      },
    ],
    candidateFulfillmentRefs: ["fulfillment:runtime:browser", "fulfillment:operator:aux-firefox"],
    sourceRefs: ["content-index:nvr-surface"],
    buildRefs: ["build:nvr-surface:local"],
    adapterRefs: ["adapter:webrtc:browser"],
    proofRequirementRefs: ["proof-requirement:long-stream-10m"],
    proofRefs: ["proof:long-stream-10m:20260522"],
    evidenceRefs: ["evidence:registry:reduced"],
    safeFacts: { target: "desktop-dev" },
    observedAt,
    expiresAt: observedAt + 3600,
  });
  assert.equal(registry.slotPostures.length, 3);
  assert.equal(registry.slotPostures[0].candidateFulfillmentRefs[0], "fulfillment:runtime:browser");

  assert.throws(() => assertContractTargetRegistryPosture({
    ...registry,
    registryRef: "contract-target-registry:bad:ready-with-degraded-slot",
    state: FABRIC.CONTRACT_TARGET_REGISTRY_STATE.READY,
  }), /ready contract target registry posture/);
  assert.throws(() => assertContractTargetRegistryPosture({
    ...registry,
    registryRef: "contract-target-registry:bad:available-without-candidate",
    slotPostures: [{
      slotRef: "slot:runtime",
      state: FABRIC.CONTRACT_TARGET_SLOT_STATE.AVAILABLE,
      platformFitState: FABRIC.CONTRACT_TARGET_PLATFORM_FIT_STATE.COMPATIBLE,
      candidateFulfillmentRefs: [],
    }],
  }), /candidateFulfillmentRefs/);
  assert.throws(() => assertContractTargetRegistryPosture({
    ...registry,
    registryRef: "contract-target-registry:bad:blocked",
    state: FABRIC.CONTRACT_TARGET_REGISTRY_STATE.BLOCKED,
    blockedReasons: [],
  }), /blockedReasons/);
  assert.throws(() => assertContractTargetRegistryPosture({
    ...registry,
    registryRef: "contract-target-registry:bad:secret",
    safeFacts: { secret: "nope" },
  }), /unsafe safe fact key|forbidden protocol field/);
});

test("local workstation contract target vector validates desktop dev proof posture", () => {
  const vector = JSON.parse(readFileSync(new URL("../vectors/contract-target-local-workstation-v1.json", import.meta.url), "utf8"));
  const target = assertContractTarget(vector.target);
  const registry = assertContractTargetRegistryPosture(vector.registry);

  assert.equal(target.platformRef, "platform:windows.desktop");
  assert.deepEqual(target.branchRefs, ["branch:0x/msa-transition"]);
  assert.deepEqual(target.negativeSlotRefs, ["slot:native-client"]);
  assert.equal(registry.state, FABRIC.CONTRACT_TARGET_REGISTRY_STATE.READY);
  assert.equal(
    registry.slotPostures.find((slot) => slot.slotRef === "slot:native-client")?.state,
    FABRIC.CONTRACT_TARGET_SLOT_STATE.NOT_REQUIRED,
  );
  assert.ok(registry.proofRefs.includes("proof:long-stream-10m:20260522T074937Z"));
});

test("lab linux contract target vector marks host slots apart from protected client proof", () => {
  const vector = JSON.parse(readFileSync(new URL("../vectors/contract-target-lab-linux-v1.json", import.meta.url), "utf8"));
  const target = assertContractTarget(vector.target);
  const registry = assertContractTargetRegistryPosture(vector.registry);

  assert.equal(target.platformRef, "platform:linux.lab");
  assert.equal(target.state, FABRIC.CONTRACT_TARGET_STATE.SELECTED);
  assert.equal(target.compatibilityState, FABRIC.CONTRACT_TARGET_COMPATIBILITY_STATE.DEGRADED);
  assert.ok(target.missingSlotRefs.includes("slot:runtime-client"));
  assert.ok(target.missingSlotRefs.includes("slot:lab-proof-automation"));
  assert.equal(registry.state, FABRIC.CONTRACT_TARGET_REGISTRY_STATE.DEGRADED);
  assert.equal(
    registry.slotPostures.find((slot) => slot.slotRef === "slot:gateway")?.state,
    FABRIC.CONTRACT_TARGET_SLOT_STATE.AVAILABLE,
  );
  assert.equal(
    registry.slotPostures.find((slot) => slot.slotRef === "slot:lab-proof-automation")?.state,
    FABRIC.CONTRACT_TARGET_SLOT_STATE.MISSING,
  );
  assert.ok(registry.proofRequirementRefs.includes("proof-requirement:lab-live"));
});

test("multi-gateway contract target vector keeps candidates in registry and fabric contributions", () => {
  const vector = JSON.parse(readFileSync(new URL("../vectors/contract-target-multi-gateway-v1.json", import.meta.url), "utf8"));
  const target = assertContractTarget(vector.target);
  const registry = assertContractTargetRegistryPosture(vector.registry);
  const contributions = vector.hostFabricContributions.map(assertHostFabricMemberContribution);
  const plan = assertHostFabricFulfillmentPlan(vector.fulfillmentPlan);

  assert.equal(target.state, FABRIC.CONTRACT_TARGET_STATE.READY);
  const gatewaySlot = registry.slotPostures.find((slot) => slot.slotRef === "slot:gateway-association");
  assert.equal(gatewaySlot.state, FABRIC.CONTRACT_TARGET_SLOT_STATE.AVAILABLE);
  assert.equal(gatewaySlot.candidateFulfillmentRefs.length, 2);
  assert.equal(gatewaySlot.selectedFulfillmentRef, "fulfillment:gateway-association:local-dev");
  assert.equal(contributions.filter((entry) => entry.role === FABRIC.MEMBER_ROLE.GATEWAY_ASSOCIATION).length, 2);
  assert.equal(contributions.find((entry) => entry.role === FABRIC.MEMBER_ROLE.SERVICE_EDGE_ADAPTER)?.subjectRef, "service:nvr");
  assert.equal(plan.state, FABRIC.FULFILLMENT_PLAN_STATE.READY);
  assert.ok(plan.memberContributionRefs.includes("fabric-contribution:gateway-association:lab-dev"));
  assert.ok(!registry.slotPostures.some((slot) => slot.safeFacts?.serviceIdentityMutation));
});

test("app runner fulfillment reports reduce operation lifecycle, release, resources, and proof", () => {
  const observedAt = 1700000020;
  const report = assertAppRunnerFulfillmentReport({
    kind: SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_REPORT,
    reportId: "app-runner:runner:app-proof:runner-operation:app-proof:execute:1",
    runnerId: "runner:lab-gateway:app-proof",
    runnerRef: BROWSER_PK,
    hostRef: "host:lab-gateway",
    runnerOperationId: "runner-operation:app-proof:execute:1",
    operation: RUNNER.OPERATION.EXECUTE,
    state: RUNNER.FULFILLMENT_STATE.SUCCEEDED,
    requesterRef: "identity:aux",
    subjectRef: "app:runner-proof",
    contractRef: "app:runner-proof",
    appContractRef: "app:runner-proof",
    appId: "constitute-runner-proof",
    version: "0.1.0",
    manifestRef: "manifest:runner-proof",
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
    sourceRefs: ["bundle:runner-proof@0.1.0"],
    grantRefs: ["grant:app:runner-proof:run"],
    capabilityRefs: ["app.runner.pin"],
    inputRefs: ["manifest:runner-proof", "app:runner-proof"],
    outputRefs: ["artifact:runner-proof:dist"],
    evidenceRefs: ["evidence:runner:accepted", "evidence:runner:completed"],
    proofRefs: ["proof:runner-proof:surface"],
    releaseRefs: ["release:runner-proof"],
    resourceBudget: {
      profileRef: "resource-profile:operator-dev",
      maxMemoryMiB: 256,
      maxCpuPct: 25,
    },
    resourcePosture: {
      kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
      postureId: "resource-posture:runner:app-proof",
      profileId: "resource-profile:operator-dev",
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { memoryMiB: 96, cpuPct: 4 },
      budgets: { memoryMiB: 256, cpuPct: 25 },
      sampledAt: observedAt,
    },
    secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:runner-proof",
      releaseRef: "release:runner-proof",
      rollbackRef: "rollback:runner-proof",
    },
    rollbackPosture: null,
    releaseRef: "release:runner-proof",
    rollbackRef: "rollback:runner-proof",
    operationPosture: {
      state: RUNNER.FULFILLMENT_STATE.SUCCEEDED,
      accepted: true,
      requestedAt: observedAt - 20,
      acceptedAt: observedAt - 18,
      startedAt: observedAt - 15,
      completedAt: observedAt - 1,
      observedAt,
    },
    fulfillmentPosture: {
      state: RUNNER.FULFILLMENT_STATE.SUCCEEDED,
      outputRefs: ["artifact:runner-proof:dist"],
      releaseRefs: ["release:runner-proof"],
      proofRefs: ["proof:runner-proof:surface"],
      evidenceRefs: ["evidence:runner:completed"],
    },
    hostFulfillmentPosture: {
      kind: SWARM.RECORD_KIND.RUNNER_HOST_FULFILLMENT_POSTURE,
      postureId: "runner-host:lab-gateway:runner-proof:execute:1",
      runnerId: "runner:lab-gateway:app-proof",
      runnerRef: BROWSER_PK,
      hostRef: "host:lab-gateway",
      operationId: "runner-operation:app-proof:execute:1",
      operation: RUNNER.OPERATION.EXECUTE,
      state: RUNNER.HOST_FULFILLMENT_STATE.SUCCEEDED,
      requesterRef: "identity:aux",
      subjectRef: "app:runner-proof",
      contractRef: "app:runner-proof",
      serviceRefs: ["app:runner-proof"],
      contractRefs: ["app:runner-proof"],
      grantRefs: ["grant:app:runner-proof:run"],
      capabilityRefs: ["app.runner.pin"],
      inputRefs: ["manifest:runner-proof", "app:runner-proof"],
      outputRefs: ["artifact:runner-proof:dist"],
      evidenceRefs: ["evidence:runner-host:accepted", "evidence:runner-host:completed"],
      proofRefs: ["proof:runner-proof:surface"],
      releaseRefs: ["release:runner-proof"],
      resourceBudget: {
        profileRef: "resource-profile:operator-dev",
        maxMemoryMiB: 256,
        maxCpuPct: 25,
      },
      resourcePosture: {
        kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
        postureId: "resource-posture:runner:app-proof",
        profileId: "resource-profile:operator-dev",
        state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
        counts: { memoryMiB: 96, cpuPct: 4 },
        budgets: { memoryMiB: 256, cpuPct: 25 },
        sampledAt: observedAt,
      },
      secretBoundary: { state: SURFACE_APP.SECRET_BOUNDARY.NOT_REQUIRED },
      releasePosture: {
        state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
        buildRef: "build:runner-proof",
        releaseRef: "release:runner-proof",
        rollbackRef: "rollback:runner-proof",
      },
      releaseRef: "release:runner-proof",
      safeFacts: { serviceHostIdentitySeparated: true },
      observedAt,
      expiresAt: observedAt + 3600,
    },
    safeFacts: {
      appId: "constitute-runner-proof",
      version: "0.1.0",
      sourceMode: SURFACE_APP.FULFILLMENT_MODE.BUNDLED,
      outputRefCount: 1,
      releaseRefCount: 1,
      proofRefCount: 1,
    },
    blockedReasons: [],
    observedAt,
    expiresAt: observedAt + 3600,
  });
  assert.equal(report.state, RUNNER.FULFILLMENT_STATE.SUCCEEDED);
  assert.equal(report.resourcePosture.state, SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET);
  assert.equal(report.hostFulfillmentPosture.hostRef, "host:lab-gateway");

  const lifecycle = assertAppRunnerFulfillmentLifecycle({
    ...report,
    kind: SWARM.RECORD_KIND.APP_RUNNER_FULFILLMENT_LIFECYCLE,
    lifecycleId: "app-runner-lifecycle:runner-proof:execute:1",
    witnessRefs: ["witness:runner:operator"],
    releaseWitnessRefs: [],
    requestedAt: observedAt - 20,
    acceptedAt: observedAt - 18,
    startedAt: observedAt - 15,
    completedAt: observedAt - 1,
  });
  assert.equal(lifecycle.state, RUNNER.FULFILLMENT_STATE.SUCCEEDED);
  assert.equal(lifecycle.reportId, report.reportId);
  assert.deepEqual(lifecycle.witnessRefs, ["witness:runner:operator"]);

  const released = assertAppRunnerFulfillmentLifecycle({
    ...lifecycle,
    lifecycleId: "app-runner-lifecycle:runner-proof:release:1",
    state: RUNNER.FULFILLMENT_STATE.RELEASED,
    releaseRefs: ["release:runner-proof"],
    releasedAt: observedAt + 10,
    observedAt: observedAt + 10,
    expiresAt: observedAt + 3600,
  });
  assert.equal(released.state, RUNNER.FULFILLMENT_STATE.RELEASED);

  assert.throws(() => assertAppRunnerFulfillmentReport({
    ...report,
    reportId: "app-runner:bad:missing-proof",
    outputRefs: [],
    proofRefs: [],
  }), /succeeded app runner fulfillment requires outputRefs or proofRefs/);

  assert.throws(() => assertAppRunnerFulfillmentReport({
    ...report,
    reportId: "app-runner:bad:missing-source",
    sourceRefs: [],
  }), /succeeded app runner fulfillment requires sourceRefs/);

  assert.throws(() => assertAppRunnerFulfillmentReport({
    ...report,
    reportId: "app-runner:bad:blocked",
    state: RUNNER.FULFILLMENT_STATE.BLOCKED,
    operationPosture: { ...report.operationPosture, state: RUNNER.FULFILLMENT_STATE.BLOCKED },
    fulfillmentPosture: { ...report.fulfillmentPosture, state: RUNNER.FULFILLMENT_STATE.BLOCKED },
    blockedReasons: [],
  }), /blocked app runner fulfillment requires blockedReasons/);

  assert.throws(() => assertAppRunnerFulfillmentReport({
    ...report,
    reportId: "app-runner:bad:secret",
    safeFacts: { token: "inline-secret" },
  }), /unsafe safe fact key|forbidden protocol field/);

  assert.throws(() => assertAppRunnerFulfillmentLifecycle({
    ...lifecycle,
    lifecycleId: "app-runner-lifecycle:bad:expired",
    state: RUNNER.FULFILLMENT_STATE.EXPIRED,
    blockedReasons: [],
    expiredAt: observedAt + 3600,
  }), /blocked app runner fulfillment lifecycle requires blockedReasons/);
});

test("service manager protected contracts gate bootstrap, secrets, train, and lab proof", () => {
  const issuedAt = 1700000000;
  const secretBoundary = assertServiceManagerSecretBoundary({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_SECRET_BOUNDARY,
    boundaryId: "secret-boundary:lab-gateway",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    state: SURFACE_APP.SECRET_BOUNDARY.RESOLVED,
    secretRefs: ["secret:gateway-lab"],
    accessGroupRefs: ["access:ops:epoch-7"],
    authorityRefs: ["authority:ops-admin"],
    evidenceRefs: ["evidence:secret-resolution"],
    safeFacts: { posture: "resolved" },
    issuedAt,
    expiresAt: issuedAt + 3600,
  });
  assert.equal(secretBoundary.state, SURFACE_APP.SECRET_BOUNDARY.RESOLVED);

  const releaseContract = assertServiceManagerReleaseContract({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_RELEASE_CONTRACT,
    contractId: "release-contract:gateway:2026-05-18",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    state: SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY,
    appContractRef: "surface-app:gateway-ui@0.1.0",
    version: "2026.05.18",
    buildRef: "build:gateway:2026-05-18",
    contentIndexRefs: ["content-index:gateway-ui:2026-05-18"],
    sourceGraphRefs: ["source:graph:gateway-ui"],
    sourceSnapshotRefs: ["source:snapshot:gateway-ui:2026-05-18"],
    sourceOperationRefs: ["source:operation:gateway-ui:release"],
    projectRefs: ["project:constituency"],
    workItemRefs: ["work-item:surface-bootstrap:2026-05-18"],
    buildRunRefs: ["build:run:gateway:2026-05-18"],
    buildArtifactRefs: ["build:artifact:gateway-ui:2026-05-18"],
    buildProofRefs: ["build-proof:gateway:2026-05-18"],
    releaseCandidateRefs: ["release:candidate:gateway:2026-05-18"],
    releaseRef: "release:gateway:2026-05-18",
    rollbackRef: "rollback:gateway:previous",
    compatibilityRefs: ["protocol:surface-app:v1"],
    authorityRefs: ["authority:ops-admin"],
    secretBoundaryRefs: [secretBoundary.boundaryId],
    labProofRefs: ["lab-proof:gateway:surface-landscape"],
    releasePosture: {
      state: SURFACE_APP.RELEASE_POSTURE.ROLLBACK_READY,
      buildRef: "build:gateway:2026-05-18",
      releaseRef: "release:gateway:2026-05-18",
      rollbackRef: "rollback:gateway:previous",
    },
    safeFacts: { compatibility: "current" },
    issuedAt,
    expiresAt: issuedAt + 7200,
  });
  assert.equal(releaseContract.state, SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY);

  const labProof = assertServiceManagerLabProof({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_LAB_PROOF,
    proofId: "lab-proof:gateway:surface-landscape",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    profile: SURFACE_APP.SERVICE_MANAGER_PROOF_PROFILE.SURFACE_LANDSCAPE,
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED,
    trainRef: "train:surface-bootstrap:2026-05-18",
    releaseContractRef: releaseContract.contractId,
    appContractRef: "surface-app:gateway-ui@0.1.0",
    surfaceRefs: ["surface:account", "surface:gateway-ui"],
    serviceRefs: ["service:gateway"],
    environmentRefs: ["env:lab"],
    artifactRefs: ["artifact:proof:surface-landscape"],
    metricsRefs: ["metrics:proof:surface-landscape"],
    proofRefs: ["proof:surface-landscape:pass"],
    safeFacts: { profile: "surfaceLandscape", verdict: "passed" },
    startedAt: issuedAt + 10,
    completedAt: issuedAt + 610,
    observedAt: issuedAt + 620,
    expiresAt: issuedAt + 7200,
  });
  assert.equal(labProof.profile, SURFACE_APP.SERVICE_MANAGER_PROOF_PROFILE.SURFACE_LANDSCAPE);

  const trainDigest = assertServiceManagerTrainDigest({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_TRAIN_DIGEST,
    trainId: "train:surface-bootstrap:2026-05-18",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED,
    repoRefs: ["repo:constitute-gateway-ui", "repo:constitute-account"],
    commitRefs: ["git:gateway-ui:275e05b", "git:account:6a166fb"],
    appContractRefs: ["surface-app:gateway-ui@0.1.0"],
    releaseContractRefs: [releaseContract.contractId],
    labProofRefs: [labProof.proofId],
    metricsRefs: ["metrics:spine:service-bootstrap"],
    observedAt: issuedAt + 630,
    expiresAt: issuedAt + 7200,
  });
  assert.equal(trainDigest.state, SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED);

  const bootstrapContract = assertSurfaceAppBootstrapContract({
    kind: SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_CONTRACT,
    bootstrapContractId: "bootstrap-contract:gateway-ui",
    appContractRef: "surface-app:gateway-ui@0.1.0",
    appId: "constitute-gateway-ui",
    state: SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY,
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.SWARM_PACKAGE,
    moduleRefs: ["module:surface-runtime-client@0.1.0", "module:gateway-view@0.1.0"],
    serviceManagerRef: "manager:lab-gateway",
    releaseContractRef: releaseContract.contractId,
    secretBoundaryRef: secretBoundary.boundaryId,
    trainDigestRef: trainDigest.trainId,
    labProofProfileRefs: [SURFACE_APP.SERVICE_MANAGER_PROOF_PROFILE.SURFACE_LANDSCAPE],
    authorityRefs: ["authority:ops-admin"],
    evidenceRefs: ["evidence:bootstrap-resolution"],
    issuedAt,
    expiresAt: issuedAt + 7200,
  });
  assert.equal(bootstrapContract.sourceMode, SURFACE_APP.FULFILLMENT_MODE.SWARM_PACKAGE);

  assert.throws(() => assertServiceManagerSecretBoundary({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_SECRET_BOUNDARY,
    boundaryId: "secret-boundary:bad",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    state: SURFACE_APP.SECRET_BOUNDARY.RESOLVED,
    issuedAt,
  }), /resolved secret boundary requires secretRefs or accessGroupRefs/);
  assert.throws(() => assertServiceManagerReleaseContract({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_RELEASE_CONTRACT,
    contractId: "release-contract:bad",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    managerRef: "member:gateway-manager",
    state: SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY,
    buildRef: "build:gateway",
    releaseRef: "release:gateway",
    issuedAt,
  }), /ready release contract requires rollbackRef/);
  assert.throws(() => assertServiceManagerLabProof({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_LAB_PROOF,
    proofId: "lab-proof:bad",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    profile: SURFACE_APP.SERVICE_MANAGER_PROOF_PROFILE.SURFACE_LANDSCAPE,
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED,
    safeFacts: { token: "inline-secret" },
    startedAt: issuedAt,
  }), /proved lab proof requires artifactRefs|unsafe safe fact key/);
  assert.throws(() => assertServiceManagerTrainDigest({
    kind: SWARM.RECORD_KIND.SERVICE_MANAGER_TRAIN_DIGEST,
    trainId: "train:bad",
    managerId: "manager:lab-gateway",
    subjectRef: "service:gateway",
    state: SURFACE_APP.SERVICE_MANAGER_PROOF_STATE.PROVED,
    observedAt: issuedAt,
  }), /proved train digest requires releaseContractRefs/);
  assert.throws(() => assertSurfaceAppBootstrapContract({
    kind: SWARM.RECORD_KIND.SURFACE_APP_BOOTSTRAP_CONTRACT,
    bootstrapContractId: "bootstrap-contract:bad",
    appContractRef: "surface-app:gateway-ui@0.1.0",
    appId: "constitute-gateway-ui",
    state: SURFACE_APP.SERVICE_MANAGER_CONTRACT_STATE.READY,
    sourceMode: SURFACE_APP.FULFILLMENT_MODE.SWARM_PACKAGE,
    moduleRefs: ["module:surface-runtime-client@0.1.0"],
    issuedAt,
  }), /non-bundled bootstrap contract requires releaseContractRef/);
});

test("storage manifest helpers validate ciphertext-addressed objects", () => {
  const ciphertext = new TextEncoder().encode("encrypted bytes");
  const chunk = makeStorageChunkRef({ ciphertext });
  assertStorageChunkRef(chunk, ciphertext);
  const manifest = makeStorageObjectManifest({
    containerId: "container-a",
    keyRef: "container-a:key",
    chunks: [chunk],
    createdAt: 1700000000,
    tags: ["proof"],
  });
  assert.equal(manifest.hashAlg, STORAGE.OBJECT_HASH_ALG);
  assert.equal(manifest.encryptionAlg, STORAGE.ENCRYPTION_ALG_XCHACHA20POLY1305);
  assert.equal(manifest.objectId, storageObjectId({ containerId: "container-a", contentHash: manifest.contentHash }));
  assertStorageObjectManifest(manifest);

  const shard = {
    shardId: "shard-a",
    containerId: "container-a",
    shardType: "safe-log-facts",
    keyRef: "container-a:shard-a",
    ciphertextHash: storageCiphertextHash(ciphertext),
    hashAlg: STORAGE.OBJECT_HASH_ALG,
    chunks: [chunk],
    objectRefs: [manifest.objectId],
    graphEdges: [],
    createdAt: 1700000000,
  };
  assertStorageIndexShard(shard);
});

test("logging helpers validate safe event envelopes", () => {
  const event = makeLogEventEnvelope({
    occurredAt: 1700000000,
    producer: {
      service: "gateway",
      component: "managed",
      instanceId: "gateway-1",
    },
    category: LOGGING.CATEGORY.CAPABILITY,
    severity: LOGGING.SEVERITY.INFO,
    outcome: LOGGING.OUTCOME.SUCCEEDED,
    subject: {
      kind: "service",
      id: "nvr",
      display: "Security Cameras",
    },
    correlation: {
      correlationId: "corr-1",
    },
    tags: ["capability"],
    safeFacts: {
      service: "nvr",
      capabilityRef: "media.stream.preview",
      operation: "request",
      result: "accepted",
    },
    encryptedDetailRefs: [{
      objectId: "object-log-detail-1",
      containerId: "container-log-detail",
      keyRef: "container-log-detail:key",
      manifestHash: "sha256:manifest-log-detail",
      summaryTags: ["debug-detail"],
    }],
    redaction: [LOGGING.REDACTION.SAFE, LOGGING.REDACTION.ENCRYPTED_DETAIL],
  });
  assertLogEventEnvelope(event);
  assert.equal(event.encryptedDetailRefs.length, 1);

  const bad = structuredClone(event);
  bad.safeFacts.privateToken = "secret";
  bad.eventId = event.eventId;
  assert.throws(() => assertLogEventEnvelope(bad), /unsafe log safe fact key/);

  const badGrant = structuredClone(event);
  badGrant.safeFacts.capabilityGrant = "delegatedAuthorityGrant";
  badGrant.eventId = event.eventId;
  assert.throws(() => assertLogEventEnvelope(badGrant), /unsafe log safe fact key/);

  const mismatch = structuredClone(event);
  mismatch.eventId = "bad";
  assert.throws(() => assertLogEventEnvelope(mismatch), /log event id mismatch/);

  const badDetail = structuredClone(event);
  badDetail.encryptedDetailRefs = [{ objectId: "object-only" }];
  badDetail.eventId = event.eventId;
  assert.throws(() => assertLogEventEnvelope(badDetail), /encryptedDetailRefs entry missing containerId/);
});

test("logging evidence profiles declare cybersec custody without raw payload", () => {
  const profile = assertLogEvidenceProfile({
    kind: LOGGING.EVIDENCE_PROFILE_RECORD_KIND,
    profileId: "logging.cybersec.default",
    consumerRef: "constitute-cybersec",
    eventClasses: [
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.CYBERSEC_AUDIT,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.RUNTIME_DIAGNOSTIC,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.SERVICE_EVENT,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.STORAGE_ACCESS,
      LOGGING.EVIDENCE_PROFILE_EVENT_CLASS.MEDIA_PATH,
    ],
    retentionWindow: "90d",
    safeIndexRefs: ["logging.events.safeIndex", "logging.dashboard.cybersecSummary"],
    detailCustody: LOGGING.EVIDENCE_DETAIL_CUSTODY.ENCRYPTED_DETAIL_REF,
    encryptedDetailRequired: true,
    accessGrantRefs: ["grant:logging.cybersec.default"],
    storageContainerRefs: ["logging-archive"],
    materializationBudgetRef: "logging.cybersec.default.90d",
    issuedAt: 1700000000,
    expiresAt: 1707776000,
  });
  assert.equal(profile.consumerRef, "constitute-cybersec");
  assert.equal(profile.detailCustody, LOGGING.EVIDENCE_DETAIL_CUSTODY.ENCRYPTED_DETAIL_REF);

  assert.throws(() => assertLogEvidenceProfile({
    ...profile,
    accessGrantRefs: [],
  }), /requires accessGrantRefs/);
  assert.throws(() => assertLogEvidenceProfile({
    ...profile,
    eventClasses: ["debugEverything"],
  }), /invalid log evidence profile eventClass/);
  assert.throws(() => assertLogEvidenceProfile({
    ...profile,
    rawPayload: "forbidden",
  }), /forbidden protocol field/);
});

const TEST_COVERAGE = {
  materializedCount: 1,
  targetCount: 1,
  completionRatio: 1,
  syncState: PROJECTION.SYNC_STATE.COMPLETE_ENOUGH,
};

const TEST_FRESHNESS = {
  state: PROJECTION.FRESHNESS.FRESH,
  updatedAt: 1700000000,
};

test("swarm frame helpers validate CAAC-by-default frames and stable ids", () => {
  const frame = makeSwarmFrame({
    kind: SWARM.FRAME_KIND.SERVICE_INTENT,
    issuer: pubkeyFromSecretKey(BROWSER_SK),
    audience: { serviceRef: "svc_opaque_nvr" },
    zoneScope: { zoneId: "zone_lab", ttl: 30, maxHops: 2 },
    issuedAt: 1700000000000,
    expiresAt: 1700000090000,
    nonce: "nonce-1",
    correlationId: "corr-1",
    channelId: "nvr.control",
    capability: SWARM.CORE_CAPABILITY.SERVICE_INTENT_INVOKE,
    body: {
      encoding: SWARM.BODY_ENCODING.CAAC,
      envelope: { envelopeId: "env-1" },
    },
    now: 1700000001000,
  });
  assert.equal(assertSwarmFrame(frame, { now: 1700000001000 }), frame);
  assert.equal(frame.frameId, makeSwarmFrame({ ...frame, frameId: undefined, now: 1700000001000 }).frameId);

  assert.throws(() => assertSwarmFrame({
    ...frame,
    frameId: undefined,
    zoneScope: undefined,
  }, { now: 1700000001000 }), /zone scope/);

  assert.throws(() => assertSwarmFrame({
    ...frame,
    frameId: undefined,
    body: { encoding: SWARM.BODY_ENCODING.PUBLIC, publicBootstrap: true, payload: { service: "nvr" } },
  }, { now: 1700000001000 }), /public swarm frame body/);

  assert.throws(() => makeSwarmFrame({
    ...frame,
    frameId: undefined,
    capability: "bad capability",
    now: 1700000001000,
  }), /capability namespace/);
});

test("zones, channels, and dynamic capability directories validate", () => {
  assert.deepEqual(assertZoneScope({ zoneId: "zone_lab", privacy: "rawIds", ttl: 30 }), {
    zoneId: "zone_lab",
    privacy: "rawIds",
    ttl: 30,
  });
  assertCapabilityName("vendor.camera.focus");
  assert.throws(() => assertCapabilityName("Camera Focus"), /capability namespace/);

  const channel = assertChannelDescriptor({
    channelId: "storage.pin.lab",
    kind: SWARM.CHANNEL_RECORD_KIND.DESCRIPTOR,
    displayName: "Storage Pin Requests",
    capabilities: [SWARM.CORE_CAPABILITY.STORAGE_PIN, "vendor.storage.audit"],
    recordKinds: [SWARM.FRAME_KIND.STORAGE_PIN_INTENT],
    ownerRefs: ["identity:owner"],
    policyRef: "policy:storage.pin.lab",
    createdAt: 1700000000,
  });
  assert.equal(channel.channelId, "storage.pin.lab");

  assert.throws(() => assertChannelMembership({
    channelId: "storage.pin.lab",
    memberRef: BROWSER_PK,
    roles: ["bad role!"],
    authorityEnvelope: { envelopeId: "auth-1" },
  }), /membership role/);
  assert.throws(() => assertChannelMembership({
    channelId: "storage.pin.lab",
    memberRef: "storage-member-1",
    roles: ["observer"],
    authorityEnvelope: { envelopeId: "auth-1" },
  }), /resolved public key/);

  const definition = assertCapabilityDefinition({
    definitionId: "cap-storage-pin",
    namespace: "storage",
    capability: SWARM.CORE_CAPABILITY.STORAGE_PIN,
    schemaRef: "constitute.capability.storage.pin.v1",
    createdAt: 1700000000,
  });
  const dynamicDefinition = assertCapabilityDefinition({
    definitionId: "cap-vendor-focus",
    namespace: "vendor",
    capability: "vendor.camera.focus",
    createdAt: 1700000001,
  });
  const advertisement = assertCapabilityAdvertisement({
    advertisementId: "ad-1",
    capability: "vendor.camera.focus",
    serviceRef: "svc_opaque_camera",
    issuedAt: 1700000000,
    expiresAt: 1700000900,
  }, { now: 1700000001 });
  const expiredAdvertisement = {
    advertisementId: "ad-expired",
    capability: "vendor.camera.focus",
    serviceRef: "svc_opaque_camera",
    issuedAt: 1,
    expiresAt: 2,
  };
  const directory = buildCapabilityDirectoryProjection({
    definitions: [definition, dynamicDefinition],
    advertisements: [advertisement, expiredAdvertisement],
    entries: [
      { capability: "vendor.camera.focus", channelId: "camera.focus", serviceRef: "svc_opaque_camera" },
      { capability: SWARM.CORE_CAPABILITY.STORAGE_PIN, channelId: "storage.pin.lab", memberRef: BROWSER_PK },
    ],
    now: 1700000001,
  });
  assert.equal(directory.advertisements.length, 1);
  assert.deepEqual(directory.entries.map((entry) => entry.capability), [
    SWARM.CORE_CAPABILITY.STORAGE_PIN,
    "vendor.camera.focus",
  ]);
});

test("participant self-capability posture separates advertisement from actionability", () => {
  const advertisement = assertCapabilityAdvertisement({
    advertisementId: "ad-stream-preview",
    capability: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    memberRef: SERVICE_PK,
    issuedAt: 1700000000,
    expiresAt: 1700000900,
  }, { now: 1700000001 });
  assert.equal(advertisement.memberRef, SERVICE_PK);
  assert.throws(() => assertSelfCapabilityAssessment(advertisement), /self capability assessment id/);

  assertParticipantRunlevelPosture({
    kind: SWARM.RECORD_KIND.PARTICIPANT_RUNLEVEL,
    runlevelId: "runlevel-browser-1",
    participantRef: BROWSER_PK,
    participantKind: "browserRuntime",
    runlevel: SWARM.PARTICIPANT_RUNLEVEL.EDGE_ATTACHED,
    facets: {
      authority: { state: SWARM.POSTURE_FACET_STATE.READY },
      resource: { state: SWARM.POSTURE_FACET_STATE.READY },
    },
    updatedAt: 1700000001,
  });

  const baseFacets = {
    authority: { state: SWARM.POSTURE_FACET_STATE.READY },
    resource: { state: SWARM.POSTURE_FACET_STATE.READY },
    policy: { state: SWARM.POSTURE_FACET_STATE.READY },
    directory: { state: SWARM.POSTURE_FACET_STATE.READY },
    route: { state: SWARM.POSTURE_FACET_STATE.READY },
    adapter: { state: SWARM.POSTURE_FACET_STATE.NOT_REQUIRED },
    retention: { state: SWARM.POSTURE_FACET_STATE.NOT_REQUIRED },
    domain: { state: SWARM.POSTURE_FACET_STATE.READY },
  };

  assertSelfCapabilityAssessment({
    kind: SWARM.RECORD_KIND.PARTICIPANT_SELF_CAPABILITY,
    assessmentId: "self-cap-stream-available",
    participantRef: BROWSER_PK,
    participantKind: "browserRuntime",
    serviceMemberRef: SERVICE_PK,
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    actions: [SWARM.SELF_CAPABILITY_ACTION.REQUEST],
    status: SWARM.SELF_CAPABILITY_STATUS.AVAILABLE,
    runlevel: SWARM.PARTICIPANT_RUNLEVEL.ROUTE_READY,
    facets: baseFacets,
    updatedAt: 1700000002,
  });

  assertSelfCapabilityAssessment({
    kind: SWARM.RECORD_KIND.PARTICIPANT_SELF_CAPABILITY,
    assessmentId: "self-cap-stream-blocked",
    participantRef: BROWSER_PK,
    participantKind: "browserRuntime",
    serviceMemberRef: SERVICE_PK,
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    actions: [SWARM.SELF_CAPABILITY_ACTION.REQUEST],
    status: SWARM.SELF_CAPABILITY_STATUS.BLOCKED,
    runlevel: SWARM.PARTICIPANT_RUNLEVEL.EDGE_ATTACHED,
    facets: {
      ...baseFacets,
      route: { state: SWARM.POSTURE_FACET_STATE.MISSING, reason: "route baseline has not materialized" },
    },
    blockedReasons: ["missingRouteBaseline"],
    updatedAt: 1700000003,
  });

  assert.throws(() => assertSelfCapabilityAssessment({
    kind: SWARM.RECORD_KIND.PARTICIPANT_SELF_CAPABILITY,
    assessmentId: "self-cap-stream-bad",
    participantRef: "service:nvr",
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    actions: [SWARM.SELF_CAPABILITY_ACTION.REQUEST],
    status: SWARM.SELF_CAPABILITY_STATUS.AVAILABLE,
    runlevel: SWARM.PARTICIPANT_RUNLEVEL.ROUTE_READY,
    facets: baseFacets,
    updatedAt: 1700000004,
  }), /resolved public key/);

  assert.throws(() => assertSelfCapabilityAssessment({
    kind: SWARM.RECORD_KIND.PARTICIPANT_SELF_CAPABILITY,
    assessmentId: "self-cap-stream-impossible",
    participantRef: BROWSER_PK,
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    actions: [SWARM.SELF_CAPABILITY_ACTION.REQUEST],
    status: SWARM.SELF_CAPABILITY_STATUS.AVAILABLE,
    runlevel: SWARM.PARTICIPANT_RUNLEVEL.ROUTE_READY,
    facets: {
      ...baseFacets,
      resource: { state: SWARM.POSTURE_FACET_STATE.DEGRADED, reason: "memory pressure" },
    },
    updatedAt: 1700000005,
  }), /available self capability/);
});

test("resource posture and retention release blockers validate before cleanup", () => {
  assertResourceProfile({
    kind: SWARM.RECORD_KIND.RESOURCE_PROFILE,
    profileId: "profile-balanced",
    profileClass: SWARM.RESOURCE_PROFILE_CLASS.BALANCED,
    budgets: { memoryMb: 2048, storageMb: 1024 },
    caps: { diagnosticEvents: 2000, peerConnections: 2 },
    ownerRef: "account:center",
    issuedAt: 1700000000,
  });

  assertResourcePosture({
    kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
    postureId: "resource-browser-1",
    profileId: "profile-balanced",
    state: SWARM.RESOURCE_POSTURE_STATE.PRESSURE,
    counts: { diagnosticEvents: 1800, peerConnections: 2 },
    budgets: { diagnosticEvents: 2000, peerConnections: 2 },
    lanes: [{
      kind: SWARM.RECORD_KIND.INGRESS_LANE_POSTURE,
      laneId: "lane-activation",
      laneKind: "activation",
      priority: 10,
      state: SWARM.RESOURCE_POSTURE_STATE.WITHIN_BUDGET,
      counts: { inFlight: 1, filtered: 70 },
      limits: { inFlight: 2 },
      relevanceRefs: ["authority", "route", "activation"],
      sampledAt: 1700000001,
    }],
    blockedReasons: ["nearDiagnosticCap"],
    sampledAt: 1700000001,
  });

  assertIngressLanePosture({
    kind: SWARM.RECORD_KIND.INGRESS_LANE_POSTURE,
    laneId: "lane-diagnostics",
    laneKind: "diagnostics",
    priority: 80,
    state: SWARM.RESOURCE_POSTURE_STATE.PRESSURE,
    counts: { inFlight: 2, dropped: 299, filtered: 84 },
    limits: { inFlight: 2 },
    blockedReasons: ["diagnosticsBackpressure"],
    sampledAt: 1700000002,
  });

  assert.throws(() => assertIngressLanePosture({
    kind: SWARM.RECORD_KIND.INGRESS_LANE_POSTURE,
    laneId: "lane-bulk",
    laneKind: "bulkRetainedData",
    priority: 90,
    state: SWARM.RESOURCE_POSTURE_STATE.OVER_BUDGET,
    counts: { replayed: 400 },
    limits: { replayed: 50 },
    sampledAt: 1700000002,
  }), /blockedReasons/);

  assert.throws(() => assertResourcePosture({
    kind: SWARM.RECORD_KIND.RESOURCE_POSTURE,
    postureId: "resource-browser-bad",
    profileId: "profile-balanced",
    state: SWARM.RESOURCE_POSTURE_STATE.OVER_BUDGET,
    counts: { diagnosticEvents: 2200 },
    budgets: { diagnosticEvents: 2000 },
    sampledAt: 1700000002,
  }), /blockedReasons/);

  assertRetentionReleasePosture({
    kind: SWARM.RECORD_KIND.RETENTION_RELEASE,
    evaluationId: "release-camera-cache-blocked",
    subjectRef: "nvr:chunk:front:1700000000",
    effectiveRetention: "durable",
    state: SWARM.RETENTION_RELEASE_STATE.RELEASE_BLOCKED,
    policyRefs: ["policy:nvr-media-retention"],
    overlayRefs: ["overlay:operator-hold"],
    ownerRefs: ["identity:operator"],
    holderRefs: [BROWSER_PK],
    fulfillmentRefs: [],
    residencyLayers: ["browserHotCache"],
    witnessRefs: ["witness:runtime:observed"],
    blockers: [{ code: "missingFulfillment", ownerRef: "identity:operator" }],
    validUntil: 1700000100,
    releaseAfter: 1700000100,
    evaluatedAt: 1700000003,
  });

  assertRetentionReleasePosture({
    kind: SWARM.RECORD_KIND.RETENTION_RELEASE,
    evaluationId: "release-debug-cache-freeable",
    subjectRef: "debug:projection:sample",
    effectiveRetention: "disposable",
    state: SWARM.RETENTION_RELEASE_STATE.FREEABLE,
    policyRefs: ["policy:debug-cache"],
    overlayRefs: ["overlay:none"],
    ownerRefs: ["runtime:browser"],
    residencyLayers: ["browserHotCache"],
    witnessRefs: ["witness:runtime:release"],
    supersessionRefs: [],
    retractionRefs: [],
    revocationRefs: [],
    validUntil: 1700000003,
    releaseAfter: 1700000004,
    evaluatedAt: 1700000004,
  });

  assert.throws(() => assertRetentionReleasePosture({
    kind: SWARM.RECORD_KIND.RETENTION_RELEASE,
    evaluationId: "release-missing-proof",
    subjectRef: "nvr:chunk:front:1700000000",
    effectiveRetention: "durable",
    state: SWARM.RETENTION_RELEASE_STATE.RELEASE_BLOCKED,
    ownerRefs: ["identity:operator"],
    residencyLayers: ["browserHotCache"],
    evaluatedAt: 1700000005,
  }), /requires blockers/);
});

test("event admission and subscription contracts separate fast filtering from proof work", () => {
  assertSubscriptionContract({
    kind: SWARM.RECORD_KIND.SUBSCRIPTION_CONTRACT,
    subscriptionId: "sub-runtime-diagnostics",
    subscriberRef: BROWSER_PK,
    publisherClass: "runtime",
    planes: [SWARM.EVENT_PLANE.DIAGNOSTIC, SWARM.EVENT_PLANE.PROJECTION],
    subjectSelector: { channelRefs: ["runtime.diagnostics", "logging.events"] },
    audience: { memberRef: BROWSER_PK, surface: "constitute-logging-ui" },
    window: { since: 1700000000, replayLimit: 40, expiresAt: 1700000300 },
    cost: { maxInFlight: 2, maxEventsPerSecond: 8 },
    proof: { requirement: SWARM.EVENT_PROOF_REQUIREMENT.SIGNATURE, verifyBefore: "materialize" },
    delivery: { mode: SWARM.EVENT_DELIVERY_MODE.OBSERVE },
    backpressure: { behavior: SWARM.EVENT_BACKPRESSURE_BEHAVIOR.SUMMARIZE },
    capabilityRefs: [SWARM.CORE_CAPABILITY.RUNTIME_DIAGNOSTICS_OBSERVE],
    issuedAt: 1700000000,
    expiresAt: 1700000300,
  });

  assertEventAdmissionEnvelope({
    kind: SWARM.RECORD_KIND.EVENT_ADMISSION,
    admissionId: "admit-runtime-diagnostic-1",
    plane: SWARM.EVENT_PLANE.DIAGNOSTIC,
    laneId: "lane-diagnostics",
    subscriptionId: "sub-runtime-diagnostics",
    publisherRef: "runtime:browser",
    subscriberRef: BROWSER_PK,
    subject: { channelRef: "runtime.diagnostics", kind: "projection.applied" },
    audience: { memberRef: BROWSER_PK, surface: "constitute-logging-ui" },
    claimedSeverity: LOGGING.SEVERITY.ERROR,
    effectivePriority: 70,
    decision: SWARM.EVENT_ADMISSION_DECISION.SUMMARIZE,
    proofRequirement: SWARM.EVENT_PROOF_REQUIREMENT.SIGNATURE,
    proofState: SWARM.EVENT_PROOF_STATE.PENDING,
    reason: "diagnostic lane pressure",
    cost: { sizeBytes: 512 },
    observedAt: 1700000001,
    expiresAt: 1700000061,
  });

  assertEventAdmissionEnvelope({
    kind: SWARM.RECORD_KIND.EVENT_ADMISSION,
    admissionId: "admit-route-1",
    plane: SWARM.EVENT_PLANE.ROUTE,
    subject: { routePromiseId: "route-front-camera" },
    audience: { memberRef: BROWSER_PK },
    effectivePriority: 5,
    decision: SWARM.EVENT_ADMISSION_DECISION.FORWARD,
    proofRequirement: SWARM.EVENT_PROOF_REQUIREMENT.NONE,
    proofState: SWARM.EVENT_PROOF_STATE.NOT_REQUIRED,
    observedAt: 1700000002,
  });

  assert.throws(() => assertEventAdmissionEnvelope({
    kind: SWARM.RECORD_KIND.EVENT_ADMISSION,
    admissionId: "bad-admission",
    plane: SWARM.EVENT_PLANE.DIAGNOSTIC,
    subject: { channelRef: "runtime.diagnostics" },
    audience: { memberRef: BROWSER_PK },
    claimedSeverity: LOGGING.SEVERITY.CRITICAL,
    effectivePriority: 1,
    decision: SWARM.EVENT_ADMISSION_DECISION.FORWARD,
    proofRequirement: SWARM.EVENT_PROOF_REQUIREMENT.NONE,
    proofState: SWARM.EVENT_PROOF_STATE.PENDING,
    observedAt: 1700000003,
  }), /proofState/);

  assert.throws(() => assertEventAdmissionEnvelope({
    kind: SWARM.RECORD_KIND.EVENT_ADMISSION,
    admissionId: "bad-bulk",
    plane: SWARM.EVENT_PLANE.BULK_RETAINED_DATA,
    subject: { projectionRef: "logging.events" },
    audience: { memberRef: BROWSER_PK },
    effectivePriority: 95,
    decision: SWARM.EVENT_ADMISSION_DECISION.FORWARD,
    proofRequirement: SWARM.EVENT_PROOF_REQUIREMENT.SIGNATURE,
    proofState: SWARM.EVENT_PROOF_STATE.PENDING,
    observedAt: 1700000004,
  }), /subscriptionId/);

  assert.throws(() => assertSubscriptionContract({
    kind: SWARM.RECORD_KIND.SUBSCRIPTION_CONTRACT,
    subscriptionId: "bad-sub",
    subscriberRef: BROWSER_PK,
    planes: [SWARM.EVENT_PLANE.DIAGNOSTIC],
    subjectSelector: { channelRefs: ["runtime.diagnostics"] },
    audience: { memberRef: BROWSER_PK },
    proof: { requirement: SWARM.EVENT_PROOF_REQUIREMENT.SIGNATURE },
    delivery: { mode: SWARM.EVENT_DELIVERY_MODE.REPLAY },
    backpressure: { behavior: "retryForever" },
    issuedAt: 1700000000,
  }), /backpressure behavior/);
});

test("materialization budgets encode copy roles and consumer floors", () => {
  const floor = assertConsumerFloor({
    kind: SWARM.RECORD_KIND.CONSUMER_FLOOR,
    floorId: "floor-logging-ui-events",
    consumerRef: "constitute-logging-ui",
    subscriptionId: "sub-runtime-diagnostics",
    materializationId: "budget-runtime-diagnostic-projection",
    subjectRef: "runtime.diagnostics",
    cursor: "runtime-event-40",
    ackFloor: "runtime-event-39",
    witnessFloor: "projection-revision-12",
    compactionFloor: "projection-revision-10",
    eventTimeFloor: 1700000000,
    observedTimeFloor: 1700000010,
    lagState: SWARM.MATERIALIZATION_LAG_STATE.LAGGING,
    reason: "consumer is behind the retained diagnostic cursor",
    redelivery: { mode: "summary", afterMs: 500 },
    replay: { maxEvents: 40 },
    sampledAt: 1700000011,
    expiresAt: 1700000070,
  });
  assert.equal(floor.lagState, SWARM.MATERIALIZATION_LAG_STATE.LAGGING);

  assertMaterializationBudget({
    kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
    budgetId: "budget-runtime-diagnostic-projection",
    sourceAuthority: "runtime:browser",
    consumerRef: "constitute-logging-ui",
    subscriberRef: BROWSER_PK,
    payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.PROJECTION,
    copyRole: SWARM.MATERIALIZATION_COPY_ROLE.PROJECTION,
    transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.CLONE,
    privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.SAFE_PROJECTION,
    state: SWARM.RESOURCE_POSTURE_STATE.PRESSURE,
    limits: { maxEvents: 40, maxBytes: 32768, maxHighCardinalityLabels: 8 },
    snapshotPolicy: { mode: "baseline-repair", maxAgeMs: 60000 },
    deltaPolicy: { mode: "preferred", maxBatch: 20 },
    coalescing: { key: "kind|channelRef|projectionKey", windowMs: 250 },
    cardinality: { labelLimit: 8, overflow: "detailRef" },
    schema: { version: "runtime.diagnostics.v1", state: SWARM.MATERIALIZATION_SCHEMA_STATE.CURRENT },
    consumerFloor: floor,
    blockedReasons: ["diagnosticLanePressure"],
    retentionClass: "short",
    issuedAt: 1700000011,
    releaseAfter: 1700000070,
    expiresAt: 1700000300,
  });

  assertMaterializationBudget({
    kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
    budgetId: "budget-nvr-media-native",
    sourceAuthority: "runtime:browser",
    consumerRef: "nvr-ui-video-element",
    payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.MEDIA,
    copyRole: SWARM.MATERIALIZATION_COPY_ROLE.TRANSPORT,
    transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.NATIVE,
    privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.UI_PROJECTION,
    limits: { maxTracks: 2 },
    issuedAt: 1700000012,
  });

  assertMaterializationBudget({
    kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
    budgetId: "budget-encrypted-detail-ref",
    sourceAuthority: "logging:events",
    consumerRef: "constitute-cybersec",
    payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.RETAINED_RAW,
    copyRole: SWARM.MATERIALIZATION_COPY_ROLE.REFERENCE_ONLY,
    transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.REFERENCE_ONLY,
    privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.ENCRYPTED_DETAIL,
    limits: { maxRefs: 500 },
    referenceRefs: ["storage:object:encrypted-detail-1"],
    issuedAt: 1700000013,
  });

  assert.throws(() => assertConsumerFloor({
    kind: SWARM.RECORD_KIND.CONSUMER_FLOOR,
    floorId: "floor-bad-time",
    consumerRef: "logging-ui",
    lagState: SWARM.MATERIALIZATION_LAG_STATE.CAUGHT_UP,
    eventTimeFloor: 1700000100,
    observedTimeFloor: 1700000000,
    sampledAt: 1700000011,
  }), /observedTimeFloor/);

  assert.throws(() => assertMaterializationBudget({
    kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
    budgetId: "budget-media-clone",
    sourceAuthority: "runtime:browser",
    consumerRef: "nvr-ui-video-element",
    payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.MEDIA,
    copyRole: SWARM.MATERIALIZATION_COPY_ROLE.DEBUG,
    transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.CLONE,
    issuedAt: 1700000012,
  }), /media payload/);

  assert.throws(() => assertMaterializationBudget({
    kind: SWARM.RECORD_KIND.MATERIALIZATION_BUDGET,
    budgetId: "budget-raw-unsafe",
    sourceAuthority: "logging:events",
    consumerRef: "logging-ui",
    payloadClass: SWARM.MATERIALIZATION_PAYLOAD_CLASS.RETAINED_RAW,
    copyRole: SWARM.MATERIALIZATION_COPY_ROLE.PROJECTION,
    transferMode: SWARM.MATERIALIZATION_TRANSFER_MODE.CLONE,
    privacyTier: SWARM.MATERIALIZATION_PRIVACY_TIER.SAFE_PROJECTION,
    issuedAt: 1700000013,
  }), /retained raw/);
});

test("contribution lifecycle validates validity witness retraction and release bounds", () => {
  const promise = assertContributionLifecycle({
    kind: SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE,
    contributionId: "contribution-route-promise-1",
    parentRef: "activation:preview-front",
    subjectRef: "route-promise-preview-front",
    writerRef: GATEWAY_PK,
    contributionType: SWARM.CONTRIBUTION_TYPE.PROMISE,
    state: SWARM.CONTRIBUTION_STATE.ACTIVE,
    role: "router",
    authorityRefs: ["grant:gateway-route"],
    scope: { channelId: "nvr.streams" },
    issuedAt: 1_700_000_000,
    validUntil: 1_700_000_060,
    releaseAfter: 1_700_000_061,
    evidenceRefs: ["route:bound"],
  });
  assert.equal(promise.validUntil, 1_700_000_060);

  assertContributionLifecycle({
    kind: SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE,
    contributionId: "witness-service-read-1",
    parentRef: "activation:preview-front",
    subjectRef: "route-promise-preview-front",
    writerRef: SERVICE_PK,
    contributionType: SWARM.CONTRIBUTION_TYPE.WITNESS,
    state: SWARM.CONTRIBUTION_STATE.WITNESSED,
    role: "executor",
    authorityRefs: ["grant:nvr-service"],
    targetContributionRef: "contribution-route-promise-1",
    witnessRefs: ["member-read:frame-1"],
    evidenceRefs: ["service.accepted:frame-1"],
    issuedAt: 1_700_000_010,
    observedAt: 1_700_000_011,
  });

  assertContributionLifecycle({
    kind: SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE,
    contributionId: "retract-route-promise-1",
    parentRef: "activation:preview-front",
    subjectRef: "route-promise-preview-front",
    writerRef: GATEWAY_PK,
    contributionType: SWARM.CONTRIBUTION_TYPE.RETRACTION,
    state: SWARM.CONTRIBUTION_STATE.RETRACTED,
    role: "router",
    authorityRefs: ["grant:gateway-route"],
    targetContributionRef: "contribution-route-promise-1",
    issuedAt: 1_700_000_030,
    retractedAt: 1_700_000_031,
  });

  assert.throws(() => assertContributionLifecycle({
    kind: SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE,
    contributionId: "bad-witness",
    parentRef: "activation:preview-front",
    subjectRef: "route-promise-preview-front",
    writerRef: SERVICE_PK,
    contributionType: SWARM.CONTRIBUTION_TYPE.WITNESS,
    state: SWARM.CONTRIBUTION_STATE.WITNESSED,
    role: "executor",
    authorityRefs: ["grant:nvr-service"],
    issuedAt: 1_700_000_010,
    observedAt: 1_700_000_011,
  }), /targetContributionRef/);

  assert.throws(() => assertContributionLifecycle({
    kind: SWARM.RECORD_KIND.CONTRIBUTION_LIFECYCLE,
    contributionId: "bad-expiry",
    parentRef: "activation:preview-front",
    subjectRef: "route-promise-preview-front",
    writerRef: GATEWAY_PK,
    contributionType: SWARM.CONTRIBUTION_TYPE.PROMISE,
    role: "router",
    authorityRefs: ["grant:gateway-route"],
    issuedAt: 1_700_000_060,
    validUntil: 1_700_000_060,
  }), /validUntil/);
});

test("projection repair posture stays distinct from routed stream activation", () => {
  assertProjectionRepairPosture({
    kind: SWARM.RECORD_KIND.PROJECTION_REPAIR_POSTURE,
    repairId: "repair-nvr-streams-1",
    projectionId: "nvr.streams",
    policyId: "nvr.streams",
    state: SWARM.PROJECTION_REPAIR_STATE.PENDING,
    currentRevision: 4,
    requiredRevision: 8,
    reason: "revisionGap",
    coverage: {
      materializedCount: 2,
      targetCount: 3,
      completionRatio: 0.66,
      syncState: PROJECTION.SYNC_STATE.DEGRADED,
    },
    observerRef: "runtime:browser",
    issuedAt: 1700000006,
    expiresAt: 1700000066,
  });

  assert.throws(() => assertProjectionRepairPosture({
    kind: SWARM.RECORD_KIND.PROJECTION_REPAIR_POSTURE,
    repairId: "repair-blocked",
    projectionId: "nvr.streams",
    policyId: "nvr.streams",
    state: SWARM.PROJECTION_REPAIR_STATE.BLOCKED,
    currentRevision: 4,
    requiredRevision: 8,
    reason: "missingObserver",
    issuedAt: 1700000006,
  }), /blockedReasons/);
});

test("convergence contracts validate shared node activation, route, stream, directory, and bootstrap records", () => {
  const { convergence } = JSON.parse(readFileSync(new URL("../vectors/swarm-runtime-v1.json", import.meta.url), "utf8"));

  assert.equal(assertNodeCapability(convergence.nodeCapability, { now: 1700000001 }).nodeCapabilityId, "node-capability-preview-front");
  assert.equal(assertRuntimeActivationRequest(convergence.activationRequest).activationId, "activation-preview-front");
  assert.equal(assertRoutePromise(convergence.routePromise).promiseId, "route-promise-preview-front");
  assert.equal(assertRouteObservation(convergence.routeObservation).state, SWARM.ROUTE_OBSERVATION_STATE.DELIVERED);
  assert.equal(assertStreamRoutePlan(convergence.streamRoutePlan).selectedPath.kind, SWARM.STREAM_PATH_KIND.BROWSER_WEBRTC);
  assert.equal(assertMemberPresence(convergence.memberPresence, { now: 1700000001 }).memberRef, SERVICE_PK);
  assert.equal(assertDirectoryEntry(convergence.directoryEntry).source, "capabilityRecord");
  assert.equal(assertBootstrapCarrierRecord(convergence.bootstrapCarrier).boundary, "bootstrap");

  // route.binding is deliberately participant-local runtime state, not a shared record kind.
  assert.equal(SWARM.RECORD_KIND.ROUTE_BINDING, undefined);
  assertLocalRouteBinding({
    bindingId: "binding-runtime-1",
    promiseId: convergence.routePromise.promiseId,
    participantRef: BROWSER_PK,
    bindingKind: "runtimeQueue",
    localRefs: { queueId: "queue-1" },
    issuedAt: 1700000002,
  });
});

test("convergence validators reject protocol leakage, incomplete route truth, and control-plane bytes", () => {
  const { convergence } = JSON.parse(readFileSync(new URL("../vectors/swarm-runtime-v1.json", import.meta.url), "utf8"));

  assert.throws(() => assertRuntimeActivationRequest({
    ...convergence.activationRequest,
    channelId: "nvr.streams",
  }), /forbidden protocol field/);
  assert.throws(() => assertRuntimeActivationRequest({
    ...convergence.activationRequest,
    params: { zoneScope: { zoneId: "zone_lab" } },
  }), /forbidden protocol field/);
  assert.throws(() => assertRoutePromise({
    ...convergence.routePromise,
    audienceRefs: [],
  }), /audienceRefs must not be empty/);
  assert.equal(assertRoutePromise({
    ...convergence.routePromise,
    serviceMemberRef: undefined,
    audienceRefs: [convergence.routePromise.servicePk],
  }).servicePk, convergence.routePromise.servicePk);
  assert.equal(assertRouteObservation({
    kind: "route.observation",
    observationId: "route-observation-member-written",
    promiseId: convergence.routePromise.promiseId,
    state: SWARM.ROUTE_OBSERVATION_STATE.MEMBER_WRITTEN,
    deliveredTo: [convergence.routePromise.serviceMemberRef],
    issuedAt: 1700000003,
  }).state, SWARM.ROUTE_OBSERVATION_STATE.MEMBER_WRITTEN);
  assert.equal(assertRouteObservation({
    kind: "route.observation",
    observationId: "route-observation-member-read",
    frameId: "frame-member-read",
    state: SWARM.ROUTE_OBSERVATION_STATE.MEMBER_READ,
    deliveredTo: [convergence.routePromise.serviceMemberRef],
    issuedAt: 1700000004,
  }).state, SWARM.ROUTE_OBSERVATION_STATE.MEMBER_READ);
  assert.throws(() => assertRouteObservation({
    kind: "route.observation",
    observationId: "route-observation-bad-member",
    frameId: "frame-bad-member",
    state: SWARM.ROUTE_OBSERVATION_STATE.MEMBER_READ,
    deliveredTo: ["service:NVR"],
    issuedAt: 1700000005,
  }), /resolved/);
  assert.throws(() => assertRouteObservation({
    kind: "route.observation",
    observationId: "route-observation-bad",
    promiseId: convergence.routePromise.promiseId,
    state: SWARM.ROUTE_OBSERVATION_STATE.OBSERVING_UNREACHABLE,
    failedPredicates: [],
    issuedAt: 1700000003,
  }), /failed predicates|release reason/);
  assert.throws(() => assertStreamRoutePlan({
    ...convergence.streamRoutePlan,
    candidatePaths: [
      {
        pathId: "path:bad",
        kind: SWARM.STREAM_PATH_KIND.BROWSER_WEBRTC,
        state: SWARM.STREAM_PATH_STATE.CANDIDATE,
        mediaBytes: "not allowed",
      },
    ],
    preferredPath: {
      pathId: "path:bad",
      kind: SWARM.STREAM_PATH_KIND.BROWSER_WEBRTC,
      state: SWARM.STREAM_PATH_STATE.CANDIDATE,
    },
    selectedPath: {
      pathId: "path:bad",
      kind: SWARM.STREAM_PATH_KIND.BROWSER_WEBRTC,
      state: SWARM.STREAM_PATH_STATE.CANDIDATE,
    },
  }), /media bytes/);
  assert.throws(() => assertNodeCapability({
    ...convergence.nodeCapability,
    capabilityRef: "Camera Preview",
  }), /capability namespace/);
});

test("swarm authority records validate identity, grant, interaction, and recovery boundaries", () => {
  const vector = JSON.parse(readFileSync(new URL("../vectors/swarm-authority-v1.json", import.meta.url), "utf8"));

  assert.equal(SWARM.RECORD_KIND.SWARM_IDENTITY, "swarm.identity");
  assert.equal(SWARM.RECORD_KIND.SWARM_INTERACTION, "swarm.interaction");
  assert.equal(SWARM.AUTHORITY_DOMAIN.IDENTITY, "identity");
  assert.equal(SWARM.INTERACTION_ROLE.EXECUTOR, "executor");
  assert.equal(SWARM.ROUTING_SCOPE_KIND.SWARM_ZONE, "swarmZone");
  assert.equal(SWARM.ROUTING_SCOPE_STATE.SYNCING, "syncing");
  assert.equal(SWARM.ROUTING_BLOCKED_REASON.MISSING_ZONE_BASELINE, "missingZoneBaseline");
  assert.equal(SWARM.ROUTING_BLOCKED_REASON.EDGE_NOT_ACCEPTED, "edgeNotAccepted");

  assertSwarmIdentity(vector.identity);
  assertSwarmDevice(vector.device);
  assertSwarmGateway(vector.gatewayA);
  assertSwarmGateway(vector.gatewayB);
  assertSwarmService(vector.service);
  assertSwarmMember(vector.runtimeMember);
  assertSwarmMember(vector.serviceMember);
  assertSwarmMember(vector.storageMember);
  assertSwarmGrant(vector.identityGrant);
  assertSwarmGrant(vector.gatewayGrant);
  assertSwarmGrant(vector.serviceGrant);
  assertSwarmGrant(vector.elevatedGrant);
  assertSwarmRole(vector.requesterRole);
  assertSwarmRole(vector.routerRole);
  assertSwarmRole(vector.executorRole);
  assertSwarmInteraction(vector.interaction);
  assert.deepEqual(assertRoutingScopePosture(vector.interaction.routingScope).zoneScope, {
    zoneId: "zone_lab",
    privacy: "rawIds",
    ttl: 30,
    maxHops: 2,
  });
  assertSwarmActivation(vector.activation);
  assertSwarmRelease(vector.release);
  assertSwarmRevocation(vector.revocation);
  assert.equal(assertSwarmIdentityGraph(vector.identityGraph).length, 6);

  const storageClaimingAuthority = structuredClone(vector.storageMember);
  storageClaimingAuthority.storage.authorityDomain = SWARM.AUTHORITY_DOMAIN.IDENTITY;
  assert.throws(() => assertSwarmMember(storageClaimingAuthority), /storage member must not claim identity authority/);

  const routeAsRoot = structuredClone(vector.identity);
  routeAsRoot.recoveryRootRefs.push(routeAsRoot.recoveryRouteRefs[0]);
  assert.throws(() => assertSwarmIdentity(routeAsRoot), /recovery route/);

  const weakElevatedGrant = structuredClone(vector.elevatedGrant);
  weakElevatedGrant.rootRefs = [];
  assert.throws(() => assertSwarmGrant(weakElevatedGrant), /elevated swarm grant/);

  const missingCoordinator = structuredClone(vector.interaction);
  missingCoordinator.participants = missingCoordinator.participants.filter((entry) => entry.role !== SWARM.INTERACTION_ROLE.COORDINATOR);
  assert.throws(() => assertSwarmInteraction(missingCoordinator), /missing coordinator/);

  const unsafeFacts = structuredClone(vector.interaction);
  unsafeFacts.safeFacts.privateKey = "secret";
  assert.throws(() => assertSwarmInteraction(unsafeFacts), /unsafe safe fact/);

  const missingZoneScope = structuredClone(vector.interaction);
  missingZoneScope.routingScope = {
    kind: SWARM.ROUTING_SCOPE_KIND.SWARM_ZONE,
    required: true,
    state: SWARM.ROUTING_SCOPE_STATE.READY,
  };
  assert.throws(() => assertSwarmInteraction(missingZoneScope), /requires zoneScope/);

  const unsupportedBlockedReason = structuredClone(vector.interaction);
  unsupportedBlockedReason.routingScope.blockedReason = "maybeLater";
  assert.throws(() => assertSwarmInteraction(unsupportedBlockedReason), /unsupported swarm interaction routingScope blockedReason/);

  const liveGraph = structuredClone(vector.identityGraph);
  liveGraph.push(vector.activation);
  assert.throws(() => assertSwarmIdentityGraph(liveGraph), /live lease or activation state/);
});

test("agreement grammar separates action authority, access epochs, private readability, and materialization", () => {
  const identityRef = `identity:${pubkeyFromSecretKey(ISSUER_SK)}`;
  const grant = {
    kind: "authority.action.grant",
    grantId: "grant:logging:writer",
    issuerRef: identityRef,
    subjectRef: `member:${BROWSER_PK}`,
    audienceRefs: [`service:${SERVICE_PK}`],
    authorityDomain: SWARM.AUTHORITY_DOMAIN.IDENTITY,
    resourceRef: "contract:logging.default",
    action: "logging.event.write",
    state: AGREEMENT.ACTION_GRANT_STATE.ACCEPTED,
    scope: { contractRef: "contract:logging.default", retentionClass: "rolling" },
    capabilityRefs: ["logging.events.observe"],
    delegation: { allowed: true, maxDepth: 1, inheritedFrom: ["grant:root:logging"] },
    evidenceRefs: ["sig:grant:logging:writer"],
    issuedAt: 1700000010,
    expiresAt: 1700000610,
  };

  assert.equal(assertActionAuthorityGrant(grant).plane, AGREEMENT.PLANE.ACTION_AUTHORITY);
  assert.throws(() => assertActionAuthorityGrant({ ...grant, plane: AGREEMENT.PLANE.ACCESS_AUTHORITY }), /plane/);
  assert.throws(() => assertActionAuthorityGrant({ ...grant, state: AGREEMENT.ACTION_GRANT_STATE.BLOCKED, blockedReason: "" }), /blockedReason/);

  assert.equal(assertActionAuthorityExercise({
    kind: "authority.action.exercise",
    exerciseId: "exercise:logging:writer:1",
    grantId: grant.grantId,
    actorRef: `member:${BROWSER_PK}`,
    subjectRef: "event:runtime:1",
    resourceRef: "contract:logging.default",
    action: "logging.event.write",
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    evidenceRefs: ["event:runtime:1"],
    issuedAt: 1700000020,
    observedAt: 1700000025,
  }).state, AGREEMENT.ACTION_GRANT_STATE.APPLIED);

  assert.equal(assertAuthorityRootOperation({
    kind: "authority.root.operation",
    operationId: "root-op:enroll-aux",
    operation: AGREEMENT.ROOT_OPERATION.ENROLL_DEVICE,
    identityRef,
    actorRef: `root:${pubkeyFromSecretKey(ISSUER_SK)}`,
    targetRef: `device:${BROWSER_PK}`,
    adminGrantRefs: ["grant:root:admin"],
    deviceRefs: [`device:${BROWSER_PK}`],
    notificationRefs: ["notification:root-enroll"],
    evidenceRefs: ["sig:root-op:enroll-aux"],
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    issuedAt: 1700000030,
  }).plane, AGREEMENT.PLANE.ACTION_AUTHORITY);
  assert.throws(() => assertAuthorityRootOperation({
    kind: "authority.root.operation",
    operationId: "root-op:rotate-bad",
    operation: AGREEMENT.ROOT_OPERATION.ROTATE_ROOT,
    identityRef,
    actorRef: `root:${pubkeyFromSecretKey(ISSUER_SK)}`,
    targetRef: `root:${GATEWAY_PK}`,
    adminGrantRefs: ["grant:root:admin"],
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    issuedAt: 1700000031,
  }), /rootRefs/);
  assert.throws(() => assertAuthorityRootOperation({
    kind: "authority.root.operation",
    operationId: "root-op:enroll-missing-device",
    operation: AGREEMENT.ROOT_OPERATION.ENROLL_DEVICE,
    identityRef,
    actorRef: `root:${pubkeyFromSecretKey(ISSUER_SK)}`,
    targetRef: `device:${BROWSER_PK}`,
    adminGrantRefs: ["grant:root:admin"],
    notificationRefs: ["notification:root-enroll"],
    evidenceRefs: ["sig:root-op:enroll-missing-device"],
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    issuedAt: 1700000032,
  }), /deviceRefs/);
  assert.throws(() => assertAuthorityRootOperation({
    kind: "authority.root.operation",
    operationId: "root-op:enroll-missing-notification",
    operation: AGREEMENT.ROOT_OPERATION.ENROLL_DEVICE,
    identityRef,
    actorRef: `root:${pubkeyFromSecretKey(ISSUER_SK)}`,
    targetRef: `device:${BROWSER_PK}`,
    adminGrantRefs: ["grant:root:admin"],
    deviceRefs: [`device:${BROWSER_PK}`],
    evidenceRefs: ["sig:root-op:enroll-missing-notification"],
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    issuedAt: 1700000033,
  }), /notificationRefs/);
  assert.throws(() => assertAuthorityRootOperation({
    kind: "authority.root.operation",
    operationId: "root-op:refresh-missing-evidence",
    operation: AGREEMENT.ROOT_OPERATION.REFRESH_ROOT,
    identityRef,
    actorRef: `root:${pubkeyFromSecretKey(ISSUER_SK)}`,
    targetRef: `root:${pubkeyFromSecretKey(ISSUER_SK)}`,
    adminGrantRefs: ["grant:root:admin"],
    state: AGREEMENT.ACTION_GRANT_STATE.APPLIED,
    issuedAt: 1700000034,
  }), /evidenceRefs/);

  const group = assertAccessGroup({
    kind: "access.group",
    groupId: "access-group:logging-secure",
    ownerRef: identityRef,
    subjectRef: "contract:logging.default",
    contentClasses: [AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL, AGREEMENT.CONTENT_CLASS.DIAGNOSTIC_DETAIL],
    memberRefs: [`member:${SERVICE_PK}`, `member:${BROWSER_PK}`],
    adminRefs: [`root:${pubkeyFromSecretKey(ISSUER_SK)}`],
    currentEpochId: "access-epoch:logging-secure:2",
    partitionRefs: ["partition:identity:logging"],
    issuedAt: 1700000040,
  });
  assert.equal(group.plane, AGREEMENT.PLANE.ACCESS_AUTHORITY);

  assert.equal(assertAccessEpoch({
    kind: "access.epoch",
    epochId: "access-epoch:logging-secure:2",
    groupId: group.groupId,
    sequence: 2,
    previousEpochId: "access-epoch:logging-secure:1",
    changeKind: AGREEMENT.ACCESS_EPOCH_CHANGE.REMOVE_MEMBER,
    memberRefs: [`member:${SERVICE_PK}`],
    removedMemberRefs: [`member:${BROWSER_PK}`],
    keyRef: "key-ref:logging-secure:2",
    proofRefs: ["sig:epoch:2"],
    issuedAt: 1700000050,
  }).changeKind, AGREEMENT.ACCESS_EPOCH_CHANGE.REMOVE_MEMBER);
  assert.throws(() => assertAccessEpoch({
    kind: "access.epoch",
    epochId: "access-epoch:logging-secure:bad",
    groupId: group.groupId,
    sequence: 2,
    changeKind: AGREEMENT.ACCESS_EPOCH_CHANGE.REMOVE_MEMBER,
    memberRefs: [`member:${SERVICE_PK}`],
    removedMemberRefs: [`member:${BROWSER_PK}`],
    keyRef: "key-ref:logging-secure:bad",
    proofRefs: ["sig:epoch:bad"],
    issuedAt: 1700000051,
  }), /previousEpochId/);

  const envelope = assertPrivateContentEnvelope({
    kind: "private.content.envelope",
    envelopeId: "private-envelope:logging-event-1",
    contentClass: AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL,
    accessGroupRef: group.groupId,
    epochId: "access-epoch:logging-secure:2",
    subjectRef: "event:runtime:1",
    issuerRef: `member:${SERVICE_PK}`,
    storageObjectRef: "storage-object:log-event-1",
    caacEnvelopeRef: "caac:log-event-1",
    recipientRefs: [`member:${SERVICE_PK}`],
    keyRef: "key-ref:logging-secure:2",
    summarySafeFacts: { eventClass: "runtimeDiagnostic", severity: "warning" },
    evidenceRefs: ["storage:pin:log-event-1"],
    issuedAt: 1700000060,
  });
  assert.equal(envelope.contentClass, AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL);
  assert.throws(() => assertPrivateContentEnvelope({
    ...envelope,
    envelopeId: "private-envelope:bad",
    ciphertext: "raw-ciphertext-body",
  }), /forbidden protocol field/);

  assert.equal(assertEventFabricAccessClass({
    kind: "event.fabric.accessClass",
    classId: "event-class:cybersec-runtime",
    contentClass: AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL,
    privacyTier: AGREEMENT.PRIVACY_TIER.DOMAIN_ENCRYPTED,
    eventClasses: ["runtimeDiagnostic", "cybersecAudit"],
    accessGroupRefs: [group.groupId],
    processorRoleRefs: ["role:logging", "role:cybersec"],
    storageClass: "storage:rolling-secure",
    retentionClass: "rolling",
    safeFactPolicy: AGREEMENT.SAFE_FACT_POLICY.INDEX_ONLY,
    indexPolicy: { cardinality: "bounded", safeKeys: ["eventClass", "severity"] },
    issuedAt: 1700000070,
  }).plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertEventFabricAccessClass({
    kind: "event.fabric.accessClass",
    classId: "event-class:bad-public",
    contentClass: AGREEMENT.CONTENT_CLASS.ENCRYPTED_RAW,
    privacyTier: AGREEMENT.PRIVACY_TIER.PUBLIC_SAFE,
    eventClasses: ["cybersecAudit"],
    accessGroupRefs: [group.groupId],
    storageClass: "storage:raw",
    retentionClass: "short",
    safeFactPolicy: AGREEMENT.SAFE_FACT_POLICY.NONE,
    issuedAt: 1700000071,
  }), /publicSafe/);

  const floor = assertConsumerFloor({
    kind: SWARM.RECORD_KIND.CONSUMER_FLOOR,
    floorId: "consumer-floor:logging.processor",
    materializationId: "event-fabric:logging-cybersec",
    consumerRef: "role:logging.processor",
    subjectRef: "event-fabric:logging.default",
    ackFloor: "event:9",
    witnessFloor: "event:8",
    compactionFloor: "snapshot:1",
    lagState: "caughtUp",
    observedAt: 1700000072,
    sampledAt: 1700000072,
  });
  const processor = assertEventFabricProcessorContract({
    kind: SWARM.RECORD_KIND.EVENT_FABRIC_PROCESSOR_CONTRACT,
    processorContractId: "processor-contract:logging.cybersec-replay",
    fabricRef: "event-fabric:logging.default",
    processorRef: "service:logging",
    processorRoleRef: "role:logging.processor",
    state: "ready",
    inputAccessClassRefs: ["event-class:cybersec-runtime"],
    inputEventClasses: ["cybersecAudit", "runtimeDiagnostic"],
    inputContentClasses: [AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL],
    outputRefs: ["projection:logging.dashboard", "storage:logging.archive"],
    storageRefs: ["storage:logging.archive"],
    accessGroupRefs: [group.groupId],
    consumerFloor: floor,
    bitemporalPolicy: {
      eventTimeField: "occurredAt",
      observedTimeField: "observedAt",
    },
    schemaPolicy: {
      currentVersion: "logging.event.v1",
      unknownVersionPosture: "ignore",
    },
    compactionPolicy: {
      snapshotCadence: "bounded",
      compactionFloor: "snapshot:1",
    },
    cardinalityPolicy: {
      maxLabelValues: 1000,
      highCardinalityOverflow: "encryptedDetailRef",
    },
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs: [group.groupId],
    },
    samplingPolicy: {
      state: "adaptive",
      degradeBefore: ["authority", "route", "activation"],
    },
    evidenceRefs: ["evidence:processor-contract"],
    issuedAt: 1700000073,
  });
  assert.equal(processor.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.equal(processor.consumerFloor.ackFloor, "event:9");
  assert.throws(() => assertEventFabricProcessorContract({
    ...processor,
    processorContractId: "processor-contract:blocked",
    state: "blocked",
    blockedReasons: [],
  }), /blocked state requires blockedReasons/);

  const processorReport = assertEventFabricProcessorReport({
    kind: SWARM.RECORD_KIND.EVENT_FABRIC_PROCESSOR_REPORT,
    reportId: "processor-report:cybersec-bootstrap:1",
    processorContractRef: processor.processorContractId,
    fabricRef: processor.fabricRef,
    processorRef: "constitute-cybersec",
    processorRoleRef: "role:cybersec.processor",
    runnerOperationRef: "runner-operation:cybersec-bootstrap:execute:1",
    state: "alerted",
    inputRefs: [processor.fabricRef, "event-class:cybersec-runtime", "encrypted-detail:logging.default"],
    outputRefs: ["cybersec:alerts", "cybersec:evidence-hold"],
    inputAccessClassRefs: ["event-class:cybersec-runtime"],
    inputEventClasses: ["cybersecAudit", "runtimeDiagnostic"],
    inputContentClasses: [AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL],
    accessGroupRefs: [group.groupId],
    observedEventRefs: ["event:runtime:media-path:1"],
    heldEventRefs: ["event:runtime:media-path:1"],
    storageRefs: ["storage:logging.archive"],
    findingRefs: ["cybersec:finding:runtime-media-path:1"],
    alertRefs: ["cybersec:alert:runtime-media-path:1"],
    evidenceHoldRefs: ["cybersec:evidence-hold:runtime-media-path:1"],
    retentionDemandRefs: ["retention:cybersec:runtime-media-path:1"],
    mitigationRecommendationRefs: ["cybersec:recommendation:runtime-media-path:observe"],
    safeFacts: {
      eventCount: 1,
      alertCount: 1,
      heldEvidenceCount: 1,
    },
    evidenceRefs: ["evidence:runner:completed", "event:runtime:media-path:1"],
    observedAt: 1700000075,
    expiresAt: 1700000435,
  });
  assert.equal(processorReport.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.equal(processorReport.observedEventRefs[0], "event:runtime:media-path:1");
  assert.throws(() => assertEventFabricProcessorReport({
    ...processorReport,
    reportId: "processor-report:blocked",
    state: "blocked",
    blockedReasons: [],
  }), /blocked state requires blockedReasons/);
  assert.throws(() => assertEventFabricProcessorReport({
    ...processorReport,
    reportId: "processor-report:leaky",
    safeFacts: { ciphertext: "not-safe" },
  }), /forbidden protocol field/);

  const cybersecSeed = assertCybersecProcessorSeed({
    kind: SWARM.RECORD_KIND.CYBERSEC_PROCESSOR_SEED,
    seedId: "cybersec-seed:logging.default",
    fabricRef: "event-fabric:logging.default",
    processorRef: "constitute-cybersec",
    processorRoleRef: "role:cybersec.processor",
    state: "ready",
    threatAnalysisRole: "eventFabricThreatAnalysis",
    inputAccessClassRefs: ["event-class:cybersec-runtime"],
    inputEventClasses: ["cybersecAudit", "runtimeDiagnostic"],
    inputContentClasses: [AGREEMENT.CONTENT_CLASS.ENCRYPTED_DETAIL],
    accessGroupRefs: [group.groupId],
    processorContractRefs: [processor.processorContractId],
    evidenceProfileRefs: ["logging.cybersec.default"],
    materializationBudgetRefs: ["logging.cybersec.default.90d"],
    storageRefs: ["storage:logging.archive"],
    detailRefs: ["encrypted-detail:logging.default"],
    alertOutputRefs: ["cybersec:alerts"],
    evidenceHoldRefs: ["cybersec:evidence-hold"],
    retentionHoldRefs: ["retention:cybersec-hold"],
    encryptedDetailCustody: {
      state: "referenceOnly",
      accessGroupRefs: [group.groupId],
    },
    semanticBoundaries: {
      logging: "mayConsumeMaterializations",
      storage: "ciphertextFulfillmentOnly",
      eventDomain: "doesNotOwn",
    },
    safeFacts: {
      purpose: "cybersecThreatAnalysis",
      detailCustody: "encryptedDetailRef",
    },
    evidenceRefs: ["evidence:cybersec-seed"],
    issuedAt: 1700000074,
    expiresAt: 1707776074,
  });
  assert.equal(cybersecSeed.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.equal(cybersecSeed.semanticBoundaries.eventDomain, "doesNotOwn");
  assert.throws(() => assertCybersecProcessorSeed({
    ...cybersecSeed,
    seedId: "cybersec-seed:blocked",
    state: "blocked",
    blockedReasons: [],
  }), /blocked state requires blockedReasons/);
  assert.throws(() => assertCybersecProcessorSeed({
    ...cybersecSeed,
    semanticBoundaries: { logging: "mayConsumeMaterializations" },
  }), /semanticBoundaries storage/);

  const finding = assertCybersecFinding({
    kind: SWARM.RECORD_KIND.CYBERSEC_FINDING,
    findingId: "cybersec:finding:runtime-media-path:1",
    processorReportRef: processorReport.reportId,
    processorRef: processorReport.processorRef,
    processorRoleRef: processorReport.processorRoleRef,
    subjectRef: "runtime:media-path:1",
    findingKind: "mediaPathAnomaly",
    severity: "medium",
    state: "open",
    confidenceScore: 0.86,
    inputAccessClassRefs: ["event-class:cybersec-runtime"],
    observedEventRefs: processorReport.observedEventRefs,
    accessGroupRefs: [group.groupId],
    evidenceRefs: [processorReport.reportId],
    evidenceHoldRefs: processorReport.evidenceHoldRefs,
    retentionDemandRefs: processorReport.retentionDemandRefs,
    mitigationRecommendationRefs: processorReport.mitigationRecommendationRefs,
    safeFacts: {
      findingKind: "mediaPathAnomaly",
      severity: "medium",
      confidenceScore: 0.86,
    },
    observedAt: 1700000076,
    expiresAt: 1700000436,
  });
  assert.equal(finding.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertCybersecFinding({
    ...finding,
    findingId: "cybersec:finding:leaky",
    safeFacts: { rawPayload: "not-safe" },
  }), /unsafe safe fact key|forbidden protocol field/);
  assert.throws(() => assertCybersecFinding({
    ...finding,
    findingId: "cybersec:finding:confidence",
    confidenceScore: 1.5,
  }), /confidenceScore/);

  const evidenceHold = assertCybersecEvidenceHold({
    kind: SWARM.RECORD_KIND.CYBERSEC_EVIDENCE_HOLD,
    holdId: "cybersec:evidence-hold:runtime-media-path:1",
    findingRef: finding.findingId,
    processorReportRef: processorReport.reportId,
    subjectRef: finding.subjectRef,
    state: "holding",
    eventRefs: processorReport.observedEventRefs,
    detailRefs: ["encrypted-detail:logging.default"],
    storageRefs: processorReport.storageRefs,
    retentionDemandRefs: processorReport.retentionDemandRefs,
    accessGroupRefs: [group.groupId],
    evidenceRefs: [finding.findingId],
    safeFacts: { heldEventCount: 1 },
    issuedAt: 1700000077,
    expiresAt: 1707776077,
  });
  assert.equal(evidenceHold.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertCybersecEvidenceHold({
    ...evidenceHold,
    holdId: "cybersec:evidence-hold:empty",
    eventRefs: [],
    detailRefs: [],
    storageRefs: [],
  }), /holding state requires eventRefs/);

  const recommendation = assertCybersecMitigationRecommendation({
    kind: SWARM.RECORD_KIND.CYBERSEC_MITIGATION_RECOMMENDATION,
    recommendationId: "cybersec:recommendation:runtime-media-path:observe",
    findingRef: finding.findingId,
    processorReportRef: processorReport.reportId,
    recommenderRef: processorReport.processorRef,
    actionKind: "requestEvidence",
    targetRef: finding.subjectRef,
    state: "recommended",
    authorityRefs: ["authority:security-ops"],
    consumerRefs: ["gateway:ops", "moderation:queue"],
    evidenceRefs: [finding.findingId],
    safeFacts: { recommendationOnly: true },
    issuedAt: 1700000078,
    expiresAt: 1700000438,
  });
  assert.equal(recommendation.plane, AGREEMENT.PLANE.MATERIALIZATION);
  const consumerPosture = assertCybersecMitigationConsumerPosture({
    kind: SWARM.RECORD_KIND.CYBERSEC_MITIGATION_CONSUMER_POSTURE,
    postureId: "cybersec:mitigation-consumer:gateway:runtime-media-path",
    recommendationRef: recommendation.recommendationId,
    findingRef: recommendation.findingRef,
    processorReportRef: recommendation.processorReportRef,
    consumerRef: "gateway:ops",
    actionKind: recommendation.actionKind,
    targetRef: recommendation.targetRef,
    state: "actionable",
    authorityRefs: recommendation.authorityRefs,
    supportedActionKinds: ["requestEvidence", "notify"],
    evidenceRefs: [recommendation.recommendationId],
    safeFacts: { recommendationOnly: true, enforcementOwner: "gateway.consumer" },
    observedAt: 1700000079,
    expiresAt: 1700000439,
  });
  assert.equal(consumerPosture.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertCybersecMitigationConsumerPosture({
    ...consumerPosture,
    postureId: "cybersec:mitigation-consumer:gateway:unsupported",
    state: "unsupported",
    blockedReasons: [],
  }), /blocked state requires blockedReasons/);
  assert.throws(() => assertCybersecMitigationRecommendation({
    ...recommendation,
    recommendationId: "cybersec:recommendation:unauthorized",
    authorityRefs: [],
  }), /actionable state requires authorityRefs/);

  assert.equal(assertAuthorityGrantRevocationPosture({
    kind: "authority.grant.revocationPosture",
    revocationId: "revocation:logging:writer",
    targetGrantRef: grant.grantId,
    issuerRef: identityRef,
    authorityDomain: SWARM.AUTHORITY_DOMAIN.IDENTITY,
    affectedGrantRefs: [grant.grantId, "grant:logging:writer:delegated"],
    affectedAccessGroupRefs: [group.groupId],
    inheritedScopeRefs: ["contract:logging.default"],
    state: AGREEMENT.ACTION_GRANT_STATE.REVOKED,
    reasonCode: "operatorRevoked",
    evidenceRefs: ["sig:revocation:logging:writer"],
    issuedAt: 1700000080,
    effectiveAt: 1700000081,
  }).plane, AGREEMENT.PLANE.ACTION_AUTHORITY);
});

test("hardening signal grammar separates observations, posture, exposure, and evidence requests", () => {
  const signal = assertHardeningSignalObservation({
    kind: SWARM.RECORD_KIND.HARDENING_SIGNAL_OBSERVATION,
    observationId: "hardening:signal:gateway-firewall:1",
    observerRef: "gateway:lab",
    subjectRef: "host:lab-gateway",
    signalKind: SWARM.HARDENING_SIGNAL_KIND.FIREWALL,
    state: SWARM.HARDENING_OBSERVATION_STATE.OBSERVED,
    severity: "info",
    authorityRefs: ["authority:ops"],
    eventRefs: ["event:firewall:allow:gateway"],
    evidenceRefs: ["evidence:firewall:gateway"],
    safeFacts: { ruleCount: 1, temporary: true },
    observedAt: 1700000100,
    expiresAt: 1700003700,
  });
  assert.equal(signal.plane, AGREEMENT.PLANE.MATERIALIZATION);

  assert.throws(() => assertHardeningSignalObservation({
    ...signal,
    observationId: "hardening:signal:missing",
    state: SWARM.HARDENING_OBSERVATION_STATE.MISSING,
    blockedReasons: [],
  }), /blockedReasons/);
  assert.throws(() => assertHardeningSignalObservation({
    ...signal,
    observationId: "hardening:signal:leaky",
    safeFacts: { rawPayload: "secret" },
  }), /unsafe safe fact key|forbidden protocol field/);

  const servicePosture = assertServiceHardeningPosture({
    kind: SWARM.RECORD_KIND.SERVICE_HARDENING_POSTURE,
    postureId: "service-hardening:gateway:1",
    serviceRef: "service:gateway",
    observerRef: "service-manager:lab",
    state: SWARM.HARDENING_POSTURE_STATE.READY,
    processPolicyRefs: ["policy:process:gateway"],
    launchPolicyRefs: ["policy:launch:gateway"],
    restartPolicyRefs: ["policy:restart:gateway"],
    adapterPostureRefs: ["adapter:gateway:quic"],
    firewallPostureRefs: ["firewall:gateway:temporary"],
    signalObservationRefs: [signal.observationId],
    evidenceRefs: [signal.observationId],
    safeFacts: { restartBackoff: "bounded" },
    observedAt: 1700000101,
    expiresAt: 1700003701,
  });
  assert.equal(servicePosture.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertServiceHardeningPosture({
    ...servicePosture,
    postureId: "service-hardening:missing-evidence",
    state: SWARM.HARDENING_POSTURE_STATE.MISSING_EVIDENCE,
    blockedReasons: [],
  }), /blockedReasons/);

  const exposure = assertNetworkExposurePosture({
    kind: SWARM.RECORD_KIND.NETWORK_EXPOSURE_POSTURE,
    postureId: "network-exposure:gateway:1",
    observerRef: "gateway:lab",
    subjectRef: "host:lab-gateway",
    state: SWARM.NETWORK_EXPOSURE_STATE.GUARDED,
    routeRefs: ["route:gateway:quic"],
    exposedPortRefs: ["udp:7447"],
    firewallPostureRefs: ["firewall:gateway:temporary"],
    ingressRefs: ["ingress:gateway:quic"],
    signalObservationRefs: [signal.observationId],
    evidenceRefs: ["evidence:netstat:gateway"],
    safeFacts: { publicPortCount: 1 },
    observedAt: 1700000102,
    expiresAt: 1700003702,
  });
  assert.equal(exposure.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertNetworkExposurePosture({
    ...exposure,
    postureId: "network-exposure:blocked",
    state: SWARM.NETWORK_EXPOSURE_STATE.BLOCKED,
    blockedReasons: [],
  }), /blockedReasons/);

  const evidenceRequest = assertEvidenceRequestPosture({
    kind: SWARM.RECORD_KIND.EVIDENCE_REQUEST_POSTURE,
    requestId: "evidence-request:cybersec:gateway-firewall",
    requesterRef: "cybersec:processor",
    targetRef: "gateway:lab",
    state: SWARM.EVIDENCE_REQUEST_STATE.FULFILLED,
    findingRefs: ["cybersec:finding:gateway-firewall"],
    recommendationRefs: ["cybersec:recommendation:request-firewall-evidence"],
    requiredEvidenceClassRefs: ["evidence-class:firewall"],
    eventRefs: ["event:firewall:allow:gateway"],
    authorityRefs: ["authority:ops"],
    evidenceRefs: [signal.observationId],
    safeFacts: { requestScope: "firewallPosture" },
    issuedAt: 1700000103,
    expiresAt: 1700003703,
  });
  assert.equal(evidenceRequest.plane, AGREEMENT.PLANE.MATERIALIZATION);
  assert.throws(() => assertEvidenceRequestPosture({
    ...evidenceRequest,
    requestId: "evidence-request:empty",
    eventRefs: [],
    detailRefs: [],
    storageRefs: [],
  }), /requires eventRefs/);
});

test("multi-identity authority proof covers sync, read, write/reduce, and revoke/expire separately", () => {
  const proof = {
    kind: SWARM.RECORD_KIND.AUTHORITY_MULTI_IDENTITY_PROOF,
    proofId: "authority-proof:aux-to-agent:full-access",
    ownerIdentityRef: "identity:aux",
    granteeIdentityRef: "identity:agent-dev",
    granteeMemberRef: `member:${BROWSER_PK}`,
    subjectRefs: [
      "contract:gateway.default",
      "contract:logging.default",
      "contract:nvr.streams",
      "contract:storage.default",
      "contract:source.default",
      "contract:build.default",
      "app:constitute-cybersec",
    ],
    actionGrantRefs: [
      "grant:gateway:agent-full-access",
      "grant:logging:agent-writer",
      "grant:nvr:agent-preview",
      "grant:storage:agent-pin",
      "grant:source:agent-update",
      "grant:build:agent-run",
    ],
    accessGroupRefs: [
      "access-group:identity:aux:cybersec-events",
      "access-group:identity:aux:source-build",
    ],
    accessEpochRefs: [
      "access-epoch:identity:aux:cybersec-events:3",
      "access-epoch:identity:aux:source-build:1",
    ],
    privateEnvelopeRefs: [
      "private-envelope:logging-event:sample",
      "private-envelope:source-build:sample",
    ],
    revocationRefs: ["revocation:grant:agent-full-access"],
    checks: [
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.SYNC,
        plane: AGREEMENT.PLANE.DELIVERY_WITNESS,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "contract:gateway.default",
        grantRefs: ["grant:gateway:agent-full-access"],
        evidenceRefs: ["witness:gateway:agent-sync"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.READ,
        plane: AGREEMENT.PLANE.ACCESS_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "event-fabric:logging.default",
        accessGroupRefs: [
          "access-group:identity:aux:cybersec-events",
          "access-group:identity:aux:source-build",
        ],
        accessEpochRefs: [
          "access-epoch:identity:aux:cybersec-events:3",
          "access-epoch:identity:aux:source-build:1",
        ],
        evidenceRefs: ["proof:caac-open:agent-dev"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.WRITE_REDUCE,
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "contract:logging.default",
        grantRefs: [
          "grant:logging:agent-writer",
          "grant:storage:agent-pin",
          "grant:source:agent-update",
          "grant:build:agent-run",
        ],
        exerciseRefs: [
          "exercise:logging:agent-writer:1",
          "exercise:storage:agent-pin:1",
          "exercise:source:agent-update:1",
          "exercise:build:agent-run:1",
        ],
        evidenceRefs: ["event:logging:agent-test"],
      },
      {
        check: AGREEMENT.AUTHORITY_PROOF_CHECK.REVOKE_EXPIRE,
        plane: AGREEMENT.PLANE.ACTION_AUTHORITY,
        state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
        targetRef: "grant:gateway:agent-full-access",
        grantRefs: ["grant:gateway:agent-full-access"],
        evidenceRefs: ["revocation:grant:agent-full-access"],
        expiresAt: 1700000900,
      },
    ],
    state: AGREEMENT.AUTHORITY_PROOF_STATE.PROVED,
    evidenceRefs: ["proof:multi-identity:agent-dev"],
    safeFacts: { proofClass: "multiIdentityFullAccess", grantee: "agent-dev" },
    issuedAt: 1700000300,
    expiresAt: 1700000900,
  };

  assert.equal(assertAuthorityMultiIdentityProof(proof).state, AGREEMENT.AUTHORITY_PROOF_STATE.PROVED);
  assert.throws(() => assertAuthorityMultiIdentityProof({
    ...proof,
    checks: proof.checks.filter((check) => check.check !== AGREEMENT.AUTHORITY_PROOF_CHECK.SYNC),
  }), /missing sync check/);
  assert.throws(() => assertAuthorityMultiIdentityProof({
    ...proof,
    checks: proof.checks.map((check) => check.check === AGREEMENT.AUTHORITY_PROOF_CHECK.READ
      ? { ...check, accessGroupRefs: [] }
      : check),
  }), /read authority proof check requires accessGroupRefs/);
  assert.throws(() => assertAuthorityMultiIdentityProof({
    ...proof,
    checks: proof.checks.map((check) => check.check === AGREEMENT.AUTHORITY_PROOF_CHECK.WRITE_REDUCE
      ? { ...check, plane: AGREEMENT.PLANE.ACCESS_AUTHORITY }
      : check),
  }), /write\/revoke authority proof checks/);
  assert.throws(() => assertAuthorityMultiIdentityProof({
    ...proof,
    revocationRefs: [],
    checks: proof.checks.map((check) => check.check === AGREEMENT.AUTHORITY_PROOF_CHECK.REVOKE_EXPIRE
      ? { ...check, expiresAt: undefined }
      : check),
  }), /revoke\/expire authority proof requires revocationRefs or expiresAt/);
});

test("swarm frame IDs canonicalize absent CAAC body fields like Rust validators", () => {
  const frame = makeSwarmFrame({
    kind: SWARM.FRAME_KIND.STREAM_INTENT,
    issuer: pubkeyFromSecretKey(ISSUER_SK),
    audience: { serviceRef: "service:nvr-test" },
    zoneScope: { zoneId: "zone-test", privacy: "rawIds", ttl: 4, maxHops: 2 },
    issuedAt: 1700000000000,
    expiresAt: 1700000060000,
    nonce: "canonical-null-body-fields",
    correlationId: "corr-canonical-null-body-fields",
    channelId: "nvr.streams",
    recordRef: { kind: "stream.session.offer", id: "offer-canonical" },
    capability: "stream.session.offer",
    body: {
      encoding: SWARM.BODY_ENCODING.CAAC,
      envelope: { envelopeId: "canonical-body" },
      publicBootstrap: false,
      payload: null,
      signature: null,
    },
    now: 1699999999000,
  });

  assert.equal(frame.body.publicBootstrap, undefined);
  assert.equal(frame.body.payload, undefined);
  assert.equal(frame.body.signature, undefined);
  assertSwarmFrame(frame, { now: 1700000000001 });
  assert.equal(assertSwarmFrame({
    ...frame,
    body: {
      ...frame.body,
      publicBootstrap: false,
      payload: null,
      signature: null,
    },
  }, { now: 1700000000001 }).frameId, frame.frameId);
});

test("CAAC validation modes keep placeholders fixture-only and product cryptographic", () => {
  assertCaacEnvelopeForMode({ envelopeId: "sealed-frame-placeholder" }, { mode: SWARM.CAAC_VALIDATION_MODE.STRUCTURAL });
  assertCaacEnvelopeForMode({ envelopeId: "sealed-frame-placeholder" }, { mode: SWARM.CAAC_VALIDATION_MODE.FIXTURE });
  assert.throws(() => assertCaacEnvelopeForMode({ envelopeId: "sealed-frame-placeholder" }, {
    mode: SWARM.CAAC_VALIDATION_MODE.PRODUCT,
  }), /placeholder rejected/);
  assert.throws(() => assertCaacEnvelopeForMode({ envelopeId: "minimal-placeholder" }, {
    mode: SWARM.CAAC_VALIDATION_MODE.PRODUCT,
  }), /placeholder rejected/);

  const gatewayPk = pubkeyFromSecretKey(GATEWAY_SK);
  const envelope = sealEnvelope({
    kind: "runtime.activation.request",
    claims: { activationId: "activation-preview-front" },
    issuerSecretKey: ISSUER_SK,
    recipientPks: [gatewayPk],
    issuedAt: 1700000000,
    expiresAt: 1700000900,
    envelopeId: "product-caac-1",
    nonces: ["000102030405060708090a0b0c0d0e0f1011121314151617"],
  });
  assert.equal(assertCaacEnvelopeForMode(envelope, {
    mode: SWARM.CAAC_VALIDATION_MODE.PRODUCT,
    now: 1700000001,
  }), envelope);
  assert.throws(() => assertCaacEnvelopeForMode({
    ...envelope,
    recipients: [{ ...envelope.recipients[0], nonce: "" }],
  }, {
    mode: SWARM.CAAC_VALIDATION_MODE.PRODUCT,
    now: 1700000001,
  }), /nonce/);
  assert.throws(() => assertCaacEnvelopeForMode(envelope, {
    mode: SWARM.CAAC_VALIDATION_MODE.PRODUCT,
    now: 1700000901,
  }), /expired/);
});

test("projection snapshots and deltas apply with repair on revision gaps", () => {
  const snapshot = assertProjectionSnapshot({
    projectionId: "proj-1",
    policyId: "default",
    revision: 4,
    state: { cameras: [{ id: "front", status: "ok" }] },
    coverage: TEST_COVERAGE,
    freshness: TEST_FRESHNESS,
    sourceRefs: [],
    issuedAt: 1700000000,
  });
  assert.equal(snapshot.revision, 4);

  const delta = assertProjectionDelta({
    projectionId: "proj-1",
    policyId: "default",
    baseRevision: 4,
    revision: 5,
    ops: [
      { op: SWARM.PROJECTION_OP.SET, path: ["cameras", 0, "status"], value: "degraded" },
      { op: SWARM.PROJECTION_OP.APPEND_UNIQUE, path: ["events"], value: { id: "evt-1" } },
    ],
    affectedRecords: ["camera:front"],
    coverage: TEST_COVERAGE,
    freshness: TEST_FRESHNESS,
    sourceRefs: [],
    issuedAt: 1700000001,
  });
  const applied = applyProjectionDelta({ state: snapshot.state, revision: 4, delta });
  assert.equal(applied.changed, true);
  assert.equal(applied.revision, 5);
  assert.equal(applied.state.cameras[0].status, "degraded");
  assert.deepEqual(applied.state.events, [{ id: "evt-1" }]);

  const gap = applyProjectionDelta({ state: snapshot.state, revision: 3, delta });
  assert.equal(gap.changed, false);
  assert.equal(gap.repairRequest.reason, "revisionGap");
  assert.equal(gap.repairRequest.requiredRevision, 4);

  assert.throws(() => assertProjectionDelta({
    ...delta,
    ops: [{ op: SWARM.PROJECTION_OP.SET, path: [], value: true }],
  }), /path cannot be empty/);
});

test("swarm edge records use generic wire names and validate replay state", () => {
  const { edge } = JSON.parse(readFileSync(new URL("../vectors/swarm-runtime-v1.json", import.meta.url), "utf8"));
  assert.equal(SWARM.WIRE_KIND.FRAME, "swarm.frame");
  assert.equal(SWARM.EDGE_KIND.HELLO, "swarm.edge.hello");
  assert.equal(SWARM.EDGE_KIND.RESUME, "swarm.edge.resume");
  assert.equal(SWARM.EDGE_KIND.ACCEPT, "swarm.edge.accept");
  assert.equal(SWARM.EDGE_KIND.CLOSE, "swarm.edge.close");
  assert.equal(SWARM.FRAME_KIND.RUNTIME_DIAGNOSTIC_EVENT, "runtime.diagnostic.event");
  assert.equal(SWARM.FRAME_KIND.RUNTIME_DIAGNOSTIC_COMMAND, "runtime.diagnostic.command");
  assert.equal(SWARM.FRAME_KIND.RUNTIME_DIAGNOSTIC_COMMAND_RESULT, "runtime.diagnostic.command.result");
  assert.equal(SWARM.RECORD_KIND.RUNTIME_DIAGNOSTIC_EVENT, "runtime.diagnostic.event");
  assert.equal(SWARM.CORE_CAPABILITY.RUNTIME_DIAGNOSTICS_OBSERVE, "runtime.diagnostics.observe");
  assert.equal(SWARM.CORE_CAPABILITY.RUNTIME_DIAGNOSTICS_COMMAND, "runtime.diagnostics.command");
  assert.equal(DIAGNOSTICS.RUNTIME_CHANNEL, "runtime.diagnostics");
  assert.equal(SWARM.RUNTIME_EDGE_KIND, undefined);

  assert.equal(assertSwarmEdgeHello(edge.hello), edge.hello);
  assert.equal(assertSwarmEdgeHello({
    ...edge.hello,
    expiresAt: Number(edge.hello.issuedAt) + 90_000,
  }).expiresAt, Number(edge.hello.issuedAt) + 90_000);
  assert.equal(assertSwarmEdgeAccept(edge.accept), edge.accept);
  assert.equal(assertSwarmEdgeResume(edge.resume), edge.resume);
  assert.equal(assertSwarmEdgeClose(edge.close), edge.close);

  assert.throws(() => assertSwarmEdgeHello({
    ...edge.hello,
    supportedVersions: [0],
  }), /supported swarm version/);
  assert.throws(() => assertSwarmEdgeHello({
    ...edge.hello,
    zoneScope: undefined,
  }), /zone scope/);
  assert.throws(() => assertSwarmEdgeResume({
    ...edge.resume,
    capabilityRefs: ["bad capability"],
  }), /capability namespace/);
  assert.throws(() => assertSwarmEdgeResume({
    ...edge.resume,
    expiresAt: edge.resume.issuedAt,
  }), /expiresAt must be after issuedAt/);
  assert.throws(() => assertSwarmEdgeAccept({
    ...edge.accept,
    lastProjectionRevisions: { "proj-1": -1 },
  }), /revision must be non-negative/);
  assert.throws(() => assertSwarmEdgeClose({
    ...edge.close,
    sealedClaims: { encoding: SWARM.BODY_ENCODING.PUBLIC, publicBootstrap: true },
  }), /sealedClaims must be sealed/);
});

test("storage pin intent derives projection from active attestations", () => {
  const intent = assertStoragePinIntent({
    intentId: "pin-intent-1",
    objectRefs: [{ objectId: "object-1" }],
    manifestHash: "manifest-hash",
    desiredReplicas: 2,
    retention: "long",
    authorityRefs: ["identity:owner"],
    expiresAt: 1700000900,
  });
  const active = assertStoragePinAttestation({
    attestationId: "att-1",
    intentId: intent.intentId,
    storageMemberRef: "storage-member-a",
    acceptedRefs: ["object-1"],
    availabilityRefs: [{ availabilityId: "avail-1" }],
    status: "pinned",
    issuedAt: 1700000001,
    expiresAt: 1700000900,
  });
  const expired = assertStoragePinAttestation({
    attestationId: "att-2",
    intentId: intent.intentId,
    storageMemberRef: "storage-member-b",
    acceptedRefs: ["object-1"],
    availabilityRefs: [{ availabilityId: "avail-2" }],
    status: "pinned",
    issuedAt: 1,
    expiresAt: 2,
  });
  const projection = deriveStoragePinProjection({ intent, attestations: [active, expired], now: 1700000002 });
  assert.equal(projection.pinnedCount, 1);
  assert.equal(projection.missingReplicas, 1);
  assert.equal(projection.status, "pending");
});

test("stream sessions and recipe records validate without carrying media bytes", () => {
  assert.equal(assertResolvedMemberRef(BROWSER_PK), BROWSER_PK);
  assert.throws(() => assertResolvedMemberRef("identity-001"), /resolved public key/);

  assertStreamSessionRecord({
    kind: SWARM.STREAM_RECORD_KIND.OFFER,
    sessionId: "stream-1",
    issuer: BROWSER_PK,
    issuedAt: 1700000000,
    transport: "webrtc",
    offer: { type: "offer", sdpRef: "encrypted-detail-ref" },
  });
  assert.throws(() => assertStreamSessionRecord({
    kind: SWARM.STREAM_RECORD_KIND.OFFER,
    sessionId: "stream-1",
    issuer: BROWSER_PK,
    issuedAt: 1700000000,
    mediaBytes: "not allowed",
  }), /media bytes/);

  assertStreamSessionIntent({
    sessionId: "stream-1",
    capabilityRef: SWARM.CORE_CAPABILITY.STREAM_SESSION_OFFER,
    requesterRef: BROWSER_PK,
    channelId: "nvr.streams",
    transport: "webrtc",
    issuedAt: 1700000000,
  });
  assert.throws(() => assertStreamSessionIntent({
    sessionId: "stream-1",
    capabilityRef: SWARM.CORE_CAPABILITY.STREAM_SESSION_OFFER,
    requesterRef: BROWSER_PK,
    channelId: "nvr.streams",
    transport: "webrtc",
    issuedAt: 1700000000,
    blobBytes: "not allowed",
  }), /media bytes/);

  assertStreamSessionAdmission({
    admissionId: "admission-1",
    sessionId: "stream-1",
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    admittedBy: SERVICE_PK,
    constraints: { routePromiseId: "route-stream-1" },
    issuedAt: 1700000001,
  });
  assert.throws(() => assertStreamSessionAdmission({
    admissionId: "admission-2",
    sessionId: "stream-1",
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    admittedBy: SERVICE_PK,
    constraints: { nested: { rawBytes: "not allowed" } },
    issuedAt: 1700000001,
  }), /media bytes/);

  assertStreamSessionReject({
    rejectId: "reject-1",
    sessionId: "stream-1",
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    rejectedBy: SERVICE_PK,
    reasonCode: "unsupportedSource",
    constraints: { routePromiseId: "route-stream-1" },
    issuedAt: 1700000001,
  });
  assert.throws(() => assertStreamSessionReject({
    rejectId: "reject-2",
    sessionId: "stream-1",
    capabilityRef: SWARM.CORE_CAPABILITY.MEDIA_STREAM_PREVIEW,
    rejectedBy: "service:nvr",
    reasonCode: "unsupportedSource",
    issuedAt: 1700000001,
  }), /resolved public key/);

  assertStreamSessionOffer({
    offerId: "offer-1",
    sessionId: "stream-1",
    transport: "webrtc",
    payload: { sdpRef: "encrypted-offer-detail-ref" },
    issuedAt: 1700000001,
  });
  assert.throws(() => assertStreamSessionOffer({
    offerId: "offer-2",
    sessionId: "stream-1",
    transport: "webrtc",
    payload: { nested: { blobBytes: "not allowed" } },
    issuedAt: 1700000001,
  }), /media bytes/);

  assertStreamSessionAnswer({
    answerId: "answer-1",
    sessionId: "stream-1",
    transport: "webrtc",
    payload: { sdpRef: "encrypted-answer-detail-ref" },
    issuedAt: 1700000001,
  });
  assertStreamSessionCandidate({
    candidateId: "candidate-1",
    sessionId: "stream-1",
    transport: "webrtc",
    candidateRole: "browser",
    actionability: "usable",
    endpoint: {
      protocol: "udp",
      address: "192.0.2.10",
      port: 5000,
      candidateType: "host",
    },
    payload: { candidateRef: "encrypted-candidate-detail-ref" },
    issuedAt: 1700000002,
  });
  assert.throws(() => assertStreamSessionCandidate({
    candidateId: "candidate-2",
    sessionId: "stream-1",
    transport: "webrtc",
    actionability: "usable",
    payload: { candidateRef: "encrypted-candidate-detail-ref" },
    issuedAt: 1700000002,
  }), /candidate role/);
  assert.throws(() => assertStreamSessionCandidate({
    candidateId: "candidate-3",
    sessionId: "stream-1",
    transport: "webrtc",
    candidateRole: "browser",
    actionability: "blocked",
    payload: { candidateRef: "encrypted-candidate-detail-ref" },
    issuedAt: 1700000002,
  }), /blocked reason/);
  assert.throws(() => assertStreamSessionCandidate({
    candidateId: "candidate-4",
    sessionId: "stream-1",
    transport: "webrtc",
    candidateRole: "browser",
    actionability: "usable",
    endpoint: { protocol: "udp", address: "192.0.2.10", port: 0 },
    payload: { candidateRef: "encrypted-candidate-detail-ref" },
    issuedAt: 1700000002,
  }), /endpoint port/);
  assertStreamSessionControl({
    controlId: "control-1",
    sessionId: "stream-1",
    command: "pause",
    params: { requestedBy: "operator" },
    issuedAt: 1700000002,
  });
  assert.throws(() => assertStreamSessionControl({
    controlId: "control-2",
    sessionId: "stream-1",
    command: "pause",
    params: { rawBytes: "not allowed" },
    issuedAt: 1700000002,
  }), /media bytes/);
  assertStreamSessionHealth({
    healthId: "health-1",
    sessionId: "stream-1",
    status: "ready",
    recovery: { backoffMs: 0 },
    issuedAt: 1700000002,
  });
  assert.throws(() => assertStreamSessionHealth({
    healthId: "health-2",
    sessionId: "stream-1",
    status: "ready",
    recovery: { payloadBlobBytes: "not allowed" },
    issuedAt: 1700000002,
  }), /media bytes/);
  assertStreamSessionClose({
    closeId: "close-1",
    sessionId: "stream-1",
    reasonCode: "complete",
    issuedAt: 1700000003,
  });
  assert.throws(() => assertStreamSessionClose({
    closeId: "close-2",
    sessionId: "stream-1",
    reasonCode: "complete",
    issuedAt: 1700000003,
    mediaData: "not allowed",
  }), /media bytes/);
  assert.throws(() => assertStreamSessionAnswer({
    answerId: "answer-2",
    sessionId: "stream-1",
    transport: "webrtc",
    payload: { nested: { mediaBytes: "not allowed" } },
    issuedAt: 1700000001,
  }), /media bytes/);
  assertMediaFulfillmentEvidence({
    kind: SWARM.RECORD_KIND.MEDIA_FULFILLMENT_EVIDENCE,
    evidenceId: "media-proof-1",
    evidenceKind: SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND.RENDER_STATE,
    state: SWARM.MEDIA_FULFILLMENT_STATE.USABLE,
    sessionId: "stream-1",
    adapterRef: "adapter:media-webrtc:browser",
    sourceRef: "camera:front",
    safeFacts: {
      readyState: 4,
      videoWidth: 1280,
      videoHeight: 720,
      visibleFrame: true,
    },
    observedAt: 1700000004,
    expiresAt: 1700000064,
  });
  assertMediaFulfillmentEvidence({
    kind: SWARM.RECORD_KIND.MEDIA_FULFILLMENT_EVIDENCE,
    evidenceId: "media-proof-2",
    evidenceKind: SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND.TRANSPORT_STATE,
    state: SWARM.MEDIA_FULFILLMENT_STATE.BLOCKED,
    sessionId: "stream-1",
    blockedReason: "iceFailed",
    safeFacts: {
      iceConnectionState: "failed",
      selectedIceServerCount: 1,
    },
    observedAt: 1700000005,
  });
  assert.throws(() => assertMediaFulfillmentEvidence({
    kind: SWARM.RECORD_KIND.MEDIA_FULFILLMENT_EVIDENCE,
    evidenceId: "media-proof-3",
    evidenceKind: SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND.TRANSPORT_STATE,
    state: SWARM.MEDIA_FULFILLMENT_STATE.BLOCKED,
    sessionId: "stream-1",
    observedAt: 1700000005,
  }), /blockedReason/);
  assert.throws(() => assertMediaFulfillmentEvidence({
    kind: SWARM.RECORD_KIND.MEDIA_FULFILLMENT_EVIDENCE,
    evidenceId: "media-proof-4",
    evidenceKind: SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND.RENDER_STATE,
    state: SWARM.MEDIA_FULFILLMENT_STATE.USABLE,
    safeFacts: { sdp: "raw session description" },
    observedAt: 1700000005,
  }), /requires sessionId/);
  assert.throws(() => assertMediaFulfillmentEvidence({
    kind: SWARM.RECORD_KIND.MEDIA_FULFILLMENT_EVIDENCE,
    evidenceId: "media-proof-5",
    evidenceKind: SWARM.MEDIA_FULFILLMENT_EVIDENCE_KIND.RENDER_STATE,
    state: SWARM.MEDIA_FULFILLMENT_STATE.USABLE,
    sessionId: "stream-1",
    safeFacts: { sdp: "raw session description" },
    observedAt: 1700000005,
  }), /unsafe safe fact/);
  assertMediaTransportPath({
    kind: SWARM.RECORD_KIND.MEDIA_TRANSPORT_PATH,
    pathId: "media-path-1",
    sessionId: "stream-1",
    activationId: "activation-1",
    routePromiseId: "route-1",
    transportProfileRef: "runtime.media.browser-webrtc.default",
    browserCandidateRefs: ["candidate:browser:1"],
    serviceCandidateRefs: ["candidate:service:1"],
    relayParticipantRefs: ["member:relay:1"],
    turnParticipantRefs: [],
    state: SWARM.MEDIA_TRANSPORT_PATH_STATE.BLOCKED,
    selectedPairState: SWARM.MEDIA_TRANSPORT_SELECTED_PAIR_STATE.FAILED,
    inboundRtpState: SWARM.MEDIA_TRANSPORT_RTP_STATE.BLOCKED,
    renderState: SWARM.MEDIA_TRANSPORT_RENDER_STATE.BLOCKED,
    blockedReason: "transportResourceExhausted",
    safeFacts: {
      servicePortLeaseCount: 32,
      renderedVideoWidth: 0,
    },
    evidenceRefs: ["media-proof-2"],
    issuedAt: 1700000006,
    expiresAt: 1700000066,
  });
  assert.throws(() => assertMediaTransportPath({
    kind: SWARM.RECORD_KIND.MEDIA_TRANSPORT_PATH,
    pathId: "media-path-2",
    sessionId: "stream-1",
    transportProfileRef: "runtime.media.browser-webrtc.default",
    state: SWARM.MEDIA_TRANSPORT_PATH_STATE.BLOCKED,
    selectedPairState: SWARM.MEDIA_TRANSPORT_SELECTED_PAIR_STATE.FAILED,
    inboundRtpState: SWARM.MEDIA_TRANSPORT_RTP_STATE.BLOCKED,
    renderState: SWARM.MEDIA_TRANSPORT_RENDER_STATE.BLOCKED,
    issuedAt: 1700000006,
  }), /blockedReason/);
  assert.throws(() => assertMediaTransportPath({
    kind: SWARM.RECORD_KIND.MEDIA_TRANSPORT_PATH,
    pathId: "media-path-3",
    sessionId: "stream-1",
    transportProfileRef: "runtime.media.browser-webrtc.default",
    state: SWARM.MEDIA_TRANSPORT_PATH_STATE.PENDING,
    selectedPairState: SWARM.MEDIA_TRANSPORT_SELECTED_PAIR_STATE.PENDING,
    inboundRtpState: SWARM.MEDIA_TRANSPORT_RTP_STATE.PENDING,
    renderState: SWARM.MEDIA_TRANSPORT_RENDER_STATE.PENDING,
    safeFacts: { sdp: "raw session description" },
    issuedAt: 1700000006,
  }), /unsafe safe fact|media transport path/);
  assertMediaTransportObservation({
    kind: SWARM.RECORD_KIND.MEDIA_TRANSPORT_OBSERVATION,
    observationId: "media-observation-1",
    pathId: "media-path-1",
    sessionId: "stream-1",
    activationId: "activation-1",
    routePromiseId: "route-1",
    participantRef: "service:abc",
    participantRole: SWARM.MEDIA_TRANSPORT_PARTICIPANT_ROLE.SERVICE,
    state: SWARM.MEDIA_TRANSPORT_OBSERVATION_STATE.DISCONNECTED,
    connectionState: "disconnected",
    selectedPairState: SWARM.MEDIA_TRANSPORT_SELECTED_PAIR_STATE.SELECTED,
    inboundRtpState: SWARM.MEDIA_TRANSPORT_RTP_STATE.STALLED,
    renderState: SWARM.MEDIA_TRANSPORT_RENDER_STATE.PENDING,
    reason: "peerConnectionDisconnected",
    safeFacts: {
      graceMs: 12000,
      sourceCount: 2,
    },
    evidenceRefs: ["media-path-1"],
    observedAt: 1700000007,
    expiresAt: 1700000067,
  });
  assert.throws(() => assertMediaTransportObservation({
    kind: SWARM.RECORD_KIND.MEDIA_TRANSPORT_OBSERVATION,
    observationId: "media-observation-2",
    pathId: "media-path-1",
    sessionId: "stream-1",
    participantRef: "service:abc",
    participantRole: SWARM.MEDIA_TRANSPORT_PARTICIPANT_ROLE.SERVICE,
    state: SWARM.MEDIA_TRANSPORT_OBSERVATION_STATE.BLOCKED,
    observedAt: 1700000007,
  }), /blockedReason/);
  assert.throws(() => assertMediaTransportObservation({
    kind: SWARM.RECORD_KIND.MEDIA_TRANSPORT_OBSERVATION,
    observationId: "media-observation-3",
    pathId: "media-path-1",
    sessionId: "stream-1",
    participantRef: "browser:abc",
    participantRole: SWARM.MEDIA_TRANSPORT_PARTICIPANT_ROLE.BROWSER,
    state: SWARM.MEDIA_TRANSPORT_OBSERVATION_STATE.CONNECTED,
    safeFacts: { sdp: "raw session description" },
    observedAt: 1700000007,
  }), /unsafe safe fact|media transport observation/);

  assertAppRecipe({
    recipeId: "recipe-community-archive",
    name: "Community Archive",
    requiredCapabilities: [SWARM.CORE_CAPABILITY.STORAGE_PIN],
    requiredChannels: ["storage.pin.lab"],
    roles: ["runner", "storage"],
  });
  assertAppRunnerAdvertisement({
    runnerId: "runner-1",
    memberRef: BROWSER_PK,
    version: "0.1.0",
    capacity: { slots: 1 },
    health: { status: "ok" },
  });
});

test("surface adapter lifecycle posture separates reconnect release and cleanup", () => {
  assert.equal(SURFACE_APP.ADAPTER_LIFECYCLE_STATE.RECONNECTING, "reconnecting");
  assert.equal(SWARM.RECORD_KIND.SURFACE_ADAPTER_LIFECYCLE_POSTURE, "surface.adapter.lifecycle.posture");
  assertSurfaceAdapterLifecyclePosture({
    kind: SWARM.RECORD_KIND.SURFACE_ADAPTER_LIFECYCLE_POSTURE,
    lifecycleId: "adapter-life:nvr-preview:1",
    adapterRef: "adapter:media-webrtc:browser",
    moduleRef: "constitute-ui/media-webrtc-adapter@0.1.0",
    subjectRef: "session:nvr-preview-1",
    surfaceRef: "surface:nvr-ui",
    role: SURFACE_APP.MODULE_ROLE.PLATFORM_ADAPTER,
    participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
    state: SURFACE_APP.ADAPTER_LIFECYCLE_STATE.RECONNECTING,
    intentRefs: ["intent:nvr-preview"],
    sessionRefs: ["session:nvr-preview-1"],
    evidenceRefs: ["media-proof:transport-state"],
    releaseRefs: ["release:nvr-ui:local"],
    reconnect: {
      attempt: 2,
      delayMs: 4000,
      nextRetryAt: 1700000010,
      reason: "inboundRtpStalled",
    },
    cleanup: {
      openResourceCount: 1,
      releaseRequired: true,
    },
    safeFacts: {
      sourceCount: 2,
      selectedIceServerCount: 1,
    },
    issuedAt: 1700000000,
    observedAt: 1700000001,
    expiresAt: 1700000060,
  });
  assertSurfaceAdapterLifecyclePosture({
    kind: SWARM.RECORD_KIND.SURFACE_ADAPTER_LIFECYCLE_POSTURE,
    lifecycleId: "adapter-life:nvr-preview:release",
    adapterRef: "adapter:media-webrtc:browser",
    subjectRef: "session:nvr-preview-1",
    role: SURFACE_APP.MODULE_ROLE.PLATFORM_ADAPTER,
    participantSide: SURFACE_APP.PARTICIPANT_SIDE.WINDOW,
    state: SURFACE_APP.ADAPTER_LIFECYCLE_STATE.RELEASED,
    sessionRefs: ["session:nvr-preview-1"],
    releaseRefs: ["release:nvr-ui:local"],
    cleanup: {
      openResourceCount: 0,
      releaseRequired: false,
      releasedAt: 1700000012,
    },
    issuedAt: 1700000010,
    observedAt: 1700000012,
  });
  assert.throws(() => assertSurfaceAdapterLifecyclePosture({
    kind: SWARM.RECORD_KIND.SURFACE_ADAPTER_LIFECYCLE_POSTURE,
    lifecycleId: "adapter-life:bad",
    adapterRef: "adapter:media-webrtc:browser",
    subjectRef: "session:nvr-preview-1",
    state: SURFACE_APP.ADAPTER_LIFECYCLE_STATE.RECONNECTING,
    issuedAt: 1700000000,
    observedAt: 1700000001,
  }), /requires reconnect posture/);
  assert.throws(() => assertSurfaceAdapterLifecyclePosture({
    kind: SWARM.RECORD_KIND.SURFACE_ADAPTER_LIFECYCLE_POSTURE,
    lifecycleId: "adapter-life:bad-release",
    adapterRef: "adapter:media-webrtc:browser",
    subjectRef: "session:nvr-preview-1",
    state: SURFACE_APP.ADAPTER_LIFECYCLE_STATE.RELEASED,
    issuedAt: 1700000000,
    observedAt: 1700000001,
  }), /release ref/);
});

test("stream session lifecycle classifier separates carrier record kind from reducer phase", () => {
  const admissionCarrier = {
    body: {
      payload: {
        recordKind: SWARM.STREAM_RECORD_KIND.ADMISSION,
        record: {
          admissionId: "admission-1",
          sessionId: "stream-1",
          admittedBy: SERVICE_PK,
        },
      },
    },
  };
  const admission = streamSessionLifecycleRecordFromCarrier(admissionCarrier);
  assert.equal(admission.phase, STREAM_SESSION_LIFECYCLE_PHASE.ADMISSION);
  assert.equal(admission.recordKind, SWARM.STREAM_RECORD_KIND.ADMISSION);
  assert.equal(admission.record.sessionId, "stream-1");

  assert.equal(
    streamSessionLifecyclePhase(SWARM.STREAM_RECORD_KIND.ANSWER),
    STREAM_SESSION_LIFECYCLE_PHASE.ANSWER,
  );
  assert.equal(
    streamSessionLifecycleRecordKind({ recordRef: { kind: SWARM.STREAM_RECORD_KIND.REJECT } }),
    SWARM.STREAM_RECORD_KIND.REJECT,
  );
  assert.equal(streamSessionLifecycleRecordFromCarrier({
    body: { payload: { recordKind: "route.observation", record: {} } },
  }), null);
});

test("swarm runtime golden vector stays canonical", () => {
  const vector = JSON.parse(readFileSync(new URL("../vectors/swarm-runtime-v1.json", import.meta.url), "utf8"));
  assert.equal(assertSwarmFrame(vector.frame, { now: 1700000001000 }).frameId, vector.frame.frameId);
  assert.equal(vector.frame.frameId, "9949c702f8c61f1faf1cf89004ad75432189546e990750a5a0f03a330f5ca6ac");
  assertProjectionDelta(vector.delta);
  const applied = applyProjectionDelta({
    state: { cameras: [{ id: "front", status: "ok" }] },
    revision: vector.delta.baseRevision,
    delta: vector.delta,
  });
  assert.equal(applied.state.cameras[0].status, "degraded");
});
