use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::caac::{CAAC_ALG_V1, CAAC_VERSION, CaacEnvelope, verify_envelope_signature};

pub const SWARM_FRAME_VERSION: u8 = 1;

pub const SWARM_WIRE_FRAME: &str = "swarm.frame";
pub const SWARM_EDGE_WIRE_HELLO: &str = "swarm.edge.hello";
pub const SWARM_EDGE_WIRE_RESUME: &str = "swarm.edge.resume";
pub const SWARM_EDGE_WIRE_ACCEPT: &str = "swarm.edge.accept";
pub const SWARM_EDGE_WIRE_CLOSE: &str = "swarm.edge.close";

pub const CAPABILITY_SWARM_EDGE_ATTACH: &str = "swarm.edge.attach";
pub const CAPABILITY_PROJECTION_OBSERVE: &str = "projection.observe";
pub const CAPABILITY_PROJECTION_DELTA_APPLY: &str = "projection.delta.apply";
pub const CAPABILITY_SERVICE_SURFACE_OBSERVE: &str = "service.surface.observe";
pub const CAPABILITY_SERVICE_INTENT_INVOKE: &str = "service.intent.invoke";
pub const CAPABILITY_STORAGE_OBJECT_PUT: &str = "storage.object.put";
pub const CAPABILITY_STORAGE_OBJECT_GET: &str = "storage.object.get";
pub const CAPABILITY_STORAGE_PIN: &str = "storage.pin";
pub const CAPABILITY_STORAGE_AVAILABILITY_ATTEST: &str = "storage.availability.attest";
pub const CAPABILITY_LOGGING_EVENTS_OBSERVE: &str = "logging.events.observe";
pub const CAPABILITY_STREAM_SESSION_OFFER: &str = "stream.session.offer";
pub const CAPABILITY_STREAM_SESSION_CONTROL: &str = "stream.session.control";
pub const CAPABILITY_MEDIA_STREAM_PREVIEW: &str = "media.stream.preview";
pub const CAPABILITY_NODE_CAPABILITY_ACTIVATE: &str = "node.capability.activate";
pub const CAPABILITY_ROUTE_PROMISE_RESOLVE: &str = "route.promise.resolve";
pub const CAPABILITY_ROUTE_OBSERVATION_PUBLISH: &str = "route.observation.publish";
pub const CAPABILITY_STREAM_ROUTE_PLAN_OBSERVE: &str = "stream.routePlan.observe";
pub const CAPABILITY_RUNTIME_DIAGNOSTICS_OBSERVE: &str = "runtime.diagnostics.observe";
pub const CAPABILITY_RUNTIME_DIAGNOSTICS_COMMAND: &str = "runtime.diagnostics.command";
pub const CAPABILITY_APP_RUNNER_PIN: &str = "app.runner.pin";

pub const STREAM_CANDIDATE_ROLE_BROWSER: &str = "browser";
pub const STREAM_CANDIDATE_ROLE_SERVICE: &str = "service";
pub const STREAM_CANDIDATE_ACTIONABILITY_USABLE: &str = "usable";
pub const STREAM_CANDIDATE_ACTIONABILITY_BLOCKED: &str = "blocked";

pub const AGREEMENT_PLANE_ACTION_AUTHORITY: &str = "actionAuthority";
pub const AGREEMENT_PLANE_ACCESS_AUTHORITY: &str = "accessAuthority";
pub const AGREEMENT_PLANE_DELIVERY_WITNESS: &str = "deliveryWitness";
pub const AGREEMENT_PLANE_MATERIALIZATION: &str = "materialization";
pub const AGREEMENT_STATE_REQUESTED: &str = "requested";
pub const AGREEMENT_STATE_ACCEPTED: &str = "accepted";
pub const AGREEMENT_STATE_APPLIED: &str = "applied";
pub const AGREEMENT_STATE_REJECTED: &str = "rejected";
pub const AGREEMENT_STATE_BLOCKED: &str = "blocked";
pub const AGREEMENT_STATE_EXPIRED: &str = "expired";
pub const AGREEMENT_STATE_REVOKED: &str = "revoked";
pub const AUTHORITY_PROOF_STATE_PROVED: &str = "proved";
pub const AUTHORITY_PROOF_STATE_DEGRADED: &str = "degraded";
pub const AUTHORITY_PROOF_STATE_BLOCKED: &str = "blocked";
pub const AUTHORITY_PROOF_STATE_EXPIRED: &str = "expired";
pub const AUTHORITY_PROOF_STATE_REVOKED: &str = "revoked";
pub const AUTHORITY_PROOF_CHECK_SYNC: &str = "sync";
pub const AUTHORITY_PROOF_CHECK_READ: &str = "read";
pub const AUTHORITY_PROOF_CHECK_WRITE_REDUCE: &str = "writeReduce";
pub const AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE: &str = "revokeExpire";

pub const RECORD_NODE_CAPABILITY: &str = "node.capability";
pub const RECORD_RUNTIME_ACTIVATION_REQUEST: &str = "runtime.activation.request";
pub const RECORD_ROUTE_PROMISE: &str = "route.promise";
pub const RECORD_ROUTE_OBSERVATION: &str = "route.observation";
pub const RECORD_STREAM_ROUTE_PLAN: &str = "stream.routePlan";
pub const RECORD_RUNTIME_DIAGNOSTIC_EVENT: &str = "runtime.diagnostic.event";
pub const RECORD_RUNTIME_DIAGNOSTIC_COMMAND: &str = "runtime.diagnostic.command";
pub const RECORD_RUNTIME_DIAGNOSTIC_COMMAND_RESULT: &str = "runtime.diagnostic.command.result";
pub const RECORD_MEMBER_PRESENCE: &str = "member.presence";
pub const RECORD_DIRECTORY_ENTRY: &str = "directory.entry";
pub const RECORD_BOOTSTRAP_CARRIER: &str = "bootstrap.carrier";
pub const RECORD_SWARM_IDENTITY: &str = "swarm.identity";
pub const RECORD_SWARM_DEVICE: &str = "swarm.device";
pub const RECORD_SWARM_GATEWAY: &str = "swarm.gateway";
pub const RECORD_SWARM_SERVICE: &str = "swarm.service";
pub const RECORD_SWARM_MEMBER: &str = "swarm.member";
pub const RECORD_SWARM_GRANT: &str = "swarm.grant";
pub const RECORD_SWARM_ROLE: &str = "swarm.role";
pub const RECORD_SWARM_INTERACTION: &str = "swarm.interaction";
pub const RECORD_SWARM_ACTIVATION: &str = "swarm.activation";
pub const RECORD_SWARM_RELEASE: &str = "swarm.release";
pub const RECORD_SWARM_REVOCATION: &str = "swarm.revocation";
pub const RECORD_AUTHORITY_ROOT_OPERATION: &str = "authority.root.operation";
pub const RECORD_AUTHORITY_ACTION_GRANT: &str = "authority.action.grant";
pub const RECORD_AUTHORITY_ACTION_EXERCISE: &str = "authority.action.exercise";
pub const RECORD_AUTHORITY_GRANT_REVOCATION_POSTURE: &str = "authority.grant.revocationPosture";
pub const RECORD_AUTHORITY_MULTI_IDENTITY_PROOF: &str = "authority.multiIdentity.proof";
pub const RECORD_ACCESS_GROUP: &str = "access.group";
pub const RECORD_ACCESS_EPOCH: &str = "access.epoch";
pub const RECORD_PRIVATE_CONTENT_ENVELOPE: &str = "private.content.envelope";
pub const RECORD_EVENT_FABRIC_ACCESS_CLASS: &str = "event.fabric.accessClass";
pub const RECORD_EVENT_FABRIC_PROCESSOR_CONTRACT: &str = "event.fabric.processor.contract";
pub const RECORD_SECURITY_PROCESSOR_SEED: &str = "security.processor.seed";
pub const RECORD_PARTICIPANT_RUNLEVEL: &str = "participant.runlevel";
pub const RECORD_PARTICIPANT_SELF_CAPABILITY: &str = "participant.selfCapability";
pub const RECORD_EVENT_ADMISSION: &str = "event.admission";
pub const RECORD_SUBSCRIPTION_CONTRACT: &str = "subscription.contract";
pub const RECORD_MATERIALIZATION_BUDGET: &str = "materialization.budget";
pub const RECORD_CONSUMER_FLOOR: &str = "consumer.floor";
pub const RECORD_RESOURCE_PROFILE: &str = "resource.profile";
pub const RECORD_RESOURCE_POSTURE: &str = "resource.posture";
pub const RECORD_RETENTION_RELEASE: &str = "retention.release";
pub const RECORD_CONTRIBUTION_LIFECYCLE: &str = "contribution.lifecycle";
pub const RECORD_MEDIA_FULFILLMENT_EVIDENCE: &str = "media.fulfillment.evidence";
pub const RECORD_MEDIA_TRANSPORT_PATH: &str = "media.transport.path";
pub const RECORD_MEDIA_TRANSPORT_OBSERVATION: &str = "media.transport.observation";
pub const RECORD_SERVICE_MANAGER_RELEASE_CONTRACT: &str = "service.manager.release.contract";
pub const RECORD_SERVICE_MANAGER_SECRET_BOUNDARY: &str = "service.manager.secretBoundary";
pub const RECORD_SERVICE_MANAGER_TRAIN_DIGEST: &str = "service.manager.train.digest";
pub const RECORD_SERVICE_MANAGER_LAB_PROOF: &str = "service.manager.labProof";
pub const RECORD_SURFACE_APP_MANIFEST: &str = "surface.app.manifest";
pub const RECORD_SURFACE_APP_BOOTSTRAP_CONTRACT: &str = "surface.app.bootstrap.contract";

pub const SURFACE_APP_CONTRACT_STATE_DRAFT: &str = "draft";
pub const SURFACE_APP_CONTRACT_STATE_READY: &str = "ready";
pub const SURFACE_APP_CONTRACT_STATE_BLOCKED: &str = "blocked";
pub const SURFACE_APP_CONTRACT_STATE_SUPERSEDED: &str = "superseded";
pub const SURFACE_APP_CONTRACT_STATE_EXPIRED: &str = "expired";

pub const SURFACE_APP_MANIFEST_VERSION_CURRENT: &str = "current";
pub const SURFACE_APP_MANIFEST_VERSION_COMPATIBLE: &str = "compatible";
pub const SURFACE_APP_MANIFEST_VERSION_UPDATE_AVAILABLE: &str = "updateAvailable";
pub const SURFACE_APP_MANIFEST_VERSION_BLOCKED: &str = "blocked";
pub const SURFACE_APP_MANIFEST_VERSION_SUPERSEDED: &str = "superseded";

pub const SURFACE_SECRET_BOUNDARY_NOT_REQUIRED: &str = "notRequired";
pub const SURFACE_SECRET_BOUNDARY_RESOLVED: &str = "resolved";
pub const SURFACE_SECRET_BOUNDARY_BLOCKED: &str = "blocked";
pub const SURFACE_SECRET_BOUNDARY_UNAVAILABLE: &str = "unavailable";

pub const SERVICE_MANAGER_PROOF_STATE_PENDING: &str = "pending";
pub const SERVICE_MANAGER_PROOF_STATE_PROVED: &str = "proved";
pub const SERVICE_MANAGER_PROOF_STATE_FAILED: &str = "failed";
pub const SERVICE_MANAGER_PROOF_STATE_BLOCKED: &str = "blocked";
pub const SERVICE_MANAGER_PROOF_STATE_EXPIRED: &str = "expired";

pub const SURFACE_FULFILLMENT_MODE_BUNDLED: &str = "bundled";
pub const SURFACE_FULFILLMENT_MODE_SWARM_PACKAGE: &str = "swarmPackage";
pub const SURFACE_FULFILLMENT_MODE_STORAGE_OBJECT: &str = "storageObject";
pub const SURFACE_FULFILLMENT_MODE_NATIVE_INSTALLED: &str = "nativeInstalled";
pub const SURFACE_FULFILLMENT_MODE_DEV_OVERLAY: &str = "devOverlay";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ZoneScope {
    pub zone_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_hops: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ZonePropagation {
    LocalOnly,
    ZoneMembers,
    ChannelMembers,
    ExplicitAudience,
    Bootstrap,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ZonePrivacy {
    RawIds,
    Pseudonymous,
    IdentityProjected,
    PublicBootstrap,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoutingScopePosture {
    pub kind: String,
    pub required: bool,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_scope: Option<ZoneScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PostureFacet {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParticipantRunlevelPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub runlevel_id: String,
    pub participant_ref: String,
    pub participant_kind: String,
    pub runlevel: String,
    #[serde(default)]
    pub facets: BTreeMap<String, PostureFacet>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SelfCapabilityAssessment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub assessment_id: String,
    pub participant_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_member_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    pub capability_ref: String,
    #[serde(default)]
    pub actions: Vec<String>,
    pub status: String,
    pub runlevel: String,
    #[serde(default)]
    pub facets: BTreeMap<String, PostureFacet>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<String>,
    pub updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub profile_id: String,
    pub profile_class: String,
    #[serde(default)]
    pub budgets: Value,
    #[serde(default)]
    pub caps: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourcePosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub posture_id: String,
    pub profile_id: String,
    pub state: String,
    #[serde(default)]
    pub counts: Value,
    #[serde(default)]
    pub budgets: Value,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub sampled_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventAdmissionEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub admission_id: String,
    pub plane: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriber_ref: Option<String>,
    #[serde(default)]
    pub subject: Value,
    #[serde(default)]
    pub audience: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_severity: Option<String>,
    pub effective_priority: u64,
    pub decision: String,
    pub proof_requirement: String,
    pub proof_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub cost: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub observed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionContract {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub subscription_id: String,
    pub subscriber_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_class: Option<String>,
    #[serde(default)]
    pub planes: Vec<String>,
    #[serde(default)]
    pub subject_selector: Value,
    #[serde(default)]
    pub audience: Value,
    #[serde(default)]
    pub window: Value,
    #[serde(default)]
    pub cost: Value,
    #[serde(default)]
    pub proof: Value,
    #[serde(default)]
    pub delivery: Value,
    #[serde(default)]
    pub backpressure: Value,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerFloor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub floor_id: String,
    pub consumer_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_time_floor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_time_floor: Option<u64>,
    pub lag_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub redelivery: Value,
    #[serde(default)]
    pub replay: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub sampled_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MaterializationSchemaPosture {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub migration_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MaterializationBudget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub budget_id: String,
    pub source_authority: String,
    pub consumer_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriber_ref: Option<String>,
    pub payload_class: String,
    pub copy_role: String,
    pub transfer_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_tier: Option<String>,
    #[serde(default = "default_within_budget")]
    pub state: String,
    #[serde(default)]
    pub limits: Value,
    #[serde(default)]
    pub snapshot_policy: Value,
    #[serde(default)]
    pub delta_policy: Value,
    #[serde(default)]
    pub coalescing: Value,
    #[serde(default)]
    pub cardinality: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<MaterializationSchemaPosture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_floor: Option<ConsumerFloor>,
    #[serde(default)]
    pub reference_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_class: Option<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

fn default_within_budget() -> String {
    "withinBudget".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionReleasePosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub evaluation_id: String,
    pub subject_ref: String,
    pub effective_retention: String,
    pub state: String,
    #[serde(default)]
    pub policy_refs: Vec<String>,
    #[serde(default)]
    pub overlay_refs: Vec<String>,
    #[serde(default)]
    pub owner_refs: Vec<String>,
    #[serde(default)]
    pub holder_refs: Vec<String>,
    #[serde(default)]
    pub fulfillment_refs: Vec<String>,
    #[serde(default)]
    pub residency_layers: Vec<String>,
    #[serde(default)]
    pub witness_refs: Vec<String>,
    #[serde(default)]
    pub supersession_refs: Vec<String>,
    #[serde(default)]
    pub retraction_refs: Vec<String>,
    #[serde(default)]
    pub revocation_refs: Vec<String>,
    #[serde(default)]
    pub blockers: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_after: Option<u64>,
    pub evaluated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContributionLifecycle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub contribution_id: String,
    pub parent_ref: String,
    pub subject_ref: String,
    pub writer_ref: String,
    pub contribution_type: String,
    #[serde(default = "default_contribution_state")]
    pub state: String,
    pub role: String,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub scope: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_contribution_ref: Option<String>,
    #[serde(default)]
    pub supersedes: Vec<String>,
    #[serde(default)]
    pub witness_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retracted_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
}

fn default_contribution_state() -> String {
    "active".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MediaFulfillmentEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub evidence_id: String,
    pub evidence_kind: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_promise_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub observed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MediaTransportPath {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub path_id: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_promise_id: Option<String>,
    pub transport_profile_ref: String,
    #[serde(default)]
    pub browser_candidate_refs: Vec<String>,
    #[serde(default)]
    pub service_candidate_refs: Vec<String>,
    #[serde(default)]
    pub relay_participant_refs: Vec<String>,
    #[serde(default)]
    pub turn_participant_refs: Vec<String>,
    pub state: String,
    pub selected_pair_state: String,
    pub inbound_rtp_state: String,
    pub render_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MediaTransportObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub observation_id: String,
    pub path_id: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_promise_id: Option<String>,
    pub participant_ref: String,
    pub participant_role: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ice_connection_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_pair_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_rtp_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub observed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmRecordRef {
    pub kind: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmAck {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked_frame_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default)]
    pub gap_after_frame_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmFrameBody {
    pub encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "is_false")]
    pub public_bootstrap: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwarmFrameKind {
    #[serde(rename = "record.publish")]
    RecordPublish,
    #[serde(rename = "record.retract")]
    RecordRetract,
    #[serde(rename = "channel.observe")]
    ChannelObserve,
    #[serde(rename = "channel.unobserve")]
    ChannelUnobserve,
    #[serde(rename = "projection.snapshot")]
    ProjectionSnapshot,
    #[serde(rename = "projection.delta")]
    ProjectionDelta,
    #[serde(rename = "projection.repair.request")]
    ProjectionRepairRequest,
    #[serde(rename = "service.intent")]
    ServiceIntent,
    #[serde(rename = "service.response")]
    ServiceResponse,
    #[serde(rename = "stream.intent")]
    StreamIntent,
    #[serde(rename = "stream.control")]
    StreamControl,
    #[serde(rename = "stream.status")]
    StreamStatus,
    #[serde(rename = "storage.pin.intent")]
    StoragePinIntent,
    #[serde(rename = "storage.pin.attestation")]
    StoragePinAttestation,
    #[serde(rename = "node.capability")]
    NodeCapability,
    #[serde(rename = "runtime.activation.request")]
    RuntimeActivationRequest,
    #[serde(rename = "route.promise")]
    RoutePromise,
    #[serde(rename = "route.observation")]
    RouteObservation,
    #[serde(rename = "stream.routePlan")]
    StreamRoutePlan,
    #[serde(rename = "runtime.diagnostic.event")]
    RuntimeDiagnosticEvent,
    #[serde(rename = "runtime.diagnostic.command")]
    RuntimeDiagnosticCommand,
    #[serde(rename = "runtime.diagnostic.command.result")]
    RuntimeDiagnosticCommandResult,
    #[serde(rename = "swarm.identity")]
    SwarmIdentity,
    #[serde(rename = "swarm.device")]
    SwarmDevice,
    #[serde(rename = "swarm.gateway")]
    SwarmGateway,
    #[serde(rename = "swarm.service")]
    SwarmService,
    #[serde(rename = "swarm.member")]
    SwarmMember,
    #[serde(rename = "swarm.grant")]
    SwarmGrant,
    #[serde(rename = "swarm.role")]
    SwarmRole,
    #[serde(rename = "swarm.interaction")]
    SwarmInteraction,
    #[serde(rename = "swarm.activation")]
    SwarmActivation,
    #[serde(rename = "swarm.release")]
    SwarmRelease,
    #[serde(rename = "swarm.revocation")]
    SwarmRevocation,
    #[serde(rename = "contribution.lifecycle")]
    ContributionLifecycle,
    #[serde(rename = "ack")]
    Ack,
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "bootstrap.discovery")]
    BootstrapDiscovery,
    #[serde(rename = "bootstrap.gatewayHint")]
    BootstrapGatewayHint,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmFrame {
    pub version: u8,
    pub frame_id: String,
    pub kind: SwarmFrameKind,
    pub issuer: String,
    #[serde(default)]
    pub audience: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_scope: Option<ZoneScope>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_ref: Option<SwarmRecordRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    pub body: SwarmFrameBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<SwarmAck>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ChannelRecordKind {
    Descriptor,
    Policy,
    Membership,
    MemberRole,
    Recommendation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDescriptor {
    pub channel_id: String,
    pub kind: String,
    pub display_name: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub record_kinds: Vec<String>,
    #[serde(default)]
    pub owner_refs: Vec<String>,
    pub policy_ref: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelPolicy {
    pub policy_id: String,
    #[serde(default)]
    pub observe: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub set: Vec<String>,
    #[serde(default)]
    pub invoke: Vec<String>,
    #[serde(default)]
    pub pin: Vec<String>,
    #[serde(default)]
    pub attest: Vec<String>,
    #[serde(default)]
    pub run: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMembership {
    pub membership_id: String,
    pub channel_id: String,
    pub member_ref: String,
    pub role: ChannelMemberRole,
    pub authority_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ChannelMemberRole {
    Owner,
    Writer,
    Observer,
    Replicator,
    Runner,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRecommendation {
    pub recommendation_id: String,
    pub channel_id: String,
    pub recommender_ref: String,
    #[serde(default)]
    pub capability_hints: Vec<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDefinition {
    pub capability: String,
    pub definition_id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub schema: Value,
    #[serde(default)]
    pub authority_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAdvertisement {
    pub advertisement_id: String,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_ref: Option<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDirectoryEntry {
    pub entry_id: String,
    pub capability: String,
    pub channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_ref: Option<String>,
    pub priority: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPolicy {
    pub policy_id: String,
    pub capability: String,
    #[serde(default)]
    pub authority_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub node_capability_id: String,
    pub node_ref: String,
    pub capability_ref: String,
    pub service_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_member_ref: String,
    #[serde(default)]
    pub backing_channel_refs: Vec<String>,
    #[serde(default)]
    pub activation_policy: Value,
    pub freshness: Value,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeActivationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub activation_id: String,
    pub node_ref: String,
    pub capability_ref: String,
    #[serde(default)]
    pub params: Value,
    pub requester_ref: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoutePromise {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub promise_id: String,
    pub activation_id: String,
    pub node_ref: String,
    pub capability_ref: String,
    pub requester_ref: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_member_ref: String,
    pub service_pk: String,
    pub channel_id: String,
    pub zone_scope: ZoneScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_zone_scope: Option<ZoneScope>,
    #[serde(default)]
    pub audience_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub route_policy: Value,
    #[serde(default)]
    pub path_refs: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub release_policy: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalRouteBinding {
    pub binding_id: String,
    pub promise_id: String,
    pub participant_ref: String,
    pub binding_kind: String,
    #[serde(default)]
    pub local_refs: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteObservationState {
    Delivered,
    MemberWritten,
    MemberRead,
    ObservingUnreachable,
    UnreachableFor,
    Rejected,
    Accepted,
    Degraded,
    Released,
    Closed,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RouteObservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub observation_id: String,
    pub state: RouteObservationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promise_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivered_to: Vec<String>,
    #[serde(default)]
    pub failed_predicates: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_reason: Option<String>,
    #[serde(default)]
    pub diagnostics: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StreamPathKind {
    Direct,
    BrowserWebRtc,
    NativeSwarm,
    GatewayRelay,
    MultiGatewayRelay,
    DegradedProjectionOnly,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StreamPathState {
    Candidate,
    Selected,
    Unavailable,
    Failed,
    Released,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ReachabilityState {
    Unknown,
    Reachable,
    ObservingUnreachable,
    UnreachableFor,
    Degraded,
    Closed,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamRoutePath {
    pub path_id: String,
    pub kind: StreamPathKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<StreamPathState>,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub diagnostics: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamRoutePlan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub session_id: String,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub requester_ref: String,
    pub service_member_ref: String,
    pub capability_ref: String,
    #[serde(default)]
    pub route_lease: Value,
    #[serde(default)]
    pub candidate_paths: Vec<StreamRoutePath>,
    pub preferred_path: StreamRoutePath,
    #[serde(default)]
    pub fallback_paths: Vec<StreamRoutePath>,
    pub selected_path: StreamRoutePath,
    pub path_state: StreamPathState,
    pub reachability_state: ReachabilityState,
    #[serde(default)]
    pub release_policy: Value,
    #[serde(default)]
    pub diagnostics: Value,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemberPresence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub member_ref: String,
    pub member_kind: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub entry_id: String,
    pub subject_ref: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapCarrierRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub carrier_id: String,
    pub carrier_kind: String,
    pub boundary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmIdentityRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub identity_id: String,
    #[serde(default)]
    pub root_refs: Vec<String>,
    #[serde(default)]
    pub recovery_root_refs: Vec<String>,
    #[serde(default)]
    pub recovery_route_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmDeviceRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub device_id: String,
    pub device_ref: String,
    pub identity_ref: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmGatewayRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub gateway_id: String,
    pub gateway_ref: String,
    #[serde(default)]
    pub owner_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmServiceRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub service_id: String,
    pub service_ref: String,
    pub service: String,
    pub contract_ref: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmMemberRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub member_id: String,
    pub member_ref: String,
    pub member_kind: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub storage: Value,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmGrantRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub grant_id: String,
    pub issuer_ref: String,
    pub subject_ref: String,
    #[serde(default)]
    pub audience_refs: Vec<String>,
    pub authority_domain: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub role_refs: Vec<String>,
    #[serde(default)]
    pub elevated: bool,
    #[serde(default)]
    pub root_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub private_refs: Vec<Value>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmRoleRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub role_id: String,
    pub role: String,
    pub member_ref: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmInteractionParticipant {
    pub role: String,
    pub member_ref: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub contract_view: Value,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmInteractionRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub interaction_id: String,
    pub contract_ref: String,
    pub interaction_kind: String,
    #[serde(default)]
    pub participants: Vec<SwarmInteractionParticipant>,
    pub state: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub authority: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_scope: Option<RoutingScopePosture>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub private_refs: Vec<Value>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmActivationRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub activation_id: String,
    pub interaction_id: String,
    pub node_ref: String,
    pub capability_ref: String,
    pub requester_ref: String,
    pub runtime_member_ref: String,
    pub state: String,
    #[serde(default)]
    pub authority_summary: Value,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmReleaseRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub release_id: String,
    pub interaction_id: String,
    pub released_by: String,
    pub reason_code: String,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmRevocationRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub revocation_id: String,
    pub target_ref: String,
    pub issuer_ref: String,
    pub authority_domain: String,
    pub reason_code: String,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityRootOperationRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub operation_id: String,
    pub operation: String,
    pub identity_ref: String,
    pub actor_ref: String,
    pub target_ref: String,
    #[serde(default)]
    pub admin_grant_refs: Vec<String>,
    #[serde(default)]
    pub root_refs: Vec<String>,
    #[serde(default)]
    pub device_refs: Vec<String>,
    #[serde(default)]
    pub notification_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActionAuthorityGrantRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub grant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plane: Option<String>,
    pub issuer_ref: String,
    pub subject_ref: String,
    #[serde(default)]
    pub audience_refs: Vec<String>,
    pub authority_domain: String,
    pub resource_ref: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Value,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub parent_grant_refs: Vec<String>,
    #[serde(default)]
    pub revocation_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub elevated: bool,
    #[serde(default)]
    pub root_refs: Vec<String>,
    #[serde(default)]
    pub delegation: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub private_refs: Vec<Value>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActionAuthorityExerciseRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub exercise_id: String,
    pub grant_id: String,
    pub actor_ref: String,
    pub subject_ref: String,
    pub resource_ref: String,
    pub action: String,
    pub state: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub result_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityGrantRevocationPostureRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub revocation_id: String,
    pub target_grant_ref: String,
    pub issuer_ref: String,
    pub authority_domain: String,
    #[serde(default)]
    pub affected_grant_refs: Vec<String>,
    #[serde(default)]
    pub affected_access_group_refs: Vec<String>,
    #[serde(default)]
    pub inherited_scope_refs: Vec<String>,
    pub state: String,
    pub reason_code: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityProofCheck {
    pub check: String,
    pub plane: String,
    pub state: String,
    pub target_ref: String,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub access_epoch_refs: Vec<String>,
    #[serde(default)]
    pub exercise_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityMultiIdentityProofRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub proof_id: String,
    pub owner_identity_ref: String,
    pub grantee_identity_ref: String,
    pub grantee_member_ref: String,
    #[serde(default)]
    pub subject_refs: Vec<String>,
    #[serde(default)]
    pub action_grant_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub access_epoch_refs: Vec<String>,
    #[serde(default)]
    pub private_envelope_refs: Vec<String>,
    #[serde(default)]
    pub revocation_refs: Vec<String>,
    #[serde(default)]
    pub checks: Vec<AuthorityProofCheck>,
    #[serde(default = "default_authority_proof_state")]
    pub state: String,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

fn default_authority_proof_state() -> String {
    AUTHORITY_PROOF_STATE_PROVED.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccessGroupRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub group_id: String,
    pub owner_ref: String,
    pub subject_ref: String,
    #[serde(default)]
    pub content_classes: Vec<String>,
    #[serde(default)]
    pub member_refs: Vec<String>,
    #[serde(default)]
    pub admin_refs: Vec<String>,
    pub current_epoch_id: String,
    #[serde(default)]
    pub partition_refs: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccessEpochRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub epoch_id: String,
    pub group_id: String,
    pub sequence: u64,
    pub change_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_epoch_id: Option<String>,
    #[serde(default)]
    pub member_refs: Vec<String>,
    #[serde(default)]
    pub added_member_refs: Vec<String>,
    #[serde(default)]
    pub removed_member_refs: Vec<String>,
    #[serde(default)]
    pub partition_refs: Vec<String>,
    pub key_ref: String,
    #[serde(default)]
    pub proof_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PrivateContentEnvelopeRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub envelope_id: String,
    pub content_class: String,
    pub access_group_ref: String,
    pub epoch_id: String,
    pub subject_ref: String,
    pub issuer_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_object_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_object_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caac_envelope_ref: Option<String>,
    #[serde(default)]
    pub recipient_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    #[serde(default)]
    pub summary_safe_facts: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventFabricAccessClassRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub class_id: String,
    pub content_class: String,
    pub privacy_tier: String,
    #[serde(default)]
    pub event_classes: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub processor_role_refs: Vec<String>,
    pub storage_class: String,
    pub retention_class: String,
    pub safe_fact_policy: String,
    #[serde(default)]
    pub index_policy: Value,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventFabricProcessorContractRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub processor_contract_id: String,
    pub fabric_ref: String,
    pub processor_ref: String,
    pub processor_role_ref: String,
    pub state: String,
    #[serde(default)]
    pub input_access_class_refs: Vec<String>,
    #[serde(default)]
    pub input_event_classes: Vec<String>,
    #[serde(default)]
    pub input_content_classes: Vec<String>,
    #[serde(default)]
    pub output_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_floor: Option<ConsumerFloor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization_budget: Option<MaterializationBudget>,
    #[serde(default)]
    pub bitemporal_policy: Value,
    #[serde(default)]
    pub schema_policy: Value,
    #[serde(default)]
    pub compaction_policy: Value,
    #[serde(default)]
    pub cardinality_policy: Value,
    #[serde(default)]
    pub encrypted_detail_custody: Value,
    #[serde(default)]
    pub sampling_policy: Value,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityProcessorSeedRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub seed_id: String,
    pub fabric_ref: String,
    pub processor_ref: String,
    pub processor_role_ref: String,
    pub state: String,
    pub threat_analysis_role: String,
    #[serde(default)]
    pub input_access_class_refs: Vec<String>,
    #[serde(default)]
    pub input_event_classes: Vec<String>,
    #[serde(default)]
    pub input_content_classes: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub processor_contract_refs: Vec<String>,
    #[serde(default)]
    pub evidence_profile_refs: Vec<String>,
    #[serde(default)]
    pub materialization_budget_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub detail_refs: Vec<String>,
    #[serde(default)]
    pub alert_output_refs: Vec<String>,
    #[serde(default)]
    pub evidence_hold_refs: Vec<String>,
    #[serde(default)]
    pub retention_hold_refs: Vec<String>,
    #[serde(default)]
    pub encrypted_detail_custody: Value,
    #[serde(default)]
    pub semantic_boundaries: Value,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerSecretBoundaryRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub boundary_id: String,
    pub manager_id: String,
    pub subject_ref: String,
    pub state: String,
    #[serde(default)]
    pub secret_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerReleaseContractRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub contract_id: String,
    pub manager_id: String,
    pub subject_ref: String,
    pub manager_ref: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_contract_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_required: Option<bool>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub secret_boundary_refs: Vec<String>,
    #[serde(default)]
    pub proof_digest_refs: Vec<String>,
    #[serde(default)]
    pub lab_proof_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerLabProofRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub proof_id: String,
    pub manager_id: String,
    pub subject_ref: String,
    pub profile: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub train_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_contract_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_contract_ref: Option<String>,
    #[serde(default)]
    pub surface_refs: Vec<String>,
    #[serde(default)]
    pub service_refs: Vec<String>,
    #[serde(default)]
    pub environment_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub metrics_refs: Vec<String>,
    #[serde(default)]
    pub proof_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceManagerTrainDigestRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub train_id: String,
    pub manager_id: String,
    pub subject_ref: String,
    pub state: String,
    #[serde(default)]
    pub repo_refs: Vec<String>,
    #[serde(default)]
    pub commit_refs: Vec<String>,
    #[serde(default)]
    pub app_contract_refs: Vec<String>,
    #[serde(default)]
    pub release_contract_refs: Vec<String>,
    #[serde(default)]
    pub operation_refs: Vec<String>,
    #[serde(default)]
    pub proof_digest_refs: Vec<String>,
    #[serde(default)]
    pub lab_proof_refs: Vec<String>,
    #[serde(default)]
    pub metrics_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub observed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceAppBootstrapContractRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub bootstrap_contract_id: String,
    pub app_contract_ref: String,
    pub app_id: String,
    pub state: String,
    pub source_mode: String,
    #[serde(default)]
    pub module_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_manager_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_contract_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_boundary_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub train_digest_ref: Option<String>,
    #[serde(default)]
    pub lab_proof_profile_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceAppManifestVersionRecord {
    pub app_contract_ref: String,
    pub version: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mode: Option<String>,
    #[serde(default)]
    pub module_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_contract_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_contract_ref: Option<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SurfaceAppManifestRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub manifest_id: String,
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub current_app_contract_ref: String,
    pub current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_source_mode: Option<String>,
    pub versions: Vec<SurfaceAppManifestVersionRecord>,
    #[serde(default)]
    pub app_contract_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub bootstrap_contract_refs: Vec<String>,
    #[serde(default)]
    pub release_contract_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaacValidationMode {
    Structural,
    Fixture,
    Product,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmProjectionSnapshot {
    pub projection_id: String,
    pub policy_id: String,
    pub revision: u64,
    pub state: Value,
    #[serde(default)]
    pub coverage: Value,
    #[serde(default)]
    pub freshness: Value,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmProjectionDelta {
    pub projection_id: String,
    pub policy_id: String,
    pub base_revision: u64,
    pub revision: u64,
    #[serde(default)]
    pub ops: Vec<ProjectionDeltaOp>,
    #[serde(default)]
    pub affected_records: Vec<Value>,
    #[serde(default)]
    pub coverage: Value,
    #[serde(default)]
    pub freshness: Value,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionDeltaOp {
    pub op: ProjectionDeltaOpKind,
    pub path: Vec<ProjectionPathSegment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionDeltaOpKind {
    Set,
    Remove,
    AppendUnique,
    Replace,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ProjectionPathSegment {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgeHello {
    pub member_kind: String,
    pub member_ref: String,
    pub zone_scope: ZoneScope,
    #[serde(default)]
    pub supported_versions: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_acked_frame_id: Option<String>,
    #[serde(default)]
    pub last_projection_revisions: Value,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub promise_refs: Vec<String>,
    pub nonce: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub sealed_claims: SwarmFrameBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgeAccept {
    pub session_id: String,
    pub member_kind: String,
    pub member_ref: String,
    pub zone_scope: ZoneScope,
    pub accepted_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_acked_frame_id: Option<String>,
    #[serde(default)]
    pub last_projection_revisions: Value,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub promise_refs: Vec<String>,
    pub nonce: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub sealed_claims: SwarmFrameBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgeResume {
    pub session_id: String,
    pub member_kind: String,
    pub member_ref: String,
    pub zone_scope: ZoneScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_acked_frame_id: Option<String>,
    #[serde(default)]
    pub last_projection_revisions: Value,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub promise_refs: Vec<String>,
    pub nonce: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub sealed_claims: SwarmFrameBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgeClose {
    pub session_id: String,
    pub member_kind: String,
    pub member_ref: String,
    pub zone_scope: ZoneScope,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_acked_frame_id: Option<String>,
    #[serde(default)]
    pub last_projection_revisions: Value,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    #[serde(default)]
    pub channel_refs: Vec<String>,
    #[serde(default)]
    pub promise_refs: Vec<String>,
    pub nonce: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub sealed_claims: SwarmFrameBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinIntent {
    pub intent_id: String,
    #[serde(default)]
    pub object_refs: Vec<String>,
    pub manifest_hash: String,
    pub desired_replicas: u32,
    pub retention: String,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinAttestation {
    pub attestation_id: String,
    pub intent_id: String,
    pub storage_member_ref: String,
    #[serde(default)]
    pub accepted_refs: Vec<String>,
    #[serde(default)]
    pub availability_refs: Vec<SwarmStorageAvailabilityRef>,
    pub status: StoragePinStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmStorageAvailabilityRef {
    pub availability_id: String,
    pub object_ref: String,
    pub storage_member_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StoragePinStatus {
    Pending,
    Accepted,
    Pinned,
    Partial,
    Rejected,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StoragePinProjectionStatus {
    Pending,
    Satisfied,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinProjection {
    pub pinned_count: u32,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub availability: Vec<SwarmStorageAvailabilityRef>,
    pub missing_replicas: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub status: StoragePinProjectionStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionIntent {
    pub session_id: String,
    pub capability_ref: String,
    pub requester_ref: String,
    pub channel_id: String,
    pub transport: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionAdmission {
    pub admission_id: String,
    pub session_id: String,
    pub capability_ref: String,
    pub admitted_by: String,
    #[serde(default)]
    pub constraints: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionOffer {
    pub offer_id: String,
    pub session_id: String,
    pub transport: String,
    #[serde(default)]
    pub payload: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionAnswer {
    pub answer_id: String,
    pub session_id: String,
    pub transport: String,
    #[serde(default)]
    pub payload: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionCandidate {
    pub candidate_id: String,
    pub session_id: String,
    pub transport: String,
    pub candidate_role: String,
    pub actionability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub endpoint: Value,
    #[serde(default)]
    pub payload: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionControl {
    pub control_id: String,
    pub session_id: String,
    pub command: String,
    #[serde(default)]
    pub params: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionHealth {
    pub health_id: String,
    pub session_id: String,
    pub status: String,
    #[serde(default)]
    pub recovery: Value,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionClose {
    pub close_id: String,
    pub session_id: String,
    pub reason_code: String,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppRecipe {
    pub recipe_id: String,
    pub version: String,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub required_channels: Vec<String>,
    #[serde(default)]
    pub required_roles: Vec<String>,
    pub entrypoint: String,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppRunnerAdvertisement {
    pub advertisement_id: String,
    pub runner_ref: String,
    pub capacity: u32,
    #[serde(default)]
    pub supported_versions: Vec<String>,
    pub health: String,
    #[serde(default)]
    pub capability_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppRunnerAttestation {
    pub attestation_id: String,
    pub runner_ref: String,
    pub recipe_id: String,
    pub status: String,
    pub issued_at: u64,
}

pub fn validate_swarm_frame(frame: &SwarmFrame, now: u64) -> Result<()> {
    if frame.version != SWARM_FRAME_VERSION {
        return Err(anyhow!("unsupported swarm frame version"));
    }
    require_non_empty(&frame.frame_id, "swarm frame missing frameId")?;
    require_non_empty(&frame.issuer, "swarm frame missing issuer")?;
    if frame.issued_at == 0 {
        return Err(anyhow!("swarm frame missing issuedAt"));
    }
    if let Some(expires_at) = frame.expires_at {
        if expires_at <= now {
            return Err(anyhow!("swarm frame expired"));
        }
    }
    require_non_empty(&frame.nonce, "swarm frame missing nonce")?;
    if frame_is_propagating(&frame.kind) {
        let scope = frame
            .zone_scope
            .as_ref()
            .ok_or_else(|| anyhow!("swarm frame missing zoneScope"))?;
        validate_zone_scope(scope)?;
    }
    if matches!(frame.kind, SwarmFrameKind::Ack | SwarmFrameKind::Reject)
        && frame
            .correlation_id
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(anyhow!("ack/reject frame missing correlationId"));
    }
    if let Some(record_ref) = &frame.record_ref {
        validate_record_ref(record_ref)?;
    }
    if let Some(capability) = &frame.capability {
        validate_capability_name(capability)?;
    }
    let expected_frame_id = swarm_frame_id(frame)?;
    if frame.frame_id != expected_frame_id {
        return Err(anyhow!("swarm frame id mismatch"));
    }
    validate_frame_body(frame)
}

pub fn swarm_frame_id(frame: &SwarmFrame) -> Result<String> {
    let material = serde_json::json!({
        "version": frame.version,
        "kind": serde_json::to_value(&frame.kind)?,
        "issuer": frame.issuer,
        "audience": frame.audience,
        "zoneScope": serde_json::to_value(&frame.zone_scope)?,
        "issuedAt": frame.issued_at,
        "expiresAt": frame.expires_at,
        "nonce": frame.nonce,
        "correlationId": frame.correlation_id,
        "channelId": frame.channel_id,
        "recordRef": serde_json::to_value(&frame.record_ref)?,
        "capability": frame.capability,
        "body": serde_json::to_value(&frame.body)?,
    });
    let material = format!("constitute-swarm-frame-v1|{}", canonical_json(&material));
    Ok(hex::encode(Sha256::digest(material.as_bytes())))
}

pub fn validate_zone_scope(scope: &ZoneScope) -> Result<()> {
    require_non_empty(&scope.zone_id, "zone scope missing zoneId")?;
    if scope.ttl == Some(0) {
        return Err(anyhow!("zone scope ttl must be positive"));
    }
    Ok(())
}

pub fn validate_channel_descriptor(descriptor: &ChannelDescriptor) -> Result<()> {
    require_non_empty(
        &descriptor.channel_id,
        "channel descriptor missing channelId",
    )?;
    require_non_empty(&descriptor.kind, "channel descriptor missing kind")?;
    require_non_empty(
        &descriptor.display_name,
        "channel descriptor missing displayName",
    )?;
    require_non_empty(
        &descriptor.policy_ref,
        "channel descriptor missing policyRef",
    )?;
    if descriptor.created_at == 0 {
        return Err(anyhow!("channel descriptor missing createdAt"));
    }
    if descriptor.record_kinds.is_empty() {
        return Err(anyhow!("channel descriptor missing recordKinds"));
    }
    for capability in &descriptor.capabilities {
        validate_capability_name(capability)?;
    }
    Ok(())
}

pub fn validate_channel_policy(policy: &ChannelPolicy) -> Result<()> {
    require_non_empty(&policy.policy_id, "channel policy missing policyId")?;
    if policy.observe.is_empty()
        || policy.write.is_empty()
        || policy.set.is_empty()
        || policy.invoke.is_empty()
        || policy.pin.is_empty()
        || policy.attest.is_empty()
        || policy.run.is_empty()
    {
        return Err(anyhow!("channel policy must name every authority class"));
    }
    Ok(())
}

pub fn validate_channel_membership(membership: &ChannelMembership) -> Result<()> {
    require_non_empty(
        &membership.membership_id,
        "channel membership missing membershipId",
    )?;
    require_non_empty(
        &membership.channel_id,
        "channel membership missing channelId",
    )?;
    validate_resolved_member_ref(
        &membership.member_ref,
        "channel membership missing memberRef",
    )?;
    require_non_empty(
        &membership.authority_ref,
        "channel membership missing authorityRef",
    )?;
    Ok(())
}

pub fn validate_channel_recommendation(recommendation: &ChannelRecommendation) -> Result<()> {
    require_non_empty(
        &recommendation.recommendation_id,
        "channel recommendation missing recommendationId",
    )?;
    require_non_empty(
        &recommendation.channel_id,
        "channel recommendation missing channelId",
    )?;
    require_non_empty(
        &recommendation.recommender_ref,
        "channel recommendation missing recommenderRef",
    )?;
    if recommendation.issued_at == 0 {
        return Err(anyhow!("channel recommendation missing issuedAt"));
    }
    for capability in &recommendation.capability_hints {
        validate_capability_name(capability)?;
    }
    Ok(())
}

pub fn validate_capability_definition(definition: &CapabilityDefinition) -> Result<()> {
    validate_capability_name(&definition.capability)?;
    require_non_empty(
        &definition.definition_id,
        "capability definition missing definitionId",
    )?;
    if !definition.schema.is_null() && !definition.schema.is_object() {
        return Err(anyhow!("capability definition schema must be an object"));
    }
    Ok(())
}

pub fn validate_capability_advertisement(
    advertisement: &CapabilityAdvertisement,
    now: u64,
) -> Result<()> {
    require_non_empty(
        &advertisement.advertisement_id,
        "capability advertisement missing advertisementId",
    )?;
    validate_capability_name(&advertisement.capability)?;
    let has_member = advertisement
        .member_ref
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let has_service = advertisement
        .service_ref
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    if !has_member && !has_service {
        return Err(anyhow!(
            "capability advertisement missing memberRef or serviceRef"
        ));
    }
    if let Some(member_ref) = advertisement.member_ref.as_deref() {
        if !member_ref.trim().is_empty() {
            validate_resolved_member_ref(member_ref, "capability advertisement missing memberRef")?;
        }
    }
    if advertisement.issued_at == 0 {
        return Err(anyhow!("capability advertisement missing issuedAt"));
    }
    if advertisement
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(anyhow!("capability advertisement expired"));
    }
    Ok(())
}

pub fn validate_capability_directory_entry(entry: &CapabilityDirectoryEntry) -> Result<()> {
    require_non_empty(&entry.entry_id, "capability directory missing entryId")?;
    validate_capability_name(&entry.capability)?;
    require_non_empty(&entry.channel_id, "capability directory missing channelId")?;
    let has_member = entry
        .member_ref
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let has_service = entry
        .service_ref
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    if !has_member && !has_service {
        return Err(anyhow!(
            "capability directory missing memberRef or serviceRef"
        ));
    }
    if let Some(member_ref) = entry.member_ref.as_deref() {
        if !member_ref.trim().is_empty() {
            validate_resolved_member_ref(member_ref, "capability directory missing memberRef")?;
        }
    }
    Ok(())
}

pub fn validate_capability_policy(policy: &CapabilityPolicy) -> Result<()> {
    require_non_empty(&policy.policy_id, "capability policy missing policyId")?;
    validate_capability_name(&policy.capability)
}

pub fn validate_node_capability(record: &NodeCapability, now: u64) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_NODE_CAPABILITY, "node capability")?;
    require_non_empty(
        &record.node_capability_id,
        "node capability missing nodeCapabilityId",
    )?;
    require_non_empty(&record.node_ref, "node capability missing nodeRef")?;
    validate_capability_name(&record.capability_ref)?;
    require_non_empty(&record.service_ref, "node capability missing serviceRef")?;
    validate_resolved_member_ref(
        &record.service_member_ref,
        "node capability missing serviceMemberRef",
    )?;
    require_non_empty_vec(
        &record.backing_channel_refs,
        "node capability missing backingChannelRefs",
    )?;
    if !record.activation_policy.is_object() {
        return Err(anyhow!(
            "node capability activationPolicy must be an object"
        ));
    }
    validate_freshness_value(&record.freshness, "node capability", now)?;
    if !record.safe_facts.is_null() && !record.safe_facts.is_object() {
        return Err(anyhow!("node capability safeFacts must be an object"));
    }
    reject_media_byte_fields(&record.safe_facts, "node capability safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("node capability missing issuedAt"));
    }
    Ok(())
}

pub fn validate_runtime_activation_request(record: &RuntimeActivationRequest) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_RUNTIME_ACTIVATION_REQUEST,
        "runtime activation request",
    )?;
    let value = serde_json::to_value(record)?;
    reject_activation_forbidden_fields(&value, "runtime activation request")?;
    require_non_empty(
        &record.activation_id,
        "runtime activation missing activationId",
    )?;
    require_non_empty(&record.node_ref, "runtime activation missing nodeRef")?;
    validate_capability_name(&record.capability_ref)?;
    if !record.params.is_object() {
        return Err(anyhow!("runtime activation params must be an object"));
    }
    validate_resolved_member_ref(
        &record.requester_ref,
        "runtime activation missing requesterRef",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("runtime activation missing issuedAt"));
    }
    if record
        .expires_at
        .map(|expires_at| expires_at <= record.issued_at)
        .unwrap_or(false)
    {
        return Err(anyhow!(
            "runtime activation expiresAt must be after issuedAt"
        ));
    }
    reject_media_byte_fields(&record.params, "runtime activation params")
}

pub fn validate_route_promise(record: &RoutePromise) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_ROUTE_PROMISE, "route promise")?;
    require_non_empty(&record.promise_id, "route promise missing promiseId")?;
    require_non_empty(&record.activation_id, "route promise missing activationId")?;
    require_non_empty(&record.node_ref, "route promise missing nodeRef")?;
    validate_capability_name(&record.capability_ref)?;
    validate_resolved_member_ref(&record.requester_ref, "route promise missing requesterRef")?;
    validate_resolved_member_ref(&record.service_pk, "route promise missing servicePk")?;
    if !record.service_member_ref.trim().is_empty() {
        validate_resolved_member_ref(
            &record.service_member_ref,
            "route promise missing serviceMemberRef",
        )?;
    }
    require_non_empty(&record.channel_id, "route promise missing channelId")?;
    validate_zone_scope(&record.zone_scope)?;
    if let Some(scope) = &record.return_zone_scope {
        validate_zone_scope(scope)?;
    }
    require_non_empty_vec(&record.audience_refs, "route promise missing audienceRefs")?;
    require_non_empty_vec(
        &record.authority_refs,
        "route promise missing authorityRefs",
    )?;
    if !record.route_policy.is_object() {
        return Err(anyhow!("route promise routePolicy must be an object"));
    }
    require_non_empty_vec(&record.path_refs, "route promise missing pathRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("route promise missing issuedAt"));
    }
    if record.expires_at == 0 {
        return Err(anyhow!("route promise missing expiresAt"));
    }
    if record.expires_at <= record.issued_at {
        return Err(anyhow!("route promise expiresAt must be after issuedAt"));
    }
    if !record.release_policy.is_object() {
        return Err(anyhow!("route promise releasePolicy must be an object"));
    }
    reject_media_byte_fields(&serde_json::to_value(record)?, "route promise")
}

pub fn validate_local_route_binding(record: &LocalRouteBinding) -> Result<()> {
    require_non_empty(&record.binding_id, "route binding missing bindingId")?;
    require_non_empty(&record.promise_id, "route binding missing promiseId")?;
    require_non_empty(
        &record.participant_ref,
        "route binding missing participantRef",
    )?;
    require_non_empty(&record.binding_kind, "route binding missing bindingKind")?;
    if !record.local_refs.is_null() && !record.local_refs.is_object() {
        return Err(anyhow!("route binding localRefs must be an object"));
    }
    if record.issued_at == 0 {
        return Err(anyhow!("route binding missing issuedAt"));
    }
    Ok(())
}

pub fn validate_route_observation(record: &RouteObservation) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_ROUTE_OBSERVATION, "route observation")?;
    require_non_empty(
        &record.observation_id,
        "route observation missing observationId",
    )?;
    let has_ref = record
        .frame_id
        .as_deref()
        .or(record.promise_id.as_deref())
        .or(record.activation_id.as_deref())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    if !has_ref {
        return Err(anyhow!(
            "route observation missing frameId, promiseId, or activationId"
        ));
    }
    for member_ref in &record.delivered_to {
        validate_resolved_member_ref(member_ref, "route observation deliveredTo memberRef")?;
    }
    for predicate in &record.failed_predicates {
        validate_route_failed_predicate(predicate)?;
    }
    if matches!(
        record.state,
        RouteObservationState::ObservingUnreachable
            | RouteObservationState::UnreachableFor
            | RouteObservationState::Rejected
    ) && record.failed_predicates.is_empty()
        && record
            .release_reason
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(anyhow!(
            "route observation failure state requires failed predicates or release reason"
        ));
    }
    if !record.diagnostics.is_null() && !record.diagnostics.is_object() {
        return Err(anyhow!("route observation diagnostics must be an object"));
    }
    if record.issued_at == 0 {
        return Err(anyhow!("route observation missing issuedAt"));
    }
    reject_media_byte_fields(&record.diagnostics, "route observation diagnostics")
}

pub fn validate_stream_route_plan(record: &StreamRoutePlan) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_STREAM_ROUTE_PLAN, "stream route plan")?;
    require_non_empty(&record.session_id, "stream route plan missing sessionId")?;
    require_non_empty_vec(&record.source_refs, "stream route plan missing sourceRefs")?;
    validate_resolved_member_ref(
        &record.requester_ref,
        "stream route plan missing requesterRef",
    )?;
    validate_resolved_member_ref(
        &record.service_member_ref,
        "stream route plan missing serviceMemberRef",
    )?;
    validate_capability_name(&record.capability_ref)?;
    if !record.route_lease.is_object() {
        return Err(anyhow!("stream route plan routeLease must be an object"));
    }
    if record.candidate_paths.is_empty() {
        return Err(anyhow!(
            "stream route plan candidatePaths must not be empty"
        ));
    }
    if record.fallback_paths.is_empty() {
        return Err(anyhow!("stream route plan fallbackPaths must not be empty"));
    }
    for path in &record.candidate_paths {
        validate_stream_route_path(path)?;
    }
    for path in &record.fallback_paths {
        validate_stream_route_path(path)?;
    }
    validate_stream_route_path(&record.preferred_path)?;
    validate_stream_route_path(&record.selected_path)?;
    if !record
        .candidate_paths
        .iter()
        .any(|path| path.path_id == record.preferred_path.path_id)
    {
        return Err(anyhow!(
            "stream route plan preferredPath must be a candidate"
        ));
    }
    if !record
        .candidate_paths
        .iter()
        .any(|path| path.path_id == record.selected_path.path_id)
    {
        return Err(anyhow!(
            "stream route plan selectedPath must be a candidate"
        ));
    }
    if !record.release_policy.is_object() {
        return Err(anyhow!("stream route plan releasePolicy must be an object"));
    }
    if record.expires_at == 0 {
        return Err(anyhow!("stream route plan missing expiresAt"));
    }
    reject_media_byte_fields(&serde_json::to_value(record)?, "stream route plan")
}

pub fn validate_member_presence(record: &MemberPresence, now: u64) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_MEMBER_PRESENCE, "member presence")?;
    validate_resolved_member_ref(&record.member_ref, "member presence missing memberRef")?;
    require_non_empty(&record.member_kind, "member presence missing memberKind")?;
    for capability in &record.capability_refs {
        validate_capability_name(capability)?;
    }
    for channel in &record.channel_refs {
        require_non_empty(channel, "member presence missing channelRef")?;
    }
    if record.issued_at == 0 {
        return Err(anyhow!("member presence missing issuedAt"));
    }
    if record
        .expires_at
        .map(|expires_at| expires_at <= now)
        .unwrap_or(false)
    {
        return Err(anyhow!("member presence expired"));
    }
    Ok(())
}

pub fn validate_directory_entry(record: &DirectoryEntry) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_DIRECTORY_ENTRY, "directory entry")?;
    require_non_empty(&record.entry_id, "directory entry missing entryId")?;
    require_non_empty(&record.subject_ref, "directory entry missing subjectRef")?;
    require_non_empty(&record.source, "directory entry missing source")?;
    if !matches!(
        record.source.as_str(),
        "channelRecord"
            | "capabilityRecord"
            | "memberRecord"
            | "projection"
            | "observation"
            | "bootstrap"
    ) {
        return Err(anyhow!("unsupported directory entry source"));
    }
    if let Some(capability) = &record.capability_ref {
        validate_capability_name(capability)?;
    }
    if let Some(channel) = &record.channel_id {
        require_non_empty(channel, "directory entry missing channelId")?;
    }
    if record.issued_at == 0 {
        return Err(anyhow!("directory entry missing issuedAt"));
    }
    Ok(())
}

pub fn validate_bootstrap_carrier_record(record: &BootstrapCarrierRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_BOOTSTRAP_CARRIER, "bootstrap carrier")?;
    require_non_empty(&record.carrier_id, "bootstrap carrier missing carrierId")?;
    require_non_empty(
        &record.carrier_kind,
        "bootstrap carrier missing carrierKind",
    )?;
    require_non_empty(&record.boundary, "bootstrap carrier missing boundary")?;
    if record.boundary != "bootstrap" && record.boundary != "fallback" {
        return Err(anyhow!(
            "bootstrap carrier boundary must be bootstrap or fallback"
        ));
    }
    if let Some(payload_ref) = &record.payload_ref {
        require_non_empty(payload_ref, "bootstrap carrier missing payloadRef")?;
    }
    if record.issued_at == 0 {
        return Err(anyhow!("bootstrap carrier missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_identity(record: &SwarmIdentityRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_IDENTITY, "swarm identity")?;
    require_non_empty(&record.identity_id, "swarm identity missing identityId")?;
    require_non_empty_vec(&record.root_refs, "swarm identity missing rootRefs")?;
    for reference in &record.recovery_root_refs {
        require_non_empty(reference, "swarm identity missing recoveryRootRef")?;
    }
    for reference in &record.recovery_route_refs {
        require_non_empty(reference, "swarm identity missing recoveryRouteRef")?;
        if record.recovery_root_refs.contains(reference) {
            return Err(anyhow!(
                "swarm identity recovery route must not be promoted as recovery root"
            ));
        }
    }
    validate_safe_facts(&record.safe_facts, "swarm identity safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm identity missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_device(record: &SwarmDeviceRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_DEVICE, "swarm device")?;
    require_non_empty(&record.device_id, "swarm device missing deviceId")?;
    require_non_empty(&record.device_ref, "swarm device missing deviceRef")?;
    require_non_empty(&record.identity_ref, "swarm device missing identityRef")?;
    validate_capability_names(&record.capability_refs)?;
    require_non_empty_vec(&record.authority_refs, "swarm device missing authorityRefs")?;
    validate_safe_facts(&record.safe_facts, "swarm device safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm device missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_gateway(record: &SwarmGatewayRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_GATEWAY, "swarm gateway")?;
    require_non_empty(&record.gateway_id, "swarm gateway missing gatewayId")?;
    require_non_empty(&record.gateway_ref, "swarm gateway missing gatewayRef")?;
    require_non_empty_vec(&record.owner_refs, "swarm gateway missing ownerRefs")?;
    require_non_empty_vec(
        &record.authority_refs,
        "swarm gateway missing authorityRefs",
    )?;
    validate_safe_facts(&record.safe_facts, "swarm gateway safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm gateway missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_service(record: &SwarmServiceRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_SERVICE, "swarm service")?;
    require_non_empty(&record.service_id, "swarm service missing serviceId")?;
    require_non_empty(&record.service_ref, "swarm service missing serviceRef")?;
    require_non_empty(&record.service, "swarm service missing service")?;
    require_non_empty(&record.contract_ref, "swarm service missing contractRef")?;
    validate_capability_names(&record.capability_refs)?;
    require_non_empty_vec(
        &record.authority_refs,
        "swarm service missing authorityRefs",
    )?;
    validate_safe_facts(&record.safe_facts, "swarm service safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm service missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_member(record: &SwarmMemberRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_MEMBER, "swarm member")?;
    require_non_empty(&record.member_id, "swarm member missing memberId")?;
    validate_resolved_member_ref(&record.member_ref, "swarm member missing memberRef")?;
    require_non_empty(&record.member_kind, "swarm member missing memberKind")?;
    validate_capability_names(&record.capability_refs)?;
    require_non_empty_vec(&record.authority_refs, "swarm member missing authorityRefs")?;
    if record
        .storage
        .get("authorityDomain")
        .and_then(Value::as_str)
        .is_some_and(|domain| domain == "identity")
    {
        return Err(anyhow!("storage member must not claim identity authority"));
    }
    validate_safe_facts(&record.safe_facts, "swarm member safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm member missing issuedAt"));
    }
    if record
        .expires_at
        .map(|expires_at| expires_at <= record.issued_at)
        .unwrap_or(false)
    {
        return Err(anyhow!("swarm member expiresAt must be after issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_grant(record: &SwarmGrantRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_GRANT, "swarm grant")?;
    require_non_empty(&record.grant_id, "swarm grant missing grantId")?;
    require_non_empty(&record.issuer_ref, "swarm grant missing issuerRef")?;
    require_non_empty(&record.subject_ref, "swarm grant missing subjectRef")?;
    require_non_empty_vec(&record.audience_refs, "swarm grant missing audienceRefs")?;
    validate_authority_domain(&record.authority_domain)?;
    validate_capability_names(&record.capability_refs)?;
    if record.elevated {
        require_non_empty_vec(&record.root_refs, "elevated swarm grant requires rootRefs")?;
    }
    validate_safe_facts(&record.safe_facts, "swarm grant safeFacts")?;
    validate_private_refs(&record.private_refs, "swarm grant privateRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm grant missing issuedAt"));
    }
    if record
        .expires_at
        .map(|expires_at| expires_at <= record.issued_at)
        .unwrap_or(false)
    {
        return Err(anyhow!("swarm grant expiresAt must be after issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_role(record: &SwarmRoleRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_ROLE, "swarm role")?;
    require_non_empty(&record.role_id, "swarm role missing roleId")?;
    validate_interaction_role(&record.role)?;
    validate_resolved_member_ref(&record.member_ref, "swarm role missing memberRef")?;
    validate_capability_names(&record.capability_refs)?;
    require_non_empty_vec(&record.authority_refs, "swarm role missing authorityRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm role missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_interaction(record: &SwarmInteractionRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_INTERACTION, "swarm interaction")?;
    require_non_empty(
        &record.interaction_id,
        "swarm interaction missing interactionId",
    )?;
    require_non_empty(
        &record.contract_ref,
        "swarm interaction missing contractRef",
    )?;
    require_non_empty(
        &record.interaction_kind,
        "swarm interaction missing interactionKind",
    )?;
    if record.participants.is_empty() {
        return Err(anyhow!("swarm interaction missing participants"));
    }
    let mut has_requester = false;
    let mut has_coordinator = false;
    for participant in &record.participants {
        validate_interaction_role(&participant.role)?;
        validate_resolved_member_ref(
            &participant.member_ref,
            "swarm interaction participant missing memberRef",
        )?;
        validate_capability_names(&participant.capability_refs)?;
        validate_safe_facts(
            &participant.safe_facts,
            "swarm interaction participant safeFacts",
        )?;
        has_requester |= participant.role == "requester";
        has_coordinator |= participant.role == "coordinator";
    }
    if !has_requester {
        return Err(anyhow!("swarm interaction missing requester participant"));
    }
    if !has_coordinator {
        return Err(anyhow!("swarm interaction missing coordinator participant"));
    }
    validate_interaction_state(&record.state)?;
    validate_capability_names(&record.capability_refs)?;
    if let Some(domains) = record.authority.get("domains").and_then(Value::as_array) {
        for domain in domains {
            validate_authority_domain(domain.as_str().unwrap_or_default())?;
        }
    }
    if let Some(routing_scope) = &record.routing_scope {
        validate_routing_scope_posture(routing_scope)?;
    }
    validate_safe_facts(&record.safe_facts, "swarm interaction safeFacts")?;
    validate_private_refs(&record.private_refs, "swarm interaction privateRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm interaction missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_activation(record: &SwarmActivationRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_ACTIVATION, "swarm activation")?;
    require_non_empty(
        &record.activation_id,
        "swarm activation missing activationId",
    )?;
    require_non_empty(
        &record.interaction_id,
        "swarm activation missing interactionId",
    )?;
    require_non_empty(&record.node_ref, "swarm activation missing nodeRef")?;
    validate_capability_name(&record.capability_ref)?;
    validate_resolved_member_ref(
        &record.requester_ref,
        "swarm activation missing requesterRef",
    )?;
    validate_resolved_member_ref(
        &record.runtime_member_ref,
        "swarm activation missing runtimeMemberRef",
    )?;
    validate_interaction_state(&record.state)?;
    let summary = record
        .authority_summary
        .as_object()
        .ok_or_else(|| anyhow!("swarm activation authoritySummary must be an object"))?;
    for domain in ["requester", "runtime", "gateway", "service"] {
        let state = summary
            .get(domain)
            .and_then(|entry| entry.get("state"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        require_non_empty(
            state,
            &format!("swarm activation authoritySummary {domain} missing state"),
        )?;
    }
    validate_safe_facts(&record.safe_facts, "swarm activation safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm activation missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_release(record: &SwarmReleaseRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_RELEASE, "swarm release")?;
    require_non_empty(&record.release_id, "swarm release missing releaseId")?;
    require_non_empty(
        &record.interaction_id,
        "swarm release missing interactionId",
    )?;
    require_non_empty(&record.released_by, "swarm release missing releasedBy")?;
    require_non_empty(&record.reason_code, "swarm release missing reasonCode")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm release missing issuedAt"));
    }
    Ok(())
}

pub fn validate_swarm_revocation(record: &SwarmRevocationRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_SWARM_REVOCATION, "swarm revocation")?;
    require_non_empty(
        &record.revocation_id,
        "swarm revocation missing revocationId",
    )?;
    require_non_empty(&record.target_ref, "swarm revocation missing targetRef")?;
    require_non_empty(&record.issuer_ref, "swarm revocation missing issuerRef")?;
    validate_authority_domain(&record.authority_domain)?;
    require_non_empty(&record.reason_code, "swarm revocation missing reasonCode")?;
    if record.issued_at == 0 {
        return Err(anyhow!("swarm revocation missing issuedAt"));
    }
    Ok(())
}

pub fn validate_authority_root_operation(record: &AuthorityRootOperationRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_AUTHORITY_ROOT_OPERATION,
        "authority root operation",
    )?;
    require_non_empty(
        &record.operation_id,
        "authority root operation missing operationId",
    )?;
    validate_root_operation(&record.operation)?;
    require_non_empty(
        &record.identity_ref,
        "authority root operation missing identityRef",
    )?;
    require_non_empty(
        &record.actor_ref,
        "authority root operation missing actorRef",
    )?;
    require_non_empty(
        &record.target_ref,
        "authority root operation missing targetRef",
    )?;
    require_non_empty_vec(
        &record.admin_grant_refs,
        "authority root operation requires adminGrantRefs",
    )?;
    for reference in &record.root_refs {
        require_non_empty(reference, "authority root operation missing rootRef")?;
    }
    for reference in &record.device_refs {
        require_non_empty(reference, "authority root operation missing deviceRef")?;
    }
    validate_action_grant_state(&record.state)?;
    if matches!(
        record.state.as_str(),
        AGREEMENT_STATE_BLOCKED | AGREEMENT_STATE_REJECTED
    ) && record
        .blocked_reason
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(anyhow!(
            "blocked or rejected authority root operation requires blockedReason"
        ));
    }
    if matches!(
        record.operation.as_str(),
        "rotateRoot" | "revokeRoot" | "addRoot"
    ) && record.root_refs.is_empty()
    {
        return Err(anyhow!(
            "root-changing authority operation requires rootRefs"
        ));
    }
    validate_safe_facts(&record.safe_facts, "authority root operation safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("authority root operation missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "authority root operation expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_action_authority_grant(record: &ActionAuthorityGrantRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_AUTHORITY_ACTION_GRANT,
        "action authority grant",
    )?;
    require_non_empty(&record.grant_id, "action authority grant missing grantId")?;
    let plane = record
        .plane
        .as_deref()
        .unwrap_or(AGREEMENT_PLANE_ACTION_AUTHORITY);
    validate_agreement_plane(plane)?;
    if plane != AGREEMENT_PLANE_ACTION_AUTHORITY {
        return Err(anyhow!(
            "action authority grant plane must be actionAuthority"
        ));
    }
    require_non_empty(
        &record.issuer_ref,
        "action authority grant missing issuerRef",
    )?;
    require_non_empty(
        &record.subject_ref,
        "action authority grant missing subjectRef",
    )?;
    require_non_empty_vec(
        &record.audience_refs,
        "action authority grant missing audienceRefs",
    )?;
    validate_authority_domain(&record.authority_domain)?;
    require_non_empty(
        &record.resource_ref,
        "action authority grant missing resourceRef",
    )?;
    require_non_empty(&record.action, "action authority grant missing action")?;
    let state = record.state.as_deref().unwrap_or(AGREEMENT_STATE_ACCEPTED);
    validate_action_grant_state(state)?;
    if matches!(state, AGREEMENT_STATE_BLOCKED | AGREEMENT_STATE_REJECTED)
        && record
            .blocked_reason
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(anyhow!(
            "blocked or rejected action authority grant requires blockedReason"
        ));
    }
    validate_capability_names(&record.capability_refs)?;
    if record.elevated {
        require_non_empty_vec(
            &record.root_refs,
            "elevated action authority grant requires rootRefs",
        )?;
    }
    if !record.scope.is_null() {
        validate_safe_facts(&record.scope, "action authority grant scope")?;
    }
    if !record.delegation.is_null() && !record.delegation.is_object() {
        return Err(anyhow!(
            "action authority grant delegation must be an object"
        ));
    }
    validate_safe_facts(&record.safe_facts, "action authority grant safeFacts")?;
    validate_private_refs(&record.private_refs, "action authority grant privateRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("action authority grant missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "action authority grant expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_action_authority_exercise(record: &ActionAuthorityExerciseRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_AUTHORITY_ACTION_EXERCISE,
        "action authority exercise",
    )?;
    require_non_empty(
        &record.exercise_id,
        "action authority exercise missing exerciseId",
    )?;
    require_non_empty(
        &record.grant_id,
        "action authority exercise missing grantId",
    )?;
    require_non_empty(
        &record.actor_ref,
        "action authority exercise missing actorRef",
    )?;
    require_non_empty(
        &record.subject_ref,
        "action authority exercise missing subjectRef",
    )?;
    require_non_empty(
        &record.resource_ref,
        "action authority exercise missing resourceRef",
    )?;
    require_non_empty(&record.action, "action authority exercise missing action")?;
    validate_action_grant_state(&record.state)?;
    if matches!(
        record.state.as_str(),
        AGREEMENT_STATE_BLOCKED
            | AGREEMENT_STATE_REJECTED
            | AGREEMENT_STATE_EXPIRED
            | AGREEMENT_STATE_REVOKED
    ) && record
        .blocked_reason
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(anyhow!(
            "blocked/rejected/expired/revoked action authority exercise requires blockedReason"
        ));
    }
    validate_safe_facts(&record.safe_facts, "action authority exercise safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("action authority exercise missing issuedAt"));
    }
    if record
        .observed_at
        .is_some_and(|observed_at| observed_at < record.issued_at)
    {
        return Err(anyhow!(
            "action authority exercise observedAt must not be before issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_authority_grant_revocation_posture(
    record: &AuthorityGrantRevocationPostureRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_AUTHORITY_GRANT_REVOCATION_POSTURE,
        "authority grant revocation posture",
    )?;
    require_non_empty(
        &record.revocation_id,
        "authority grant revocation posture missing revocationId",
    )?;
    require_non_empty(
        &record.target_grant_ref,
        "authority grant revocation posture missing targetGrantRef",
    )?;
    require_non_empty(
        &record.issuer_ref,
        "authority grant revocation posture missing issuerRef",
    )?;
    validate_authority_domain(&record.authority_domain)?;
    require_non_empty_vec(
        &record.affected_grant_refs,
        "authority grant revocation posture missing affectedGrantRefs",
    )?;
    validate_action_grant_state(&record.state)?;
    require_non_empty(
        &record.reason_code,
        "authority grant revocation posture missing reasonCode",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!(
            "authority grant revocation posture missing issuedAt"
        ));
    }
    if record
        .effective_at
        .is_some_and(|effective_at| effective_at < record.issued_at)
    {
        return Err(anyhow!(
            "authority grant revocation posture effectiveAt must not be before issuedAt"
        ));
    }
    Ok(())
}

fn validate_authority_proof_check_record(record: &AuthorityProofCheck) -> Result<()> {
    validate_authority_proof_check(&record.check)?;
    validate_agreement_plane(&record.plane)?;
    validate_authority_proof_state(&record.state)?;
    require_non_empty(
        &record.target_ref,
        "authority proof check missing targetRef",
    )?;
    for reference in &record.grant_refs {
        require_non_empty(reference, "authority proof check missing grantRef")?;
    }
    for reference in &record.access_group_refs {
        require_non_empty(reference, "authority proof check missing accessGroupRef")?;
    }
    for reference in &record.access_epoch_refs {
        require_non_empty(reference, "authority proof check missing accessEpochRef")?;
    }
    for reference in &record.exercise_refs {
        require_non_empty(reference, "authority proof check missing exerciseRef")?;
    }
    for reference in &record.evidence_refs {
        require_non_empty(reference, "authority proof check missing evidenceRef")?;
    }
    if matches!(
        record.state.as_str(),
        AUTHORITY_PROOF_STATE_DEGRADED
            | AUTHORITY_PROOF_STATE_BLOCKED
            | AUTHORITY_PROOF_STATE_EXPIRED
            | AUTHORITY_PROOF_STATE_REVOKED
    ) && record
        .blocked_reason
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(anyhow!(
            "non-proved authority proof check requires blockedReason"
        ));
    }
    match record.check.as_str() {
        AUTHORITY_PROOF_CHECK_SYNC if record.plane != AGREEMENT_PLANE_DELIVERY_WITNESS => {
            return Err(anyhow!(
                "sync authority proof check must use deliveryWitness plane"
            ));
        }
        AUTHORITY_PROOF_CHECK_READ if record.plane != AGREEMENT_PLANE_ACCESS_AUTHORITY => {
            return Err(anyhow!(
                "read authority proof check must use accessAuthority plane"
            ));
        }
        AUTHORITY_PROOF_CHECK_WRITE_REDUCE | AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE
            if record.plane != AGREEMENT_PLANE_ACTION_AUTHORITY =>
        {
            return Err(anyhow!(
                "write/revoke authority proof checks must use actionAuthority plane"
            ));
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_authority_multi_identity_proof(
    record: &AuthorityMultiIdentityProofRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_AUTHORITY_MULTI_IDENTITY_PROOF,
        "authority multi-identity proof",
    )?;
    require_non_empty(
        &record.proof_id,
        "authority multi-identity proof missing proofId",
    )?;
    require_non_empty(
        &record.owner_identity_ref,
        "authority multi-identity proof missing ownerIdentityRef",
    )?;
    require_non_empty(
        &record.grantee_identity_ref,
        "authority multi-identity proof missing granteeIdentityRef",
    )?;
    require_non_empty(
        &record.grantee_member_ref,
        "authority multi-identity proof missing granteeMemberRef",
    )?;
    require_non_empty_vec(
        &record.subject_refs,
        "authority multi-identity proof missing subjectRefs",
    )?;
    require_non_empty_vec(
        &record.action_grant_refs,
        "authority multi-identity proof missing actionGrantRefs",
    )?;
    require_non_empty_vec(
        &record.access_group_refs,
        "authority multi-identity proof missing accessGroupRefs",
    )?;
    if record.checks.is_empty() {
        return Err(anyhow!("authority multi-identity proof missing checks"));
    }
    validate_authority_proof_state(&record.state)?;
    let mut kinds = BTreeSet::new();
    let mut has_action = false;
    let mut has_access = false;
    let mut has_delivery = false;
    let mut read_has_group = false;
    let mut revoke_has_expiry = false;
    for check in &record.checks {
        validate_authority_proof_check_record(check)?;
        kinds.insert(check.check.as_str());
        has_action |= check.plane == AGREEMENT_PLANE_ACTION_AUTHORITY;
        has_access |= check.plane == AGREEMENT_PLANE_ACCESS_AUTHORITY;
        has_delivery |= check.plane == AGREEMENT_PLANE_DELIVERY_WITNESS;
        if check.check == AUTHORITY_PROOF_CHECK_READ && !check.access_group_refs.is_empty() {
            read_has_group = true;
        }
        if check.check == AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE && check.expires_at.is_some() {
            revoke_has_expiry = true;
        }
    }
    for required in [
        AUTHORITY_PROOF_CHECK_SYNC,
        AUTHORITY_PROOF_CHECK_READ,
        AUTHORITY_PROOF_CHECK_WRITE_REDUCE,
        AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE,
    ] {
        if !kinds.contains(required) {
            return Err(anyhow!(
                "authority multi-identity proof missing {required} check"
            ));
        }
    }
    if !has_action {
        return Err(anyhow!(
            "authority multi-identity proof requires actionAuthority check"
        ));
    }
    if !has_access {
        return Err(anyhow!(
            "authority multi-identity proof requires accessAuthority check"
        ));
    }
    if !has_delivery {
        return Err(anyhow!(
            "authority multi-identity proof requires deliveryWitness check"
        ));
    }
    if !read_has_group {
        return Err(anyhow!(
            "read authority proof check requires accessGroupRefs"
        ));
    }
    if record.revocation_refs.is_empty() && !revoke_has_expiry {
        return Err(anyhow!(
            "revoke/expire authority proof requires revocationRefs or expiresAt"
        ));
    }
    if matches!(
        record.state.as_str(),
        AUTHORITY_PROOF_STATE_BLOCKED | AUTHORITY_PROOF_STATE_DEGRADED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "blocked or degraded authority multi-identity proof requires blockedReasons"
        ));
    }
    validate_safe_facts(
        &record.safe_facts,
        "authority multi-identity proof safeFacts",
    )?;
    reject_private_content_fields(
        &record.safe_facts,
        "authority multi-identity proof safeFacts",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("authority multi-identity proof missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "authority multi-identity proof expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_access_group(record: &AccessGroupRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_ACCESS_GROUP, "access group")?;
    require_non_empty(&record.group_id, "access group missing groupId")?;
    require_non_empty(&record.owner_ref, "access group missing ownerRef")?;
    require_non_empty(&record.subject_ref, "access group missing subjectRef")?;
    require_non_empty_vec(
        &record.content_classes,
        "access group missing contentClasses",
    )?;
    for content_class in &record.content_classes {
        validate_content_class(content_class)?;
    }
    require_non_empty_vec(&record.member_refs, "access group missing memberRefs")?;
    require_non_empty_vec(&record.admin_refs, "access group missing adminRefs")?;
    require_non_empty(
        &record.current_epoch_id,
        "access group missing currentEpochId",
    )?;
    validate_safe_facts(&record.safe_facts, "access group safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("access group missing issuedAt"));
    }
    Ok(())
}

pub fn validate_access_epoch(record: &AccessEpochRecord) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_ACCESS_EPOCH, "access epoch")?;
    require_non_empty(&record.epoch_id, "access epoch missing epochId")?;
    require_non_empty(&record.group_id, "access epoch missing groupId")?;
    if record.sequence == 0 {
        return Err(anyhow!("access epoch sequence must be positive integer"));
    }
    validate_access_epoch_change(&record.change_kind)?;
    require_non_empty_vec(&record.member_refs, "access epoch missing memberRefs")?;
    require_non_empty(&record.key_ref, "access epoch missing keyRef")?;
    require_non_empty_vec(&record.proof_refs, "access epoch missing proofRefs")?;
    if matches!(
        record.change_kind.as_str(),
        "removeMember" | "revokeMember" | "rotateKey"
    ) && record
        .previous_epoch_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(anyhow!(
            "revoking or rotating access epoch requires previousEpochId"
        ));
    }
    if matches!(record.change_kind.as_str(), "removeMember" | "revokeMember")
        && record.removed_member_refs.is_empty()
    {
        return Err(anyhow!(
            "member removal access epoch requires removedMemberRefs"
        ));
    }
    if record.change_kind == "addMember" && record.added_member_refs.is_empty() {
        return Err(anyhow!(
            "member addition access epoch requires addedMemberRefs"
        ));
    }
    validate_safe_facts(&record.safe_facts, "access epoch safeFacts")?;
    reject_private_content_fields(&record.safe_facts, "access epoch safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("access epoch missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!("access epoch expiresAt must be after issuedAt"));
    }
    Ok(())
}

pub fn validate_private_content_envelope(record: &PrivateContentEnvelopeRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_PRIVATE_CONTENT_ENVELOPE,
        "private content envelope",
    )?;
    reject_private_content_fields(&serde_json::to_value(record)?, "private content envelope")?;
    require_non_empty(
        &record.envelope_id,
        "private content envelope missing envelopeId",
    )?;
    validate_content_class(&record.content_class)?;
    if !matches!(
        record.content_class.as_str(),
        "encryptedDetail" | "encryptedRaw" | "mediaReference" | "diagnosticDetail"
    ) {
        return Err(anyhow!(
            "private content envelope requires encrypted/detail/media content class"
        ));
    }
    require_non_empty(
        &record.access_group_ref,
        "private content envelope missing accessGroupRef",
    )?;
    require_non_empty(&record.epoch_id, "private content envelope missing epochId")?;
    require_non_empty(
        &record.subject_ref,
        "private content envelope missing subjectRef",
    )?;
    require_non_empty(
        &record.issuer_ref,
        "private content envelope missing issuerRef",
    )?;
    let body_refs = [
        record.ciphertext_ref.as_deref(),
        record.storage_object_ref.as_deref(),
        record.detail_ref.as_deref(),
        record.media_object_ref.as_deref(),
        record.caac_envelope_ref.as_deref(),
    ];
    if !body_refs
        .iter()
        .flatten()
        .any(|reference| !reference.trim().is_empty())
    {
        return Err(anyhow!(
            "private content envelope requires a content reference"
        ));
    }
    validate_safe_facts(
        &record.summary_safe_facts,
        "private content envelope summarySafeFacts",
    )?;
    reject_private_content_fields(
        &record.summary_safe_facts,
        "private content envelope summarySafeFacts",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("private content envelope missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "private content envelope expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_event_fabric_access_class(record: &EventFabricAccessClassRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_EVENT_FABRIC_ACCESS_CLASS,
        "event fabric access class",
    )?;
    require_non_empty(
        &record.class_id,
        "event fabric access class missing classId",
    )?;
    validate_content_class(&record.content_class)?;
    validate_agreement_privacy_tier(&record.privacy_tier)?;
    require_non_empty_vec(
        &record.event_classes,
        "event fabric access class missing eventClasses",
    )?;
    require_non_empty_vec(
        &record.access_group_refs,
        "event fabric access class missing accessGroupRefs",
    )?;
    require_non_empty(
        &record.storage_class,
        "event fabric access class missing storageClass",
    )?;
    require_non_empty(
        &record.retention_class,
        "event fabric access class missing retentionClass",
    )?;
    validate_safe_fact_policy(&record.safe_fact_policy)?;
    if matches!(
        record.content_class.as_str(),
        "encryptedDetail" | "encryptedRaw" | "diagnosticDetail"
    ) && record.privacy_tier == "publicSafe"
    {
        return Err(anyhow!(
            "encrypted event fabric access class must not use publicSafe privacy tier"
        ));
    }
    validate_safe_facts(
        &record.index_policy,
        "event fabric access class indexPolicy",
    )?;
    validate_safe_facts(&record.safe_facts, "event fabric access class safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("event fabric access class missing issuedAt"));
    }
    Ok(())
}

fn validate_policy_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>> {
    if value.is_null() {
        return Ok(None);
    }
    validate_safe_facts(value, context)?;
    value
        .as_object()
        .map(Some)
        .ok_or_else(|| anyhow!("{context} must be an object"))
}

fn require_policy_string(
    policy: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<()> {
    let Some(value) = policy.get(key).and_then(Value::as_str) else {
        return Err(anyhow!("{context} missing {key}"));
    };
    require_non_empty(value, &format!("{context} missing {key}"))
}

pub fn validate_event_fabric_processor_contract(
    record: &EventFabricProcessorContractRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_EVENT_FABRIC_PROCESSOR_CONTRACT,
        "event fabric processor contract",
    )?;
    require_non_empty(
        &record.processor_contract_id,
        "event fabric processor contract missing processorContractId",
    )?;
    require_non_empty(
        &record.fabric_ref,
        "event fabric processor contract missing fabricRef",
    )?;
    require_non_empty(
        &record.processor_ref,
        "event fabric processor contract missing processorRef",
    )?;
    require_non_empty(
        &record.processor_role_ref,
        "event fabric processor contract missing processorRoleRef",
    )?;
    if !matches!(
        record.state.as_str(),
        "ready" | "degraded" | "blocked" | "pending" | "expired"
    ) {
        return Err(anyhow!("invalid event fabric processor contract state"));
    }
    require_non_empty_vec(
        &record.input_access_class_refs,
        "event fabric processor contract requires inputAccessClassRefs",
    )?;
    validate_reference_list(
        &record.input_access_class_refs,
        "event fabric processor contract missing inputAccessClassRefs",
    )?;
    require_non_empty_vec(
        &record.input_event_classes,
        "event fabric processor contract requires inputEventClasses",
    )?;
    validate_reference_list(
        &record.input_event_classes,
        "event fabric processor contract missing inputEventClasses",
    )?;
    require_non_empty_vec(
        &record.input_content_classes,
        "event fabric processor contract requires inputContentClasses",
    )?;
    for content_class in &record.input_content_classes {
        validate_content_class(content_class)?;
    }
    validate_reference_list(
        &record.output_refs,
        "event fabric processor contract missing outputRefs",
    )?;
    validate_reference_list(
        &record.storage_refs,
        "event fabric processor contract missing storageRefs",
    )?;
    validate_reference_list(
        &record.access_group_refs,
        "event fabric processor contract missing accessGroupRefs",
    )?;
    if let Some(floor) = &record.consumer_floor {
        validate_consumer_floor(floor)?;
    }
    if let Some(budget) = &record.materialization_budget {
        validate_materialization_budget(budget)?;
    }
    if let Some(policy) = validate_policy_object(
        &record.bitemporal_policy,
        "event fabric processor contract bitemporalPolicy",
    )? {
        require_policy_string(
            policy,
            "eventTimeField",
            "event fabric processor contract bitemporalPolicy",
        )?;
        require_policy_string(
            policy,
            "observedTimeField",
            "event fabric processor contract bitemporalPolicy",
        )?;
    }
    if let Some(policy) = validate_policy_object(
        &record.schema_policy,
        "event fabric processor contract schemaPolicy",
    )? {
        require_policy_string(
            policy,
            "currentVersion",
            "event fabric processor contract schemaPolicy",
        )?;
    }
    validate_policy_object(
        &record.compaction_policy,
        "event fabric processor contract compactionPolicy",
    )?;
    validate_policy_object(
        &record.cardinality_policy,
        "event fabric processor contract cardinalityPolicy",
    )?;
    if let Some(policy) = validate_policy_object(
        &record.encrypted_detail_custody,
        "event fabric processor contract encryptedDetailCustody",
    )? {
        require_policy_string(
            policy,
            "state",
            "event fabric processor contract encryptedDetailCustody",
        )?;
    }
    if let Some(policy) = validate_policy_object(
        &record.sampling_policy,
        "event fabric processor contract samplingPolicy",
    )? {
        require_policy_string(
            policy,
            "state",
            "event fabric processor contract samplingPolicy",
        )?;
    }
    validate_reference_list(
        &record.evidence_refs,
        "event fabric processor contract missing evidenceRefs",
    )?;
    if record.state == "blocked" && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "event fabric processor contract blocked state requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "event fabric processor contract missing blockedReasons",
    )?;
    validate_safe_facts(
        &record.safe_facts,
        "event fabric processor contract safeFacts",
    )?;
    reject_private_content_fields(
        &record.safe_facts,
        "event fabric processor contract safeFacts",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("event fabric processor contract missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "event fabric processor contract expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_security_processor_seed(record: &SecurityProcessorSeedRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SECURITY_PROCESSOR_SEED,
        "security processor seed",
    )?;
    require_non_empty(&record.seed_id, "security processor seed missing seedId")?;
    require_non_empty(
        &record.fabric_ref,
        "security processor seed missing fabricRef",
    )?;
    require_non_empty(
        &record.processor_ref,
        "security processor seed missing processorRef",
    )?;
    require_non_empty(
        &record.processor_role_ref,
        "security processor seed missing processorRoleRef",
    )?;
    require_non_empty(
        &record.threat_analysis_role,
        "security processor seed missing threatAnalysisRole",
    )?;
    if !matches!(
        record.state.as_str(),
        "ready" | "degraded" | "blocked" | "pending" | "expired"
    ) {
        return Err(anyhow!("invalid security processor seed state"));
    }
    require_non_empty_vec(
        &record.input_access_class_refs,
        "security processor seed requires inputAccessClassRefs",
    )?;
    validate_reference_list(
        &record.input_access_class_refs,
        "security processor seed missing inputAccessClassRefs",
    )?;
    require_non_empty_vec(
        &record.input_event_classes,
        "security processor seed requires inputEventClasses",
    )?;
    validate_reference_list(
        &record.input_event_classes,
        "security processor seed missing inputEventClasses",
    )?;
    require_non_empty_vec(
        &record.input_content_classes,
        "security processor seed requires inputContentClasses",
    )?;
    for content_class in &record.input_content_classes {
        validate_content_class(content_class)?;
    }
    validate_reference_list(
        &record.access_group_refs,
        "security processor seed missing accessGroupRefs",
    )?;
    validate_reference_list(
        &record.processor_contract_refs,
        "security processor seed missing processorContractRefs",
    )?;
    validate_reference_list(
        &record.evidence_profile_refs,
        "security processor seed missing evidenceProfileRefs",
    )?;
    validate_reference_list(
        &record.materialization_budget_refs,
        "security processor seed missing materializationBudgetRefs",
    )?;
    validate_reference_list(
        &record.storage_refs,
        "security processor seed missing storageRefs",
    )?;
    validate_reference_list(
        &record.detail_refs,
        "security processor seed missing detailRefs",
    )?;
    validate_reference_list(
        &record.alert_output_refs,
        "security processor seed missing alertOutputRefs",
    )?;
    validate_reference_list(
        &record.evidence_hold_refs,
        "security processor seed missing evidenceHoldRefs",
    )?;
    validate_reference_list(
        &record.retention_hold_refs,
        "security processor seed missing retentionHoldRefs",
    )?;
    if let Some(policy) = validate_policy_object(
        &record.encrypted_detail_custody,
        "security processor seed encryptedDetailCustody",
    )? {
        require_policy_string(
            policy,
            "state",
            "security processor seed encryptedDetailCustody",
        )?;
    }
    let Some(boundaries) = validate_policy_object(
        &record.semantic_boundaries,
        "security processor seed semanticBoundaries",
    )?
    else {
        return Err(anyhow!(
            "security processor seed requires semanticBoundaries"
        ));
    };
    require_policy_string(
        boundaries,
        "logging",
        "security processor seed semanticBoundaries",
    )?;
    require_policy_string(
        boundaries,
        "storage",
        "security processor seed semanticBoundaries",
    )?;
    require_policy_string(
        boundaries,
        "eventDomain",
        "security processor seed semanticBoundaries",
    )?;
    if record.state == "blocked" && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "security processor seed blocked state requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.evidence_refs,
        "security processor seed missing evidenceRefs",
    )?;
    validate_reference_list(
        &record.blocked_reasons,
        "security processor seed missing blockedReasons",
    )?;
    validate_safe_facts(&record.safe_facts, "security processor seed safeFacts")?;
    reject_private_content_fields(&record.safe_facts, "security processor seed safeFacts")?;
    reject_media_byte_fields(&serde_json::to_value(record)?, "security processor seed")?;
    if record.issued_at == 0 {
        return Err(anyhow!("security processor seed missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "security processor seed expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_service_manager_secret_boundary(
    record: &ServiceManagerSecretBoundaryRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SERVICE_MANAGER_SECRET_BOUNDARY,
        "service manager secret boundary",
    )?;
    reject_private_content_fields(
        &serde_json::to_value(record)?,
        "service manager secret boundary",
    )?;
    require_non_empty(
        &record.boundary_id,
        "service manager secret boundary missing boundaryId",
    )?;
    require_non_empty(
        &record.manager_id,
        "service manager secret boundary missing managerId",
    )?;
    require_non_empty(
        &record.subject_ref,
        "service manager secret boundary missing subjectRef",
    )?;
    validate_surface_secret_boundary_state(&record.state)?;
    validate_reference_list(
        &record.secret_refs,
        "service manager secret boundary missing secretRefs",
    )?;
    validate_reference_list(
        &record.access_group_refs,
        "service manager secret boundary missing accessGroupRefs",
    )?;
    validate_reference_list(
        &record.authority_refs,
        "service manager secret boundary missing authorityRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "service manager secret boundary missing evidenceRefs",
    )?;
    if record.state == SURFACE_SECRET_BOUNDARY_RESOLVED
        && record.secret_refs.is_empty()
        && record.access_group_refs.is_empty()
    {
        return Err(anyhow!(
            "service manager resolved secret boundary requires secretRefs or accessGroupRefs"
        ));
    }
    if record.state == SURFACE_SECRET_BOUNDARY_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "service manager blocked secret boundary requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "service manager secret boundary missing blockedReasons",
    )?;
    validate_safe_facts(
        &record.safe_facts,
        "service manager secret boundary safeFacts",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("service manager secret boundary missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "service manager secret boundary expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_service_manager_release_contract(
    record: &ServiceManagerReleaseContractRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SERVICE_MANAGER_RELEASE_CONTRACT,
        "service manager release contract",
    )?;
    reject_private_content_fields(
        &serde_json::to_value(record)?,
        "service manager release contract",
    )?;
    require_non_empty(
        &record.contract_id,
        "service manager release contract missing contractId",
    )?;
    require_non_empty(
        &record.manager_id,
        "service manager release contract missing managerId",
    )?;
    require_non_empty(
        &record.subject_ref,
        "service manager release contract missing subjectRef",
    )?;
    require_non_empty(
        &record.manager_ref,
        "service manager release contract missing managerRef",
    )?;
    validate_service_manager_contract_state(&record.state)?;
    validate_optional_ref(
        record.app_contract_ref.as_deref(),
        "service manager release contract missing appContractRef",
    )?;
    validate_optional_ref(
        record.version.as_deref(),
        "service manager release contract missing version",
    )?;
    validate_optional_ref(
        record.build_ref.as_deref(),
        "service manager release contract missing buildRef",
    )?;
    validate_optional_ref(
        record.release_ref.as_deref(),
        "service manager release contract missing releaseRef",
    )?;
    validate_optional_ref(
        record.rollback_ref.as_deref(),
        "service manager release contract missing rollbackRef",
    )?;
    validate_reference_list(
        &record.compatibility_refs,
        "service manager release contract missing compatibilityRefs",
    )?;
    validate_reference_list(
        &record.authority_refs,
        "service manager release contract missing authorityRefs",
    )?;
    validate_reference_list(
        &record.secret_boundary_refs,
        "service manager release contract missing secretBoundaryRefs",
    )?;
    validate_reference_list(
        &record.proof_digest_refs,
        "service manager release contract missing proofDigestRefs",
    )?;
    validate_reference_list(
        &record.lab_proof_refs,
        "service manager release contract missing labProofRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "service manager release contract missing evidenceRefs",
    )?;
    if record.state == SURFACE_APP_CONTRACT_STATE_READY {
        if record
            .build_ref
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(anyhow!(
                "service manager ready release contract requires buildRef"
            ));
        }
        if record
            .release_ref
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(anyhow!(
                "service manager ready release contract requires releaseRef"
            ));
        }
        if record.rollback_required.unwrap_or(true)
            && record
                .rollback_ref
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
        {
            return Err(anyhow!(
                "service manager ready release contract requires rollbackRef unless rollbackRequired is false"
            ));
        }
    }
    if record.state == SURFACE_APP_CONTRACT_STATE_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "service manager blocked release contract requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "service manager release contract missing blockedReasons",
    )?;
    validate_safe_facts(
        &record.safe_facts,
        "service manager release contract safeFacts",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("service manager release contract missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "service manager release contract expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_service_manager_lab_proof(record: &ServiceManagerLabProofRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SERVICE_MANAGER_LAB_PROOF,
        "service manager lab proof",
    )?;
    reject_private_content_fields(&serde_json::to_value(record)?, "service manager lab proof")?;
    require_non_empty(
        &record.proof_id,
        "service manager lab proof missing proofId",
    )?;
    require_non_empty(
        &record.manager_id,
        "service manager lab proof missing managerId",
    )?;
    require_non_empty(
        &record.subject_ref,
        "service manager lab proof missing subjectRef",
    )?;
    validate_service_manager_proof_profile(&record.profile)?;
    validate_service_manager_proof_state(&record.state)?;
    validate_optional_ref(
        record.train_ref.as_deref(),
        "service manager lab proof missing trainRef",
    )?;
    validate_optional_ref(
        record.release_contract_ref.as_deref(),
        "service manager lab proof missing releaseContractRef",
    )?;
    validate_optional_ref(
        record.app_contract_ref.as_deref(),
        "service manager lab proof missing appContractRef",
    )?;
    validate_reference_list(
        &record.surface_refs,
        "service manager lab proof missing surfaceRefs",
    )?;
    validate_reference_list(
        &record.service_refs,
        "service manager lab proof missing serviceRefs",
    )?;
    validate_reference_list(
        &record.environment_refs,
        "service manager lab proof missing environmentRefs",
    )?;
    validate_reference_list(
        &record.artifact_refs,
        "service manager lab proof missing artifactRefs",
    )?;
    validate_reference_list(
        &record.metrics_refs,
        "service manager lab proof missing metricsRefs",
    )?;
    validate_reference_list(
        &record.proof_refs,
        "service manager lab proof missing proofRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "service manager lab proof missing evidenceRefs",
    )?;
    if matches!(
        record.state.as_str(),
        SERVICE_MANAGER_PROOF_STATE_BLOCKED | SERVICE_MANAGER_PROOF_STATE_FAILED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "service manager blocked or failed lab proof requires blockedReasons"
        ));
    }
    if record.state == SERVICE_MANAGER_PROOF_STATE_PROVED
        && record.artifact_refs.is_empty()
        && record.metrics_refs.is_empty()
        && record.proof_refs.is_empty()
    {
        return Err(anyhow!(
            "service manager proved lab proof requires artifactRefs, metricsRefs, or proofRefs"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "service manager lab proof missing blockedReasons",
    )?;
    validate_safe_facts(&record.safe_facts, "service manager lab proof safeFacts")?;
    if record.started_at == 0 {
        return Err(anyhow!("service manager lab proof missing startedAt"));
    }
    if record
        .completed_at
        .is_some_and(|completed_at| completed_at < record.started_at)
    {
        return Err(anyhow!(
            "service manager lab proof completedAt must not be before startedAt"
        ));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.started_at)
    {
        return Err(anyhow!(
            "service manager lab proof expiresAt must be after startedAt"
        ));
    }
    Ok(())
}

pub fn validate_service_manager_train_digest(
    record: &ServiceManagerTrainDigestRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SERVICE_MANAGER_TRAIN_DIGEST,
        "service manager train digest",
    )?;
    reject_private_content_fields(
        &serde_json::to_value(record)?,
        "service manager train digest",
    )?;
    require_non_empty(
        &record.train_id,
        "service manager train digest missing trainId",
    )?;
    require_non_empty(
        &record.manager_id,
        "service manager train digest missing managerId",
    )?;
    require_non_empty(
        &record.subject_ref,
        "service manager train digest missing subjectRef",
    )?;
    validate_service_manager_proof_state(&record.state)?;
    validate_reference_list(
        &record.repo_refs,
        "service manager train digest missing repoRefs",
    )?;
    validate_reference_list(
        &record.commit_refs,
        "service manager train digest missing commitRefs",
    )?;
    validate_reference_list(
        &record.app_contract_refs,
        "service manager train digest missing appContractRefs",
    )?;
    validate_reference_list(
        &record.release_contract_refs,
        "service manager train digest missing releaseContractRefs",
    )?;
    validate_reference_list(
        &record.operation_refs,
        "service manager train digest missing operationRefs",
    )?;
    validate_reference_list(
        &record.proof_digest_refs,
        "service manager train digest missing proofDigestRefs",
    )?;
    validate_reference_list(
        &record.lab_proof_refs,
        "service manager train digest missing labProofRefs",
    )?;
    validate_reference_list(
        &record.metrics_refs,
        "service manager train digest missing metricsRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "service manager train digest missing evidenceRefs",
    )?;
    if matches!(
        record.state.as_str(),
        SERVICE_MANAGER_PROOF_STATE_BLOCKED | SERVICE_MANAGER_PROOF_STATE_FAILED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "service manager blocked or failed train digest requires blockedReasons"
        ));
    }
    if record.state == SERVICE_MANAGER_PROOF_STATE_PROVED {
        require_non_empty_vec(
            &record.release_contract_refs,
            "service manager proved train digest requires releaseContractRefs",
        )?;
        if record.lab_proof_refs.is_empty() && record.proof_digest_refs.is_empty() {
            return Err(anyhow!(
                "service manager proved train digest requires labProofRefs or proofDigestRefs"
            ));
        }
    }
    validate_reference_list(
        &record.blocked_reasons,
        "service manager train digest missing blockedReasons",
    )?;
    validate_safe_facts(&record.safe_facts, "service manager train digest safeFacts")?;
    if record.observed_at == 0 {
        return Err(anyhow!("service manager train digest missing observedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.observed_at)
    {
        return Err(anyhow!(
            "service manager train digest expiresAt must be after observedAt"
        ));
    }
    Ok(())
}

pub fn validate_surface_app_bootstrap_contract(
    record: &SurfaceAppBootstrapContractRecord,
) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SURFACE_APP_BOOTSTRAP_CONTRACT,
        "surface app bootstrap contract",
    )?;
    reject_private_content_fields(
        &serde_json::to_value(record)?,
        "surface app bootstrap contract",
    )?;
    require_non_empty(
        &record.bootstrap_contract_id,
        "surface app bootstrap contract missing bootstrapContractId",
    )?;
    require_non_empty(
        &record.app_contract_ref,
        "surface app bootstrap contract missing appContractRef",
    )?;
    require_non_empty(
        &record.app_id,
        "surface app bootstrap contract missing appId",
    )?;
    validate_service_manager_contract_state(&record.state)?;
    validate_surface_fulfillment_mode(&record.source_mode)?;
    validate_reference_list(
        &record.module_refs,
        "surface app bootstrap contract missing moduleRefs",
    )?;
    validate_optional_ref(
        record.service_manager_ref.as_deref(),
        "surface app bootstrap contract missing serviceManagerRef",
    )?;
    validate_optional_ref(
        record.release_contract_ref.as_deref(),
        "surface app bootstrap contract missing releaseContractRef",
    )?;
    validate_optional_ref(
        record.secret_boundary_ref.as_deref(),
        "surface app bootstrap contract missing secretBoundaryRef",
    )?;
    validate_optional_ref(
        record.train_digest_ref.as_deref(),
        "surface app bootstrap contract missing trainDigestRef",
    )?;
    validate_reference_list(
        &record.lab_proof_profile_refs,
        "surface app bootstrap contract missing labProofProfileRefs",
    )?;
    validate_reference_list(
        &record.authority_refs,
        "surface app bootstrap contract missing authorityRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "surface app bootstrap contract missing evidenceRefs",
    )?;
    if record.state == SURFACE_APP_CONTRACT_STATE_READY {
        require_non_empty_vec(
            &record.module_refs,
            "surface app ready bootstrap contract requires moduleRefs",
        )?;
        if matches!(
            record.source_mode.as_str(),
            SURFACE_FULFILLMENT_MODE_SWARM_PACKAGE
                | SURFACE_FULFILLMENT_MODE_STORAGE_OBJECT
                | SURFACE_FULFILLMENT_MODE_NATIVE_INSTALLED
        ) && record
            .release_contract_ref
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(anyhow!(
                "surface app non-bundled bootstrap contract requires releaseContractRef"
            ));
        }
    }
    if record.state == SURFACE_APP_CONTRACT_STATE_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "surface app blocked bootstrap contract requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "surface app bootstrap contract missing blockedReasons",
    )?;
    validate_safe_facts(
        &record.safe_facts,
        "surface app bootstrap contract safeFacts",
    )?;
    if record.issued_at == 0 {
        return Err(anyhow!("surface app bootstrap contract missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "surface app bootstrap contract expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

fn validate_surface_app_manifest_version(record: &SurfaceAppManifestVersionRecord) -> Result<()> {
    require_non_empty(
        &record.app_contract_ref,
        "surface app manifest version missing appContractRef",
    )?;
    require_non_empty(
        &record.version,
        "surface app manifest version missing version",
    )?;
    validate_surface_app_manifest_version_state(&record.state)?;
    if let Some(source_mode) = record.source_mode.as_deref() {
        validate_surface_fulfillment_mode(source_mode)?;
        if matches!(
            record.state.as_str(),
            SURFACE_APP_MANIFEST_VERSION_CURRENT
                | SURFACE_APP_MANIFEST_VERSION_COMPATIBLE
                | SURFACE_APP_MANIFEST_VERSION_UPDATE_AVAILABLE
        ) && matches!(
            source_mode,
            SURFACE_FULFILLMENT_MODE_SWARM_PACKAGE
                | SURFACE_FULFILLMENT_MODE_STORAGE_OBJECT
                | SURFACE_FULFILLMENT_MODE_NATIVE_INSTALLED
        ) && record
            .release_contract_ref
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(anyhow!(
                "surface app manifest non-bundled version requires releaseContractRef"
            ));
        }
    }
    validate_reference_list(
        &record.module_refs,
        "surface app manifest version missing moduleRefs",
    )?;
    validate_reference_list(
        &record.compatibility_refs,
        "surface app manifest version missing compatibilityRefs",
    )?;
    validate_optional_ref(
        record.bootstrap_contract_ref.as_deref(),
        "surface app manifest version missing bootstrapContractRef",
    )?;
    validate_optional_ref(
        record.release_contract_ref.as_deref(),
        "surface app manifest version missing releaseContractRef",
    )?;
    validate_reference_list(
        &record.authority_refs,
        "surface app manifest version missing authorityRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "surface app manifest version missing evidenceRefs",
    )?;
    if record.state == SURFACE_APP_MANIFEST_VERSION_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "surface app manifest blocked version requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "surface app manifest version missing blockedReasons",
    )?;
    Ok(())
}

pub fn validate_surface_app_manifest(record: &SurfaceAppManifestRecord) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SURFACE_APP_MANIFEST,
        "surface app manifest",
    )?;
    reject_private_content_fields(&serde_json::to_value(record)?, "surface app manifest")?;
    require_non_empty(
        &record.manifest_id,
        "surface app manifest missing manifestId",
    )?;
    require_non_empty(&record.app_id, "surface app manifest missing appId")?;
    require_non_empty(
        &record.current_app_contract_ref,
        "surface app manifest missing currentAppContractRef",
    )?;
    require_non_empty(
        &record.current_version,
        "surface app manifest missing currentVersion",
    )?;
    if let Some(state) = record.state.as_deref() {
        validate_surface_app_manifest_version_state(state)?;
    }
    if let Some(source_mode) = record.default_source_mode.as_deref() {
        validate_surface_fulfillment_mode(source_mode)?;
    }
    if record.versions.is_empty() {
        return Err(anyhow!("surface app manifest requires versions"));
    }
    for version in &record.versions {
        validate_surface_app_manifest_version(version)?;
    }
    if !record.versions.iter().any(|version| {
        version.app_contract_ref == record.current_app_contract_ref
            && version.version == record.current_version
    }) {
        return Err(anyhow!(
            "surface app manifest missing current version claim"
        ));
    }
    validate_reference_list(
        &record.app_contract_refs,
        "surface app manifest missing appContractRefs",
    )?;
    validate_reference_list(
        &record.compatibility_refs,
        "surface app manifest missing compatibilityRefs",
    )?;
    validate_reference_list(
        &record.bootstrap_contract_refs,
        "surface app manifest missing bootstrapContractRefs",
    )?;
    validate_reference_list(
        &record.release_contract_refs,
        "surface app manifest missing releaseContractRefs",
    )?;
    validate_reference_list(
        &record.authority_refs,
        "surface app manifest missing authorityRefs",
    )?;
    validate_reference_list(
        &record.evidence_refs,
        "surface app manifest missing evidenceRefs",
    )?;
    if record.state.as_deref() == Some(SURFACE_APP_MANIFEST_VERSION_BLOCKED)
        && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "surface app manifest blocked state requires blockedReasons"
        ));
    }
    validate_reference_list(
        &record.blocked_reasons,
        "surface app manifest missing blockedReasons",
    )?;
    validate_safe_facts(&record.safe_facts, "surface app manifest safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("surface app manifest missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "surface app manifest expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn validate_swarm_identity_graph(records: &[Value]) -> Result<()> {
    for record in records {
        let Some(object) = record.as_object() else {
            return Err(anyhow!("swarm identity graph record must be an object"));
        };
        let kind = object
            .get("kind")
            .or_else(|| object.get("recordKind"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(
            kind,
            RECORD_SWARM_INTERACTION
                | RECORD_SWARM_ACTIVATION
                | RECORD_ROUTE_PROMISE
                | RECORD_CONTRIBUTION_LIFECYCLE
                | RECORD_MEDIA_TRANSPORT_PATH
                | RECORD_MEDIA_TRANSPORT_OBSERVATION
                | "stream.session.offer"
                | "stream.session.answer"
                | "stream.session.candidate"
                | "stream.session.control"
                | "stream.session.health"
                | "stream.session.close"
        ) {
            return Err(anyhow!(
                "swarm identity graph must not contain live lease or activation state"
            ));
        }
        if ["lease", "routePromise", "activeSession", "streamSession"]
            .iter()
            .any(|key| object.contains_key(*key))
        {
            return Err(anyhow!(
                "swarm identity graph must not contain live lease or activation state"
            ));
        }
    }
    Ok(())
}

pub fn validate_caac_envelope_for_mode(
    envelope: &Value,
    mode: CaacValidationMode,
    now: u64,
) -> Result<()> {
    if !envelope.is_object() {
        return Err(anyhow!("caac envelope must be an object"));
    }
    if mode == CaacValidationMode::Structural {
        require_non_empty(
            envelope
                .get("envelopeId")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "caac envelope missing envelopeId",
        )?;
        return Ok(());
    }
    if mode == CaacValidationMode::Fixture && is_fixture_caac_placeholder(envelope) {
        return Ok(());
    }
    if is_fixture_caac_placeholder(envelope) {
        return Err(anyhow!("fixture caac placeholder rejected in product mode"));
    }
    let parsed: CaacEnvelope = serde_json::from_value(envelope.clone())
        .map_err(|_| anyhow!("invalid product caac envelope"))?;
    if parsed.version != CAAC_VERSION {
        return Err(anyhow!("unsupported caac envelope version"));
    }
    if parsed.alg != CAAC_ALG_V1 {
        return Err(anyhow!("unsupported caac envelope algorithm"));
    }
    if parsed.expires_at <= now {
        return Err(anyhow!("caac envelope expired"));
    }
    if parsed.recipients.is_empty() {
        return Err(anyhow!("caac envelope missing recipients"));
    }
    for recipient in &parsed.recipients {
        require_non_empty(&recipient.recipient_pk, "caac envelope missing recipientPk")?;
        require_non_empty(&recipient.nonce, "caac envelope missing nonce")?;
        require_non_empty(&recipient.ciphertext, "caac envelope missing ciphertext")?;
    }
    if !verify_envelope_signature(&parsed)? {
        return Err(anyhow!("invalid caac envelope signature"));
    }
    Ok(())
}

pub fn validate_capability_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.len() > 128 {
        return Err(anyhow!("capability name too long"));
    }
    let segments: Vec<&str> = trimmed.split('.').collect();
    if segments.len() < 2 {
        return Err(anyhow!("invalid capability namespace"));
    }
    for segment in segments {
        if segment.is_empty() {
            return Err(anyhow!("invalid capability namespace"));
        }
        let mut chars = segment.chars();
        let first = chars.next().unwrap_or_default();
        if !first.is_ascii_lowercase() {
            return Err(anyhow!("invalid capability namespace"));
        }
        if !segment
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
        {
            return Err(anyhow!("invalid capability namespace"));
        }
    }
    Ok(())
}

pub fn capability_entries_matching(
    entries: &[CapabilityDirectoryEntry],
    capability: &str,
) -> Vec<CapabilityDirectoryEntry> {
    let mut matches: Vec<_> = entries
        .iter()
        .filter(|entry| entry.capability == capability)
        .cloned()
        .collect();
    matches.sort_by(|a, b| {
        a.channel_id
            .cmp(&b.channel_id)
            .then(a.priority.cmp(&b.priority))
            .then(a.entry_id.cmp(&b.entry_id))
    });
    matches
}

pub fn active_capability_advertisements<'a>(
    advertisements: &'a [CapabilityAdvertisement],
    now: u64,
) -> Vec<&'a CapabilityAdvertisement> {
    advertisements
        .iter()
        .filter(|advertisement| {
            advertisement
                .expires_at
                .map(|expires_at| expires_at > now)
                .unwrap_or(true)
        })
        .collect()
}

pub fn validate_projection_snapshot(snapshot: &SwarmProjectionSnapshot) -> Result<()> {
    require_non_empty(
        &snapshot.projection_id,
        "projection snapshot missing projectionId",
    )?;
    require_non_empty(&snapshot.policy_id, "projection snapshot missing policyId")?;
    if snapshot.issued_at == 0 {
        return Err(anyhow!("projection snapshot missing issuedAt"));
    }
    Ok(())
}

pub fn validate_projection_delta(
    delta: &SwarmProjectionDelta,
    current_revision: u64,
) -> Result<()> {
    require_non_empty(
        &delta.projection_id,
        "projection delta missing projectionId",
    )?;
    require_non_empty(&delta.policy_id, "projection delta missing policyId")?;
    if delta.base_revision != current_revision {
        return Err(anyhow!("projection delta base revision mismatch"));
    }
    if delta.revision <= delta.base_revision {
        return Err(anyhow!("projection delta revision must advance"));
    }
    if delta.ops.is_empty() {
        return Err(anyhow!("projection delta missing ops"));
    }
    if delta.issued_at == 0 {
        return Err(anyhow!("projection delta missing issuedAt"));
    }
    for op in &delta.ops {
        validate_projection_delta_op(op)?;
    }
    Ok(())
}

pub fn validate_projection_delta_op(op: &ProjectionDeltaOp) -> Result<()> {
    if op.path.is_empty() {
        return Err(anyhow!("projection delta op missing path"));
    }
    for segment in &op.path {
        if let ProjectionPathSegment::Key(key) = segment {
            require_non_empty(key, "projection delta op has empty path segment")?;
        }
    }
    match op.op {
        ProjectionDeltaOpKind::Remove => {
            if op.value.is_some() {
                return Err(anyhow!("projection remove op must not carry value"));
            }
        }
        ProjectionDeltaOpKind::Set
        | ProjectionDeltaOpKind::AppendUnique
        | ProjectionDeltaOpKind::Replace => {
            if op.value.is_none() {
                return Err(anyhow!("projection delta op missing value"));
            }
        }
    }
    Ok(())
}

pub fn validate_swarm_edge_hello(hello: &SwarmEdgeHello) -> Result<()> {
    if !hello
        .supported_versions
        .contains(&(SWARM_FRAME_VERSION as u32))
    {
        return Err(anyhow!("swarm edge hello missing supported swarm version"));
    }
    validate_swarm_edge_common(
        &hello.member_kind,
        &hello.member_ref,
        &hello.zone_scope,
        &hello.capability_refs,
        &hello.channel_refs,
        &hello.promise_refs,
        &hello.last_acked_frame_id,
        &hello.last_projection_revisions,
        &hello.nonce,
        hello.issued_at,
        hello.expires_at,
        &hello.sealed_claims,
        "swarm edge hello",
    )
}

pub fn validate_swarm_edge_accept(accept: &SwarmEdgeAccept) -> Result<()> {
    require_non_empty(&accept.session_id, "swarm edge accept missing sessionId")?;
    if accept.accepted_version != SWARM_FRAME_VERSION as u32 {
        return Err(anyhow!("swarm edge accept unsupported version"));
    }
    validate_swarm_edge_common(
        &accept.member_kind,
        &accept.member_ref,
        &accept.zone_scope,
        &accept.capability_refs,
        &accept.channel_refs,
        &accept.promise_refs,
        &accept.last_acked_frame_id,
        &accept.last_projection_revisions,
        &accept.nonce,
        accept.issued_at,
        accept.expires_at,
        &accept.sealed_claims,
        "swarm edge accept",
    )
}

pub fn validate_swarm_edge_resume(resume: &SwarmEdgeResume) -> Result<()> {
    require_non_empty(&resume.session_id, "swarm edge resume missing sessionId")?;
    validate_swarm_edge_common(
        &resume.member_kind,
        &resume.member_ref,
        &resume.zone_scope,
        &resume.capability_refs,
        &resume.channel_refs,
        &resume.promise_refs,
        &resume.last_acked_frame_id,
        &resume.last_projection_revisions,
        &resume.nonce,
        resume.issued_at,
        resume.expires_at,
        &resume.sealed_claims,
        "swarm edge resume",
    )
}

pub fn validate_swarm_edge_close(close: &SwarmEdgeClose) -> Result<()> {
    require_non_empty(&close.session_id, "swarm edge close missing sessionId")?;
    require_non_empty(&close.reason_code, "swarm edge close missing reasonCode")?;
    validate_swarm_edge_common(
        &close.member_kind,
        &close.member_ref,
        &close.zone_scope,
        &close.capability_refs,
        &close.channel_refs,
        &close.promise_refs,
        &close.last_acked_frame_id,
        &close.last_projection_revisions,
        &close.nonce,
        close.issued_at,
        close.expires_at,
        &close.sealed_claims,
        "swarm edge close",
    )
}

fn validate_swarm_edge_common(
    member_kind: &str,
    member_ref: &str,
    zone_scope: &ZoneScope,
    capability_refs: &[String],
    channel_refs: &[String],
    promise_refs: &[String],
    last_acked_frame_id: &Option<String>,
    last_projection_revisions: &Value,
    nonce: &str,
    issued_at: u64,
    expires_at: Option<u64>,
    sealed_claims: &SwarmFrameBody,
    context: &str,
) -> Result<()> {
    require_non_empty(member_kind, &format!("{context} missing memberKind"))?;
    validate_resolved_member_ref(member_ref, &format!("{context} missing memberRef"))?;
    validate_zone_scope(zone_scope)?;
    for capability in capability_refs {
        validate_capability_name(capability)?;
    }
    for channel_ref in channel_refs {
        require_non_empty(channel_ref, &format!("{context} missing channelRef"))?;
    }
    for promise_ref in promise_refs {
        require_non_empty(promise_ref, &format!("{context} missing promiseRef"))?;
    }
    if let Some(frame_id) = last_acked_frame_id {
        require_non_empty(frame_id, &format!("{context} missing lastAckedFrameId"))?;
    }
    validate_projection_revision_map(last_projection_revisions, context)?;
    require_non_empty(nonce, &format!("{context} missing nonce"))?;
    if issued_at == 0 {
        return Err(anyhow!("{context} missing issuedAt"));
    }
    if expires_at.is_some_and(|value| value <= issued_at) {
        return Err(anyhow!("{context} expiresAt must be after issuedAt"));
    }
    require_sealed_body(
        sealed_claims,
        &format!("{context} sealedClaims must be sealed"),
    )
}

fn validate_projection_revision_map(value: &Value, context: &str) -> Result<()> {
    let map = value
        .as_object()
        .ok_or_else(|| anyhow!("{context} lastProjectionRevisions must be an object"))?;
    for (projection_id, revision) in map {
        require_non_empty(
            projection_id,
            &format!("{context} lastProjectionRevisions missing projectionId"),
        )?;
        if revision.as_u64().is_none() {
            return Err(anyhow!(
                "{context} lastProjectionRevisions revision must be non-negative"
            ));
        }
    }
    Ok(())
}

pub fn validate_storage_pin_intent(intent: &StoragePinIntent) -> Result<()> {
    require_non_empty(&intent.intent_id, "storage pin intent missing intentId")?;
    if intent.object_refs.is_empty() {
        return Err(anyhow!("storage pin intent missing objectRefs"));
    }
    require_non_empty(
        &intent.manifest_hash,
        "storage pin intent missing manifestHash",
    )?;
    if intent.desired_replicas == 0 {
        return Err(anyhow!(
            "storage pin intent desiredReplicas must be positive"
        ));
    }
    require_non_empty(&intent.retention, "storage pin intent missing retention")?;
    if intent.authority_refs.is_empty() {
        return Err(anyhow!("storage pin intent missing authorityRefs"));
    }
    Ok(())
}

pub fn validate_storage_pin_attestation(attestation: &StoragePinAttestation) -> Result<()> {
    require_non_empty(
        &attestation.attestation_id,
        "storage pin attestation missing attestationId",
    )?;
    require_non_empty(
        &attestation.intent_id,
        "storage pin attestation missing intentId",
    )?;
    require_non_empty(
        &attestation.storage_member_ref,
        "storage pin attestation missing storageMemberRef",
    )?;
    if attestation.issued_at == 0 {
        return Err(anyhow!("storage pin attestation missing issuedAt"));
    }
    for availability in &attestation.availability_refs {
        validate_storage_availability_ref(availability)?;
    }
    Ok(())
}

pub fn validate_storage_availability_ref(availability: &SwarmStorageAvailabilityRef) -> Result<()> {
    require_non_empty(
        &availability.availability_id,
        "storage availability missing availabilityId",
    )?;
    require_non_empty(
        &availability.object_ref,
        "storage availability missing objectRef",
    )?;
    require_non_empty(
        &availability.storage_member_ref,
        "storage availability missing storageMemberRef",
    )?;
    Ok(())
}

pub fn storage_pin_projection_from_intent(
    intent: &StoragePinIntent,
) -> Result<StoragePinProjection> {
    validate_storage_pin_intent(intent)?;
    Ok(StoragePinProjection {
        pinned_count: 0,
        members: vec![],
        availability: vec![],
        missing_replicas: intent.desired_replicas,
        expires_at: intent.expires_at,
        status: StoragePinProjectionStatus::Pending,
    })
}

pub fn storage_pin_projection_from_records(
    intent: &StoragePinIntent,
    attestations: &[StoragePinAttestation],
    now: u64,
) -> Result<StoragePinProjection> {
    validate_storage_pin_intent(intent)?;

    let mut members = Vec::<String>::new();
    let mut availability = Vec::<SwarmStorageAvailabilityRef>::new();

    for attestation in attestations {
        validate_storage_pin_attestation(attestation)?;
        if attestation.intent_id != intent.intent_id {
            continue;
        }
        if attestation
            .expires_at
            .map(|expires_at| expires_at <= now)
            .unwrap_or(false)
        {
            continue;
        }
        if !matches!(
            attestation.status,
            StoragePinStatus::Accepted | StoragePinStatus::Pinned
        ) {
            continue;
        }
        if !members.contains(&attestation.storage_member_ref) {
            members.push(attestation.storage_member_ref.clone());
        }
        availability.extend(attestation.availability_refs.clone());
    }

    members.sort();
    availability.sort_by(|left, right| {
        left.availability_id
            .cmp(&right.availability_id)
            .then(left.object_ref.cmp(&right.object_ref))
            .then(left.storage_member_ref.cmp(&right.storage_member_ref))
    });

    let pinned_count = members.len() as u32;
    let missing_replicas = intent.desired_replicas.saturating_sub(pinned_count);
    Ok(StoragePinProjection {
        pinned_count,
        members,
        availability,
        missing_replicas,
        expires_at: intent.expires_at,
        status: if missing_replicas == 0 {
            StoragePinProjectionStatus::Satisfied
        } else {
            StoragePinProjectionStatus::Pending
        },
    })
}

pub fn validate_stream_session_intent(intent: &StreamSessionIntent) -> Result<()> {
    require_non_empty(
        &intent.session_id,
        "stream session intent missing sessionId",
    )?;
    validate_capability_name(&intent.capability_ref)?;
    validate_resolved_member_ref(
        &intent.requester_ref,
        "stream session intent missing requesterRef",
    )?;
    require_non_empty(
        &intent.channel_id,
        "stream session intent missing channelId",
    )?;
    require_non_empty(&intent.transport, "stream session intent missing transport")?;
    if intent.issued_at == 0 {
        return Err(anyhow!("stream session intent missing issuedAt"));
    }
    Ok(())
}

pub fn validate_stream_session_admission(admission: &StreamSessionAdmission) -> Result<()> {
    require_non_empty(
        &admission.admission_id,
        "stream session admission missing admissionId",
    )?;
    require_non_empty(
        &admission.session_id,
        "stream session admission missing sessionId",
    )?;
    validate_capability_name(&admission.capability_ref)?;
    validate_resolved_member_ref(
        &admission.admitted_by,
        "stream session admission missing admittedBy",
    )?;
    if admission.issued_at == 0 {
        return Err(anyhow!("stream session admission missing issuedAt"));
    }
    Ok(())
}

pub fn validate_stream_session_offer(offer: &StreamSessionOffer) -> Result<()> {
    require_non_empty(&offer.offer_id, "stream session offer missing offerId")?;
    require_non_empty(&offer.session_id, "stream session offer missing sessionId")?;
    require_non_empty(&offer.transport, "stream session offer missing transport")?;
    if !offer.payload.is_object() {
        return Err(anyhow!("stream session offer payload must be an object"));
    }
    reject_media_byte_fields(&offer.payload, "stream session offer")?;
    if offer.issued_at == 0 {
        return Err(anyhow!("stream session offer missing issuedAt"));
    }
    Ok(())
}

pub fn validate_stream_session_answer(answer: &StreamSessionAnswer) -> Result<()> {
    require_non_empty(&answer.answer_id, "stream session answer missing answerId")?;
    require_non_empty(
        &answer.session_id,
        "stream session answer missing sessionId",
    )?;
    require_non_empty(&answer.transport, "stream session answer missing transport")?;
    if !answer.payload.is_object() {
        return Err(anyhow!("stream session answer payload must be an object"));
    }
    reject_media_byte_fields(&answer.payload, "stream session answer")?;
    if answer.issued_at == 0 {
        return Err(anyhow!("stream session answer missing issuedAt"));
    }
    Ok(())
}

pub fn validate_stream_session_candidate(candidate: &StreamSessionCandidate) -> Result<()> {
    require_non_empty(
        &candidate.candidate_id,
        "stream session candidate missing candidateId",
    )?;
    require_non_empty(
        &candidate.session_id,
        "stream session candidate missing sessionId",
    )?;
    require_non_empty(
        &candidate.transport,
        "stream session candidate missing transport",
    )?;
    require_non_empty(
        &candidate.candidate_role,
        "stream session candidate missing candidateRole",
    )?;
    if !matches!(
        candidate.candidate_role.as_str(),
        STREAM_CANDIDATE_ROLE_BROWSER | STREAM_CANDIDATE_ROLE_SERVICE
    ) {
        return Err(anyhow!("stream session candidate role is unsupported"));
    }
    require_non_empty(
        &candidate.actionability,
        "stream session candidate missing actionability",
    )?;
    if !matches!(
        candidate.actionability.as_str(),
        STREAM_CANDIDATE_ACTIONABILITY_USABLE | STREAM_CANDIDATE_ACTIONABILITY_BLOCKED
    ) {
        return Err(anyhow!(
            "stream session candidate actionability is unsupported"
        ));
    }
    if candidate.actionability == STREAM_CANDIDATE_ACTIONABILITY_BLOCKED
        && candidate
            .blocked_reason
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(anyhow!("stream session candidate missing blockedReason"));
    }
    validate_stream_candidate_endpoint(&candidate.endpoint)?;
    if !candidate.payload.is_object() {
        return Err(anyhow!(
            "stream session candidate payload must be an object"
        ));
    }
    reject_media_byte_fields(&candidate.payload, "stream session candidate")?;
    if candidate.issued_at == 0 {
        return Err(anyhow!("stream session candidate missing issuedAt"));
    }
    Ok(())
}

fn validate_stream_candidate_endpoint(endpoint: &Value) -> Result<()> {
    if endpoint.is_null() {
        return Ok(());
    }
    let Some(map) = endpoint.as_object() else {
        return Err(anyhow!(
            "stream session candidate endpoint must be an object"
        ));
    };
    for key in ["protocol", "address", "candidateType"] {
        if let Some(value) = map.get(key) {
            let Some(text) = value.as_str() else {
                return Err(anyhow!(
                    "stream session candidate endpoint {key} must be a string"
                ));
            };
            require_non_empty(
                text,
                &format!("stream session candidate endpoint {key} is empty"),
            )?;
        }
    }
    if let Some(port) = map.get("port") {
        let Some(port) = port.as_u64() else {
            return Err(anyhow!("stream session candidate endpoint port is invalid"));
        };
        if !(1..=65_535).contains(&port) {
            return Err(anyhow!("stream session candidate endpoint port is invalid"));
        }
    }
    Ok(())
}

pub fn validate_stream_session_control(control: &StreamSessionControl) -> Result<()> {
    require_non_empty(
        &control.control_id,
        "stream session control missing controlId",
    )?;
    require_non_empty(
        &control.session_id,
        "stream session control missing sessionId",
    )?;
    require_non_empty(&control.command, "stream session control missing command")?;
    if !control.params.is_null() && !control.params.is_object() {
        return Err(anyhow!("stream session control params must be an object"));
    }
    reject_media_byte_fields(&control.params, "stream session control")?;
    if control.issued_at == 0 {
        return Err(anyhow!("stream session control missing issuedAt"));
    }
    Ok(())
}

pub fn validate_stream_session_close(close: &StreamSessionClose) -> Result<()> {
    require_non_empty(&close.close_id, "stream session close missing closeId")?;
    require_non_empty(&close.session_id, "stream session close missing sessionId")?;
    require_non_empty(
        &close.reason_code,
        "stream session close missing reasonCode",
    )?;
    if close.issued_at == 0 {
        return Err(anyhow!("stream session close missing issuedAt"));
    }
    Ok(())
}

pub fn validate_stream_session_health(health: &StreamSessionHealth) -> Result<()> {
    require_non_empty(&health.health_id, "stream session health missing healthId")?;
    require_non_empty(
        &health.session_id,
        "stream session health missing sessionId",
    )?;
    require_non_empty(&health.status, "stream session health missing status")?;
    if !health.recovery.is_null() && !health.recovery.is_object() {
        return Err(anyhow!("stream session health recovery must be an object"));
    }
    reject_media_byte_fields(&health.recovery, "stream session health")?;
    if health.issued_at == 0 {
        return Err(anyhow!("stream session health missing issuedAt"));
    }
    Ok(())
}

pub fn validate_app_recipe(recipe: &AppRecipe) -> Result<()> {
    require_non_empty(&recipe.recipe_id, "app recipe missing recipeId")?;
    require_non_empty(&recipe.version, "app recipe missing version")?;
    if recipe.required_capabilities.is_empty() {
        return Err(anyhow!("app recipe missing requiredCapabilities"));
    }
    if recipe.required_channels.is_empty() {
        return Err(anyhow!("app recipe missing requiredChannels"));
    }
    if recipe.required_roles.is_empty() {
        return Err(anyhow!("app recipe missing requiredRoles"));
    }
    for capability in &recipe.required_capabilities {
        validate_capability_name(capability)?;
    }
    require_non_empty(&recipe.entrypoint, "app recipe missing entrypoint")?;
    if recipe.issued_at == 0 {
        return Err(anyhow!("app recipe missing issuedAt"));
    }
    Ok(())
}

pub fn validate_app_runner_advertisement(advertisement: &AppRunnerAdvertisement) -> Result<()> {
    require_non_empty(
        &advertisement.advertisement_id,
        "app runner advertisement missing advertisementId",
    )?;
    require_non_empty(
        &advertisement.runner_ref,
        "app runner advertisement missing runnerRef",
    )?;
    if advertisement.capacity == 0 {
        return Err(anyhow!(
            "app runner advertisement capacity must be positive"
        ));
    }
    if advertisement.supported_versions.is_empty() {
        return Err(anyhow!(
            "app runner advertisement missing supportedVersions"
        ));
    }
    require_non_empty(
        &advertisement.health,
        "app runner advertisement missing health",
    )?;
    for capability in &advertisement.capability_refs {
        validate_capability_name(capability)?;
    }
    if advertisement.issued_at == 0 {
        return Err(anyhow!("app runner advertisement missing issuedAt"));
    }
    Ok(())
}

pub fn validate_app_runner_attestation(attestation: &AppRunnerAttestation) -> Result<()> {
    require_non_empty(
        &attestation.attestation_id,
        "app runner attestation missing attestationId",
    )?;
    require_non_empty(
        &attestation.runner_ref,
        "app runner attestation missing runnerRef",
    )?;
    require_non_empty(
        &attestation.recipe_id,
        "app runner attestation missing recipeId",
    )?;
    require_non_empty(&attestation.status, "app runner attestation missing status")?;
    if attestation.issued_at == 0 {
        return Err(anyhow!("app runner attestation missing issuedAt"));
    }
    Ok(())
}

fn validate_frame_body(frame: &SwarmFrame) -> Result<()> {
    match frame.body.encoding.as_str() {
        "caac" => {
            let envelope = frame
                .body
                .envelope
                .as_ref()
                .ok_or_else(|| anyhow!("swarm frame CAAC body missing envelope"))?;
            if !envelope.is_object() {
                return Err(anyhow!("swarm frame CAAC body envelope must be an object"));
            }
            Ok(())
        }
        "public" => {
            if !public_bootstrap_body_allowed(&frame.kind) || !frame.body.public_bootstrap {
                return Err(anyhow!(
                    "public swarm frame body is only allowed for explicit bootstrap metadata"
                ));
            }
            if frame
                .body
                .payload
                .as_ref()
                .map(|payload| !payload.is_object())
                .unwrap_or(false)
            {
                return Err(anyhow!("public swarm frame payload must be an object"));
            }
            Ok(())
        }
        _ => Err(anyhow!("unsupported swarm frame body encoding")),
    }
}

fn require_sealed_body(body: &SwarmFrameBody, message: &str) -> Result<()> {
    if body.encoding != "caac" {
        return Err(anyhow!(message.to_string()));
    }
    if body.envelope.as_ref().is_some_and(Value::is_object) {
        Ok(())
    } else {
        Err(anyhow!(message.to_string()))
    }
}

fn public_bootstrap_body_allowed(kind: &SwarmFrameKind) -> bool {
    matches!(
        kind,
        SwarmFrameKind::BootstrapDiscovery | SwarmFrameKind::BootstrapGatewayHint
    )
}

fn reject_media_byte_fields(value: &Value, context: &str) -> Result<()> {
    if contains_media_byte_field(value) {
        Err(anyhow!("{context} contains media byte field"))
    } else {
        Ok(())
    }
}

fn contains_media_byte_field(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| is_media_byte_key(key) || contains_media_byte_field(value)),
        Value::Array(items) => items.iter().any(contains_media_byte_field),
        _ => false,
    }
}

fn is_media_byte_key(key: &str) -> bool {
    matches!(
        key,
        "mediaBytes"
            | "payloadBytes"
            | "mediaData"
            | "mediaChunk"
            | "encodedMediaBytes"
            | "blobBytes"
            | "payloadBlobBytes"
            | "blobData"
            | "blobChunk"
            | "encodedBlobBytes"
            | "binaryBytes"
            | "rawBytes"
    )
}

fn validate_optional_kind(kind: &Option<String>, expected: &str, context: &str) -> Result<()> {
    if let Some(kind) = kind {
        if kind != expected {
            return Err(anyhow!("{context} kind must be {expected}"));
        }
    }
    Ok(())
}

fn require_non_empty_vec(values: &[String], message: &str) -> Result<()> {
    if values.is_empty() {
        return Err(anyhow!(message.to_string()));
    }
    for value in values {
        require_non_empty(value, message)?;
    }
    Ok(())
}

fn validate_reference_list(values: &[String], message: &str) -> Result<()> {
    for value in values {
        require_non_empty(value, message)?;
    }
    Ok(())
}

fn validate_optional_ref(value: Option<&str>, message: &str) -> Result<()> {
    if let Some(value) = value {
        require_non_empty(value, message)?;
    }
    Ok(())
}

fn validate_capability_names(values: &[String]) -> Result<()> {
    for value in values {
        validate_capability_name(value)?;
    }
    Ok(())
}

fn validate_authority_domain(domain: &str) -> Result<()> {
    if matches!(
        domain,
        "identity" | "gateway" | "service" | "device" | "runtime"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported authority domain"))
    }
}

fn validate_service_manager_contract_state(state: &str) -> Result<()> {
    if matches!(
        state,
        SURFACE_APP_CONTRACT_STATE_DRAFT
            | SURFACE_APP_CONTRACT_STATE_READY
            | SURFACE_APP_CONTRACT_STATE_BLOCKED
            | SURFACE_APP_CONTRACT_STATE_SUPERSEDED
            | SURFACE_APP_CONTRACT_STATE_EXPIRED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported service manager contract state"))
    }
}

fn validate_surface_app_manifest_version_state(state: &str) -> Result<()> {
    if matches!(
        state,
        SURFACE_APP_MANIFEST_VERSION_CURRENT
            | SURFACE_APP_MANIFEST_VERSION_COMPATIBLE
            | SURFACE_APP_MANIFEST_VERSION_UPDATE_AVAILABLE
            | SURFACE_APP_MANIFEST_VERSION_BLOCKED
            | SURFACE_APP_MANIFEST_VERSION_SUPERSEDED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported surface app manifest version state"))
    }
}

fn validate_surface_secret_boundary_state(state: &str) -> Result<()> {
    if matches!(
        state,
        SURFACE_SECRET_BOUNDARY_NOT_REQUIRED
            | SURFACE_SECRET_BOUNDARY_RESOLVED
            | SURFACE_SECRET_BOUNDARY_BLOCKED
            | SURFACE_SECRET_BOUNDARY_UNAVAILABLE
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported surface secret boundary state"))
    }
}

fn validate_service_manager_proof_state(state: &str) -> Result<()> {
    if matches!(
        state,
        SERVICE_MANAGER_PROOF_STATE_PENDING
            | SERVICE_MANAGER_PROOF_STATE_PROVED
            | SERVICE_MANAGER_PROOF_STATE_FAILED
            | SERVICE_MANAGER_PROOF_STATE_BLOCKED
            | SERVICE_MANAGER_PROOF_STATE_EXPIRED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported service manager proof state"))
    }
}

fn validate_service_manager_proof_profile(profile: &str) -> Result<()> {
    if matches!(
        profile,
        "surfaceLandscape"
            | "nvrLive30s"
            | "longStream10m"
            | "loggingPressure"
            | "directEdge"
            | "nativeChecks"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported service manager proof profile"))
    }
}

fn validate_surface_fulfillment_mode(mode: &str) -> Result<()> {
    if matches!(
        mode,
        SURFACE_FULFILLMENT_MODE_BUNDLED
            | SURFACE_FULFILLMENT_MODE_SWARM_PACKAGE
            | SURFACE_FULFILLMENT_MODE_STORAGE_OBJECT
            | SURFACE_FULFILLMENT_MODE_NATIVE_INSTALLED
            | SURFACE_FULFILLMENT_MODE_DEV_OVERLAY
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported surface fulfillment mode"))
    }
}

fn validate_agreement_plane(plane: &str) -> Result<()> {
    if matches!(
        plane,
        AGREEMENT_PLANE_ACTION_AUTHORITY
            | AGREEMENT_PLANE_ACCESS_AUTHORITY
            | AGREEMENT_PLANE_DELIVERY_WITNESS
            | AGREEMENT_PLANE_MATERIALIZATION
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported agreement plane"))
    }
}

fn validate_action_grant_state(state: &str) -> Result<()> {
    if matches!(
        state,
        AGREEMENT_STATE_REQUESTED
            | AGREEMENT_STATE_ACCEPTED
            | AGREEMENT_STATE_APPLIED
            | AGREEMENT_STATE_REJECTED
            | AGREEMENT_STATE_BLOCKED
            | AGREEMENT_STATE_EXPIRED
            | AGREEMENT_STATE_REVOKED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported action grant state"))
    }
}

fn validate_authority_proof_state(state: &str) -> Result<()> {
    if matches!(
        state,
        AUTHORITY_PROOF_STATE_PROVED
            | AUTHORITY_PROOF_STATE_DEGRADED
            | AUTHORITY_PROOF_STATE_BLOCKED
            | AUTHORITY_PROOF_STATE_EXPIRED
            | AUTHORITY_PROOF_STATE_REVOKED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported authority proof state"))
    }
}

fn validate_authority_proof_check(check: &str) -> Result<()> {
    if matches!(
        check,
        AUTHORITY_PROOF_CHECK_SYNC
            | AUTHORITY_PROOF_CHECK_READ
            | AUTHORITY_PROOF_CHECK_WRITE_REDUCE
            | AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported authority proof check"))
    }
}

fn validate_root_operation(operation: &str) -> Result<()> {
    if matches!(
        operation,
        "addRoot" | "refreshRoot" | "rotateRoot" | "revokeRoot" | "enrollDevice" | "revokeDevice"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported root operation"))
    }
}

fn validate_access_epoch_change(change: &str) -> Result<()> {
    if matches!(
        change,
        "create"
            | "addMember"
            | "removeMember"
            | "rotateKey"
            | "revokeMember"
            | "partitionSplit"
            | "partitionMerge"
            | "purposeKey"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported access epoch change"))
    }
}

fn validate_content_class(content_class: &str) -> Result<()> {
    if matches!(
        content_class,
        "safeFacts"
            | "safeIndex"
            | "uiProjection"
            | "encryptedDetail"
            | "encryptedRaw"
            | "mediaReference"
            | "diagnosticDetail"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported content class"))
    }
}

fn validate_agreement_privacy_tier(privacy_tier: &str) -> Result<()> {
    if matches!(
        privacy_tier,
        "publicSafe" | "domainSafe" | "domainEncrypted" | "privateEncrypted"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported agreement privacy tier"))
    }
}

fn validate_safe_fact_policy(policy: &str) -> Result<()> {
    if matches!(policy, "none" | "minimal" | "indexOnly" | "projectionSafe") {
        Ok(())
    } else {
        Err(anyhow!("unsupported safe fact policy"))
    }
}

fn validate_interaction_role(role: &str) -> Result<()> {
    if matches!(
        role,
        "requester"
            | "coordinator"
            | "router"
            | "executor"
            | "adapter"
            | "storage"
            | "observer"
            | "owner"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported interaction role"))
    }
}

fn validate_interaction_state(state: &str) -> Result<()> {
    if matches!(
        state,
        "prepared"
            | "accepted"
            | "routed"
            | "serviceAccepted"
            | "active"
            | "rejected"
            | "released"
            | "expired"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported interaction state"))
    }
}

fn validate_routing_scope_kind(kind: &str) -> Result<()> {
    if matches!(
        kind,
        "local" | "swarmZone" | "explicitAudience" | "explicitMember" | "bootstrap"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported routing scope kind"))
    }
}

fn validate_routing_scope_state(state: &str) -> Result<()> {
    if matches!(
        state,
        "notRequired" | "ready" | "syncing" | "stale" | "missing" | "unavailable"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported routing scope state"))
    }
}

fn validate_routing_blocked_reason(reason: &str) -> Result<()> {
    if matches!(
        reason,
        "missingZoneBaseline"
            | "noMemberInZone"
            | "zeroPropagation"
            | "zoneMismatch"
            | "audienceMismatch"
            | "edgeNotAccepted"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported routing blocked reason"))
    }
}

fn validate_routing_scope_posture(posture: &RoutingScopePosture) -> Result<()> {
    validate_routing_scope_kind(&posture.kind)?;
    validate_routing_scope_state(&posture.state)?;
    if posture.required && posture.state == "notRequired" {
        return Err(anyhow!(
            "routing scope notRequired state cannot be required"
        ));
    }
    if posture.kind == "swarmZone"
        && posture.required
        && matches!(posture.state.as_str(), "ready" | "syncing" | "stale")
        && posture.zone_scope.is_none()
    {
        return Err(anyhow!(
            "routing scope swarmZone posture requires zoneScope"
        ));
    }
    if let Some(scope) = &posture.zone_scope {
        validate_zone_scope(scope)?;
    }
    if let Some(reason) = &posture.blocked_reason {
        validate_routing_blocked_reason(reason)?;
    }
    Ok(())
}

fn validate_participant_runlevel(value: &str) -> Result<()> {
    if matches!(
        value,
        "localCache"
            | "authorityReady"
            | "edgeAttached"
            | "directoryReady"
            | "routeReady"
            | "interactive"
            | "fulfilling"
            | "degraded"
            | "blocked"
            | "unavailable"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported participant runlevel"))
    }
}

fn validate_self_capability_action(value: &str) -> Result<()> {
    if matches!(
        value,
        "observe" | "request" | "route" | "fulfill" | "retain" | "release" | "administer"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported self capability action"))
    }
}

fn validate_self_capability_status(value: &str) -> Result<()> {
    if matches!(
        value,
        "available" | "degraded" | "blocked" | "disabled" | "unknown"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported self capability status"))
    }
}

fn validate_posture_facet_state(value: &str) -> Result<()> {
    if matches!(
        value,
        "ready" | "notRequired" | "missing" | "blocked" | "degraded" | "unknown"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported posture facet state"))
    }
}

fn validate_resource_profile_class(value: &str) -> Result<()> {
    if matches!(
        value,
        "thinClient" | "balanced" | "offlineFirst" | "archiveNode" | "operatorDev" | "custom"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported resource profile class"))
    }
}

fn validate_resource_posture_state(value: &str) -> Result<()> {
    if matches!(
        value,
        "withinBudget" | "pressure" | "overBudget" | "sweeping" | "blocked" | "unavailable"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported resource posture state"))
    }
}

fn validate_event_plane(value: &str) -> Result<()> {
    if matches!(
        value,
        "authority"
            | "route"
            | "activation"
            | "projection"
            | "projectionRepair"
            | "retention"
            | "diagnostic"
            | "devBridge"
            | "loggingReplay"
            | "bulkRetainedData"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported event plane"))
    }
}

fn validate_event_admission_decision(value: &str) -> Result<()> {
    if matches!(value, "forward" | "drop" | "defer" | "summarize" | "reject") {
        Ok(())
    } else {
        Err(anyhow!("unsupported event admission decision"))
    }
}

fn validate_event_proof_requirement(value: &str) -> Result<()> {
    if matches!(
        value,
        "none" | "signature" | "authority" | "sealed" | "execution"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported event proof requirement"))
    }
}

fn validate_event_proof_state(value: &str) -> Result<()> {
    if matches!(value, "notRequired" | "pending" | "verified" | "failed") {
        Ok(())
    } else {
        Err(anyhow!("unsupported event proof state"))
    }
}

fn validate_event_delivery_mode(value: &str) -> Result<()> {
    if matches!(
        value,
        "push" | "pull" | "observe" | "replay" | "delta" | "summary"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported event delivery mode"))
    }
}

fn validate_event_backpressure_behavior(value: &str) -> Result<()> {
    if matches!(value, "drop" | "defer" | "summarize" | "reject" | "forward") {
        Ok(())
    } else {
        Err(anyhow!("unsupported event backpressure behavior"))
    }
}

fn validate_materialization_payload_class(value: &str) -> Result<()> {
    if matches!(
        value,
        "control" | "evidence" | "projection" | "retainedRaw" | "media" | "bulk"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported materialization payload class"))
    }
}

fn validate_materialization_copy_role(value: &str) -> Result<()> {
    if matches!(
        value,
        "transport"
            | "projection"
            | "cache"
            | "buffer"
            | "retention"
            | "debug"
            | "evidence"
            | "referenceOnly"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported materialization copy role"))
    }
}

fn validate_materialization_transfer_mode(value: &str) -> Result<()> {
    if matches!(
        value,
        "clone" | "transferable" | "shared" | "native" | "referenceOnly"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported materialization transfer mode"))
    }
}

fn validate_materialization_lag_state(value: &str) -> Result<()> {
    if matches!(
        value,
        "caughtUp" | "lagging" | "stale" | "blocked" | "unknown"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported materialization lag state"))
    }
}

fn validate_materialization_schema_state(value: &str) -> Result<()> {
    if matches!(
        value,
        "current" | "compatible" | "migrating" | "ignore" | "quarantined" | "blocked"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported materialization schema state"))
    }
}

fn validate_materialization_privacy_tier(value: &str) -> Result<()> {
    if matches!(
        value,
        "encryptedRaw"
            | "encryptedDetail"
            | "safeFacts"
            | "safeIndex"
            | "safeProjection"
            | "uiProjection"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported materialization privacy tier"))
    }
}

fn validate_log_severity(value: &str) -> Result<()> {
    if matches!(
        value,
        "debug" | "info" | "notice" | "warning" | "error" | "critical"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported event claimedSeverity"))
    }
}

fn validate_retention_release_state(value: &str) -> Result<()> {
    if matches!(value, "freeable" | "releaseBlocked") {
        Ok(())
    } else {
        Err(anyhow!("unsupported retention release state"))
    }
}

fn validate_media_fulfillment_evidence_kind(value: &str) -> Result<()> {
    if matches!(
        value,
        "transportState"
            | "selectedCandidatePair"
            | "inboundStats"
            | "trackState"
            | "renderState"
            | "release"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported media fulfillment evidence kind"))
    }
}

fn validate_media_fulfillment_state(value: &str) -> Result<()> {
    if matches!(value, "pending" | "usable" | "blocked" | "released") {
        Ok(())
    } else {
        Err(anyhow!("unsupported media fulfillment state"))
    }
}

fn validate_media_transport_path_state(value: &str) -> Result<()> {
    if matches!(value, "pending" | "actionable" | "blocked" | "released") {
        Ok(())
    } else {
        Err(anyhow!("unsupported media transport path state"))
    }
}

fn validate_media_transport_selected_pair_state(value: &str) -> Result<()> {
    if matches!(value, "pending" | "selected" | "failed" | "none") {
        Ok(())
    } else {
        Err(anyhow!("unsupported media transport selected pair state"))
    }
}

fn validate_media_transport_rtp_state(value: &str) -> Result<()> {
    if matches!(
        value,
        "pending" | "flowing" | "stalled" | "blocked" | "released"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported media transport RTP state"))
    }
}

fn validate_media_transport_render_state(value: &str) -> Result<()> {
    if matches!(value, "pending" | "visible" | "blocked" | "released") {
        Ok(())
    } else {
        Err(anyhow!("unsupported media transport render state"))
    }
}

fn validate_media_transport_participant_role(value: &str) -> Result<()> {
    if matches!(
        value,
        "browser" | "service" | "gateway" | "relay" | "turn" | "runtime"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported media transport participant role"))
    }
}

fn validate_media_transport_observation_state(value: &str) -> Result<()> {
    if matches!(
        value,
        "pending"
            | "connecting"
            | "connected"
            | "disconnected"
            | "recovering"
            | "failed"
            | "closed"
            | "released"
            | "blocked"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported media transport observation state"))
    }
}

fn validate_posture_facet(facet: &PostureFacet, context: &str) -> Result<()> {
    validate_posture_facet_state(&facet.state)?;
    if matches!(facet.state.as_str(), "missing" | "blocked" | "degraded")
        && facet
            .reason
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(anyhow!("{context} requires reason"));
    }
    for value in facet
        .evidence_refs
        .iter()
        .chain(facet.authority_refs.iter())
        .chain(facet.policy_refs.iter())
    {
        require_non_empty(value, &format!("{context} missing reference"))?;
    }
    Ok(())
}

fn validate_posture_facets(
    facets: &BTreeMap<String, PostureFacet>,
    required: &[&str],
    context: &str,
) -> Result<()> {
    for required_key in required {
        if !facets.contains_key(*required_key) {
            return Err(anyhow!("{context} missing {required_key} facet"));
        }
    }
    for (key, facet) in facets {
        require_non_empty(key, &format!("{context} missing facet name"))?;
        validate_posture_facet(facet, &format!("{context}.{key}"))?;
    }
    Ok(())
}

fn blocking_facet_reasons(facets: &BTreeMap<String, PostureFacet>) -> Vec<String> {
    facets
        .iter()
        .filter(|(_, facet)| matches!(facet.state.as_str(), "missing" | "blocked"))
        .map(|(name, facet)| {
            facet
                .reason
                .clone()
                .unwrap_or_else(|| format!("{name}.{}", facet.state))
        })
        .collect()
}

fn degraded_facet_reasons(facets: &BTreeMap<String, PostureFacet>) -> Vec<String> {
    facets
        .iter()
        .filter(|(_, facet)| facet.state == "degraded")
        .map(|(name, facet)| {
            facet
                .reason
                .clone()
                .unwrap_or_else(|| format!("{name}.degraded"))
        })
        .collect()
}

pub fn validate_participant_runlevel_posture(record: &ParticipantRunlevelPosture) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_PARTICIPANT_RUNLEVEL,
        "participant runlevel posture",
    )?;
    require_non_empty(
        &record.runlevel_id,
        "participant runlevel missing runlevelId",
    )?;
    validate_resolved_member_ref(
        &record.participant_ref,
        "participant runlevel missing participantRef",
    )?;
    require_non_empty(
        &record.participant_kind,
        "participant runlevel missing participantKind",
    )?;
    validate_participant_runlevel(&record.runlevel)?;
    validate_posture_facets(&record.facets, &[], "participant runlevel facets")?;
    if record.updated_at == 0 {
        return Err(anyhow!("participant runlevel missing updatedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.updated_at)
    {
        return Err(anyhow!(
            "participant runlevel expiresAt must be after updatedAt"
        ));
    }
    Ok(())
}

pub fn validate_self_capability_assessment(record: &SelfCapabilityAssessment) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_PARTICIPANT_SELF_CAPABILITY,
        "self capability assessment",
    )?;
    require_non_empty(
        &record.assessment_id,
        "self capability missing assessmentId",
    )?;
    validate_resolved_member_ref(
        &record.participant_ref,
        "self capability missing participantRef",
    )?;
    if let Some(service_member_ref) = &record.service_member_ref {
        if !service_member_ref.trim().is_empty() {
            validate_resolved_member_ref(
                service_member_ref,
                "self capability missing serviceMemberRef",
            )?;
        }
    }
    validate_capability_name(&record.capability_ref)?;
    require_non_empty_vec(&record.actions, "self capability missing actions")?;
    for action in &record.actions {
        validate_self_capability_action(action)?;
    }
    validate_self_capability_status(&record.status)?;
    validate_participant_runlevel(&record.runlevel)?;
    validate_posture_facets(
        &record.facets,
        &[
            "authority",
            "resource",
            "policy",
            "directory",
            "route",
            "adapter",
            "retention",
            "domain",
        ],
        "self capability facets",
    )?;
    let blocking_reasons = blocking_facet_reasons(&record.facets);
    let degraded_reasons = degraded_facet_reasons(&record.facets);
    if record.status == "available"
        && (!blocking_reasons.is_empty()
            || !degraded_reasons.is_empty()
            || !record.blocked_reasons.is_empty())
    {
        return Err(anyhow!(
            "available self capability cannot carry blocked or degraded posture"
        ));
    }
    if matches!(record.status.as_str(), "blocked" | "disabled")
        && blocking_reasons.is_empty()
        && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!("blocked self capability requires blocked reason"));
    }
    if record.status == "degraded" && !blocking_reasons.is_empty() {
        return Err(anyhow!(
            "degraded self capability cannot carry blocking posture"
        ));
    }
    if record.updated_at == 0 {
        return Err(anyhow!("self capability missing updatedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.updated_at)
    {
        return Err(anyhow!("self capability expiresAt must be after updatedAt"));
    }
    Ok(())
}

pub fn validate_resource_profile(record: &ResourceProfile) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_RESOURCE_PROFILE, "resource profile")?;
    require_non_empty(&record.profile_id, "resource profile missing profileId")?;
    validate_resource_profile_class(&record.profile_class)?;
    validate_safe_facts(&record.budgets, "resource profile budgets")?;
    validate_safe_facts(&record.caps, "resource profile caps")?;
    if record.issued_at == 0 {
        return Err(anyhow!("resource profile missing issuedAt"));
    }
    Ok(())
}

pub fn validate_resource_posture(record: &ResourcePosture) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_RESOURCE_POSTURE, "resource posture")?;
    require_non_empty(&record.posture_id, "resource posture missing postureId")?;
    require_non_empty(&record.profile_id, "resource posture missing profileId")?;
    validate_resource_posture_state(&record.state)?;
    validate_safe_facts(&record.counts, "resource posture counts")?;
    validate_safe_facts(&record.budgets, "resource posture budgets")?;
    if matches!(record.state.as_str(), "pressure" | "overBudget" | "blocked")
        && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "resource posture pressure states require blockedReasons"
        ));
    }
    if record.sampled_at == 0 {
        return Err(anyhow!("resource posture missing sampledAt"));
    }
    Ok(())
}

fn require_value_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("{context} missing {field}"))
}

pub fn validate_event_admission_envelope(record: &EventAdmissionEnvelope) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_EVENT_ADMISSION,
        "event admission envelope",
    )?;
    require_non_empty(&record.admission_id, "event admission missing admissionId")?;
    validate_event_plane(&record.plane)?;
    if let Some(lane_id) = &record.lane_id {
        require_non_empty(lane_id, "event admission missing laneId")?;
    }
    if let Some(subscription_id) = &record.subscription_id {
        require_non_empty(subscription_id, "event admission missing subscriptionId")?;
    }
    if let Some(publisher_ref) = &record.publisher_ref {
        require_non_empty(publisher_ref, "event admission missing publisherRef")?;
    }
    if let Some(subscriber_ref) = &record.subscriber_ref {
        require_non_empty(subscriber_ref, "event admission missing subscriberRef")?;
    }
    if !record.subject.is_object() {
        return Err(anyhow!("event admission subject must be an object"));
    }
    if !record.audience.is_object() {
        return Err(anyhow!("event admission audience must be an object"));
    }
    validate_safe_facts(&record.subject, "event admission subject")?;
    validate_safe_facts(&record.audience, "event admission audience")?;
    if let Some(severity) = &record.claimed_severity {
        validate_log_severity(severity)?;
    }
    validate_event_admission_decision(&record.decision)?;
    validate_event_proof_requirement(&record.proof_requirement)?;
    validate_event_proof_state(&record.proof_state)?;
    if matches!(
        record.decision.as_str(),
        "drop" | "defer" | "summarize" | "reject"
    ) && record
        .reason
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(anyhow!("event admission filtered decisions require reason"));
    }
    if record.proof_requirement == "none" && record.proof_state != "notRequired" {
        return Err(anyhow!(
            "event admission proofState must be notRequired when proofRequirement is none"
        ));
    }
    if record.proof_requirement != "none" && record.proof_state == "notRequired" {
        return Err(anyhow!(
            "event admission proofState cannot be notRequired when proof is required"
        ));
    }
    if record.decision == "forward" && record.proof_state == "failed" {
        return Err(anyhow!("event admission cannot forward failed proof"));
    }
    validate_safe_facts(&record.cost, "event admission cost")?;
    for evidence_ref in &record.evidence_refs {
        require_non_empty(evidence_ref, "event admission missing evidenceRef")?;
    }
    if record.observed_at == 0 {
        return Err(anyhow!("event admission missing observedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.observed_at)
    {
        return Err(anyhow!(
            "event admission expiresAt must be after observedAt"
        ));
    }
    if record.plane == "bulkRetainedData"
        && record.decision == "forward"
        && record
            .subscription_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(anyhow!(
            "event admission bulk retained data forward requires subscriptionId"
        ));
    }
    Ok(())
}

pub fn validate_subscription_contract(record: &SubscriptionContract) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_SUBSCRIPTION_CONTRACT,
        "subscription contract",
    )?;
    require_non_empty(
        &record.subscription_id,
        "subscription missing subscriptionId",
    )?;
    require_non_empty(&record.subscriber_ref, "subscription missing subscriberRef")?;
    if let Some(publisher_ref) = &record.publisher_ref {
        require_non_empty(publisher_ref, "subscription missing publisherRef")?;
    }
    if let Some(publisher_class) = &record.publisher_class {
        require_non_empty(publisher_class, "subscription missing publisherClass")?;
    }
    require_non_empty_vec(&record.planes, "subscription missing planes")?;
    let mut seen_planes = Vec::new();
    for plane in &record.planes {
        validate_event_plane(plane)?;
        if seen_planes.contains(plane) {
            return Err(anyhow!("subscription planes must be unique"));
        }
        seen_planes.push(plane.clone());
    }
    if !record.subject_selector.is_object() {
        return Err(anyhow!("subscription subjectSelector must be an object"));
    }
    if !record.audience.is_object() {
        return Err(anyhow!("subscription audience must be an object"));
    }
    if !record.proof.is_object() {
        return Err(anyhow!("subscription proof must be an object"));
    }
    if !record.delivery.is_object() {
        return Err(anyhow!("subscription delivery must be an object"));
    }
    if !record.backpressure.is_object() {
        return Err(anyhow!("subscription backpressure must be an object"));
    }
    validate_safe_facts(&record.subject_selector, "subscription subjectSelector")?;
    validate_safe_facts(&record.audience, "subscription audience")?;
    validate_safe_facts(&record.window, "subscription window")?;
    validate_safe_facts(&record.cost, "subscription cost")?;
    validate_safe_facts(&record.proof, "subscription proof")?;
    validate_event_proof_requirement(require_value_string(
        &record.proof,
        "requirement",
        "subscription proof",
    )?)?;
    validate_safe_facts(&record.delivery, "subscription delivery")?;
    validate_event_delivery_mode(require_value_string(
        &record.delivery,
        "mode",
        "subscription delivery",
    )?)?;
    validate_safe_facts(&record.backpressure, "subscription backpressure")?;
    validate_event_backpressure_behavior(require_value_string(
        &record.backpressure,
        "behavior",
        "subscription backpressure",
    )?)?;
    for capability_ref in &record.capability_refs {
        validate_capability_name(capability_ref)?;
    }
    for authority_ref in &record.authority_refs {
        require_non_empty(authority_ref, "subscription missing authorityRef")?;
    }
    if record.issued_at == 0 {
        return Err(anyhow!("subscription missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!("subscription expiresAt must be after issuedAt"));
    }
    Ok(())
}

fn validate_materialization_schema_posture(
    posture: &MaterializationSchemaPosture,
    context: &str,
) -> Result<()> {
    validate_materialization_schema_state(&posture.state)?;
    if matches!(posture.state.as_str(), "ignore" | "quarantined" | "blocked")
        && posture
            .reason
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(anyhow!("{context} schema state requires reason"));
    }
    for migration_ref in &posture.migration_refs {
        require_non_empty(migration_ref, "materialization schema missing migrationRef")?;
    }
    Ok(())
}

pub fn validate_consumer_floor(record: &ConsumerFloor) -> Result<()> {
    validate_optional_kind(&record.kind, RECORD_CONSUMER_FLOOR, "consumer floor")?;
    require_non_empty(&record.floor_id, "consumer floor missing floorId")?;
    require_non_empty(&record.consumer_ref, "consumer floor missing consumerRef")?;
    if let Some(subscription_id) = &record.subscription_id {
        require_non_empty(subscription_id, "consumer floor missing subscriptionId")?;
    }
    if let Some(materialization_id) = &record.materialization_id {
        require_non_empty(
            materialization_id,
            "consumer floor missing materializationId",
        )?;
    }
    if let Some(subject_ref) = &record.subject_ref {
        require_non_empty(subject_ref, "consumer floor missing subjectRef")?;
    }
    validate_materialization_lag_state(&record.lag_state)?;
    if matches!(record.lag_state.as_str(), "lagging" | "stale" | "blocked")
        && record
            .reason
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        return Err(anyhow!("consumer floor lag state requires reason"));
    }
    if record
        .event_time_floor
        .zip(record.observed_time_floor)
        .is_some_and(|(event_time, observed_time)| observed_time < event_time)
    {
        return Err(anyhow!(
            "consumer floor observedTimeFloor must not be before eventTimeFloor"
        ));
    }
    validate_safe_facts(&record.redelivery, "consumer floor redelivery")?;
    validate_safe_facts(&record.replay, "consumer floor replay")?;
    for evidence_ref in &record.evidence_refs {
        require_non_empty(evidence_ref, "consumer floor missing evidenceRef")?;
    }
    if record.sampled_at == 0 {
        return Err(anyhow!("consumer floor missing sampledAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.sampled_at)
    {
        return Err(anyhow!("consumer floor expiresAt must be after sampledAt"));
    }
    Ok(())
}

pub fn validate_materialization_budget(record: &MaterializationBudget) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_MATERIALIZATION_BUDGET,
        "materialization budget",
    )?;
    require_non_empty(&record.budget_id, "materialization budget missing budgetId")?;
    require_non_empty(
        &record.source_authority,
        "materialization budget missing sourceAuthority",
    )?;
    require_non_empty(
        &record.consumer_ref,
        "materialization budget missing consumerRef",
    )?;
    if let Some(subscriber_ref) = &record.subscriber_ref {
        require_non_empty(
            subscriber_ref,
            "materialization budget missing subscriberRef",
        )?;
    }
    validate_materialization_payload_class(&record.payload_class)?;
    validate_materialization_copy_role(&record.copy_role)?;
    validate_materialization_transfer_mode(&record.transfer_mode)?;
    if let Some(privacy_tier) = &record.privacy_tier {
        validate_materialization_privacy_tier(privacy_tier)?;
    }
    validate_resource_posture_state(&record.state)?;
    validate_safe_facts(&record.limits, "materialization budget limits")?;
    validate_safe_facts(
        &record.snapshot_policy,
        "materialization budget snapshotPolicy",
    )?;
    validate_safe_facts(&record.delta_policy, "materialization budget deltaPolicy")?;
    validate_safe_facts(&record.coalescing, "materialization budget coalescing")?;
    validate_safe_facts(&record.cardinality, "materialization budget cardinality")?;
    if let Some(schema) = &record.schema {
        validate_materialization_schema_posture(schema, "materialization budget")?;
    }
    if let Some(floor) = &record.consumer_floor {
        validate_consumer_floor(floor)?;
    }
    if matches!(record.state.as_str(), "pressure" | "overBudget" | "blocked")
        && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "materialization budget pressure states require blockedReasons"
        ));
    }
    if record.payload_class == "media" && record.transfer_mode == "clone" {
        return Err(anyhow!(
            "materialization budget media payload must not use clone transfer"
        ));
    }
    if record.payload_class == "retainedRaw" {
        let privacy_tier = record.privacy_tier.as_deref().unwrap_or_default();
        if !matches!(privacy_tier, "encryptedRaw" | "encryptedDetail") {
            return Err(anyhow!(
                "materialization budget retained raw payload requires encrypted privacy tier"
            ));
        }
    }
    if record.transfer_mode == "referenceOnly" && record.reference_refs.is_empty() {
        return Err(anyhow!(
            "materialization budget referenceOnly transfer requires referenceRefs"
        ));
    }
    for reference_ref in &record.reference_refs {
        require_non_empty(reference_ref, "materialization budget missing referenceRef")?;
    }
    for blocked_reason in &record.blocked_reasons {
        require_non_empty(
            blocked_reason,
            "materialization budget missing blockedReason",
        )?;
    }
    for evidence_ref in &record.evidence_refs {
        require_non_empty(evidence_ref, "materialization budget missing evidenceRef")?;
    }
    if let Some(retention_class) = &record.retention_class {
        require_non_empty(
            retention_class,
            "materialization budget missing retentionClass",
        )?;
    }
    if record.issued_at == 0 {
        return Err(anyhow!("materialization budget missing issuedAt"));
    }
    if record
        .release_after
        .is_some_and(|release_after| release_after < record.issued_at)
    {
        return Err(anyhow!(
            "materialization budget releaseAfter must not be before issuedAt"
        ));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "materialization budget expiresAt must be after issuedAt"
        ));
    }
    let value = serde_json::to_value(record)?;
    reject_media_byte_fields(&value, "materialization budget")?;
    Ok(())
}

pub fn validate_retention_release_posture(record: &RetentionReleasePosture) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_RETENTION_RELEASE,
        "retention release posture",
    )?;
    require_non_empty(
        &record.evaluation_id,
        "retention release missing evaluationId",
    )?;
    require_non_empty(&record.subject_ref, "retention release missing subjectRef")?;
    require_non_empty(
        &record.effective_retention,
        "retention release missing effectiveRetention",
    )?;
    validate_retention_release_state(&record.state)?;
    validate_reference_list(&record.policy_refs, "retention release policyRefs")?;
    validate_reference_list(&record.overlay_refs, "retention release overlayRefs")?;
    require_non_empty_vec(&record.owner_refs, "retention release missing ownerRefs")?;
    validate_reference_list(&record.holder_refs, "retention release holderRefs")?;
    validate_reference_list(
        &record.fulfillment_refs,
        "retention release fulfillmentRefs",
    )?;
    require_non_empty_vec(
        &record.residency_layers,
        "retention release missing residencyLayers",
    )?;
    validate_reference_list(&record.witness_refs, "retention release witnessRefs")?;
    validate_reference_list(
        &record.supersession_refs,
        "retention release supersessionRefs",
    )?;
    validate_reference_list(&record.retraction_refs, "retention release retractionRefs")?;
    validate_reference_list(&record.revocation_refs, "retention release revocationRefs")?;
    if record.state == "releaseBlocked" && record.blockers.is_empty() {
        return Err(anyhow!(
            "releaseBlocked retention posture requires blockers"
        ));
    }
    if record.state == "freeable" && !record.blockers.is_empty() {
        return Err(anyhow!("freeable retention posture cannot carry blockers"));
    }
    if record.evaluated_at == 0 {
        return Err(anyhow!("retention release missing evaluatedAt"));
    }
    if let (Some(valid_until), Some(release_after)) = (record.valid_until, record.release_after) {
        if release_after < valid_until {
            return Err(anyhow!(
                "retention release releaseAfter must not be before validUntil"
            ));
        }
    }
    Ok(())
}

pub fn validate_contribution_lifecycle(record: &ContributionLifecycle) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_CONTRIBUTION_LIFECYCLE,
        "contribution lifecycle",
    )?;
    require_non_empty(
        &record.contribution_id,
        "contribution lifecycle missing contributionId",
    )?;
    require_non_empty(
        &record.parent_ref,
        "contribution lifecycle missing parentRef",
    )?;
    require_non_empty(
        &record.subject_ref,
        "contribution lifecycle missing subjectRef",
    )?;
    require_non_empty(
        &record.writer_ref,
        "contribution lifecycle missing writerRef",
    )?;
    validate_contribution_type(&record.contribution_type)?;
    validate_contribution_state(&record.state)?;
    require_non_empty(&record.role, "contribution lifecycle missing role")?;
    require_non_empty_vec(
        &record.authority_refs,
        "contribution lifecycle missing authorityRefs",
    )?;
    if !record.scope.is_null() && !record.scope.is_object() {
        return Err(anyhow!("contribution lifecycle scope must be an object"));
    }
    for value in &record.supersedes {
        require_non_empty(
            value,
            "contribution lifecycle supersedes contains empty ref",
        )?;
    }
    for value in &record.witness_refs {
        require_non_empty(
            value,
            "contribution lifecycle witnessRefs contains empty ref",
        )?;
    }
    for value in &record.evidence_refs {
        require_non_empty(
            value,
            "contribution lifecycle evidenceRefs contains empty ref",
        )?;
    }
    for value in &record.blocked_reasons {
        require_non_empty(
            value,
            "contribution lifecycle blockedReasons contains empty ref",
        )?;
    }
    if record.issued_at == 0 {
        return Err(anyhow!("contribution lifecycle missing issuedAt"));
    }
    if record
        .valid_until
        .is_some_and(|valid_until| valid_until <= record.issued_at)
    {
        return Err(anyhow!(
            "contribution lifecycle validUntil must be after issuedAt"
        ));
    }
    if record
        .release_after
        .is_some_and(|release_after| release_after < record.issued_at)
    {
        return Err(anyhow!(
            "contribution lifecycle releaseAfter must not be before issuedAt"
        ));
    }
    if record
        .retracted_at
        .is_some_and(|retracted_at| retracted_at < record.issued_at)
    {
        return Err(anyhow!(
            "contribution lifecycle retractedAt must not be before issuedAt"
        ));
    }
    if matches!(
        record.contribution_type.as_str(),
        "witness" | "retraction" | "release"
    ) && record
        .target_contribution_ref
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        return Err(anyhow!(
            "contribution lifecycle {} requires targetContributionRef",
            record.contribution_type
        ));
    }
    if record.contribution_type == "witness" && record.observed_at.unwrap_or_default() == 0 {
        return Err(anyhow!(
            "contribution lifecycle witness requires observedAt"
        ));
    }
    if record.state == "witnessed" && record.witness_refs.is_empty() {
        return Err(anyhow!(
            "contribution lifecycle witnessed state requires witnessRefs"
        ));
    }
    if record.state == "retracted" && record.retracted_at.is_none() {
        return Err(anyhow!(
            "contribution lifecycle retracted state requires retractedAt"
        ));
    }
    if record.state == "blocked" && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "contribution lifecycle blocked state requires blockedReasons"
        ));
    }
    reject_media_byte_fields(&serde_json::to_value(record)?, "contribution lifecycle")
}

fn validate_contribution_type(value: &str) -> Result<()> {
    match value {
        "claim" | "promise" | "fulfillment" | "witness" | "retraction" | "release" | "expiry"
        | "observation" => Ok(()),
        _ => Err(anyhow!(
            "unsupported contribution lifecycle contributionType"
        )),
    }
}

fn validate_contribution_state(value: &str) -> Result<()> {
    match value {
        "active" | "witnessed" | "retracted" | "released" | "expired" | "blocked" => Ok(()),
        _ => Err(anyhow!("unsupported contribution lifecycle state")),
    }
}

pub fn validate_media_fulfillment_evidence(record: &MediaFulfillmentEvidence) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_MEDIA_FULFILLMENT_EVIDENCE,
        "media fulfillment evidence",
    )?;
    require_non_empty(
        &record.evidence_id,
        "media fulfillment evidence missing evidenceId",
    )?;
    validate_media_fulfillment_evidence_kind(&record.evidence_kind)?;
    validate_media_fulfillment_state(&record.state)?;
    let has_scope = [
        record.session_id.as_deref(),
        record.activation_id.as_deref(),
        record.interaction_id.as_deref(),
        record.correlation_id.as_deref(),
    ]
    .iter()
    .flatten()
    .any(|value| !value.trim().is_empty());
    if !has_scope {
        return Err(anyhow!(
            "media fulfillment evidence requires sessionId, activationId, interactionId, or correlationId"
        ));
    }
    for (value, field) in [
        (&record.route_promise_id, "routePromiseId"),
        (&record.participant_ref, "participantRef"),
        (&record.adapter_ref, "adapterRef"),
        (&record.service_ref, "serviceRef"),
        (&record.source_ref, "sourceRef"),
    ] {
        if let Some(value) = value {
            require_non_empty(
                value,
                &format!("media fulfillment evidence missing {field}"),
            )?;
        }
    }
    if record.state == "blocked"
        && record
            .blocked_reason
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(anyhow!(
            "blocked media fulfillment evidence requires blockedReason"
        ));
    }
    if record.state == "released" && record.evidence_kind != "release" {
        return Err(anyhow!(
            "released media fulfillment evidence must use release evidence kind"
        ));
    }
    validate_safe_facts(&record.safe_facts, "media fulfillment evidence safeFacts")?;
    if record.observed_at == 0 {
        return Err(anyhow!("media fulfillment evidence missing observedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.observed_at)
    {
        return Err(anyhow!(
            "media fulfillment evidence expiresAt must be after observedAt"
        ));
    }
    reject_media_byte_fields(&record.safe_facts, "media fulfillment evidence")?;
    Ok(())
}

pub fn validate_media_transport_path(record: &MediaTransportPath) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_MEDIA_TRANSPORT_PATH,
        "media transport path",
    )?;
    require_non_empty(&record.path_id, "media transport path missing pathId")?;
    require_non_empty(&record.session_id, "media transport path missing sessionId")?;
    require_non_empty(
        &record.transport_profile_ref,
        "media transport path missing transportProfileRef",
    )?;
    if let Some(activation_id) = &record.activation_id {
        require_non_empty(activation_id, "media transport path missing activationId")?;
    }
    if let Some(route_promise_id) = &record.route_promise_id {
        require_non_empty(
            route_promise_id,
            "media transport path missing routePromiseId",
        )?;
    }
    validate_media_transport_path_state(&record.state)?;
    validate_media_transport_selected_pair_state(&record.selected_pair_state)?;
    validate_media_transport_rtp_state(&record.inbound_rtp_state)?;
    validate_media_transport_render_state(&record.render_state)?;
    if record.state == "blocked"
        && record
            .blocked_reason
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(anyhow!(
            "blocked media transport path requires blockedReason"
        ));
    }
    for (refs, label) in [
        (&record.browser_candidate_refs, "browserCandidateRefs"),
        (&record.service_candidate_refs, "serviceCandidateRefs"),
        (&record.relay_participant_refs, "relayParticipantRefs"),
        (&record.turn_participant_refs, "turnParticipantRefs"),
        (&record.evidence_refs, "evidenceRefs"),
    ] {
        for value in refs {
            require_non_empty(value, &format!("media transport path missing {label}"))?;
        }
    }
    validate_safe_facts(&record.safe_facts, "media transport path safeFacts")?;
    if record.issued_at == 0 {
        return Err(anyhow!("media transport path missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "media transport path expiresAt must be after issuedAt"
        ));
    }
    reject_media_byte_fields(&serde_json::to_value(record)?, "media transport path")?;
    Ok(())
}

pub fn validate_media_transport_observation(record: &MediaTransportObservation) -> Result<()> {
    validate_optional_kind(
        &record.kind,
        RECORD_MEDIA_TRANSPORT_OBSERVATION,
        "media transport observation",
    )?;
    require_non_empty(
        &record.observation_id,
        "media transport observation missing observationId",
    )?;
    require_non_empty(
        &record.path_id,
        "media transport observation missing pathId",
    )?;
    require_non_empty(
        &record.session_id,
        "media transport observation missing sessionId",
    )?;
    if let Some(activation_id) = &record.activation_id {
        require_non_empty(
            activation_id,
            "media transport observation missing activationId",
        )?;
    }
    if let Some(route_promise_id) = &record.route_promise_id {
        require_non_empty(
            route_promise_id,
            "media transport observation missing routePromiseId",
        )?;
    }
    require_non_empty(
        &record.participant_ref,
        "media transport observation missing participantRef",
    )?;
    validate_media_transport_participant_role(&record.participant_role)?;
    validate_media_transport_observation_state(&record.state)?;
    if let Some(selected_pair_state) = &record.selected_pair_state {
        validate_media_transport_selected_pair_state(selected_pair_state)?;
    }
    if let Some(inbound_rtp_state) = &record.inbound_rtp_state {
        validate_media_transport_rtp_state(inbound_rtp_state)?;
    }
    if let Some(render_state) = &record.render_state {
        validate_media_transport_render_state(render_state)?;
    }
    if record.state == "blocked"
        && record
            .blocked_reason
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        return Err(anyhow!(
            "blocked media transport observation requires blockedReason"
        ));
    }
    for value in &record.evidence_refs {
        require_non_empty(value, "media transport observation missing evidenceRefs")?;
    }
    validate_safe_facts(&record.safe_facts, "media transport observation safeFacts")?;
    if record.observed_at == 0 {
        return Err(anyhow!("media transport observation missing observedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.observed_at)
    {
        return Err(anyhow!(
            "media transport observation expiresAt must be after observedAt"
        ));
    }
    reject_media_byte_fields(
        &serde_json::to_value(record)?,
        "media transport observation",
    )?;
    Ok(())
}

fn validate_safe_facts(value: &Value, context: &str) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    if !value.is_object() {
        return Err(anyhow!("{context} must be an object"));
    }
    reject_media_byte_fields(value, context)?;
    reject_unsafe_safe_fact_fields(value, context)
}

fn reject_unsafe_safe_fact_fields(value: &Value, context: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_unsafe_safe_fact_key(key) {
                    return Err(anyhow!("{context} contains unsafe safe fact: {key}"));
                }
                reject_unsafe_safe_fact_fields(child, context)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_unsafe_safe_fact_fields(item, context)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reject_private_content_fields(value: &Value, context: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_private_content_field(key) {
                    return Err(anyhow!(
                        "{context} contains forbidden private content field: {key}"
                    ));
                }
                reject_private_content_fields(child, context)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_private_content_fields(item, context)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_private_content_field(key: &str) -> bool {
    matches!(
        key,
        "plaintext"
            | "cleartext"
            | "body"
            | "payload"
            | "contents"
            | "content"
            | "value"
            | "ciphertext"
            | "sealedPayload"
            | "wrappedKey"
            | "key"
            | "secret"
            | "password"
            | "token"
            | "privateKey"
            | "secretKey"
    )
}

fn is_unsafe_safe_fact_key(key: &str) -> bool {
    matches!(
        key,
        "privateKey"
            | "secretKey"
            | "seed"
            | "mnemonic"
            | "password"
            | "credential"
            | "credentials"
            | "token"
            | "accessToken"
            | "refreshToken"
            | "authorization"
            | "cookie"
            | "sessionCookie"
            | "sdp"
            | "offerSdp"
            | "answerSdp"
            | "cameraUrl"
            | "servicePrivateUrl"
            | "rtspUrl"
            | "decryptedData"
    )
}

fn validate_private_refs(values: &[Value], context: &str) -> Result<()> {
    for value in values {
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("{context} entry must be an object"))?;
        require_non_empty(
            object
                .get("ref")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            &format!("{context} missing ref"),
        )?;
        if let Some(kind) = object.get("kind").and_then(Value::as_str) {
            require_non_empty(kind, &format!("{context} missing kind"))?;
        }
    }
    Ok(())
}

fn validate_freshness_value(value: &Value, context: &str, now: u64) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{context} freshness must be an object"))?;
    require_non_empty(
        object
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        &format!("{context} freshness missing state"),
    )?;
    if object
        .get("updatedAt")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        == 0
    {
        return Err(anyhow!("{context} freshness missing updatedAt"));
    }
    if object
        .get("expiresAt")
        .and_then(Value::as_u64)
        .map(|expires_at| expires_at <= now)
        .unwrap_or(false)
    {
        return Err(anyhow!("{context} expired"));
    }
    Ok(())
}

fn reject_activation_forbidden_fields(value: &Value, context: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if activation_forbidden_field(key) {
                    return Err(anyhow!(
                        "{context} contains forbidden protocol field: {key}"
                    ));
                }
                reject_activation_forbidden_fields(child, context)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_activation_forbidden_fields(item, context)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn activation_forbidden_field(key: &str) -> bool {
    matches!(
        key,
        "frameKind"
            | "recordKind"
            | "channelId"
            | "routeZone"
            | "zoneId"
            | "zoneScope"
            | "ttl"
            | "maxHops"
            | "capability"
            | "wireCapability"
            | "servicePk"
            | "gatewayPk"
            | "audience"
            | "audienceRefs"
            | "recipientPks"
            | "caacRecipients"
            | "serviceUrl"
            | "routeUrl"
    )
}

fn validate_route_failed_predicate(predicate: &str) -> Result<()> {
    if matches!(
        predicate,
        "zone"
            | "channel"
            | "capability"
            | "audience"
            | "ttlOrHopBudget"
            | "staleRouteLease"
            | "detachedMember"
            | "servicePolicy"
            | "participantRelease"
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported route failed predicate"))
    }
}

fn validate_stream_route_path(path: &StreamRoutePath) -> Result<()> {
    require_non_empty(&path.path_id, "stream route path missing pathId")?;
    for reference in &path.refs {
        require_non_empty(reference, "stream route path missing ref")?;
    }
    reject_media_byte_fields(&serde_json::to_value(path)?, "stream route path")
}

fn is_fixture_caac_placeholder(envelope: &Value) -> bool {
    let Some(object) = envelope.as_object() else {
        return false;
    };
    let placeholder_values = [
        object.get("envelopeId"),
        object.get("signature"),
        object.get("sealedPayload"),
        object.get("placeholder"),
        object.get("ciphertext"),
    ];
    if placeholder_values.into_iter().flatten().any(|value| {
        value
            .as_str()
            .map(is_fixture_caac_placeholder_value)
            .unwrap_or(false)
    }) {
        return true;
    }
    object.contains_key("envelopeId")
        && !object.contains_key("alg")
        && !object.contains_key("recipients")
        && !object.contains_key("signature")
}

fn is_fixture_caac_placeholder_value(value: &str) -> bool {
    matches!(
        value,
        "sealed-frame-placeholder"
            | "service-stream-placeholder"
            | "edge-hello-claims"
            | "edge-accept-claims"
            | "edge-resume-claims"
            | "edge-close-claims"
    )
}

fn frame_is_propagating(kind: &SwarmFrameKind) -> bool {
    matches!(
        kind,
        SwarmFrameKind::RecordPublish
            | SwarmFrameKind::RecordRetract
            | SwarmFrameKind::ChannelObserve
            | SwarmFrameKind::ChannelUnobserve
            | SwarmFrameKind::ProjectionSnapshot
            | SwarmFrameKind::ProjectionDelta
            | SwarmFrameKind::ProjectionRepairRequest
            | SwarmFrameKind::ServiceIntent
            | SwarmFrameKind::ServiceResponse
            | SwarmFrameKind::StreamIntent
            | SwarmFrameKind::StreamControl
            | SwarmFrameKind::StreamStatus
            | SwarmFrameKind::StoragePinIntent
            | SwarmFrameKind::StoragePinAttestation
            | SwarmFrameKind::NodeCapability
            | SwarmFrameKind::RuntimeActivationRequest
            | SwarmFrameKind::RoutePromise
            | SwarmFrameKind::RouteObservation
            | SwarmFrameKind::StreamRoutePlan
            | SwarmFrameKind::SwarmIdentity
            | SwarmFrameKind::SwarmDevice
            | SwarmFrameKind::SwarmGateway
            | SwarmFrameKind::SwarmService
            | SwarmFrameKind::SwarmMember
            | SwarmFrameKind::SwarmGrant
            | SwarmFrameKind::SwarmRole
            | SwarmFrameKind::SwarmInteraction
            | SwarmFrameKind::SwarmActivation
            | SwarmFrameKind::SwarmRelease
            | SwarmFrameKind::SwarmRevocation
            | SwarmFrameKind::ContributionLifecycle
    )
}

fn validate_record_ref(record_ref: &SwarmRecordRef) -> Result<()> {
    require_non_empty(&record_ref.kind, "record ref missing kind")?;
    require_non_empty(&record_ref.id, "record ref missing id")
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("string serializes"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serializes"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn require_non_empty(value: &str, message: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!(message.to_string()));
    }
    Ok(())
}

pub fn validate_resolved_member_ref(value: &str, message: &str) -> Result<()> {
    let text = value.trim();
    require_non_empty(text, message)?;
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("{message} must be a resolved public key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caac::seal_envelope_with_options;
    use crate::nostr::pubkey_from_sk_hex;
    use serde::Deserialize;
    use serde_json::json;

    const ISSUER_SK: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const GATEWAY_SK: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const SERVICE_SK: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const BROWSER_SK: &str = "0000000000000000000000000000000000000000000000000000000000000004";

    fn zone_scope() -> ZoneScope {
        ZoneScope {
            zone_id: "zone-raw-1".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(30),
            max_hops: Some(3),
        }
    }

    fn sealed_body() -> SwarmFrameBody {
        SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(json!({ "envelopeId": "env-1" })),
            public_bootstrap: false,
            payload: None,
            signature: None,
        }
    }

    fn valid_frame() -> SwarmFrame {
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::ServiceIntent,
            issuer: "actor-raw-1".to_string(),
            audience: json!({ "serviceRef": "service-raw-1" }),
            zone_scope: Some(zone_scope()),
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_000_100),
            nonce: "nonce-1".to_string(),
            correlation_id: Some("corr-1".to_string()),
            channel_id: Some("channel-raw-1".to_string()),
            record_ref: None,
            capability: Some(CAPABILITY_SERVICE_INTENT_INVOKE.to_string()),
            body: sealed_body(),
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    #[test]
    fn validates_valid_swarm_frame() {
        validate_swarm_frame(&valid_frame(), 1_700_000_001).expect("valid frame");
    }

    #[test]
    fn rejects_missing_zone_scope_for_propagating_frame() {
        let mut frame = valid_frame();
        frame.zone_scope = None;
        assert!(validate_swarm_frame(&frame, 1_700_000_001).is_err());
    }

    #[test]
    fn rejects_plaintext_body_where_caac_is_required() {
        let mut frame = valid_frame();
        frame.body = SwarmFrameBody {
            encoding: "plaintext".to_string(),
            envelope: None,
            public_bootstrap: false,
            payload: Some(json!({ "raw": true })),
            signature: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        assert!(validate_swarm_frame(&frame, 1_700_000_001).is_err());
    }

    #[test]
    fn rejects_swarm_frame_id_mismatch() {
        let mut frame = valid_frame();
        frame.frame_id = "bad-frame-id".to_string();
        assert!(validate_swarm_frame(&frame, 1_700_000_001).is_err());
    }

    #[test]
    fn rejects_invalid_capability_namespace() {
        assert!(validate_capability_name("Service.Intent.Invoke").is_err());
        assert!(validate_capability_name("service").is_err());
        assert!(validate_capability_name("service..invoke").is_err());
    }

    #[test]
    fn rejects_projection_delta_base_mismatch() {
        let delta = SwarmProjectionDelta {
            projection_id: "projection-1".to_string(),
            policy_id: "policy-1".to_string(),
            base_revision: 10,
            revision: 11,
            ops: vec![ProjectionDeltaOp {
                op: ProjectionDeltaOpKind::Set,
                path: vec![ProjectionPathSegment::Key("status".to_string())],
                value: Some(json!("ok")),
            }],
            affected_records: vec![],
            coverage: json!({}),
            freshness: json!({}),
            source_refs: vec!["service-raw-1".to_string()],
            issued_at: 1_700_000_001,
        };
        assert!(validate_projection_delta(&delta, 9).is_err());
        validate_projection_delta(&delta, 10).expect("matching base revision");
    }

    #[test]
    fn validates_channel_capability_pin_stream_and_recipe_records() {
        let channel = ChannelDescriptor {
            channel_id: "channel-raw-1".to_string(),
            kind: "service".to_string(),
            display_name: "Runtime edge".to_string(),
            capabilities: vec![
                CAPABILITY_SWARM_EDGE_ATTACH.to_string(),
                CAPABILITY_PROJECTION_OBSERVE.to_string(),
            ],
            record_kinds: vec![
                "capability.directoryEntry".to_string(),
                "projection.delta".to_string(),
            ],
            owner_refs: vec!["member-raw-1".to_string()],
            policy_ref: "policy-1".to_string(),
            created_at: 1_700_000_000,
            expires_at: None,
        };
        validate_channel_descriptor(&channel).expect("valid channel");

        let policy = ChannelPolicy {
            policy_id: "policy-1".to_string(),
            observe: vec!["role:observer".to_string()],
            write: vec!["role:writer".to_string()],
            set: vec!["role:writer".to_string()],
            invoke: vec!["role:writer".to_string()],
            pin: vec!["role:replicator".to_string()],
            attest: vec!["role:replicator".to_string()],
            run: vec!["role:runner".to_string()],
        };
        validate_channel_policy(&policy).expect("valid policy");

        let definition = CapabilityDefinition {
            capability: "vendor.camera.preview".to_string(),
            definition_id: "capability-def-1".to_string(),
            summary: "Preview stream.".to_string(),
            schema: json!({ "type": "object" }),
            authority_refs: vec!["member-raw-1".to_string()],
        };
        validate_capability_definition(&definition).expect("dynamic capability");

        let advertisement = CapabilityAdvertisement {
            advertisement_id: "ad-1".to_string(),
            capability: definition.capability.clone(),
            member_ref: Some(pubkey_from_sk_hex(BROWSER_SK).expect("browser pk")),
            service_ref: Some("service-raw-1".to_string()),
            channel_refs: vec![channel.channel_id.clone()],
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_000_100),
        };
        validate_capability_advertisement(&advertisement, 1_700_000_001)
            .expect("valid advertisement");

        let entries = vec![
            CapabilityDirectoryEntry {
                entry_id: "entry-b".to_string(),
                capability: definition.capability.clone(),
                channel_id: "channel-b".to_string(),
                member_ref: Some(pubkey_from_sk_hex(BROWSER_SK).expect("browser pk")),
                service_ref: None,
                priority: 20,
            },
            CapabilityDirectoryEntry {
                entry_id: "entry-a".to_string(),
                capability: definition.capability.clone(),
                channel_id: "channel-a".to_string(),
                member_ref: None,
                service_ref: Some("service-raw-1".to_string()),
                priority: 10,
            },
        ];
        for entry in &entries {
            validate_capability_directory_entry(entry).expect("valid entry");
        }
        let sorted = capability_entries_matching(&entries, &definition.capability);
        assert_eq!(sorted[0].channel_id, "channel-a");

        let pin = StoragePinIntent {
            intent_id: "pin-1".to_string(),
            object_refs: vec!["object-raw-1".to_string()],
            manifest_hash: "sha256:abc".to_string(),
            desired_replicas: 2,
            retention: "long".to_string(),
            authority_refs: vec!["authority-raw-1".to_string()],
            expires_at: Some(1_700_010_000),
        };
        validate_storage_pin_intent(&pin).expect("valid pin intent");
        let projection = storage_pin_projection_from_intent(&pin).expect("pin projection");
        assert_eq!(projection.status, StoragePinProjectionStatus::Pending);
        assert_eq!(projection.missing_replicas, 2);

        let availability = SwarmStorageAvailabilityRef {
            availability_id: "availability-1".to_string(),
            object_ref: "object-raw-1".to_string(),
            storage_member_ref: "storage-member-raw-1".to_string(),
            expires_at: Some(1_700_010_000),
        };
        let attestation = StoragePinAttestation {
            attestation_id: "attestation-1".to_string(),
            intent_id: pin.intent_id.clone(),
            storage_member_ref: "storage-member-raw-1".to_string(),
            accepted_refs: pin.object_refs.clone(),
            availability_refs: vec![availability],
            status: StoragePinStatus::Accepted,
            expires_at: Some(1_700_010_000),
            issued_at: 1_700_000_010,
        };
        let second_attestation = StoragePinAttestation {
            attestation_id: "attestation-2".to_string(),
            intent_id: pin.intent_id.clone(),
            storage_member_ref: "storage-member-raw-2".to_string(),
            accepted_refs: pin.object_refs.clone(),
            availability_refs: vec![SwarmStorageAvailabilityRef {
                availability_id: "availability-2".to_string(),
                object_ref: "object-raw-1".to_string(),
                storage_member_ref: "storage-member-raw-2".to_string(),
                expires_at: Some(1_700_010_000),
            }],
            status: StoragePinStatus::Pinned,
            expires_at: Some(1_700_010_000),
            issued_at: 1_700_000_011,
        };
        let expired_attestation = StoragePinAttestation {
            attestation_id: "attestation-expired".to_string(),
            intent_id: pin.intent_id.clone(),
            storage_member_ref: "storage-member-raw-3".to_string(),
            accepted_refs: pin.object_refs.clone(),
            availability_refs: vec![SwarmStorageAvailabilityRef {
                availability_id: "availability-expired".to_string(),
                object_ref: "object-raw-1".to_string(),
                storage_member_ref: "storage-member-raw-3".to_string(),
                expires_at: Some(2),
            }],
            status: StoragePinStatus::Pinned,
            expires_at: Some(2),
            issued_at: 1,
        };
        validate_storage_pin_attestation(&attestation).expect("valid attestation");
        validate_storage_pin_attestation(&second_attestation).expect("valid pinned attestation");
        let derived = storage_pin_projection_from_records(
            &pin,
            &[attestation, second_attestation, expired_attestation],
            1_700_000_011,
        )
        .expect("derived pin projection");
        assert_eq!(derived.pinned_count, 2);
        assert_eq!(derived.missing_replicas, 0);
        assert_eq!(derived.status, StoragePinProjectionStatus::Satisfied);
        assert!(
            !derived
                .members
                .contains(&"storage-member-raw-3".to_string())
        );

        let stream = StreamSessionIntent {
            session_id: "stream-1".to_string(),
            capability_ref: CAPABILITY_STREAM_SESSION_OFFER.to_string(),
            requester_ref: pubkey_from_sk_hex(BROWSER_SK).expect("browser pk"),
            channel_id: channel.channel_id,
            transport: "webrtc".to_string(),
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_000_500),
        };
        validate_stream_session_intent(&stream).expect("valid stream intent");
        let offer = StreamSessionOffer {
            offer_id: "offer-1".to_string(),
            session_id: stream.session_id.clone(),
            transport: "webrtc".to_string(),
            payload: json!({ "sdp": "opaque-offer" }),
            issued_at: 1_700_000_001,
        };
        validate_stream_session_offer(&offer).expect("valid stream offer");
        let mut bad_offer = offer.clone();
        bad_offer.payload = json!({ "blobBytes": "not allowed" });
        assert!(validate_stream_session_offer(&bad_offer).is_err());
        let answer = StreamSessionAnswer {
            answer_id: "answer-1".to_string(),
            session_id: stream.session_id.clone(),
            transport: "webrtc".to_string(),
            payload: json!({ "sdpRef": "encrypted-answer-detail-ref" }),
            issued_at: 1_700_000_002,
        };
        validate_stream_session_answer(&answer).expect("valid stream answer");
        let candidate = StreamSessionCandidate {
            candidate_id: "candidate-1".to_string(),
            session_id: stream.session_id.clone(),
            transport: "webrtc".to_string(),
            candidate_role: STREAM_CANDIDATE_ROLE_BROWSER.to_string(),
            actionability: STREAM_CANDIDATE_ACTIONABILITY_USABLE.to_string(),
            blocked_reason: None,
            endpoint: serde_json::json!({
                "protocol": "udp",
                "address": "192.0.2.10",
                "port": 5000,
                "candidateType": "host",
            }),
            payload: json!({ "candidateRef": "encrypted-candidate-detail-ref" }),
            issued_at: 1_700_000_003,
        };
        validate_stream_session_candidate(&candidate).expect("valid stream candidate");
        let mut blocked_candidate = candidate.clone();
        blocked_candidate.candidate_id = "candidate-2".to_string();
        blocked_candidate.actionability = STREAM_CANDIDATE_ACTIONABILITY_BLOCKED.to_string();
        blocked_candidate.blocked_reason = Some("missingCandidateEndpoint".to_string());
        validate_stream_session_candidate(&blocked_candidate).expect("blocked candidate");
        let mut bad_candidate = candidate;
        bad_candidate.candidate_id = "candidate-3".to_string();
        bad_candidate.endpoint =
            serde_json::json!({ "protocol": "udp", "address": "192.0.2.10", "port": 0 });
        assert!(validate_stream_session_candidate(&bad_candidate).is_err());
        let control = StreamSessionControl {
            control_id: "control-1".to_string(),
            session_id: stream.session_id.clone(),
            command: "pause".to_string(),
            params: json!({ "requestedBy": "operator" }),
            issued_at: 1_700_000_004,
        };
        validate_stream_session_control(&control).expect("valid stream control");
        let mut bad_control = control;
        bad_control.params = json!({ "rawBytes": "not allowed" });
        assert!(validate_stream_session_control(&bad_control).is_err());
        let health = StreamSessionHealth {
            health_id: "health-1".to_string(),
            session_id: stream.session_id.clone(),
            status: "ready".to_string(),
            recovery: json!({ "backoffMs": 0 }),
            issued_at: 1_700_000_004,
        };
        validate_stream_session_health(&health).expect("valid stream health");
        let mut bad_health = health;
        bad_health.recovery = json!({ "payloadBlobBytes": "not allowed" });
        assert!(validate_stream_session_health(&bad_health).is_err());
        let close = StreamSessionClose {
            close_id: "close-1".to_string(),
            session_id: stream.session_id.clone(),
            reason_code: "complete".to_string(),
            issued_at: 1_700_000_004,
        };
        validate_stream_session_close(&close).expect("valid stream close");
        let mut bad_answer = answer;
        bad_answer.payload = json!({ "mediaBytes": "not allowed" });
        assert!(validate_stream_session_answer(&bad_answer).is_err());

        let recipe = AppRecipe {
            recipe_id: "recipe-1".to_string(),
            version: "1.0.0".to_string(),
            required_capabilities: vec![CAPABILITY_APP_RUNNER_PIN.to_string()],
            required_channels: vec!["channel-a".to_string()],
            required_roles: vec!["runner".to_string()],
            entrypoint: "app://recipe-1".to_string(),
            issued_at: 1_700_000_000,
        };
        validate_app_recipe(&recipe).expect("valid recipe");
        let runner = AppRunnerAdvertisement {
            advertisement_id: "runner-ad-1".to_string(),
            runner_ref: "runner-raw-1".to_string(),
            capacity: 1,
            supported_versions: vec!["1.0.0".to_string()],
            health: "ready".to_string(),
            capability_refs: vec![CAPABILITY_APP_RUNNER_PIN.to_string()],
            issued_at: 1_700_000_001,
            expires_at: Some(1_700_000_500),
        };
        validate_app_runner_advertisement(&runner).expect("valid runner");
    }

    #[test]
    fn validates_participant_self_capability_resource_and_retention_posture() {
        let participant_ref = pubkey_from_sk_hex(BROWSER_SK).expect("browser pk");
        let service_member_ref = pubkey_from_sk_hex(GATEWAY_SK).expect("gateway pk");
        let facet = |state: &str, reason: Option<&str>| PostureFacet {
            state: state.to_string(),
            reason: reason.map(str::to_string),
            evidence_refs: vec![],
            authority_refs: vec![],
            policy_refs: vec![],
            updated_at: None,
        };

        let mut runlevel_facets = BTreeMap::new();
        runlevel_facets.insert("authority".to_string(), facet("ready", None));
        validate_participant_runlevel_posture(&ParticipantRunlevelPosture {
            kind: Some(RECORD_PARTICIPANT_RUNLEVEL.to_string()),
            runlevel_id: "runlevel-browser-1".to_string(),
            participant_ref: participant_ref.clone(),
            participant_kind: "browserRuntime".to_string(),
            runlevel: "routeReady".to_string(),
            facets: runlevel_facets,
            evidence_refs: vec![],
            authority_refs: vec![participant_ref.clone()],
            reason: None,
            updated_at: 1_700_000_001,
            expires_at: None,
        })
        .expect("valid runlevel posture");

        let advertisement = CapabilityAdvertisement {
            advertisement_id: "ad-preview".to_string(),
            capability: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
            member_ref: Some(service_member_ref.clone()),
            service_ref: None,
            channel_refs: vec!["nvr.streams".to_string()],
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_000_100),
        };
        validate_capability_advertisement(&advertisement, 1_700_000_001)
            .expect("valid advertisement");
        let ad_value = serde_json::to_value(&advertisement).expect("ad json");
        assert!(serde_json::from_value::<SelfCapabilityAssessment>(ad_value).is_err());

        let mut facets = BTreeMap::new();
        for key in [
            "authority",
            "resource",
            "policy",
            "directory",
            "route",
            "domain",
        ] {
            facets.insert(key.to_string(), facet("ready", None));
        }
        facets.insert("adapter".to_string(), facet("notRequired", None));
        facets.insert("retention".to_string(), facet("notRequired", None));

        validate_self_capability_assessment(&SelfCapabilityAssessment {
            kind: Some(RECORD_PARTICIPANT_SELF_CAPABILITY.to_string()),
            assessment_id: "self-cap-preview".to_string(),
            participant_ref: participant_ref.clone(),
            participant_kind: Some("browserRuntime".to_string()),
            service_ref: Some("service:nvr".to_string()),
            service_member_ref: Some(service_member_ref.clone()),
            subject_ref: Some("nvr.streams".to_string()),
            capability_ref: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
            actions: vec!["request".to_string()],
            status: "available".to_string(),
            runlevel: "routeReady".to_string(),
            facets: facets.clone(),
            blocked_reasons: vec![],
            evidence_refs: vec![],
            authority_refs: vec![participant_ref.clone()],
            policy_refs: vec![],
            updated_at: 1_700_000_002,
            expires_at: None,
        })
        .expect("valid self capability");

        let mut impossible_facets = facets.clone();
        impossible_facets.insert(
            "route".to_string(),
            facet("missing", Some("route baseline missing")),
        );
        assert!(
            validate_self_capability_assessment(&SelfCapabilityAssessment {
                kind: Some(RECORD_PARTICIPANT_SELF_CAPABILITY.to_string()),
                assessment_id: "self-cap-impossible".to_string(),
                participant_ref: participant_ref.clone(),
                participant_kind: Some("browserRuntime".to_string()),
                service_ref: None,
                service_member_ref: Some(service_member_ref.clone()),
                subject_ref: Some("nvr.streams".to_string()),
                capability_ref: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
                actions: vec!["request".to_string()],
                status: "available".to_string(),
                runlevel: "routeReady".to_string(),
                facets: impossible_facets,
                blocked_reasons: vec![],
                evidence_refs: vec![],
                authority_refs: vec![],
                policy_refs: vec![],
                updated_at: 1_700_000_003,
                expires_at: None,
            })
            .is_err()
        );

        validate_resource_profile(&ResourceProfile {
            kind: Some(RECORD_RESOURCE_PROFILE.to_string()),
            profile_id: "profile-balanced".to_string(),
            profile_class: "balanced".to_string(),
            budgets: json!({ "memoryMb": 2048 }),
            caps: json!({ "diagnostics": 300 }),
            owner_ref: Some("account:center".to_string()),
            issued_at: 1_700_000_004,
        })
        .expect("valid resource profile");
        assert!(
            validate_resource_posture(&ResourcePosture {
                kind: Some(RECORD_RESOURCE_POSTURE.to_string()),
                posture_id: "resource-bad".to_string(),
                profile_id: "profile-balanced".to_string(),
                state: "overBudget".to_string(),
                counts: json!({ "diagnostics": 400 }),
                budgets: json!({ "diagnostics": 300 }),
                blocked_reasons: vec![],
                sampled_at: 1_700_000_005,
            })
            .is_err()
        );

        validate_retention_release_posture(&RetentionReleasePosture {
            kind: Some(RECORD_RETENTION_RELEASE.to_string()),
            evaluation_id: "release-blocked".to_string(),
            subject_ref: "nvr:chunk:front:0".to_string(),
            effective_retention: "durable".to_string(),
            state: "releaseBlocked".to_string(),
            policy_refs: vec!["policy:nvr-media-retention".to_string()],
            overlay_refs: vec!["overlay:operator-hold".to_string()],
            owner_refs: vec!["identity:operator".to_string()],
            holder_refs: vec![participant_ref.clone()],
            fulfillment_refs: vec![],
            residency_layers: vec!["browserHotCache".to_string()],
            witness_refs: vec!["witness:runtime:observed".to_string()],
            supersession_refs: vec![],
            retraction_refs: vec![],
            revocation_refs: vec![],
            blockers: vec![json!({ "code": "missingFulfillment" })],
            valid_until: Some(1_700_000_010),
            release_after: Some(1_700_000_010),
            evaluated_at: 1_700_000_006,
        })
        .expect("valid retention release posture");

        let promise = ContributionLifecycle {
            kind: Some(RECORD_CONTRIBUTION_LIFECYCLE.to_string()),
            contribution_id: "contribution-route-promise-1".to_string(),
            parent_ref: "activation:preview-front".to_string(),
            subject_ref: "route-promise-preview-front".to_string(),
            writer_ref: service_member_ref.clone(),
            contribution_type: "promise".to_string(),
            state: "active".to_string(),
            role: "router".to_string(),
            authority_refs: vec!["grant:gateway-route".to_string()],
            scope: json!({ "channelId": "nvr.streams" }),
            target_contribution_ref: None,
            supersedes: vec![],
            witness_refs: vec![],
            evidence_refs: vec!["route:bound".to_string()],
            blocked_reasons: vec![],
            issued_at: 1_700_000_010,
            valid_until: Some(1_700_000_070),
            release_after: Some(1_700_000_071),
            retracted_at: None,
            observed_at: None,
        };
        validate_contribution_lifecycle(&promise).expect("valid contribution promise");

        validate_contribution_lifecycle(&ContributionLifecycle {
            kind: Some(RECORD_CONTRIBUTION_LIFECYCLE.to_string()),
            contribution_id: "witness-service-read-1".to_string(),
            parent_ref: "activation:preview-front".to_string(),
            subject_ref: "route-promise-preview-front".to_string(),
            writer_ref: participant_ref.clone(),
            contribution_type: "witness".to_string(),
            state: "witnessed".to_string(),
            role: "executor".to_string(),
            authority_refs: vec!["grant:nvr-service".to_string()],
            scope: Value::Null,
            target_contribution_ref: Some("contribution-route-promise-1".to_string()),
            supersedes: vec![],
            witness_refs: vec!["member-read:frame-1".to_string()],
            evidence_refs: vec!["service.accepted:frame-1".to_string()],
            blocked_reasons: vec![],
            issued_at: 1_700_000_020,
            valid_until: None,
            release_after: None,
            retracted_at: None,
            observed_at: Some(1_700_000_021),
        })
        .expect("valid contribution witness");

        let mut missing_target = promise.clone();
        missing_target.contribution_id = "bad-witness".to_string();
        missing_target.contribution_type = "witness".to_string();
        missing_target.observed_at = Some(1_700_000_022);
        assert!(validate_contribution_lifecycle(&missing_target).is_err());

        let mut bad_expiry = promise;
        bad_expiry.contribution_id = "bad-expiry".to_string();
        bad_expiry.valid_until = Some(bad_expiry.issued_at);
        assert!(validate_contribution_lifecycle(&bad_expiry).is_err());
    }

    #[test]
    fn validates_event_admission_and_subscription_contracts() {
        let browser_ref = pubkey_from_sk_hex(BROWSER_SK).expect("browser pk");
        validate_subscription_contract(&SubscriptionContract {
            kind: Some(RECORD_SUBSCRIPTION_CONTRACT.to_string()),
            subscription_id: "sub-runtime-diagnostics".to_string(),
            subscriber_ref: browser_ref.clone(),
            publisher_ref: None,
            publisher_class: Some("runtime".to_string()),
            planes: vec!["diagnostic".to_string(), "projection".to_string()],
            subject_selector: json!({ "channelRefs": ["runtime.diagnostics", "logging.events"] }),
            audience: json!({ "memberRef": browser_ref, "surface": "constitute-logging-ui" }),
            window: json!({ "since": 1_700_000_000u64, "replayLimit": 40 }),
            cost: json!({ "maxInFlight": 2, "maxEventsPerSecond": 8 }),
            proof: json!({ "requirement": "signature", "verifyBefore": "materialize" }),
            delivery: json!({ "mode": "observe" }),
            backpressure: json!({ "behavior": "summarize" }),
            capability_refs: vec![CAPABILITY_RUNTIME_DIAGNOSTICS_OBSERVE.to_string()],
            authority_refs: vec![],
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_000_300),
        })
        .expect("valid subscription contract");

        validate_event_admission_envelope(&EventAdmissionEnvelope {
            kind: Some(RECORD_EVENT_ADMISSION.to_string()),
            admission_id: "admit-runtime-diagnostic-1".to_string(),
            plane: "diagnostic".to_string(),
            lane_id: Some("lane-diagnostics".to_string()),
            subscription_id: Some("sub-runtime-diagnostics".to_string()),
            publisher_ref: Some("runtime:browser".to_string()),
            subscriber_ref: Some("constitute-logging-ui".to_string()),
            subject: json!({ "channelRef": "runtime.diagnostics", "kind": "projection.applied" }),
            audience: json!({ "surface": "constitute-logging-ui" }),
            claimed_severity: Some("error".to_string()),
            effective_priority: 70,
            decision: "summarize".to_string(),
            proof_requirement: "signature".to_string(),
            proof_state: "pending".to_string(),
            reason: Some("diagnostic lane pressure".to_string()),
            cost: json!({ "sizeBytes": 512 }),
            evidence_refs: vec![],
            observed_at: 1_700_000_001,
            expires_at: Some(1_700_000_061),
        })
        .expect("valid event admission envelope");

        assert!(
            validate_event_admission_envelope(&EventAdmissionEnvelope {
                kind: Some(RECORD_EVENT_ADMISSION.to_string()),
                admission_id: "bad-admission".to_string(),
                plane: "diagnostic".to_string(),
                lane_id: None,
                subscription_id: None,
                publisher_ref: None,
                subscriber_ref: None,
                subject: json!({ "channelRef": "runtime.diagnostics" }),
                audience: json!({ "surface": "constitute-logging-ui" }),
                claimed_severity: Some("critical".to_string()),
                effective_priority: 1,
                decision: "forward".to_string(),
                proof_requirement: "none".to_string(),
                proof_state: "pending".to_string(),
                reason: None,
                cost: Value::Null,
                evidence_refs: vec![],
                observed_at: 1_700_000_002,
                expires_at: None,
            })
            .is_err()
        );

        assert!(
            validate_subscription_contract(&SubscriptionContract {
                kind: Some(RECORD_SUBSCRIPTION_CONTRACT.to_string()),
                subscription_id: "bad-sub".to_string(),
                subscriber_ref: "constitute-logging-ui".to_string(),
                publisher_ref: None,
                publisher_class: None,
                planes: vec!["diagnostic".to_string()],
                subject_selector: json!({ "channelRefs": ["runtime.diagnostics"] }),
                audience: json!({ "surface": "constitute-logging-ui" }),
                window: Value::Null,
                cost: Value::Null,
                proof: json!({ "requirement": "signature" }),
                delivery: json!({ "mode": "replay" }),
                backpressure: json!({ "behavior": "retryForever" }),
                capability_refs: vec![],
                authority_refs: vec![],
                issued_at: 1_700_000_000,
                expires_at: None,
            })
            .is_err()
        );

        let floor = ConsumerFloor {
            kind: Some(RECORD_CONSUMER_FLOOR.to_string()),
            floor_id: "floor-logging-ui-events".to_string(),
            consumer_ref: "constitute-logging-ui".to_string(),
            subscription_id: Some("sub-runtime-diagnostics".to_string()),
            materialization_id: Some("budget-runtime-diagnostic-projection".to_string()),
            subject_ref: Some("runtime.diagnostics".to_string()),
            cursor: Some("runtime-event-40".to_string()),
            ack_floor: Some("runtime-event-39".to_string()),
            witness_floor: Some("projection-revision-12".to_string()),
            compaction_floor: Some("projection-revision-10".to_string()),
            event_time_floor: Some(1_700_000_000),
            observed_time_floor: Some(1_700_000_010),
            lag_state: "lagging".to_string(),
            reason: Some("consumer is behind the retained diagnostic cursor".to_string()),
            redelivery: json!({ "mode": "summary" }),
            replay: json!({ "maxEvents": 40 }),
            evidence_refs: vec![],
            sampled_at: 1_700_000_011,
            expires_at: Some(1_700_000_070),
        };
        validate_consumer_floor(&floor).expect("valid consumer floor");

        validate_materialization_budget(&MaterializationBudget {
            kind: Some(RECORD_MATERIALIZATION_BUDGET.to_string()),
            budget_id: "budget-runtime-diagnostic-projection".to_string(),
            source_authority: "runtime:browser".to_string(),
            consumer_ref: "constitute-logging-ui".to_string(),
            subscriber_ref: Some(pubkey_from_sk_hex(BROWSER_SK).expect("browser pk")),
            payload_class: "projection".to_string(),
            copy_role: "projection".to_string(),
            transfer_mode: "clone".to_string(),
            privacy_tier: Some("safeProjection".to_string()),
            state: "pressure".to_string(),
            limits: json!({ "maxEvents": 40, "maxBytes": 32768, "maxHighCardinalityLabels": 8 }),
            snapshot_policy: json!({ "mode": "baseline-repair" }),
            delta_policy: json!({ "mode": "preferred" }),
            coalescing: json!({ "key": "kind|channelRef|projectionKey" }),
            cardinality: json!({ "labelLimit": 8, "overflow": "detailRef" }),
            schema: Some(MaterializationSchemaPosture {
                state: "current".to_string(),
                version: Some("runtime.diagnostics.v1".to_string()),
                reason: None,
                migration_refs: vec![],
            }),
            consumer_floor: Some(floor),
            reference_refs: vec![],
            blocked_reasons: vec!["diagnosticLanePressure".to_string()],
            evidence_refs: vec![],
            retention_class: Some("short".to_string()),
            issued_at: 1_700_000_011,
            release_after: Some(1_700_000_070),
            expires_at: Some(1_700_000_300),
        })
        .expect("valid materialization budget");

        validate_materialization_budget(&MaterializationBudget {
            kind: Some(RECORD_MATERIALIZATION_BUDGET.to_string()),
            budget_id: "budget-encrypted-detail-ref".to_string(),
            source_authority: "logging:events".to_string(),
            consumer_ref: "constitute-security".to_string(),
            subscriber_ref: None,
            payload_class: "retainedRaw".to_string(),
            copy_role: "referenceOnly".to_string(),
            transfer_mode: "referenceOnly".to_string(),
            privacy_tier: Some("encryptedDetail".to_string()),
            state: "withinBudget".to_string(),
            limits: json!({ "maxRefs": 500 }),
            snapshot_policy: Value::Null,
            delta_policy: Value::Null,
            coalescing: Value::Null,
            cardinality: Value::Null,
            schema: None,
            consumer_floor: None,
            reference_refs: vec!["storage:object:encrypted-detail-1".to_string()],
            blocked_reasons: vec![],
            evidence_refs: vec![],
            retention_class: None,
            issued_at: 1_700_000_013,
            release_after: None,
            expires_at: None,
        })
        .expect("valid retained raw reference budget");

        assert!(
            validate_materialization_budget(&MaterializationBudget {
                kind: Some(RECORD_MATERIALIZATION_BUDGET.to_string()),
                budget_id: "budget-media-clone".to_string(),
                source_authority: "runtime:browser".to_string(),
                consumer_ref: "nvr-ui-video-element".to_string(),
                subscriber_ref: None,
                payload_class: "media".to_string(),
                copy_role: "debug".to_string(),
                transfer_mode: "clone".to_string(),
                privacy_tier: None,
                state: "withinBudget".to_string(),
                limits: Value::Null,
                snapshot_policy: Value::Null,
                delta_policy: Value::Null,
                coalescing: Value::Null,
                cardinality: Value::Null,
                schema: None,
                consumer_floor: None,
                reference_refs: vec![],
                blocked_reasons: vec![],
                evidence_refs: vec![],
                retention_class: None,
                issued_at: 1_700_000_012,
                release_after: None,
                expires_at: None,
            })
            .is_err()
        );
    }

    #[test]
    fn validates_convergence_contracts_and_negative_boundaries() {
        let vector_json =
            std::fs::read_to_string("vectors/swarm-runtime-v1.json").expect("golden vector");
        let vector: SwarmRuntimeVector =
            serde_json::from_str(&vector_json).expect("golden vector parses in Rust");
        let convergence = vector.convergence;

        validate_node_capability(&convergence.node_capability, 1_700_000_001)
            .expect("node capability");
        validate_runtime_activation_request(&convergence.activation_request)
            .expect("activation request");
        validate_route_promise(&convergence.route_promise).expect("route promise");
        validate_route_observation(&convergence.route_observation).expect("route observation");
        validate_stream_route_plan(&convergence.stream_route_plan).expect("stream route plan");
        validate_member_presence(&convergence.member_presence, 1_700_000_001)
            .expect("member presence");
        validate_directory_entry(&convergence.directory_entry).expect("directory entry");
        validate_bootstrap_carrier_record(&convergence.bootstrap_carrier)
            .expect("bootstrap carrier");

        let binding = LocalRouteBinding {
            binding_id: "binding-runtime-1".to_string(),
            promise_id: convergence.route_promise.promise_id.clone(),
            participant_ref: "member:browser:lab-1".to_string(),
            binding_kind: "runtimeQueue".to_string(),
            local_refs: json!({ "queueId": "queue-1" }),
            issued_at: 1_700_000_002,
        };
        validate_local_route_binding(&binding).expect("local route binding");

        let mut leaked_activation = convergence.activation_request.clone();
        leaked_activation.params = json!({ "zoneScope": { "zoneId": "zone_lab" } });
        assert!(validate_runtime_activation_request(&leaked_activation).is_err());

        let mut missing_audience = convergence.route_promise.clone();
        missing_audience.audience_refs.clear();
        assert!(validate_route_promise(&missing_audience).is_err());

        let missing_failure_predicate = RouteObservation {
            kind: Some(RECORD_ROUTE_OBSERVATION.to_string()),
            observation_id: "route-observation-bad".to_string(),
            state: RouteObservationState::ObservingUnreachable,
            frame_id: None,
            promise_id: Some(convergence.route_promise.promise_id.clone()),
            activation_id: None,
            delivered_to: vec![],
            failed_predicates: vec![],
            release_reason: None,
            diagnostics: json!({}),
            issued_at: 1_700_000_003,
        };
        assert!(validate_route_observation(&missing_failure_predicate).is_err());

        let mut bad_plan = convergence.stream_route_plan.clone();
        bad_plan.candidate_paths[0].diagnostics = json!({ "mediaBytes": "not allowed" });
        assert!(validate_stream_route_plan(&bad_plan).is_err());

        let mut bad_capability = convergence.node_capability;
        bad_capability.capability_ref = "Camera Preview".to_string();
        assert!(validate_node_capability(&bad_capability, 1_700_000_001).is_err());
    }

    #[test]
    fn validates_caac_mode_split() {
        let placeholder = json!({ "envelopeId": "sealed-frame-placeholder" });
        validate_caac_envelope_for_mode(&placeholder, CaacValidationMode::Structural, 0)
            .expect("structural placeholder");
        validate_caac_envelope_for_mode(&placeholder, CaacValidationMode::Fixture, 0)
            .expect("fixture placeholder");
        assert!(
            validate_caac_envelope_for_mode(&placeholder, CaacValidationMode::Product, 0).is_err()
        );

        let gateway_pk = pubkey_from_sk_hex(GATEWAY_SK).expect("gateway pk");
        let product = seal_envelope_with_options(
            "runtime.activation.request",
            &json!({ "activationId": "activation-preview-front" }),
            ISSUER_SK,
            &[gateway_pk],
            1_700_000_000,
            1_700_000_900,
            "product-caac-1".to_string(),
            vec!["000102030405060708090a0b0c0d0e0f1011121314151617".to_string()],
        )
        .expect("seal product envelope");
        let product_value = serde_json::to_value(&product).expect("product caac json");
        validate_caac_envelope_for_mode(&product_value, CaacValidationMode::Product, 1_700_000_001)
            .expect("product caac");
        assert!(
            validate_caac_envelope_for_mode(
                &product_value,
                CaacValidationMode::Product,
                1_700_000_901,
            )
            .is_err()
        );

        let mut missing_nonce = product_value.clone();
        missing_nonce["recipients"][0]["nonce"] = json!("");
        assert!(
            validate_caac_envelope_for_mode(
                &missing_nonce,
                CaacValidationMode::Product,
                1_700_000_001,
            )
            .is_err()
        );
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SwarmRuntimeVector {
        frame: SwarmFrame,
        delta: SwarmProjectionDelta,
        convergence: SwarmConvergenceVector,
        edge: SwarmEdgeVector,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SwarmConvergenceVector {
        node_capability: NodeCapability,
        activation_request: RuntimeActivationRequest,
        route_promise: RoutePromise,
        route_observation: RouteObservation,
        stream_route_plan: StreamRoutePlan,
        member_presence: MemberPresence,
        directory_entry: DirectoryEntry,
        bootstrap_carrier: BootstrapCarrierRecord,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SwarmEdgeVector {
        hello: SwarmEdgeHello,
        accept: SwarmEdgeAccept,
        resume: SwarmEdgeResume,
        close: SwarmEdgeClose,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SwarmAuthorityVector {
        identity: SwarmIdentityRecord,
        device: SwarmDeviceRecord,
        gateway_a: SwarmGatewayRecord,
        gateway_b: SwarmGatewayRecord,
        service: SwarmServiceRecord,
        runtime_member: SwarmMemberRecord,
        service_member: SwarmMemberRecord,
        storage_member: SwarmMemberRecord,
        identity_grant: SwarmGrantRecord,
        gateway_grant: SwarmGrantRecord,
        service_grant: SwarmGrantRecord,
        elevated_grant: SwarmGrantRecord,
        requester_role: SwarmRoleRecord,
        router_role: SwarmRoleRecord,
        executor_role: SwarmRoleRecord,
        interaction: SwarmInteractionRecord,
        activation: SwarmActivationRecord,
        release: SwarmReleaseRecord,
        revocation: SwarmRevocationRecord,
        identity_graph: Vec<Value>,
    }

    #[test]
    fn validates_swarm_authority_records_and_boundaries() {
        let vector_json =
            std::fs::read_to_string("vectors/swarm-authority-v1.json").expect("authority vector");
        let vector: SwarmAuthorityVector =
            serde_json::from_str(&vector_json).expect("authority vector parses in Rust");

        validate_swarm_identity(&vector.identity).expect("identity");
        validate_swarm_device(&vector.device).expect("device");
        validate_swarm_gateway(&vector.gateway_a).expect("gateway a");
        validate_swarm_gateway(&vector.gateway_b).expect("gateway b");
        validate_swarm_service(&vector.service).expect("service");
        validate_swarm_member(&vector.runtime_member).expect("runtime member");
        validate_swarm_member(&vector.service_member).expect("service member");
        validate_swarm_member(&vector.storage_member).expect("storage member");
        validate_swarm_grant(&vector.identity_grant).expect("identity grant");
        validate_swarm_grant(&vector.gateway_grant).expect("gateway grant");
        validate_swarm_grant(&vector.service_grant).expect("service grant");
        validate_swarm_grant(&vector.elevated_grant).expect("elevated grant");
        validate_swarm_role(&vector.requester_role).expect("requester role");
        validate_swarm_role(&vector.router_role).expect("router role");
        validate_swarm_role(&vector.executor_role).expect("executor role");
        validate_swarm_interaction(&vector.interaction).expect("interaction");
        validate_swarm_activation(&vector.activation).expect("activation");
        validate_swarm_release(&vector.release).expect("release");
        validate_swarm_revocation(&vector.revocation).expect("revocation");
        validate_swarm_identity_graph(&vector.identity_graph).expect("identity graph");

        let mut storage_claiming_authority = vector.storage_member.clone();
        storage_claiming_authority.storage = json!({
            "memberKind": "browserIndexedDbCache",
            "authorityDomain": "identity"
        });
        assert!(validate_swarm_member(&storage_claiming_authority).is_err());

        let mut route_as_root = vector.identity.clone();
        route_as_root
            .recovery_root_refs
            .push(route_as_root.recovery_route_refs[0].clone());
        assert!(validate_swarm_identity(&route_as_root).is_err());

        let mut weak_elevated_grant = vector.elevated_grant.clone();
        weak_elevated_grant.root_refs.clear();
        assert!(validate_swarm_grant(&weak_elevated_grant).is_err());

        let mut missing_coordinator = vector.interaction.clone();
        missing_coordinator
            .participants
            .retain(|participant| participant.role != "coordinator");
        assert!(validate_swarm_interaction(&missing_coordinator).is_err());

        let mut unsafe_interaction = vector.interaction.clone();
        unsafe_interaction.safe_facts = json!({ "privateKey": "secret" });
        assert!(validate_swarm_interaction(&unsafe_interaction).is_err());

        let mut live_graph = vector.identity_graph.clone();
        live_graph.push(serde_json::to_value(vector.activation).expect("activation json"));
        assert!(validate_swarm_identity_graph(&live_graph).is_err());
    }

    #[test]
    fn validates_agreement_authority_access_and_private_content_records() {
        let issuer_ref = format!(
            "identity:{}",
            pubkey_from_sk_hex(ISSUER_SK).expect("issuer pk")
        );
        let browser_member = format!(
            "member:{}",
            pubkey_from_sk_hex(BROWSER_SK).expect("browser pk")
        );
        let service_member = format!(
            "member:{}",
            pubkey_from_sk_hex(SERVICE_SK).expect("service pk")
        );

        let grant = ActionAuthorityGrantRecord {
            kind: Some(RECORD_AUTHORITY_ACTION_GRANT.to_string()),
            grant_id: "grant:logging:writer".to_string(),
            plane: Some(AGREEMENT_PLANE_ACTION_AUTHORITY.to_string()),
            issuer_ref: issuer_ref.clone(),
            subject_ref: browser_member.clone(),
            audience_refs: vec![service_member.clone()],
            authority_domain: "identity".to_string(),
            resource_ref: "contract:logging.default".to_string(),
            action: "logging.event.write".to_string(),
            state: Some(AGREEMENT_STATE_ACCEPTED.to_string()),
            scope: json!({ "contractRef": "contract:logging.default", "retentionClass": "rolling" }),
            capability_refs: vec![CAPABILITY_LOGGING_EVENTS_OBSERVE.to_string()],
            parent_grant_refs: vec!["grant:root:logging".to_string()],
            revocation_refs: vec![],
            evidence_refs: vec!["sig:grant:logging:writer".to_string()],
            elevated: false,
            root_refs: vec![],
            delegation: json!({ "allowed": true, "maxDepth": 1 }),
            blocked_reason: None,
            safe_facts: Value::Null,
            private_refs: vec![],
            issued_at: 1_700_000_010,
            expires_at: Some(1_700_000_610),
        };
        validate_action_authority_grant(&grant).expect("valid action grant");

        let mut wrong_plane = grant.clone();
        wrong_plane.plane = Some(AGREEMENT_PLANE_ACCESS_AUTHORITY.to_string());
        assert!(validate_action_authority_grant(&wrong_plane).is_err());

        let root_operation = AuthorityRootOperationRecord {
            kind: Some(RECORD_AUTHORITY_ROOT_OPERATION.to_string()),
            operation_id: "root-op:enroll-aux".to_string(),
            operation: "enrollDevice".to_string(),
            identity_ref: issuer_ref.clone(),
            actor_ref: format!("root:{}", pubkey_from_sk_hex(ISSUER_SK).expect("issuer pk")),
            target_ref: format!(
                "device:{}",
                pubkey_from_sk_hex(BROWSER_SK).expect("browser pk")
            ),
            admin_grant_refs: vec!["grant:root:admin".to_string()],
            root_refs: vec![],
            device_refs: vec![format!(
                "device:{}",
                pubkey_from_sk_hex(BROWSER_SK).expect("browser pk")
            )],
            notification_refs: vec!["notification:root-enroll".to_string()],
            evidence_refs: vec!["sig:root-op:enroll-aux".to_string()],
            state: AGREEMENT_STATE_APPLIED.to_string(),
            blocked_reason: None,
            safe_facts: Value::Null,
            issued_at: 1_700_000_030,
            expires_at: None,
        };
        validate_authority_root_operation(&root_operation).expect("valid root operation");

        let mut bad_root_rotation = root_operation.clone();
        bad_root_rotation.operation = "rotateRoot".to_string();
        bad_root_rotation.root_refs.clear();
        assert!(validate_authority_root_operation(&bad_root_rotation).is_err());

        let group = AccessGroupRecord {
            kind: Some(RECORD_ACCESS_GROUP.to_string()),
            group_id: "access-group:logging-secure".to_string(),
            owner_ref: issuer_ref.clone(),
            subject_ref: "contract:logging.default".to_string(),
            content_classes: vec![
                "encryptedDetail".to_string(),
                "diagnosticDetail".to_string(),
            ],
            member_refs: vec![service_member.clone(), browser_member.clone()],
            admin_refs: vec![format!(
                "root:{}",
                pubkey_from_sk_hex(ISSUER_SK).expect("issuer pk")
            )],
            current_epoch_id: "access-epoch:logging-secure:2".to_string(),
            partition_refs: vec!["partition:identity:logging".to_string()],
            policy_refs: vec![],
            safe_facts: Value::Null,
            issued_at: 1_700_000_040,
        };
        validate_access_group(&group).expect("valid access group");

        let epoch = AccessEpochRecord {
            kind: Some(RECORD_ACCESS_EPOCH.to_string()),
            epoch_id: "access-epoch:logging-secure:2".to_string(),
            group_id: group.group_id.clone(),
            sequence: 2,
            change_kind: "removeMember".to_string(),
            previous_epoch_id: Some("access-epoch:logging-secure:1".to_string()),
            member_refs: vec![service_member.clone()],
            added_member_refs: vec![],
            removed_member_refs: vec![browser_member.clone()],
            partition_refs: vec![],
            key_ref: "key-ref:logging-secure:2".to_string(),
            proof_refs: vec!["sig:epoch:2".to_string()],
            safe_facts: Value::Null,
            issued_at: 1_700_000_050,
            expires_at: None,
        };
        validate_access_epoch(&epoch).expect("valid access epoch");
        let mut bad_epoch = epoch.clone();
        bad_epoch.previous_epoch_id = None;
        assert!(validate_access_epoch(&bad_epoch).is_err());

        let envelope = PrivateContentEnvelopeRecord {
            kind: Some(RECORD_PRIVATE_CONTENT_ENVELOPE.to_string()),
            envelope_id: "private-envelope:logging-event-1".to_string(),
            content_class: "encryptedDetail".to_string(),
            access_group_ref: group.group_id.clone(),
            epoch_id: epoch.epoch_id.clone(),
            subject_ref: "event:runtime:1".to_string(),
            issuer_ref: service_member.clone(),
            ciphertext_ref: None,
            storage_object_ref: Some("storage-object:log-event-1".to_string()),
            detail_ref: None,
            media_object_ref: None,
            caac_envelope_ref: Some("caac:log-event-1".to_string()),
            recipient_refs: vec![service_member.clone()],
            key_ref: Some("key-ref:logging-secure:2".to_string()),
            summary_safe_facts: json!({ "eventClass": "runtimeDiagnostic", "severity": "warning" }),
            evidence_refs: vec!["storage:pin:log-event-1".to_string()],
            issued_at: 1_700_000_060,
            expires_at: None,
        };
        validate_private_content_envelope(&envelope).expect("valid private envelope");
        let mut bad_envelope = envelope.clone();
        bad_envelope.summary_safe_facts = json!({ "ciphertext": "raw-ciphertext-body" });
        assert!(validate_private_content_envelope(&bad_envelope).is_err());

        let event_class = EventFabricAccessClassRecord {
            kind: Some(RECORD_EVENT_FABRIC_ACCESS_CLASS.to_string()),
            class_id: "event-class:security-runtime".to_string(),
            content_class: "encryptedDetail".to_string(),
            privacy_tier: "domainEncrypted".to_string(),
            event_classes: vec!["runtimeDiagnostic".to_string(), "securityAudit".to_string()],
            access_group_refs: vec![group.group_id.clone()],
            processor_role_refs: vec!["role:logging".to_string(), "role:security".to_string()],
            storage_class: "storage:rolling-secure".to_string(),
            retention_class: "rolling".to_string(),
            safe_fact_policy: "indexOnly".to_string(),
            index_policy: json!({ "cardinality": "bounded", "safeKeys": ["eventClass", "severity"] }),
            safe_facts: Value::Null,
            issued_at: 1_700_000_070,
        };
        validate_event_fabric_access_class(&event_class).expect("valid event access class");
        let mut bad_event_class = event_class.clone();
        bad_event_class.privacy_tier = "publicSafe".to_string();
        assert!(validate_event_fabric_access_class(&bad_event_class).is_err());

        let processor_floor = ConsumerFloor {
            kind: Some(RECORD_CONSUMER_FLOOR.to_string()),
            floor_id: "consumer-floor:logging.processor".to_string(),
            consumer_ref: "role:logging.processor".to_string(),
            subscription_id: None,
            materialization_id: Some("event-fabric:logging-security".to_string()),
            subject_ref: Some("event-fabric:logging.default".to_string()),
            cursor: None,
            ack_floor: Some("event:9".to_string()),
            witness_floor: Some("event:8".to_string()),
            compaction_floor: Some("snapshot:1".to_string()),
            event_time_floor: None,
            observed_time_floor: Some(1_700_000_072),
            lag_state: "caughtUp".to_string(),
            reason: None,
            redelivery: json!({ "mode": "processorReplay" }),
            replay: json!({ "mode": "bitemporal" }),
            evidence_refs: vec!["evidence:consumer-floor".to_string()],
            sampled_at: 1_700_000_072,
            expires_at: Some(1_700_000_132),
        };
        let processor = EventFabricProcessorContractRecord {
            kind: Some(RECORD_EVENT_FABRIC_PROCESSOR_CONTRACT.to_string()),
            processor_contract_id: "processor-contract:logging.security-replay".to_string(),
            fabric_ref: "event-fabric:logging.default".to_string(),
            processor_ref: "service:logging".to_string(),
            processor_role_ref: "role:logging.processor".to_string(),
            state: "ready".to_string(),
            input_access_class_refs: vec![event_class.class_id.clone()],
            input_event_classes: event_class.event_classes.clone(),
            input_content_classes: vec!["encryptedDetail".to_string()],
            output_refs: vec![
                "projection:logging.dashboard".to_string(),
                "storage:logging.archive".to_string(),
            ],
            storage_refs: vec!["storage:logging.archive".to_string()],
            access_group_refs: vec![group.group_id.clone()],
            consumer_floor: Some(processor_floor),
            materialization_budget: None,
            bitemporal_policy: json!({
                "eventTimeField": "occurredAt",
                "observedTimeField": "observedAt"
            }),
            schema_policy: json!({
                "currentVersion": "logging.event.v1",
                "unknownVersionPosture": "ignore"
            }),
            compaction_policy: json!({
                "snapshotCadence": "bounded",
                "compactionFloor": "snapshot:1"
            }),
            cardinality_policy: json!({
                "maxLabelValues": 1000,
                "highCardinalityOverflow": "encryptedDetailRef"
            }),
            encrypted_detail_custody: json!({
                "state": "referenceOnly",
                "accessGroupRefs": [group.group_id.clone()]
            }),
            sampling_policy: json!({
                "state": "adaptive",
                "degradeBefore": ["authority", "route", "activation"]
            }),
            safe_facts: Value::Null,
            evidence_refs: vec!["evidence:processor-contract".to_string()],
            blocked_reasons: Vec::new(),
            issued_at: 1_700_000_073,
            expires_at: Some(1_700_000_433),
        };
        validate_event_fabric_processor_contract(&processor)
            .expect("valid event fabric processor contract");
        let mut bad_processor = processor.clone();
        bad_processor.processor_contract_id = "processor-contract:blocked".to_string();
        bad_processor.state = "blocked".to_string();
        assert!(validate_event_fabric_processor_contract(&bad_processor).is_err());

        let security_seed = SecurityProcessorSeedRecord {
            kind: Some(RECORD_SECURITY_PROCESSOR_SEED.to_string()),
            seed_id: "security-seed:logging.default".to_string(),
            fabric_ref: "event-fabric:logging.default".to_string(),
            processor_ref: "constitute-security".to_string(),
            processor_role_ref: "role:security.processor".to_string(),
            state: "ready".to_string(),
            threat_analysis_role: "eventFabricThreatAnalysis".to_string(),
            input_access_class_refs: vec![event_class.class_id.clone()],
            input_event_classes: event_class.event_classes.clone(),
            input_content_classes: vec!["encryptedDetail".to_string()],
            access_group_refs: vec![group.group_id.clone()],
            processor_contract_refs: vec![processor.processor_contract_id.clone()],
            evidence_profile_refs: vec!["logging.security.default".to_string()],
            materialization_budget_refs: vec!["logging.security.default.90d".to_string()],
            storage_refs: vec!["storage:logging.archive".to_string()],
            detail_refs: vec!["encrypted-detail:logging.default".to_string()],
            alert_output_refs: vec!["security:alerts".to_string()],
            evidence_hold_refs: vec!["security:evidence-hold".to_string()],
            retention_hold_refs: vec!["retention:security-hold".to_string()],
            encrypted_detail_custody: json!({
                "state": "referenceOnly",
                "accessGroupRefs": [group.group_id.clone()]
            }),
            semantic_boundaries: json!({
                "logging": "mayConsumeMaterializations",
                "storage": "ciphertextFulfillmentOnly",
                "eventDomain": "doesNotOwn"
            }),
            safe_facts: json!({
                "purpose": "securityThreatAnalysis",
                "detailCustody": "encryptedDetailRef"
            }),
            evidence_refs: vec!["evidence:security-seed".to_string()],
            blocked_reasons: Vec::new(),
            issued_at: 1_700_000_074,
            expires_at: Some(1_707_776_074),
        };
        validate_security_processor_seed(&security_seed).expect("valid security processor seed");
        let mut bad_seed = security_seed.clone();
        bad_seed.state = "blocked".to_string();
        assert!(validate_security_processor_seed(&bad_seed).is_err());
        let mut missing_boundary = security_seed;
        missing_boundary.semantic_boundaries = json!({ "logging": "mayConsumeMaterializations" });
        assert!(validate_security_processor_seed(&missing_boundary).is_err());

        let revocation = AuthorityGrantRevocationPostureRecord {
            kind: Some(RECORD_AUTHORITY_GRANT_REVOCATION_POSTURE.to_string()),
            revocation_id: "revocation:logging:writer".to_string(),
            target_grant_ref: grant.grant_id.clone(),
            issuer_ref: issuer_ref.clone(),
            authority_domain: "identity".to_string(),
            affected_grant_refs: vec![
                "grant:logging:writer".to_string(),
                "grant:logging:writer:delegated".to_string(),
            ],
            affected_access_group_refs: vec![group.group_id.clone()],
            inherited_scope_refs: vec!["contract:logging.default".to_string()],
            state: AGREEMENT_STATE_REVOKED.to_string(),
            reason_code: "operatorRevoked".to_string(),
            evidence_refs: vec!["sig:revocation:logging:writer".to_string()],
            issued_at: 1_700_000_080,
            effective_at: Some(1_700_000_081),
        };
        validate_authority_grant_revocation_posture(&revocation)
            .expect("valid grant revocation posture");

        let proof = AuthorityMultiIdentityProofRecord {
            kind: Some(RECORD_AUTHORITY_MULTI_IDENTITY_PROOF.to_string()),
            proof_id: "authority-proof:aux-to-agent:full-access".to_string(),
            owner_identity_ref: "identity:aux".to_string(),
            grantee_identity_ref: "identity:agent-dev".to_string(),
            grantee_member_ref: browser_member.clone(),
            subject_refs: vec![
                "contract:gateway.default".to_string(),
                "contract:logging.default".to_string(),
                "contract:nvr.streams".to_string(),
            ],
            action_grant_refs: vec![grant.grant_id.clone()],
            access_group_refs: vec![group.group_id.clone()],
            access_epoch_refs: vec![epoch.epoch_id.clone()],
            private_envelope_refs: vec![envelope.envelope_id.clone()],
            revocation_refs: vec![revocation.revocation_id.clone()],
            checks: vec![
                AuthorityProofCheck {
                    check: AUTHORITY_PROOF_CHECK_SYNC.to_string(),
                    plane: AGREEMENT_PLANE_DELIVERY_WITNESS.to_string(),
                    state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                    target_ref: "contract:gateway.default".to_string(),
                    grant_refs: vec![grant.grant_id.clone()],
                    access_group_refs: vec![],
                    access_epoch_refs: vec![],
                    exercise_refs: vec![],
                    evidence_refs: vec!["witness:gateway:agent-sync".to_string()],
                    blocked_reason: None,
                    expires_at: None,
                },
                AuthorityProofCheck {
                    check: AUTHORITY_PROOF_CHECK_READ.to_string(),
                    plane: AGREEMENT_PLANE_ACCESS_AUTHORITY.to_string(),
                    state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                    target_ref: "event-fabric:logging.default".to_string(),
                    grant_refs: vec![],
                    access_group_refs: vec![group.group_id.clone()],
                    access_epoch_refs: vec![epoch.epoch_id.clone()],
                    exercise_refs: vec![],
                    evidence_refs: vec!["proof:caac-open:agent-dev".to_string()],
                    blocked_reason: None,
                    expires_at: None,
                },
                AuthorityProofCheck {
                    check: AUTHORITY_PROOF_CHECK_WRITE_REDUCE.to_string(),
                    plane: AGREEMENT_PLANE_ACTION_AUTHORITY.to_string(),
                    state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                    target_ref: "contract:logging.default".to_string(),
                    grant_refs: vec![grant.grant_id.clone()],
                    access_group_refs: vec![],
                    access_epoch_refs: vec![],
                    exercise_refs: vec!["exercise:logging:agent-writer:1".to_string()],
                    evidence_refs: vec!["event:logging:agent-test".to_string()],
                    blocked_reason: None,
                    expires_at: None,
                },
                AuthorityProofCheck {
                    check: AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE.to_string(),
                    plane: AGREEMENT_PLANE_ACTION_AUTHORITY.to_string(),
                    state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                    target_ref: grant.grant_id.clone(),
                    grant_refs: vec![grant.grant_id.clone()],
                    access_group_refs: vec![],
                    access_epoch_refs: vec![],
                    exercise_refs: vec![],
                    evidence_refs: vec![revocation.revocation_id.clone()],
                    blocked_reason: None,
                    expires_at: Some(1_700_000_610),
                },
            ],
            state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
            blocked_reasons: vec![],
            evidence_refs: vec!["proof:multi-identity:agent-dev".to_string()],
            safe_facts: json!({ "proofClass": "multiIdentityFullAccess" }),
            issued_at: 1_700_000_090,
            expires_at: Some(1_700_000_610),
        };
        validate_authority_multi_identity_proof(&proof)
            .expect("valid multi-identity authority proof");
        let mut missing_sync = proof.clone();
        missing_sync
            .checks
            .retain(|check| check.check != AUTHORITY_PROOF_CHECK_SYNC);
        assert!(validate_authority_multi_identity_proof(&missing_sync).is_err());
        let mut wrong_read = proof.clone();
        wrong_read.checks[1].access_group_refs.clear();
        assert!(validate_authority_multi_identity_proof(&wrong_read).is_err());
        let mut wrong_write_plane = proof.clone();
        wrong_write_plane.checks[2].plane = AGREEMENT_PLANE_ACCESS_AUTHORITY.to_string();
        assert!(validate_authority_multi_identity_proof(&wrong_write_plane).is_err());
    }

    #[test]
    fn validates_service_manager_protected_bootstrap_contracts() {
        let secret_boundary = ServiceManagerSecretBoundaryRecord {
            kind: Some(RECORD_SERVICE_MANAGER_SECRET_BOUNDARY.to_string()),
            boundary_id: "secret-boundary:lab-gateway".to_string(),
            manager_id: "manager:lab-gateway".to_string(),
            subject_ref: "service:gateway".to_string(),
            state: SURFACE_SECRET_BOUNDARY_RESOLVED.to_string(),
            secret_refs: vec!["secret:gateway-lab".to_string()],
            access_group_refs: vec!["access:ops:epoch-7".to_string()],
            authority_refs: vec!["authority:ops-admin".to_string()],
            evidence_refs: vec!["evidence:secret-resolution".to_string()],
            blocked_reasons: vec![],
            safe_facts: json!({ "posture": "resolved" }),
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_003_600),
        };
        validate_service_manager_secret_boundary(&secret_boundary).expect("valid secret boundary");

        let release_contract = ServiceManagerReleaseContractRecord {
            kind: Some(RECORD_SERVICE_MANAGER_RELEASE_CONTRACT.to_string()),
            contract_id: "release-contract:gateway:2026-05-18".to_string(),
            manager_id: "manager:lab-gateway".to_string(),
            subject_ref: "service:gateway".to_string(),
            manager_ref: "member:gateway-manager".to_string(),
            state: SURFACE_APP_CONTRACT_STATE_READY.to_string(),
            app_contract_ref: Some("surface-app:gateway-ui@0.1.0".to_string()),
            version: Some("2026.05.18".to_string()),
            build_ref: Some("build:gateway:2026-05-18".to_string()),
            release_ref: Some("release:gateway:2026-05-18".to_string()),
            rollback_ref: Some("rollback:gateway:previous".to_string()),
            rollback_required: None,
            compatibility_refs: vec!["protocol:surface-app:v1".to_string()],
            authority_refs: vec!["authority:ops-admin".to_string()],
            secret_boundary_refs: vec![secret_boundary.boundary_id.clone()],
            proof_digest_refs: vec![],
            lab_proof_refs: vec!["lab-proof:gateway:surface-landscape".to_string()],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            safe_facts: json!({ "compatibility": "current" }),
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_007_200),
        };
        validate_service_manager_release_contract(&release_contract)
            .expect("valid release contract");

        let lab_proof = ServiceManagerLabProofRecord {
            kind: Some(RECORD_SERVICE_MANAGER_LAB_PROOF.to_string()),
            proof_id: "lab-proof:gateway:surface-landscape".to_string(),
            manager_id: "manager:lab-gateway".to_string(),
            subject_ref: "service:gateway".to_string(),
            profile: "surfaceLandscape".to_string(),
            state: SERVICE_MANAGER_PROOF_STATE_PROVED.to_string(),
            train_ref: Some("train:surface-bootstrap:2026-05-18".to_string()),
            release_contract_ref: Some(release_contract.contract_id.clone()),
            app_contract_ref: Some("surface-app:gateway-ui@0.1.0".to_string()),
            surface_refs: vec![
                "surface:account".to_string(),
                "surface:gateway-ui".to_string(),
            ],
            service_refs: vec!["service:gateway".to_string()],
            environment_refs: vec!["env:lab".to_string()],
            artifact_refs: vec!["artifact:proof:surface-landscape".to_string()],
            metrics_refs: vec!["metrics:proof:surface-landscape".to_string()],
            proof_refs: vec!["proof:surface-landscape:pass".to_string()],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            safe_facts: json!({ "profile": "surfaceLandscape", "verdict": "passed" }),
            started_at: 1_700_000_010,
            accepted_at: None,
            completed_at: Some(1_700_000_610),
            observed_at: Some(1_700_000_620),
            expires_at: Some(1_700_007_200),
        };
        validate_service_manager_lab_proof(&lab_proof).expect("valid lab proof");

        let train_digest = ServiceManagerTrainDigestRecord {
            kind: Some(RECORD_SERVICE_MANAGER_TRAIN_DIGEST.to_string()),
            train_id: "train:surface-bootstrap:2026-05-18".to_string(),
            manager_id: "manager:lab-gateway".to_string(),
            subject_ref: "service:gateway".to_string(),
            state: SERVICE_MANAGER_PROOF_STATE_PROVED.to_string(),
            repo_refs: vec!["repo:constitute-gateway-ui".to_string()],
            commit_refs: vec!["git:gateway-ui:275e05b".to_string()],
            app_contract_refs: vec!["surface-app:gateway-ui@0.1.0".to_string()],
            release_contract_refs: vec![release_contract.contract_id.clone()],
            operation_refs: vec![],
            proof_digest_refs: vec![],
            lab_proof_refs: vec![lab_proof.proof_id.clone()],
            metrics_refs: vec!["metrics:spine:service-bootstrap".to_string()],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            safe_facts: Value::Null,
            observed_at: 1_700_000_630,
            expires_at: Some(1_700_007_200),
        };
        validate_service_manager_train_digest(&train_digest).expect("valid train digest");

        let bootstrap_contract = SurfaceAppBootstrapContractRecord {
            kind: Some(RECORD_SURFACE_APP_BOOTSTRAP_CONTRACT.to_string()),
            bootstrap_contract_id: "bootstrap-contract:gateway-ui".to_string(),
            app_contract_ref: "surface-app:gateway-ui@0.1.0".to_string(),
            app_id: "constitute-gateway-ui".to_string(),
            state: SURFACE_APP_CONTRACT_STATE_READY.to_string(),
            source_mode: SURFACE_FULFILLMENT_MODE_SWARM_PACKAGE.to_string(),
            module_refs: vec![
                "module:surface-runtime-client@0.1.0".to_string(),
                "module:gateway-view@0.1.0".to_string(),
            ],
            service_manager_ref: Some("manager:lab-gateway".to_string()),
            release_contract_ref: Some(release_contract.contract_id.clone()),
            secret_boundary_ref: Some(secret_boundary.boundary_id),
            train_digest_ref: Some(train_digest.train_id),
            lab_proof_profile_refs: vec!["surfaceLandscape".to_string()],
            authority_refs: vec!["authority:ops-admin".to_string()],
            evidence_refs: vec!["evidence:bootstrap-resolution".to_string()],
            blocked_reasons: vec![],
            safe_facts: Value::Null,
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_007_200),
        };
        validate_surface_app_bootstrap_contract(&bootstrap_contract)
            .expect("valid bootstrap contract");

        let mut bad_release = release_contract;
        bad_release.rollback_ref = None;
        assert!(validate_service_manager_release_contract(&bad_release).is_err());

        let mut bad_proof = lab_proof;
        bad_proof.artifact_refs.clear();
        bad_proof.metrics_refs.clear();
        bad_proof.proof_refs.clear();
        assert!(validate_service_manager_lab_proof(&bad_proof).is_err());

        let mut bad_bootstrap = bootstrap_contract;
        bad_bootstrap.release_contract_ref = None;
        assert!(validate_surface_app_bootstrap_contract(&bad_bootstrap).is_err());
    }

    #[test]
    fn validates_surface_app_manifest_version_pins() {
        let manifest = SurfaceAppManifestRecord {
            kind: Some(RECORD_SURFACE_APP_MANIFEST.to_string()),
            manifest_id: "surface-app-manifest:nvr-ui".to_string(),
            app_id: "constitute-nvr-ui".to_string(),
            state: Some(SURFACE_APP_MANIFEST_VERSION_CURRENT.to_string()),
            current_app_contract_ref: "surface-app:nvr-ui@0.1.0".to_string(),
            current_version: "0.1.0".to_string(),
            default_source_mode: Some(SURFACE_FULFILLMENT_MODE_BUNDLED.to_string()),
            versions: vec![SurfaceAppManifestVersionRecord {
                app_contract_ref: "surface-app:nvr-ui@0.1.0".to_string(),
                version: "0.1.0".to_string(),
                state: SURFACE_APP_MANIFEST_VERSION_CURRENT.to_string(),
                source_mode: Some(SURFACE_FULFILLMENT_MODE_BUNDLED.to_string()),
                module_refs: vec!["module:runtime-client@0.1.0".to_string()],
                compatibility_refs: vec!["protocol:surface-app:v1".to_string()],
                bootstrap_contract_ref: None,
                release_contract_ref: None,
                authority_refs: vec![],
                evidence_refs: vec![],
                blocked_reasons: vec![],
            }],
            app_contract_refs: vec!["surface-app:nvr-ui@0.1.0".to_string()],
            compatibility_refs: vec!["protocol:surface-app:v1".to_string()],
            bootstrap_contract_refs: vec![],
            release_contract_refs: vec![],
            authority_refs: vec![],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            safe_facts: Value::Null,
            issued_at: 1_700_000_000,
            expires_at: Some(1_700_003_600),
        };
        validate_surface_app_manifest(&manifest).expect("valid manifest");

        let mut missing_current = manifest.clone();
        missing_current.current_version = "0.2.0".to_string();
        assert!(validate_surface_app_manifest(&missing_current).is_err());

        let mut remote_without_release = manifest;
        remote_without_release.current_app_contract_ref = "surface-app:nvr-ui@0.2.0".to_string();
        remote_without_release.current_version = "0.2.0".to_string();
        remote_without_release.versions = vec![SurfaceAppManifestVersionRecord {
            app_contract_ref: "surface-app:nvr-ui@0.2.0".to_string(),
            version: "0.2.0".to_string(),
            state: SURFACE_APP_MANIFEST_VERSION_CURRENT.to_string(),
            source_mode: Some(SURFACE_FULFILLMENT_MODE_SWARM_PACKAGE.to_string()),
            module_refs: vec![],
            compatibility_refs: vec![],
            bootstrap_contract_ref: None,
            release_contract_ref: None,
            authority_refs: vec![],
            evidence_refs: vec![],
            blocked_reasons: vec![],
        }];
        assert!(validate_surface_app_manifest(&remote_without_release).is_err());
    }

    #[test]
    fn validates_media_fulfillment_evidence() {
        let render = MediaFulfillmentEvidence {
            kind: Some(RECORD_MEDIA_FULFILLMENT_EVIDENCE.to_string()),
            evidence_id: "media-proof-1".to_string(),
            evidence_kind: "renderState".to_string(),
            state: "usable".to_string(),
            session_id: Some("stream-1".to_string()),
            activation_id: None,
            interaction_id: None,
            correlation_id: None,
            route_promise_id: None,
            participant_ref: None,
            adapter_ref: Some("adapter:media-webrtc:browser".to_string()),
            service_ref: None,
            source_ref: Some("camera:front".to_string()),
            blocked_reason: None,
            safe_facts: json!({
                "readyState": 4,
                "videoWidth": 1280,
                "videoHeight": 720,
                "visibleFrame": true
            }),
            evidence_refs: vec![],
            observed_at: 1_700_000_004,
            expires_at: Some(1_700_000_064),
        };
        validate_media_fulfillment_evidence(&render).expect("valid render evidence");

        let mut blocked = render.clone();
        blocked.evidence_id = "media-proof-2".to_string();
        blocked.evidence_kind = "transportState".to_string();
        blocked.state = "blocked".to_string();
        blocked.blocked_reason = Some("iceFailed".to_string());
        blocked.safe_facts = json!({
            "iceConnectionState": "failed",
            "selectedIceServerCount": 1
        });
        validate_media_fulfillment_evidence(&blocked).expect("valid blocked evidence");

        let mut missing_reason = blocked.clone();
        missing_reason.blocked_reason = None;
        assert!(validate_media_fulfillment_evidence(&missing_reason).is_err());

        let mut unsafe_fact = render.clone();
        unsafe_fact.safe_facts = json!({ "sdp": "raw session description" });
        assert!(validate_media_fulfillment_evidence(&unsafe_fact).is_err());

        let mut missing_scope = render;
        missing_scope.session_id = None;
        assert!(validate_media_fulfillment_evidence(&missing_scope).is_err());
    }

    #[test]
    fn validates_media_transport_path() {
        let path = MediaTransportPath {
            kind: Some(RECORD_MEDIA_TRANSPORT_PATH.to_string()),
            path_id: "media-path-1".to_string(),
            session_id: "stream-1".to_string(),
            activation_id: Some("activation-1".to_string()),
            route_promise_id: Some("route-1".to_string()),
            transport_profile_ref: "runtime.media.browser-webrtc.default".to_string(),
            browser_candidate_refs: vec!["candidate:browser:1".to_string()],
            service_candidate_refs: vec!["candidate:service:1".to_string()],
            relay_participant_refs: vec!["member:relay:1".to_string()],
            turn_participant_refs: vec![],
            state: "blocked".to_string(),
            selected_pair_state: "failed".to_string(),
            inbound_rtp_state: "blocked".to_string(),
            render_state: "blocked".to_string(),
            blocked_reason: Some("transportResourceExhausted".to_string()),
            safe_facts: json!({
                "servicePortLeaseCount": 32,
                "renderedVideoWidth": 0
            }),
            evidence_refs: vec!["media-proof-2".to_string()],
            issued_at: 1_700_000_006,
            expires_at: Some(1_700_000_066),
        };
        validate_media_transport_path(&path).expect("valid media transport path");

        let mut missing_reason = path.clone();
        missing_reason.blocked_reason = None;
        assert!(validate_media_transport_path(&missing_reason).is_err());

        let mut unsafe_path = path;
        unsafe_path.safe_facts = json!({ "sdp": "raw session description" });
        assert!(validate_media_transport_path(&unsafe_path).is_err());

        let mut live_graph = vec![json!({
            "kind": RECORD_MEDIA_TRANSPORT_PATH,
            "pathId": "media-path-1",
            "sessionId": "stream-1"
        })];
        assert!(validate_swarm_identity_graph(&live_graph).is_err());
        live_graph.clear();
        assert!(validate_swarm_identity_graph(&live_graph).is_ok());
    }

    #[test]
    fn validates_media_transport_observation() {
        let observation = MediaTransportObservation {
            kind: Some(RECORD_MEDIA_TRANSPORT_OBSERVATION.to_string()),
            observation_id: "media-observation-1".to_string(),
            path_id: "media-path-1".to_string(),
            session_id: "stream-1".to_string(),
            activation_id: Some("activation-1".to_string()),
            route_promise_id: Some("route-1".to_string()),
            participant_ref: "service:abc".to_string(),
            participant_role: "service".to_string(),
            state: "disconnected".to_string(),
            connection_state: Some("disconnected".to_string()),
            ice_connection_state: None,
            selected_pair_state: Some("selected".to_string()),
            inbound_rtp_state: Some("stalled".to_string()),
            render_state: Some("pending".to_string()),
            blocked_reason: None,
            reason: Some("peerConnectionDisconnected".to_string()),
            safe_facts: json!({
                "graceMs": 12_000,
                "sourceCount": 2
            }),
            evidence_refs: vec!["media-path-1".to_string()],
            observed_at: 1_700_000_007,
            expires_at: Some(1_700_000_067),
        };
        validate_media_transport_observation(&observation).expect("valid media observation");

        let mut missing_reason = observation.clone();
        missing_reason.state = "blocked".to_string();
        missing_reason.blocked_reason = None;
        assert!(validate_media_transport_observation(&missing_reason).is_err());

        let mut unsafe_fact = observation;
        unsafe_fact.safe_facts = json!({ "sdp": "raw session description" });
        assert!(validate_media_transport_observation(&unsafe_fact).is_err());

        let live_graph = vec![json!({
            "kind": RECORD_MEDIA_TRANSPORT_OBSERVATION,
            "observationId": "media-observation-1"
        })];
        assert!(validate_swarm_identity_graph(&live_graph).is_err());
    }

    #[test]
    fn validates_shared_js_swarm_runtime_vector() {
        let vector_json =
            std::fs::read_to_string("vectors/swarm-runtime-v1.json").expect("golden vector");
        let vector: SwarmRuntimeVector =
            serde_json::from_str(&vector_json).expect("golden vector parses in Rust");

        assert_eq!(SWARM_WIRE_FRAME, "swarm.frame");
        assert_eq!(SWARM_EDGE_WIRE_HELLO, "swarm.edge.hello");
        assert_eq!(SWARM_EDGE_WIRE_RESUME, "swarm.edge.resume");
        assert_eq!(SWARM_EDGE_WIRE_ACCEPT, "swarm.edge.accept");
        assert_eq!(SWARM_EDGE_WIRE_CLOSE, "swarm.edge.close");
        assert_eq!(
            CAPABILITY_RUNTIME_DIAGNOSTICS_OBSERVE,
            "runtime.diagnostics.observe"
        );
        assert_eq!(
            CAPABILITY_RUNTIME_DIAGNOSTICS_COMMAND,
            "runtime.diagnostics.command"
        );
        assert_eq!(RECORD_RUNTIME_DIAGNOSTIC_EVENT, "runtime.diagnostic.event");
        assert_eq!(
            RECORD_RUNTIME_DIAGNOSTIC_COMMAND,
            "runtime.diagnostic.command"
        );
        assert_eq!(
            RECORD_RUNTIME_DIAGNOSTIC_COMMAND_RESULT,
            "runtime.diagnostic.command.result"
        );
        assert_eq!(
            vector.frame.frame_id,
            "9949c702f8c61f1faf1cf89004ad75432189546e990750a5a0f03a330f5ca6ac"
        );
        validate_swarm_frame(&vector.frame, 1_700_000_001_000).expect("golden frame");
        validate_projection_delta(&vector.delta, vector.delta.base_revision)
            .expect("golden projection delta");
        validate_swarm_edge_hello(&vector.edge.hello).expect("golden edge hello");
        validate_swarm_edge_accept(&vector.edge.accept).expect("golden edge accept");
        validate_swarm_edge_resume(&vector.edge.resume).expect("golden edge resume");
        validate_swarm_edge_close(&vector.edge.close).expect("golden edge close");

        let mut bad_resume = vector.edge.resume.clone();
        bad_resume.capability_refs = vec!["bad capability".to_string()];
        assert!(validate_swarm_edge_resume(&bad_resume).is_err());
        let mut bad_accept = vector.edge.accept.clone();
        bad_accept.last_projection_revisions = json!({ "proj-1": -1 });
        assert!(validate_swarm_edge_accept(&bad_accept).is_err());
        let mut bad_close = vector.edge.close;
        bad_close.sealed_claims = SwarmFrameBody {
            encoding: "public".to_string(),
            envelope: None,
            public_bootstrap: true,
            payload: Some(json!({ "reason": "plain" })),
            signature: None,
        };
        assert!(validate_swarm_edge_close(&bad_close).is_err());
    }
}
