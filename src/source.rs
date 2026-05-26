use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RECORD_SOURCE_VERSION_GRAPH: &str = "source.version.graph";
pub const RECORD_SOURCE_SNAPSHOT: &str = "source.snapshot";
pub const RECORD_SOURCE_VERSION_INDEX_ENTRY: &str = "source.version-index.entry";
pub const RECORD_SOURCE_VERSION_INDEX_PROJECTION: &str = "source.version-index.projection";
pub const RECORD_SOURCE_REF_TRANSITION_POSTURE: &str = "source.ref.transition.posture";
pub const RECORD_SOURCE_VERSION_INDEX_DELTA_POSTURE: &str = "source.version-index.delta.posture";
pub const RECORD_SOURCE_APPLIED_REF_PROJECTION: &str = "source.applied-ref.projection";
pub const RECORD_SOURCE_REF_STORE_JOURNAL: &str = "source.ref.store.journal";
pub const RECORD_SOURCE_REF_STORE_REPLAY_POSTURE: &str = "source.ref.store.replay.posture";
pub const RECORD_SOURCE_PROMOTION_ROLLBACK_POSTURE: &str = "source.promotion.rollback.posture";
pub const RECORD_SOURCE_PROMOTION_WITNESS_POSTURE: &str = "source.promotion.witness.posture";
pub const RECORD_SWARM_WORKSPACE_AUTHORING_PROJECTION: &str =
    "swarm.workspace.authoring.projection";
pub const RECORD_SWARM_WORKSPACE_AUTHORING_ENTRY: &str = "swarm.workspace.authoring.entry";
pub const RECORD_SWARM_WORKSPACE_AUTHORING_CANDIDATE_SNAPSHOT_POSTURE: &str =
    "swarm.workspace.authoring.candidate-snapshot.posture";
pub const RECORD_SWARM_WORKSPACE_AUTHORING_CANDIDATE_FEEDBACK_POSTURE: &str =
    "swarm.workspace.authoring.candidate-feedback.posture";
pub const RECORD_SOURCE_REF_UPDATE: &str = "source.ref.update";
pub const RECORD_SOURCE_WRITER_GRANT: &str = "source.writer.grant";
pub const RECORD_SOURCE_IMPORT_PROOF: &str = "source.import.proof";
pub const RECORD_SOURCE_PROJECT_OPERATION: &str = "source.project.operation";

pub const SOURCE_GRAPH_STATE_READY: &str = "ready";
pub const SOURCE_GRAPH_STATE_DEGRADED: &str = "degraded";
pub const SOURCE_GRAPH_STATE_BLOCKED: &str = "blocked";

pub const SOURCE_REF_KIND_BRANCH: &str = "branch";
pub const SOURCE_REF_KIND_TAG: &str = "tag";
pub const SOURCE_REF_KIND_NOTE: &str = "note";

pub const SOURCE_UPDATE_STATE_REQUESTED: &str = "requested";
pub const SOURCE_UPDATE_STATE_ACCEPTED: &str = "accepted";
pub const SOURCE_UPDATE_STATE_APPLIED: &str = "applied";
pub const SOURCE_UPDATE_STATE_REJECTED: &str = "rejected";
pub const SOURCE_UPDATE_STATE_BLOCKED: &str = "blocked";
pub const SOURCE_UPDATE_STATE_SUPERSEDED: &str = "superseded";

pub const SOURCE_PROJECT_OPERATION_STATE_REQUESTED: &str = "requested";
pub const SOURCE_PROJECT_OPERATION_STATE_READY: &str = "ready";
pub const SOURCE_PROJECT_OPERATION_STATE_APPLIED: &str = "applied";
pub const SOURCE_PROJECT_OPERATION_STATE_BLOCKED: &str = "blocked";
pub const SOURCE_PROJECT_OPERATION_STATE_REJECTED: &str = "rejected";
pub const SOURCE_PROJECT_OPERATION_STATE_SUPERSEDED: &str = "superseded";

pub const SOURCE_PROJECT_COMPATIBILITY_SUPPORTED: &str = "supported";
pub const SOURCE_PROJECT_COMPATIBILITY_DEGRADED: &str = "degraded";
pub const SOURCE_PROJECT_COMPATIBILITY_UNSUPPORTED: &str = "unsupported";

pub const SOURCE_IMPORT_STATE_PENDING: &str = "pending";
pub const SOURCE_IMPORT_STATE_IMPORTED: &str = "imported";
pub const SOURCE_IMPORT_STATE_BLOCKED: &str = "blocked";
pub const SOURCE_IMPORT_STATE_FAILED: &str = "failed";

pub const SOURCE_SIGNATURE_POSTURE_SIGNED: &str = "signed";
pub const SOURCE_SIGNATURE_POSTURE_DEV_UNSIGNED: &str = "devUnsigned";
pub const SOURCE_SIGNATURE_POSTURE_BLOCKED: &str = "blocked";

pub const SOURCE_OPERATION_IMPORT: &str = "import";
pub const SOURCE_OPERATION_FETCH: &str = "fetch";
pub const SOURCE_OPERATION_PUSH: &str = "push";
pub const SOURCE_OPERATION_STATUS: &str = "status";
pub const SOURCE_OPERATION_REF_UPDATE: &str = "refUpdate";
pub const SOURCE_OPERATION_BRANCH: &str = "branch";
pub const SOURCE_OPERATION_TAG: &str = "tag";
pub const SOURCE_OPERATION_RELEASE: &str = "release";
pub const SOURCE_OPERATION_PROJECT_LINK: &str = "projectLink";
pub const SOURCE_OPERATION_EXPORT: &str = "export";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceGraphPolicy {
    pub fast_forward_only: bool,
    pub review_required: bool,
    pub signed_updates_required: bool,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceVersionGraph {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub source_graph_ref: String,
    pub owner_ref: String,
    pub storage_backend_ref: String,
    pub default_branch_ref: String,
    pub head_snapshot_ref: String,
    pub state: String,
    pub policy: SourceGraphPolicy,
    #[serde(default)]
    pub branch_refs: Vec<String>,
    #[serde(default)]
    pub tag_refs: Vec<String>,
    #[serde(default)]
    pub writer_grant_refs: Vec<String>,
    #[serde(default)]
    pub release_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceFileEntry {
    pub file_ref: String,
    pub path_ref: String,
    pub virtual_path: String,
    pub hash_ref: String,
    pub byte_length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_object_ref: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub source_graph_ref: String,
    pub snapshot_ref: String,
    pub commit_ref: String,
    pub tree_ref: String,
    pub tree_hash_ref: String,
    #[serde(default)]
    pub parent_snapshot_refs: Vec<String>,
    #[serde(default)]
    pub file_entries: Vec<SourceFileEntry>,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    pub author_ref: String,
    pub signature_posture: String,
    pub message_digest_ref: String,
    #[serde(default)]
    pub branch_refs: Vec<String>,
    #[serde(default)]
    pub candidate_refs: Vec<String>,
    #[serde(default)]
    pub writer_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub materialized_projection_refs: Vec<String>,
    #[serde(default)]
    pub dirty_projection_refs: Vec<String>,
    #[serde(default)]
    pub signature_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceVersionIndexEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub entry_ref: String,
    pub contract_ref: String,
    pub contract_version_ref: String,
    pub selected_version_ref: String,
    pub module_ref: String,
    pub repo_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_version: Option<String>,
    pub source_snapshot_ref: String,
    pub content_index_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_hash_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_by_ref: Option<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub writer_grant_refs: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceVersionIndexProjection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub version_index_ref: String,
    pub source_snapshot_ref: String,
    pub content_index_ref: String,
    #[serde(default)]
    pub entry_count: u64,
    #[serde(default)]
    pub entries: Vec<SourceVersionIndexEntry>,
    #[serde(default)]
    pub selected_version_refs: Vec<String>,
    #[serde(default)]
    pub contract_version_refs: Vec<String>,
    #[serde(default)]
    pub module_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceVersionIndexDeltaEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_version_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_version_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_snapshot_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_index_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_hash_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_by_ref: Option<String>,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub writer_grant_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceRefTransitionPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub transition_ref: String,
    pub state: String,
    pub target_ref: String,
    pub repo_ref: String,
    pub from_source_snapshot_ref: String,
    pub to_source_snapshot_ref: String,
    pub from_content_index_ref: String,
    pub to_content_index_ref: String,
    pub from_selected_version_ref: String,
    pub to_selected_version_ref: String,
    pub lifecycle_manifest_ref: String,
    pub promotion_intent_ref: String,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    #[serde(default)]
    pub witness_refs: Vec<String>,
    #[serde(default)]
    pub rollback_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceVersionIndexDeltaPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub delta_ref: String,
    pub state: String,
    pub version_index_ref: String,
    pub repo_ref: String,
    pub target_ref: String,
    pub from_entry: SourceVersionIndexDeltaEntry,
    pub to_entry: SourceVersionIndexDeltaEntry,
    #[serde(default)]
    pub input_refs: Vec<String>,
    #[serde(default)]
    pub output_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourcePromotionRollbackPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub rollback_ref: String,
    pub state: String,
    pub target_ref: String,
    pub restore_source_snapshot_ref: String,
    pub restore_content_index_ref: String,
    pub restore_selected_version_ref: String,
    #[serde(default)]
    pub rollback_gate_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourcePromotionWitnessPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub witness_ref: String,
    pub state: String,
    pub subject_ref: String,
    pub lifecycle_manifest_ref: String,
    pub promotion_intent_ref: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub proof_gate_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub storage_pin_refs: Vec<String>,
    #[serde(default)]
    pub storage_availability_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceAppliedRefProjection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub projection_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply_ref: Option<String>,
    pub repo_ref: String,
    pub target_ref: String,
    pub lifecycle_manifest_ref: String,
    pub promotion_intent_ref: String,
    pub source_ref_transition_ref: String,
    pub version_index_delta_ref: String,
    pub witness_ref: String,
    pub rollback_ref: String,
    pub from_source_snapshot_ref: String,
    pub to_source_snapshot_ref: String,
    pub from_content_index_ref: String,
    pub to_content_index_ref: String,
    pub from_selected_version_ref: String,
    pub to_selected_version_ref: String,
    pub to_version_index_entry: SourceVersionIndexDeltaEntry,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    #[serde(default)]
    pub proof_gate_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub storage_pin_refs: Vec<String>,
    #[serde(default)]
    pub storage_availability_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceRefStoreCurrentEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_ref: Option<String>,
    pub repo_ref: String,
    pub target_ref: String,
    #[serde(default)]
    pub source_ref_update_refs: Vec<String>,
    pub source_ref_transition_ref: String,
    pub version_index_delta_ref: String,
    pub witness_ref: String,
    pub rollback_ref: String,
    pub lifecycle_manifest_ref: String,
    pub promotion_intent_ref: String,
    pub from_source_snapshot_ref: String,
    pub to_source_snapshot_ref: String,
    pub from_content_index_ref: String,
    pub to_content_index_ref: String,
    pub from_selected_version_ref: String,
    pub to_selected_version_ref: String,
    pub to_version_index_entry: SourceVersionIndexDeltaEntry,
    #[serde(default)]
    pub authority_refs: Vec<String>,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    #[serde(default)]
    pub proof_gate_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub storage_pin_refs: Vec<String>,
    #[serde(default)]
    pub storage_availability_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceRefStoreJournal {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub store_ref: String,
    pub journal_ref: String,
    pub source_graph_ref: String,
    pub target_ref: String,
    pub repo_ref: String,
    pub current: SourceRefStoreCurrentEntry,
    #[serde(default)]
    pub transitions: Vec<SourceRefStoreCurrentEntry>,
    #[serde(default)]
    pub transition_count: u64,
    #[serde(default)]
    pub source_ref_updates: Vec<SourceRefUpdate>,
    #[serde(default)]
    pub source_ref_update_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    #[serde(default)]
    pub storage_availability_refs: Vec<String>,
    #[serde(default)]
    pub storage_pin_intent_refs: Vec<String>,
    #[serde(default)]
    pub storage_pin_attestation_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceRefStoreReplayPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub replay_ref: String,
    pub store_ref: String,
    pub journal_ref: String,
    pub target_ref: String,
    pub expected_target_ref: String,
    pub repo_ref: String,
    pub current_transition_ref: String,
    pub current_version_index_delta_ref: String,
    pub current_selected_version_ref: String,
    #[serde(default)]
    pub transition_count: u64,
    #[serde(default)]
    pub source_ref_update_refs: Vec<String>,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    #[serde(default)]
    pub storage_availability_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthoringProofTarget {
    pub proof_target_ref: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_adapter_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthoringCandidateFeedbackPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    #[serde(default)]
    pub candidate_snapshot_refs: Vec<String>,
    #[serde(default)]
    pub candidate_refs: Vec<String>,
    #[serde(default)]
    pub source_ref_update_refs: Vec<String>,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    #[serde(default)]
    pub availability_refs: Vec<String>,
    #[serde(default)]
    pub proof_event_refs: Vec<String>,
    #[serde(default)]
    pub promotion_intent_refs: Vec<String>,
    #[serde(default)]
    pub lifecycle_request_refs: Vec<String>,
    #[serde(default)]
    pub report_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthoringWorkspaceEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub entry_ref: String,
    pub state: String,
    pub repo_ref: String,
    pub module_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub selected_version_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_version_ref: Option<String>,
    pub source_snapshot_ref: String,
    pub content_index_ref: String,
    #[serde(default)]
    pub candidate_refs: Vec<String>,
    #[serde(default)]
    pub dirty_projection_refs: Vec<String>,
    #[serde(default)]
    pub editable_file_refs: Vec<String>,
    #[serde(default)]
    pub editable_file_count: u64,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    #[serde(default)]
    pub availability_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_feedback: Option<AuthoringCandidateFeedbackPosture>,
    #[serde(default)]
    pub materialized_projection_refs: Vec<String>,
    #[serde(default)]
    pub tool_mount_refs: Vec<String>,
    #[serde(default)]
    pub proof_targets: Vec<AuthoringProofTarget>,
    #[serde(default)]
    pub proof_target_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthoringWorkspaceProjection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub workspace_ref: String,
    pub source_snapshot_ref: String,
    pub content_index_ref: String,
    pub version_index_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver_ref: Option<String>,
    #[serde(default)]
    pub entry_count: u64,
    #[serde(default)]
    pub editable_file_count: u64,
    #[serde(default)]
    pub selected_version_refs: Vec<String>,
    #[serde(default)]
    pub candidate_refs: Vec<String>,
    #[serde(default)]
    pub dirty_projection_refs: Vec<String>,
    #[serde(default)]
    pub tool_mount_refs: Vec<String>,
    #[serde(default)]
    pub proof_target_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promotion_intent_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_manifest_ref: Option<String>,
    #[serde(default)]
    pub authoring_entries: Vec<AuthoringWorkspaceEntry>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthoringCandidateSnapshotPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub state: String,
    pub candidate_snapshot_ref: String,
    pub candidate_ref: String,
    pub edit_intent_ref: String,
    pub workspace_ref: String,
    pub entry_ref: String,
    pub repo_ref: String,
    pub module_ref: String,
    pub selected_version_ref: String,
    pub parent_source_snapshot_ref: String,
    pub content_index_ref: String,
    #[serde(default)]
    pub dirty_projection_refs: Vec<String>,
    #[serde(default)]
    pub editable_file_count: u64,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    #[serde(default)]
    pub fulfilled_storage_object_refs: Vec<String>,
    #[serde(default)]
    pub availability_refs: Vec<String>,
    #[serde(default)]
    pub tool_mount_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_proof_target: Option<AuthoringProofTarget>,
    #[serde(default)]
    pub proof_target_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceRefUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub update_ref: String,
    pub source_graph_ref: String,
    pub ref_name: String,
    pub ref_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_snapshot_ref: Option<String>,
    pub to_snapshot_ref: String,
    pub writer_ref: String,
    pub state: String,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub witness_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub policy: SourceGraphPolicy,
    pub signed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceWriterGrant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub grant_ref: String,
    pub source_graph_ref: String,
    pub issuer_ref: String,
    pub subject_ref: String,
    #[serde(default)]
    pub scope_refs: Vec<String>,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceImportProof {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub import_ref: String,
    pub source_graph_ref: String,
    pub tool_ref: String,
    pub input_ref: String,
    pub output_snapshot_ref: String,
    pub state: String,
    #[serde(default)]
    pub imported_object_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub observed_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceProjectOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub operation_ref: String,
    pub source_graph_ref: String,
    pub subject_ref: String,
    pub actor_ref: String,
    pub operation: String,
    pub state: String,
    pub compatibility_state: String,
    #[serde(default)]
    pub scope_refs: Vec<String>,
    #[serde(default)]
    pub source_snapshot_refs: Vec<String>,
    #[serde(default)]
    pub content_index_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub branch_refs: Vec<String>,
    #[serde(default)]
    pub tag_refs: Vec<String>,
    #[serde(default)]
    pub release_refs: Vec<String>,
    #[serde(default)]
    pub project_refs: Vec<String>,
    #[serde(default)]
    pub work_item_refs: Vec<String>,
    #[serde(default)]
    pub build_target_refs: Vec<String>,
    #[serde(default)]
    pub build_profile_refs: Vec<String>,
    #[serde(default)]
    pub build_proof_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub proof_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub rollback_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

pub fn validate_source_version_graph(record: &SourceVersionGraph) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_VERSION_GRAPH,
        "source version graph",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source version graph")?;
    validate_contract_ref(
        &record.source_graph_ref,
        "source version graph sourceGraphRef",
    )?;
    validate_contract_ref(&record.owner_ref, "source version graph ownerRef")?;
    validate_contract_ref(
        &record.storage_backend_ref,
        "source version graph storageBackendRef",
    )?;
    validate_contract_ref(
        &record.default_branch_ref,
        "source version graph defaultBranchRef",
    )?;
    validate_contract_ref(
        &record.head_snapshot_ref,
        "source version graph headSnapshotRef",
    )?;
    validate_source_graph_state(&record.state)?;
    validate_source_policy(&record.policy)?;
    validate_ref_list(&record.branch_refs, "source version graph branchRefs")?;
    validate_ref_list(&record.tag_refs, "source version graph tagRefs")?;
    validate_ref_list(
        &record.writer_grant_refs,
        "source version graph writerGrantRefs",
    )?;
    validate_ref_list(&record.release_refs, "source version graph releaseRefs")?;
    validate_ref_list(&record.evidence_refs, "source version graph evidenceRefs")?;
    validate_reason_list(
        &record.blocked_reasons,
        "source version graph blockedReasons",
    )?;
    if record.state == SOURCE_GRAPH_STATE_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "source version graph blocked state needs blockedReasons"
        ));
    }
    validate_time_bounds(record.issued_at, record.expires_at, "source version graph")?;
    Ok(())
}

pub fn validate_source_snapshot(record: &SourceSnapshot) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_SNAPSHOT,
        "source snapshot",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source snapshot")?;
    validate_contract_ref(&record.source_graph_ref, "source snapshot sourceGraphRef")?;
    validate_contract_ref(&record.snapshot_ref, "source snapshot snapshotRef")?;
    validate_contract_ref(&record.commit_ref, "source snapshot commitRef")?;
    validate_contract_ref(&record.tree_ref, "source snapshot treeRef")?;
    validate_hash_ref(&record.tree_hash_ref, "source snapshot treeHashRef")?;
    validate_ref_list(
        &record.parent_snapshot_refs,
        "source snapshot parentSnapshotRefs",
    )?;
    for file_entry in &record.file_entries {
        validate_source_file_entry(file_entry)?;
    }
    if record.file_entries.is_empty() {
        return Err(anyhow!("source snapshot needs fileEntries"));
    }
    validate_storage_object_ref_list(
        &record.storage_object_refs,
        "source snapshot storageObjectRefs",
    )?;
    if record.storage_object_refs.is_empty() {
        return Err(anyhow!("source snapshot needs storageObjectRefs"));
    }
    validate_contract_ref(&record.author_ref, "source snapshot authorRef")?;
    validate_source_signature_posture(&record.signature_posture)?;
    validate_contract_ref(
        &record.message_digest_ref,
        "source snapshot messageDigestRef",
    )?;
    validate_ref_list(&record.branch_refs, "source snapshot branchRefs")?;
    validate_ref_list(&record.candidate_refs, "source snapshot candidateRefs")?;
    validate_ref_list(&record.writer_grant_refs, "source snapshot writerGrantRefs")?;
    validate_ref_list(&record.authority_refs, "source snapshot authorityRefs")?;
    validate_ref_list(
        &record.materialized_projection_refs,
        "source snapshot materializedProjectionRefs",
    )?;
    validate_ref_list(
        &record.dirty_projection_refs,
        "source snapshot dirtyProjectionRefs",
    )?;
    validate_ref_list(&record.signature_refs, "source snapshot signatureRefs")?;
    validate_ref_list(&record.evidence_refs, "source snapshot evidenceRefs")?;
    if record.signature_posture == SOURCE_SIGNATURE_POSTURE_SIGNED
        && record.signature_refs.is_empty()
    {
        return Err(anyhow!("signed source snapshot needs signatureRefs"));
    }
    if record.signature_posture == SOURCE_SIGNATURE_POSTURE_DEV_UNSIGNED
        && record.evidence_refs.is_empty()
    {
        return Err(anyhow!("dev-unsigned source snapshot needs evidenceRefs"));
    }
    if !record.dirty_projection_refs.is_empty() && record.candidate_refs.is_empty() {
        return Err(anyhow!(
            "dirty source snapshot projection needs candidateRefs"
        ));
    }
    if record.issued_at == 0 {
        return Err(anyhow!("source snapshot missing issuedAt"));
    }
    Ok(())
}

pub fn validate_source_version_index_projection(
    record: &SourceVersionIndexProjection,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_VERSION_INDEX_PROJECTION,
        "source version-index projection",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source version-index projection",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source version-index projection safeFacts",
    )?;
    validate_posture_state(&record.state, "source version-index projection state")?;
    validate_contract_ref(
        &record.version_index_ref,
        "source version-index projection versionIndexRef",
    )?;
    validate_contract_ref(
        &record.source_snapshot_ref,
        "source version-index projection sourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.content_index_ref,
        "source version-index projection contentIndexRef",
    )?;
    for entry in &record.entries {
        validate_source_version_index_entry(entry)?;
    }
    if record.entries.is_empty() {
        return Err(anyhow!("source version-index projection needs entries"));
    }
    if record.entry_count != 0 && record.entry_count as usize != record.entries.len() {
        return Err(anyhow!(
            "source version-index projection entryCount must match entries"
        ));
    }
    validate_ref_list(
        &record.selected_version_refs,
        "source version-index projection selectedVersionRefs",
    )?;
    validate_ref_list(
        &record.contract_version_refs,
        "source version-index projection contractVersionRefs",
    )?;
    validate_ref_list(
        &record.module_refs,
        "source version-index projection moduleRefs",
    )?;
    validate_ref_list(
        &record.evidence_refs,
        "source version-index projection evidenceRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source version-index projection blockedReasons",
    )?;
    validate_optional_text(
        record.observed_at.as_deref(),
        "source version-index projection observedAt",
    )?;
    Ok(())
}

pub fn validate_source_ref_transition_posture(record: &SourceRefTransitionPosture) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_REF_TRANSITION_POSTURE,
        "source ref transition posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source ref transition posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source ref transition posture safeFacts",
    )?;
    validate_contract_ref(
        &record.transition_ref,
        "source ref transition transitionRef",
    )?;
    validate_posture_state(&record.state, "source ref transition state")?;
    validate_contract_ref(&record.target_ref, "source ref transition targetRef")?;
    validate_contract_ref(&record.repo_ref, "source ref transition repoRef")?;
    validate_contract_ref(
        &record.from_source_snapshot_ref,
        "source ref transition fromSourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.to_source_snapshot_ref,
        "source ref transition toSourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.from_content_index_ref,
        "source ref transition fromContentIndexRef",
    )?;
    validate_contract_ref(
        &record.to_content_index_ref,
        "source ref transition toContentIndexRef",
    )?;
    validate_contract_ref(
        &record.from_selected_version_ref,
        "source ref transition fromSelectedVersionRef",
    )?;
    validate_contract_ref(
        &record.to_selected_version_ref,
        "source ref transition toSelectedVersionRef",
    )?;
    validate_contract_ref(
        &record.lifecycle_manifest_ref,
        "source ref transition lifecycleManifestRef",
    )?;
    validate_contract_ref(
        &record.promotion_intent_ref,
        "source ref transition promotionIntentRef",
    )?;
    validate_ref_list(
        &record.authority_refs,
        "source ref transition authorityRefs",
    )?;
    validate_ref_list(&record.grant_refs, "source ref transition grantRefs")?;
    validate_ref_list(&record.witness_refs, "source ref transition witnessRefs")?;
    validate_ref_list(&record.rollback_refs, "source ref transition rollbackRefs")?;
    validate_reason_list(
        &record.blocked_reasons,
        "source ref transition blockedReasons",
    )?;
    if record.state == SOURCE_UPDATE_STATE_APPLIED && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "applied source ref transition cannot carry blockedReasons"
        ));
    }
    if record.state == SOURCE_UPDATE_STATE_APPLIED
        && (record.authority_refs.is_empty()
            || record.grant_refs.is_empty()
            || record.witness_refs.is_empty()
            || record.rollback_refs.is_empty())
    {
        return Err(anyhow!(
            "applied source ref transition needs authority, grant, witness, and rollback refs"
        ));
    }
    Ok(())
}

fn validate_source_version_index_delta_entry(
    entry: &SourceVersionIndexDeltaEntry,
    context: &str,
    require_selection: bool,
) -> Result<()> {
    if let Some(entry_ref) = entry.entry_ref.as_deref() {
        validate_contract_ref(entry_ref, &format!("{context} entryRef"))?;
    }
    if let Some(contract_ref) = entry.contract_ref.as_deref() {
        validate_contract_ref(contract_ref, &format!("{context} contractRef"))?;
    }
    if let Some(contract_version_ref) = entry.contract_version_ref.as_deref() {
        validate_contract_ref(
            contract_version_ref,
            &format!("{context} contractVersionRef"),
        )?;
    }
    if let Some(selected_version_ref) = entry.selected_version_ref.as_deref() {
        validate_contract_ref(
            selected_version_ref,
            &format!("{context} selectedVersionRef"),
        )?;
    } else if require_selection {
        return Err(anyhow!("{context} needs selectedVersionRef"));
    }
    if let Some(module_ref) = entry.module_ref.as_deref() {
        validate_contract_ref(module_ref, &format!("{context} moduleRef"))?;
    }
    if let Some(repo_ref) = entry.repo_ref.as_deref() {
        validate_contract_ref(repo_ref, &format!("{context} repoRef"))?;
    }
    validate_optional_text(
        entry.declared_version.as_deref(),
        &format!("{context} declaredVersion"),
    )?;
    if let Some(source_snapshot_ref) = entry.source_snapshot_ref.as_deref() {
        validate_contract_ref(source_snapshot_ref, &format!("{context} sourceSnapshotRef"))?;
    } else if require_selection {
        return Err(anyhow!("{context} needs sourceSnapshotRef"));
    }
    if let Some(content_index_ref) = entry.content_index_ref.as_deref() {
        validate_contract_ref(content_index_ref, &format!("{context} contentIndexRef"))?;
    } else if require_selection {
        return Err(anyhow!("{context} needs contentIndexRef"));
    }
    if let Some(tree_hash_ref) = entry.tree_hash_ref.as_deref() {
        validate_hash_ref(tree_hash_ref, &format!("{context} treeHashRef"))?;
    }
    validate_optional_ref(
        entry.artifact_ref.as_deref(),
        &format!("{context} artifactRef"),
    )?;
    validate_optional_ref(
        entry.selected_by_ref.as_deref(),
        &format!("{context} selectedByRef"),
    )?;
    validate_ref_list(&entry.authority_refs, &format!("{context} authorityRefs"))?;
    validate_ref_list(
        &entry.writer_grant_refs,
        &format!("{context} writerGrantRefs"),
    )?;
    Ok(())
}

pub fn validate_source_version_index_delta_posture(
    record: &SourceVersionIndexDeltaPosture,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_VERSION_INDEX_DELTA_POSTURE,
        "source version-index delta posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source version-index delta posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source version-index delta posture safeFacts",
    )?;
    validate_contract_ref(&record.delta_ref, "source version-index delta deltaRef")?;
    validate_posture_state(&record.state, "source version-index delta state")?;
    validate_contract_ref(
        &record.version_index_ref,
        "source version-index delta versionIndexRef",
    )?;
    validate_contract_ref(&record.repo_ref, "source version-index delta repoRef")?;
    validate_contract_ref(&record.target_ref, "source version-index delta targetRef")?;
    validate_source_version_index_delta_entry(
        &record.from_entry,
        "source version-index delta fromEntry",
        true,
    )?;
    validate_source_version_index_delta_entry(
        &record.to_entry,
        "source version-index delta toEntry",
        true,
    )?;
    validate_ref_list(&record.input_refs, "source version-index delta inputRefs")?;
    validate_ref_list(&record.output_refs, "source version-index delta outputRefs")?;
    validate_reason_list(
        &record.blocked_reasons,
        "source version-index delta blockedReasons",
    )?;
    if record.state == SOURCE_UPDATE_STATE_APPLIED && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "applied source version-index delta cannot carry blockedReasons"
        ));
    }
    Ok(())
}

pub fn validate_source_promotion_rollback_posture(
    record: &SourcePromotionRollbackPosture,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_PROMOTION_ROLLBACK_POSTURE,
        "source promotion rollback posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source promotion rollback posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source promotion rollback posture safeFacts",
    )?;
    validate_contract_ref(
        &record.rollback_ref,
        "source promotion rollback rollbackRef",
    )?;
    validate_posture_state(&record.state, "source promotion rollback state")?;
    validate_contract_ref(&record.target_ref, "source promotion rollback targetRef")?;
    validate_contract_ref(
        &record.restore_source_snapshot_ref,
        "source promotion rollback restoreSourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.restore_content_index_ref,
        "source promotion rollback restoreContentIndexRef",
    )?;
    validate_contract_ref(
        &record.restore_selected_version_ref,
        "source promotion rollback restoreSelectedVersionRef",
    )?;
    validate_ref_list(
        &record.rollback_gate_refs,
        "source promotion rollback rollbackGateRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source promotion rollback blockedReasons",
    )?;
    if record.state == SOURCE_UPDATE_STATE_APPLIED && record.rollback_gate_refs.is_empty() {
        return Err(anyhow!(
            "applied source promotion rollback needs rollbackGateRefs"
        ));
    }
    Ok(())
}

pub fn validate_source_promotion_witness_posture(
    record: &SourcePromotionWitnessPosture,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_PROMOTION_WITNESS_POSTURE,
        "source promotion witness posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source promotion witness posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source promotion witness posture safeFacts",
    )?;
    validate_contract_ref(&record.witness_ref, "source promotion witness witnessRef")?;
    validate_posture_state(&record.state, "source promotion witness state")?;
    validate_contract_ref(&record.subject_ref, "source promotion witness subjectRef")?;
    validate_contract_ref(
        &record.lifecycle_manifest_ref,
        "source promotion witness lifecycleManifestRef",
    )?;
    validate_contract_ref(
        &record.promotion_intent_ref,
        "source promotion witness promotionIntentRef",
    )?;
    validate_ref_list(
        &record.evidence_refs,
        "source promotion witness evidenceRefs",
    )?;
    validate_ref_list(
        &record.proof_gate_refs,
        "source promotion witness proofGateRefs",
    )?;
    validate_storage_object_ref_list(&record.storage_refs, "source promotion witness storageRefs")?;
    validate_ref_list(
        &record.storage_pin_refs,
        "source promotion witness storagePinRefs",
    )?;
    validate_ref_list(
        &record.storage_availability_refs,
        "source promotion witness storageAvailabilityRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source promotion witness blockedReasons",
    )?;
    if record.state == SOURCE_UPDATE_STATE_APPLIED
        && (record.evidence_refs.is_empty() || record.proof_gate_refs.is_empty())
    {
        return Err(anyhow!(
            "applied source promotion witness needs evidenceRefs and proofGateRefs"
        ));
    }
    Ok(())
}

pub fn validate_source_applied_ref_projection(record: &SourceAppliedRefProjection) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_APPLIED_REF_PROJECTION,
        "source applied-ref projection",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source applied-ref projection",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source applied-ref projection safeFacts",
    )?;
    validate_posture_state(&record.state, "source applied-ref projection state")?;
    validate_contract_ref(
        &record.projection_ref,
        "source applied-ref projection projectionRef",
    )?;
    validate_optional_ref(
        record.report_ref.as_deref(),
        "source applied-ref projection reportRef",
    )?;
    validate_optional_ref(
        record.apply_ref.as_deref(),
        "source applied-ref projection applyRef",
    )?;
    validate_contract_ref(&record.repo_ref, "source applied-ref projection repoRef")?;
    validate_contract_ref(
        &record.target_ref,
        "source applied-ref projection targetRef",
    )?;
    validate_contract_ref(
        &record.lifecycle_manifest_ref,
        "source applied-ref projection lifecycleManifestRef",
    )?;
    validate_contract_ref(
        &record.promotion_intent_ref,
        "source applied-ref projection promotionIntentRef",
    )?;
    validate_contract_ref(
        &record.source_ref_transition_ref,
        "source applied-ref projection sourceRefTransitionRef",
    )?;
    validate_contract_ref(
        &record.version_index_delta_ref,
        "source applied-ref projection versionIndexDeltaRef",
    )?;
    validate_contract_ref(
        &record.witness_ref,
        "source applied-ref projection witnessRef",
    )?;
    validate_contract_ref(
        &record.rollback_ref,
        "source applied-ref projection rollbackRef",
    )?;
    validate_contract_ref(
        &record.from_source_snapshot_ref,
        "source applied-ref projection fromSourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.to_source_snapshot_ref,
        "source applied-ref projection toSourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.from_content_index_ref,
        "source applied-ref projection fromContentIndexRef",
    )?;
    validate_contract_ref(
        &record.to_content_index_ref,
        "source applied-ref projection toContentIndexRef",
    )?;
    validate_contract_ref(
        &record.from_selected_version_ref,
        "source applied-ref projection fromSelectedVersionRef",
    )?;
    validate_contract_ref(
        &record.to_selected_version_ref,
        "source applied-ref projection toSelectedVersionRef",
    )?;
    validate_source_version_index_delta_entry(
        &record.to_version_index_entry,
        "source applied-ref projection toVersionIndexEntry",
        true,
    )?;
    validate_ref_list(
        &record.authority_refs,
        "source applied-ref projection authorityRefs",
    )?;
    validate_ref_list(
        &record.grant_refs,
        "source applied-ref projection grantRefs",
    )?;
    validate_ref_list(
        &record.proof_gate_refs,
        "source applied-ref projection proofGateRefs",
    )?;
    validate_ref_list(
        &record.evidence_refs,
        "source applied-ref projection evidenceRefs",
    )?;
    validate_storage_object_ref_list(
        &record.storage_refs,
        "source applied-ref projection storageRefs",
    )?;
    validate_ref_list(
        &record.storage_pin_refs,
        "source applied-ref projection storagePinRefs",
    )?;
    validate_ref_list(
        &record.storage_availability_refs,
        "source applied-ref projection storageAvailabilityRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source applied-ref projection blockedReasons",
    )?;
    validate_optional_text(
        record.observed_at.as_deref(),
        "source applied-ref projection observedAt",
    )?;
    if record.state == SOURCE_UPDATE_STATE_APPLIED && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "applied source applied-ref projection cannot carry blockedReasons"
        ));
    }
    Ok(())
}

fn validate_source_ref_store_current_entry(
    record: &SourceRefStoreCurrentEntry,
    context: &str,
) -> Result<()> {
    validate_optional_ref(record.apply_ref.as_deref(), &format!("{context} applyRef"))?;
    validate_optional_ref(
        record.report_ref.as_deref(),
        &format!("{context} reportRef"),
    )?;
    validate_contract_ref(&record.repo_ref, &format!("{context} repoRef"))?;
    validate_contract_ref(&record.target_ref, &format!("{context} targetRef"))?;
    validate_ref_list(
        &record.source_ref_update_refs,
        &format!("{context} sourceRefUpdateRefs"),
    )?;
    validate_contract_ref(
        &record.source_ref_transition_ref,
        &format!("{context} sourceRefTransitionRef"),
    )?;
    validate_contract_ref(
        &record.version_index_delta_ref,
        &format!("{context} versionIndexDeltaRef"),
    )?;
    validate_contract_ref(&record.witness_ref, &format!("{context} witnessRef"))?;
    validate_contract_ref(&record.rollback_ref, &format!("{context} rollbackRef"))?;
    validate_contract_ref(
        &record.lifecycle_manifest_ref,
        &format!("{context} lifecycleManifestRef"),
    )?;
    validate_contract_ref(
        &record.promotion_intent_ref,
        &format!("{context} promotionIntentRef"),
    )?;
    validate_contract_ref(
        &record.from_source_snapshot_ref,
        &format!("{context} fromSourceSnapshotRef"),
    )?;
    validate_contract_ref(
        &record.to_source_snapshot_ref,
        &format!("{context} toSourceSnapshotRef"),
    )?;
    validate_contract_ref(
        &record.from_content_index_ref,
        &format!("{context} fromContentIndexRef"),
    )?;
    validate_contract_ref(
        &record.to_content_index_ref,
        &format!("{context} toContentIndexRef"),
    )?;
    validate_contract_ref(
        &record.from_selected_version_ref,
        &format!("{context} fromSelectedVersionRef"),
    )?;
    validate_contract_ref(
        &record.to_selected_version_ref,
        &format!("{context} toSelectedVersionRef"),
    )?;
    validate_source_version_index_delta_entry(
        &record.to_version_index_entry,
        &format!("{context} toVersionIndexEntry"),
        true,
    )?;
    validate_ref_list(&record.authority_refs, &format!("{context} authorityRefs"))?;
    validate_ref_list(&record.grant_refs, &format!("{context} grantRefs"))?;
    validate_ref_list(&record.proof_gate_refs, &format!("{context} proofGateRefs"))?;
    validate_ref_list(&record.evidence_refs, &format!("{context} evidenceRefs"))?;
    validate_storage_object_ref_list(&record.storage_refs, &format!("{context} storageRefs"))?;
    validate_ref_list(
        &record.storage_pin_refs,
        &format!("{context} storagePinRefs"),
    )?;
    validate_ref_list(
        &record.storage_availability_refs,
        &format!("{context} storageAvailabilityRefs"),
    )?;
    validate_optional_text(
        record.observed_at.as_deref(),
        &format!("{context} observedAt"),
    )?;
    Ok(())
}

pub fn validate_source_ref_store_journal(record: &SourceRefStoreJournal) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_REF_STORE_JOURNAL,
        "source ref store journal",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source ref store journal")?;
    reject_private_fields(&record.safe_facts, "source ref store journal safeFacts")?;
    validate_posture_state(&record.state, "source ref store journal state")?;
    validate_contract_ref(&record.store_ref, "source ref store journal storeRef")?;
    validate_contract_ref(&record.journal_ref, "source ref store journal journalRef")?;
    validate_contract_ref(
        &record.source_graph_ref,
        "source ref store journal sourceGraphRef",
    )?;
    validate_contract_ref(&record.target_ref, "source ref store journal targetRef")?;
    validate_contract_ref(&record.repo_ref, "source ref store journal repoRef")?;
    validate_source_ref_store_current_entry(&record.current, "source ref store current")?;
    if record.current.target_ref != record.target_ref {
        return Err(anyhow!(
            "source ref store current targetRef must match journal targetRef"
        ));
    }
    if record.current.repo_ref != record.repo_ref {
        return Err(anyhow!(
            "source ref store current repoRef must match journal repoRef"
        ));
    }
    for (index, entry) in record.transitions.iter().enumerate() {
        validate_source_ref_store_current_entry(
            entry,
            &format!("source ref store transition {index}"),
        )?;
        if entry.target_ref != record.target_ref {
            return Err(anyhow!(
                "source ref store transition targetRef must match journal targetRef"
            ));
        }
    }
    if record.transition_count != record.transitions.len() as u64 {
        return Err(anyhow!(
            "source ref store journal transitionCount must equal transitions length"
        ));
    }
    for (index, update) in record.source_ref_updates.iter().enumerate() {
        validate_source_ref_update(update).map_err(|error| {
            anyhow!("source ref store journal sourceRefUpdates[{index}]: {error}")
        })?;
    }
    validate_ref_list(
        &record.source_ref_update_refs,
        "source ref store journal sourceRefUpdateRefs",
    )?;
    validate_ref_list(
        &record.evidence_refs,
        "source ref store journal evidenceRefs",
    )?;
    validate_storage_object_ref_list(
        &record.storage_object_refs,
        "source ref store journal storageObjectRefs",
    )?;
    validate_ref_list(
        &record.storage_availability_refs,
        "source ref store journal storageAvailabilityRefs",
    )?;
    validate_ref_list(
        &record.storage_pin_intent_refs,
        "source ref store journal storagePinIntentRefs",
    )?;
    validate_ref_list(
        &record.storage_pin_attestation_refs,
        "source ref store journal storagePinAttestationRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source ref store journal blockedReasons",
    )?;
    validate_optional_text(
        record.updated_at.as_deref(),
        "source ref store journal updatedAt",
    )?;
    if record.state == SOURCE_GRAPH_STATE_READY && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "ready source ref store journal cannot carry blockedReasons"
        ));
    }
    Ok(())
}

pub fn validate_source_ref_store_replay_posture(
    record: &SourceRefStoreReplayPosture,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_REF_STORE_REPLAY_POSTURE,
        "source ref store replay posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "source ref store replay posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "source ref store replay posture safeFacts",
    )?;
    validate_posture_state(&record.state, "source ref store replay posture state")?;
    validate_contract_ref(&record.replay_ref, "source ref store replay replayRef")?;
    validate_contract_ref(&record.store_ref, "source ref store replay storeRef")?;
    validate_contract_ref(&record.journal_ref, "source ref store replay journalRef")?;
    validate_contract_ref(&record.target_ref, "source ref store replay targetRef")?;
    validate_contract_ref(
        &record.expected_target_ref,
        "source ref store replay expectedTargetRef",
    )?;
    validate_contract_ref(&record.repo_ref, "source ref store replay repoRef")?;
    validate_contract_ref(
        &record.current_transition_ref,
        "source ref store replay currentTransitionRef",
    )?;
    validate_contract_ref(
        &record.current_version_index_delta_ref,
        "source ref store replay currentVersionIndexDeltaRef",
    )?;
    validate_contract_ref(
        &record.current_selected_version_ref,
        "source ref store replay currentSelectedVersionRef",
    )?;
    validate_ref_list(
        &record.source_ref_update_refs,
        "source ref store replay sourceRefUpdateRefs",
    )?;
    validate_storage_object_ref_list(
        &record.storage_object_refs,
        "source ref store replay storageObjectRefs",
    )?;
    validate_ref_list(
        &record.storage_availability_refs,
        "source ref store replay storageAvailabilityRefs",
    )?;
    validate_ref_list(
        &record.evidence_refs,
        "source ref store replay evidenceRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source ref store replay blockedReasons",
    )?;
    validate_optional_text(
        record.observed_at.as_deref(),
        "source ref store replay observedAt",
    )?;
    if record.state == SOURCE_GRAPH_STATE_READY && record.target_ref != record.expected_target_ref {
        return Err(anyhow!(
            "ready source ref store replay targetRef must match expectedTargetRef"
        ));
    }
    if record.state == SOURCE_GRAPH_STATE_READY && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "ready source ref store replay cannot carry blockedReasons"
        ));
    }
    Ok(())
}

pub fn validate_authoring_workspace_projection(
    record: &AuthoringWorkspaceProjection,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SWARM_WORKSPACE_AUTHORING_PROJECTION,
        "authoring workspace projection",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "authoring workspace projection",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "authoring workspace projection safeFacts",
    )?;
    validate_posture_state(&record.state, "authoring workspace projection state")?;
    validate_contract_ref(
        &record.workspace_ref,
        "authoring workspace projection workspaceRef",
    )?;
    validate_contract_ref(
        &record.source_snapshot_ref,
        "authoring workspace projection sourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.content_index_ref,
        "authoring workspace projection contentIndexRef",
    )?;
    validate_contract_ref(
        &record.version_index_ref,
        "authoring workspace projection versionIndexRef",
    )?;
    validate_optional_ref_allow_empty(
        record.resolver_ref.as_deref(),
        "authoring workspace projection resolverRef",
    )?;
    for entry in &record.authoring_entries {
        validate_authoring_workspace_entry(entry)?;
    }
    if record.authoring_entries.is_empty() {
        return Err(anyhow!(
            "authoring workspace projection needs authoringEntries"
        ));
    }
    if record.entry_count != 0 && record.entry_count as usize != record.authoring_entries.len() {
        return Err(anyhow!(
            "authoring workspace projection entryCount must match entries"
        ));
    }
    validate_ref_list(
        &record.selected_version_refs,
        "authoring workspace projection selectedVersionRefs",
    )?;
    validate_ref_list(
        &record.candidate_refs,
        "authoring workspace projection candidateRefs",
    )?;
    validate_ref_list(
        &record.dirty_projection_refs,
        "authoring workspace projection dirtyProjectionRefs",
    )?;
    validate_ref_list(
        &record.tool_mount_refs,
        "authoring workspace projection toolMountRefs",
    )?;
    validate_ref_list(
        &record.proof_target_refs,
        "authoring workspace projection proofTargetRefs",
    )?;
    validate_optional_ref_allow_empty(
        record.promotion_intent_ref.as_deref(),
        "authoring workspace projection promotionIntentRef",
    )?;
    validate_optional_ref_allow_empty(
        record.lifecycle_manifest_ref.as_deref(),
        "authoring workspace projection lifecycleManifestRef",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "authoring workspace projection blockedReasons",
    )?;
    validate_optional_text(
        record.observed_at.as_deref(),
        "authoring workspace projection observedAt",
    )?;
    Ok(())
}

pub fn validate_authoring_candidate_snapshot_posture(
    record: &AuthoringCandidateSnapshotPosture,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SWARM_WORKSPACE_AUTHORING_CANDIDATE_SNAPSHOT_POSTURE,
        "authoring candidate snapshot posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "authoring candidate snapshot posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "authoring candidate snapshot posture safeFacts",
    )?;
    validate_posture_state(&record.state, "authoring candidate snapshot posture state")?;
    validate_contract_ref(
        &record.candidate_snapshot_ref,
        "authoring candidate snapshot posture candidateSnapshotRef",
    )?;
    validate_contract_ref(
        &record.candidate_ref,
        "authoring candidate snapshot posture candidateRef",
    )?;
    validate_contract_ref(
        &record.edit_intent_ref,
        "authoring candidate snapshot posture editIntentRef",
    )?;
    validate_contract_ref(
        &record.workspace_ref,
        "authoring candidate snapshot posture workspaceRef",
    )?;
    validate_contract_ref(
        &record.entry_ref,
        "authoring candidate snapshot posture entryRef",
    )?;
    validate_contract_ref(
        &record.repo_ref,
        "authoring candidate snapshot posture repoRef",
    )?;
    validate_contract_ref(
        &record.module_ref,
        "authoring candidate snapshot posture moduleRef",
    )?;
    validate_contract_ref(
        &record.selected_version_ref,
        "authoring candidate snapshot posture selectedVersionRef",
    )?;
    validate_contract_ref(
        &record.parent_source_snapshot_ref,
        "authoring candidate snapshot posture parentSourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.content_index_ref,
        "authoring candidate snapshot posture contentIndexRef",
    )?;
    validate_ref_list(
        &record.dirty_projection_refs,
        "authoring candidate snapshot posture dirtyProjectionRefs",
    )?;
    validate_storage_object_ref_list(
        &record.storage_object_refs,
        "authoring candidate snapshot posture storageObjectRefs",
    )?;
    validate_storage_object_ref_list(
        &record.fulfilled_storage_object_refs,
        "authoring candidate snapshot posture fulfilledStorageObjectRefs",
    )?;
    validate_ref_list(
        &record.availability_refs,
        "authoring candidate snapshot posture availabilityRefs",
    )?;
    validate_ref_list(
        &record.tool_mount_refs,
        "authoring candidate snapshot posture toolMountRefs",
    )?;
    if let Some(target) = record.selected_proof_target.as_ref() {
        validate_authoring_proof_target(target)?;
    }
    validate_ref_list(
        &record.proof_target_refs,
        "authoring candidate snapshot posture proofTargetRefs",
    )?;
    validate_ref_list(
        &record.evidence_refs,
        "authoring candidate snapshot posture evidenceRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "authoring candidate snapshot posture blockedReasons",
    )?;
    if record.state == "ready" && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "ready authoring candidate snapshot posture cannot carry blockedReasons"
        ));
    }
    Ok(())
}

pub fn validate_source_ref_update(record: &SourceRefUpdate) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_REF_UPDATE,
        "source ref update",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source ref update")?;
    validate_contract_ref(&record.update_ref, "source ref update updateRef")?;
    validate_contract_ref(&record.source_graph_ref, "source ref update sourceGraphRef")?;
    validate_ref_name(&record.ref_name)?;
    validate_source_ref_kind(&record.ref_kind)?;
    validate_optional_ref(
        record.from_snapshot_ref.as_deref(),
        "source ref update fromSnapshotRef",
    )?;
    validate_contract_ref(&record.to_snapshot_ref, "source ref update toSnapshotRef")?;
    validate_contract_ref(&record.writer_ref, "source ref update writerRef")?;
    validate_source_update_state(&record.state)?;
    validate_ref_list(&record.grant_refs, "source ref update grantRefs")?;
    validate_ref_list(&record.evidence_refs, "source ref update evidenceRefs")?;
    validate_ref_list(&record.witness_refs, "source ref update witnessRefs")?;
    validate_reason_list(&record.blocked_reasons, "source ref update blockedReasons")?;
    validate_source_policy(&record.policy)?;
    if record.signed_at == 0 {
        return Err(anyhow!("source ref update missing signedAt"));
    }
    if record
        .valid_until
        .is_some_and(|valid_until| valid_until <= record.signed_at)
    {
        return Err(anyhow!(
            "source ref update validUntil must be after signedAt"
        ));
    }
    if matches!(
        record.state.as_str(),
        SOURCE_UPDATE_STATE_ACCEPTED | SOURCE_UPDATE_STATE_APPLIED
    ) && record.grant_refs.is_empty()
    {
        return Err(anyhow!("accepted source ref update needs grantRefs"));
    }
    if matches!(
        record.state.as_str(),
        SOURCE_UPDATE_STATE_REJECTED | SOURCE_UPDATE_STATE_BLOCKED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "blocked or rejected source ref update needs blockedReasons"
        ));
    }
    if matches!(
        record.state.as_str(),
        SOURCE_UPDATE_STATE_ACCEPTED | SOURCE_UPDATE_STATE_APPLIED
    ) && record.policy.fast_forward_only
        && record.from_snapshot_ref.is_none()
    {
        return Err(anyhow!(
            "fast-forward source ref update needs fromSnapshotRef"
        ));
    }
    Ok(())
}

pub fn validate_source_writer_grant(record: &SourceWriterGrant) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_WRITER_GRANT,
        "source writer grant",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source writer grant")?;
    validate_contract_ref(&record.grant_ref, "source writer grant grantRef")?;
    validate_contract_ref(
        &record.source_graph_ref,
        "source writer grant sourceGraphRef",
    )?;
    validate_contract_ref(&record.issuer_ref, "source writer grant issuerRef")?;
    validate_contract_ref(&record.subject_ref, "source writer grant subjectRef")?;
    validate_ref_list(&record.scope_refs, "source writer grant scopeRefs")?;
    validate_source_operations(&record.allowed_operations)?;
    validate_ref_list(&record.evidence_refs, "source writer grant evidenceRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("source writer grant missing issuedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.issued_at)
    {
        return Err(anyhow!(
            "source writer grant expiresAt must be after issuedAt"
        ));
    }
    if record
        .revoked_at
        .is_some_and(|revoked_at| revoked_at <= record.issued_at)
    {
        return Err(anyhow!(
            "source writer grant revokedAt must be after issuedAt"
        ));
    }
    if record.allowed_operations.is_empty() {
        return Err(anyhow!("source writer grant needs allowedOperations"));
    }
    Ok(())
}

pub fn validate_source_import_proof(record: &SourceImportProof) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_IMPORT_PROOF,
        "source import proof",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source import proof")?;
    validate_contract_ref(&record.import_ref, "source import proof importRef")?;
    validate_contract_ref(
        &record.source_graph_ref,
        "source import proof sourceGraphRef",
    )?;
    validate_contract_ref(&record.tool_ref, "source import proof toolRef")?;
    validate_contract_ref(&record.input_ref, "source import proof inputRef")?;
    validate_contract_ref(
        &record.output_snapshot_ref,
        "source import proof outputSnapshotRef",
    )?;
    validate_import_state(&record.state)?;
    validate_storage_object_ref_list(
        &record.imported_object_refs,
        "source import proof importedObjectRefs",
    )?;
    validate_ref_list(&record.evidence_refs, "source import proof evidenceRefs")?;
    validate_reason_list(
        &record.blocked_reasons,
        "source import proof blockedReasons",
    )?;
    if record.state == SOURCE_IMPORT_STATE_IMPORTED && record.imported_object_refs.is_empty() {
        return Err(anyhow!("imported source proof needs importedObjectRefs"));
    }
    if matches!(
        record.state.as_str(),
        SOURCE_IMPORT_STATE_BLOCKED | SOURCE_IMPORT_STATE_FAILED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "blocked or failed source import proof needs blockedReasons"
        ));
    }
    if record.observed_at == 0 {
        return Err(anyhow!("source import proof missing observedAt"));
    }
    Ok(())
}

pub fn validate_source_project_operation(record: &SourceProjectOperation) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_PROJECT_OPERATION,
        "source project operation",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source project operation")?;
    reject_private_fields(&record.safe_facts, "source project operation safeFacts")?;
    validate_contract_ref(
        &record.operation_ref,
        "source project operation operationRef",
    )?;
    validate_contract_ref(
        &record.source_graph_ref,
        "source project operation sourceGraphRef",
    )?;
    validate_contract_ref(&record.subject_ref, "source project operation subjectRef")?;
    validate_contract_ref(&record.actor_ref, "source project operation actorRef")?;
    validate_source_operation(&record.operation)?;
    validate_source_project_operation_state(&record.state)?;
    validate_source_project_compatibility_state(&record.compatibility_state)?;
    validate_ref_list(&record.scope_refs, "source project operation scopeRefs")?;
    validate_ref_list(
        &record.source_snapshot_refs,
        "source project operation sourceSnapshotRefs",
    )?;
    validate_ref_list(
        &record.content_index_refs,
        "source project operation contentIndexRefs",
    )?;
    validate_storage_object_ref_list(&record.storage_refs, "source project operation storageRefs")?;
    validate_ref_list(&record.branch_refs, "source project operation branchRefs")?;
    validate_ref_list(&record.tag_refs, "source project operation tagRefs")?;
    validate_ref_list(&record.release_refs, "source project operation releaseRefs")?;
    validate_ref_list(&record.project_refs, "source project operation projectRefs")?;
    validate_ref_list(
        &record.work_item_refs,
        "source project operation workItemRefs",
    )?;
    validate_ref_list(
        &record.build_target_refs,
        "source project operation buildTargetRefs",
    )?;
    validate_ref_list(
        &record.build_profile_refs,
        "source project operation buildProfileRefs",
    )?;
    validate_ref_list(
        &record.build_proof_refs,
        "source project operation buildProofRefs",
    )?;
    validate_ref_list(
        &record.compatibility_refs,
        "source project operation compatibilityRefs",
    )?;
    validate_ref_list(&record.proof_refs, "source project operation proofRefs")?;
    validate_ref_list(
        &record.evidence_refs,
        "source project operation evidenceRefs",
    )?;
    validate_ref_list(
        &record.rollback_refs,
        "source project operation rollbackRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "source project operation blockedReasons",
    )?;
    validate_time_bounds(
        record.issued_at,
        record.expires_at,
        "source project operation",
    )?;
    if matches!(
        record.state.as_str(),
        SOURCE_PROJECT_OPERATION_STATE_BLOCKED | SOURCE_PROJECT_OPERATION_STATE_REJECTED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "blocked or rejected source project operation needs blockedReasons"
        ));
    }
    if record.compatibility_state == SOURCE_PROJECT_COMPATIBILITY_UNSUPPORTED
        && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "unsupported source project operation needs blockedReasons"
        ));
    }
    if record.state == SOURCE_PROJECT_OPERATION_STATE_APPLIED
        && record.proof_refs.is_empty()
        && record.evidence_refs.is_empty()
    {
        return Err(anyhow!(
            "applied source project operation needs proofRefs or evidenceRefs"
        ));
    }
    if record.operation == SOURCE_OPERATION_RELEASE
        && record.release_refs.is_empty()
        && record.state != SOURCE_PROJECT_OPERATION_STATE_BLOCKED
    {
        return Err(anyhow!(
            "release source project operation needs releaseRefs unless blocked"
        ));
    }
    if record.operation == SOURCE_OPERATION_PROJECT_LINK
        && record.project_refs.is_empty()
        && record.work_item_refs.is_empty()
    {
        return Err(anyhow!(
            "project link source project operation needs projectRefs or workItemRefs"
        ));
    }
    Ok(())
}

pub fn source_ref(kind: &str, id: &str) -> String {
    format!("source:{kind}:{id}")
}

fn validate_source_policy(policy: &SourceGraphPolicy) -> Result<()> {
    validate_source_operations(&policy.allowed_operations)?;
    if policy.allowed_operations.is_empty() {
        return Err(anyhow!("source policy needs allowedOperations"));
    }
    Ok(())
}

fn validate_source_operations(values: &[String]) -> Result<()> {
    for value in values {
        validate_source_operation(value)?;
    }
    Ok(())
}

fn validate_source_operation(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_OPERATION_IMPORT
            | SOURCE_OPERATION_FETCH
            | SOURCE_OPERATION_PUSH
            | SOURCE_OPERATION_STATUS
            | SOURCE_OPERATION_REF_UPDATE
            | SOURCE_OPERATION_BRANCH
            | SOURCE_OPERATION_TAG
            | SOURCE_OPERATION_RELEASE
            | SOURCE_OPERATION_PROJECT_LINK
            | SOURCE_OPERATION_EXPORT
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source operation"))
    }
}

fn validate_source_graph_state(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_GRAPH_STATE_READY | SOURCE_GRAPH_STATE_DEGRADED | SOURCE_GRAPH_STATE_BLOCKED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source graph state"))
    }
}

fn validate_source_signature_posture(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_SIGNATURE_POSTURE_SIGNED
            | SOURCE_SIGNATURE_POSTURE_DEV_UNSIGNED
            | SOURCE_SIGNATURE_POSTURE_BLOCKED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source signature posture"))
    }
}

fn validate_source_file_entry(record: &SourceFileEntry) -> Result<()> {
    validate_contract_ref(&record.file_ref, "source file entry fileRef")?;
    validate_contract_ref(&record.path_ref, "source file entry pathRef")?;
    validate_virtual_path(&record.virtual_path)?;
    validate_hash_ref(&record.hash_ref, "source file entry hashRef")?;
    if record.byte_length == 0 {
        return Err(anyhow!("source file entry missing byteLength"));
    }
    if let Some(storage_object_ref) = record.storage_object_ref.as_deref() {
        validate_storage_object_ref(storage_object_ref, "source file entry storageObjectRef")?;
    }
    validate_ref_list(&record.evidence_refs, "source file entry evidenceRefs")
}

fn validate_source_version_index_entry(record: &SourceVersionIndexEntry) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SOURCE_VERSION_INDEX_ENTRY,
        "source version-index entry",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "source version-index entry")?;
    reject_private_fields(&record.safe_facts, "source version-index entry safeFacts")?;
    validate_contract_ref(&record.entry_ref, "source version-index entry entryRef")?;
    validate_contract_ref(
        &record.contract_ref,
        "source version-index entry contractRef",
    )?;
    validate_contract_ref(
        &record.contract_version_ref,
        "source version-index entry contractVersionRef",
    )?;
    validate_contract_ref(
        &record.selected_version_ref,
        "source version-index entry selectedVersionRef",
    )?;
    validate_contract_ref(&record.module_ref, "source version-index entry moduleRef")?;
    validate_contract_ref(&record.repo_ref, "source version-index entry repoRef")?;
    validate_optional_text(record.role.as_deref(), "source version-index entry role")?;
    validate_optional_text(
        record.declared_version.as_deref(),
        "source version-index entry declaredVersion",
    )?;
    validate_contract_ref(
        &record.source_snapshot_ref,
        "source version-index entry sourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.content_index_ref,
        "source version-index entry contentIndexRef",
    )?;
    if let Some(tree_hash_ref) = record.tree_hash_ref.as_deref() {
        validate_hash_ref(tree_hash_ref, "source version-index entry treeHashRef")?;
    }
    validate_optional_ref(
        record.artifact_ref.as_deref(),
        "source version-index entry artifactRef",
    )?;
    validate_optional_ref(
        record.compatibility_ref.as_deref(),
        "source version-index entry compatibilityRef",
    )?;
    validate_optional_ref(
        record.selected_by_ref.as_deref(),
        "source version-index entry selectedByRef",
    )?;
    validate_ref_list(
        &record.authority_refs,
        "source version-index entry authorityRefs",
    )?;
    validate_ref_list(
        &record.writer_grant_refs,
        "source version-index entry writerGrantRefs",
    )?;
    Ok(())
}

fn validate_authoring_proof_target(record: &AuthoringProofTarget) -> Result<()> {
    validate_contract_ref(
        &record.proof_target_ref,
        "authoring proof target proofTargetRef",
    )?;
    validate_posture_state(&record.state, "authoring proof target state")?;
    validate_optional_ref_allow_empty(
        record.action_adapter_ref.as_deref(),
        "authoring proof target actionAdapterRef",
    )?;
    validate_optional_ref_allow_empty(
        record.latest_evidence_ref.as_deref(),
        "authoring proof target latestEvidenceRef",
    )?;
    Ok(())
}

fn validate_authoring_candidate_feedback_posture(
    record: &AuthoringCandidateFeedbackPosture,
) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SWARM_WORKSPACE_AUTHORING_CANDIDATE_FEEDBACK_POSTURE,
        "authoring candidate feedback posture",
    )?;
    reject_private_fields(
        &serde_json::to_value(record)?,
        "authoring candidate feedback posture",
    )?;
    reject_private_fields(
        &record.safe_facts,
        "authoring candidate feedback posture safeFacts",
    )?;
    validate_posture_state(&record.state, "authoring candidate feedback posture state")?;
    validate_ref_list(
        &record.candidate_snapshot_refs,
        "authoring candidate feedback posture candidateSnapshotRefs",
    )?;
    validate_ref_list(
        &record.candidate_refs,
        "authoring candidate feedback posture candidateRefs",
    )?;
    validate_ref_list(
        &record.source_ref_update_refs,
        "authoring candidate feedback posture sourceRefUpdateRefs",
    )?;
    validate_storage_object_ref_list(
        &record.storage_object_refs,
        "authoring candidate feedback posture storageObjectRefs",
    )?;
    validate_ref_list(
        &record.availability_refs,
        "authoring candidate feedback posture availabilityRefs",
    )?;
    validate_ref_list(
        &record.proof_event_refs,
        "authoring candidate feedback posture proofEventRefs",
    )?;
    validate_ref_list(
        &record.promotion_intent_refs,
        "authoring candidate feedback posture promotionIntentRefs",
    )?;
    validate_ref_list(
        &record.lifecycle_request_refs,
        "authoring candidate feedback posture lifecycleRequestRefs",
    )?;
    validate_ref_list(
        &record.report_refs,
        "authoring candidate feedback posture reportRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "authoring candidate feedback posture blockedReasons",
    )?;
    if record.state == "ready" && record.candidate_snapshot_refs.is_empty() {
        return Err(anyhow!(
            "ready authoring candidate feedback posture needs candidateSnapshotRefs"
        ));
    }
    if record.state == "ready" && !record.blocked_reasons.is_empty() {
        return Err(anyhow!(
            "ready authoring candidate feedback posture cannot carry blockedReasons"
        ));
    }
    Ok(())
}

fn validate_authoring_workspace_entry(record: &AuthoringWorkspaceEntry) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_SWARM_WORKSPACE_AUTHORING_ENTRY,
        "authoring workspace entry",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "authoring workspace entry")?;
    reject_private_fields(&record.safe_facts, "authoring workspace entry safeFacts")?;
    validate_contract_ref(&record.entry_ref, "authoring workspace entry entryRef")?;
    validate_posture_state(&record.state, "authoring workspace entry state")?;
    validate_contract_ref(&record.repo_ref, "authoring workspace entry repoRef")?;
    validate_contract_ref(&record.module_ref, "authoring workspace entry moduleRef")?;
    validate_optional_text(record.role.as_deref(), "authoring workspace entry role")?;
    validate_contract_ref(
        &record.selected_version_ref,
        "authoring workspace entry selectedVersionRef",
    )?;
    validate_optional_ref_allow_empty(
        record.contract_version_ref.as_deref(),
        "authoring workspace entry contractVersionRef",
    )?;
    validate_contract_ref(
        &record.source_snapshot_ref,
        "authoring workspace entry sourceSnapshotRef",
    )?;
    validate_contract_ref(
        &record.content_index_ref,
        "authoring workspace entry contentIndexRef",
    )?;
    validate_ref_list(
        &record.candidate_refs,
        "authoring workspace entry candidateRefs",
    )?;
    validate_ref_list(
        &record.dirty_projection_refs,
        "authoring workspace entry dirtyProjectionRefs",
    )?;
    validate_ref_list(
        &record.editable_file_refs,
        "authoring workspace entry editableFileRefs",
    )?;
    validate_storage_object_ref_list(
        &record.storage_object_refs,
        "authoring workspace entry storageObjectRefs",
    )?;
    validate_ref_list(
        &record.availability_refs,
        "authoring workspace entry availabilityRefs",
    )?;
    if let Some(candidate_feedback) = record.candidate_feedback.as_ref() {
        validate_authoring_candidate_feedback_posture(candidate_feedback)?;
    }
    validate_ref_list(
        &record.materialized_projection_refs,
        "authoring workspace entry materializedProjectionRefs",
    )?;
    validate_ref_list(
        &record.tool_mount_refs,
        "authoring workspace entry toolMountRefs",
    )?;
    for target in &record.proof_targets {
        validate_authoring_proof_target(target)?;
    }
    validate_ref_list(
        &record.proof_target_refs,
        "authoring workspace entry proofTargetRefs",
    )?;
    validate_reason_list(
        &record.blocked_reasons,
        "authoring workspace entry blockedReasons",
    )?;
    Ok(())
}

fn validate_source_ref_kind(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_REF_KIND_BRANCH | SOURCE_REF_KIND_TAG | SOURCE_REF_KIND_NOTE
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source ref kind"))
    }
}

fn validate_source_update_state(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_UPDATE_STATE_REQUESTED
            | SOURCE_UPDATE_STATE_ACCEPTED
            | SOURCE_UPDATE_STATE_APPLIED
            | SOURCE_UPDATE_STATE_REJECTED
            | SOURCE_UPDATE_STATE_BLOCKED
            | SOURCE_UPDATE_STATE_SUPERSEDED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source ref update state"))
    }
}

fn validate_source_project_operation_state(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_PROJECT_OPERATION_STATE_REQUESTED
            | SOURCE_PROJECT_OPERATION_STATE_READY
            | SOURCE_PROJECT_OPERATION_STATE_APPLIED
            | SOURCE_PROJECT_OPERATION_STATE_BLOCKED
            | SOURCE_PROJECT_OPERATION_STATE_REJECTED
            | SOURCE_PROJECT_OPERATION_STATE_SUPERSEDED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source project operation state"))
    }
}

fn validate_source_project_compatibility_state(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_PROJECT_COMPATIBILITY_SUPPORTED
            | SOURCE_PROJECT_COMPATIBILITY_DEGRADED
            | SOURCE_PROJECT_COMPATIBILITY_UNSUPPORTED
    ) {
        Ok(())
    } else {
        Err(anyhow!(
            "unsupported source project operation compatibility state"
        ))
    }
}

fn validate_import_state(value: &str) -> Result<()> {
    if matches!(
        value,
        SOURCE_IMPORT_STATE_PENDING
            | SOURCE_IMPORT_STATE_IMPORTED
            | SOURCE_IMPORT_STATE_BLOCKED
            | SOURCE_IMPORT_STATE_FAILED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported source import state"))
    }
}

fn validate_optional_kind(kind: Option<&str>, expected: &str, context: &str) -> Result<()> {
    if let Some(kind) = kind {
        if kind != expected {
            return Err(anyhow!("{context} kind mismatch"));
        }
    }
    Ok(())
}

fn validate_optional_ref(value: Option<&str>, context: &str) -> Result<()> {
    if let Some(value) = value {
        validate_contract_ref(value, context)?;
    }
    Ok(())
}

fn validate_optional_ref_allow_empty(value: Option<&str>, context: &str) -> Result<()> {
    if let Some(value) = value {
        if !value.is_empty() {
            validate_contract_ref(value, context)?;
        }
    }
    Ok(())
}

fn validate_ref_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        validate_contract_ref(value, context)?;
    }
    Ok(())
}

fn validate_storage_object_ref_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        validate_storage_object_ref(value, context)?;
    }
    Ok(())
}

fn validate_storage_object_ref(value: &str, context: &str) -> Result<()> {
    validate_contract_ref(value, context)?;
    let object_id = value
        .strip_prefix("storage:object:")
        .ok_or_else(|| anyhow!("{context} must be storage object refs"))?;
    if object_id.len() == 64 && object_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow!(
            "{context} must be content-addressed storage object refs"
        ))
    }
}

fn validate_hash_ref(value: &str, context: &str) -> Result<()> {
    validate_contract_ref(value, context)?;
    let hash = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("{context} must be sha256 hash ref"))?;
    if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow!("{context} must be sha256:<64 hex>"))
    }
}

fn validate_virtual_path(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("source file entry missing virtualPath"));
    }
    if value != value.trim()
        || value.contains('\\')
        || value.contains("..")
        || value.starts_with('/')
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
        || value.contains(':')
    {
        return Err(anyhow!(
            "source file entry virtualPath must be a logical relative path"
        ));
    }
    Ok(())
}

fn validate_reason_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        validate_reason(value, context)?;
    }
    Ok(())
}

fn validate_posture_state(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() || value.chars().any(char::is_whitespace) {
        return Err(anyhow!("{context} must be a compact state token"));
    }
    Ok(())
}

fn validate_optional_text(value: Option<&str>, context: &str) -> Result<()> {
    if let Some(value) = value {
        if value.trim().is_empty() || value != value.trim() || value.contains('\\') {
            return Err(anyhow!("{context} must be non-empty clean text"));
        }
    }
    Ok(())
}

fn validate_contract_ref(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{context} is empty"));
    }
    if value != value.trim()
        || value.chars().any(char::is_whitespace)
        || value.contains('\\')
        || value.starts_with('/')
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
        || !value.contains(':')
    {
        return Err(anyhow!(
            "{context} must be a contract/storage ref, not a raw path or URL"
        ));
    }
    Ok(())
}

fn validate_reason(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{context} contains empty reason"));
    }
    if value != value.trim()
        || value.chars().any(char::is_whitespace)
        || value.contains('\\')
        || value.starts_with('/')
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
    {
        return Err(anyhow!(
            "{context} must contain reason codes, not paths or text blobs"
        ));
    }
    Ok(())
}

fn validate_ref_name(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("source ref update missing refName"));
    }
    if value != value.trim()
        || value.contains('\\')
        || value.contains("..")
        || value.starts_with('/')
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
    {
        return Err(anyhow!("source refName must be a logical git-style ref"));
    }
    Ok(())
}

fn validate_time_bounds(issued_at: u64, expires_at: Option<u64>, context: &str) -> Result<()> {
    if issued_at == 0 {
        return Err(anyhow!("{context} missing issuedAt"));
    }
    if expires_at.is_some_and(|expires_at| expires_at <= issued_at) {
        return Err(anyhow!("{context} expiresAt must be after issuedAt"));
    }
    Ok(())
}

fn reject_private_fields(value: &Value, context: &str) -> Result<()> {
    let Value::Object(map) = value else {
        return Ok(());
    };
    for key in map.keys() {
        let lower = key.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "raw"
                | "payload"
                | "sourcebytes"
                | "packbytes"
                | "codebytes"
                | "ciphertext"
                | "localpath"
                | "filesystempath"
                | "workspacepath"
                | "secret"
                | "credential"
        ) {
            return Err(anyhow!("{context} contains private or bulk field {key}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SOURCE_STORAGE_OBJECT_REF: &str =
        "storage:object:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn policy() -> SourceGraphPolicy {
        SourceGraphPolicy {
            fast_forward_only: true,
            review_required: true,
            signed_updates_required: true,
            allowed_operations: vec![
                SOURCE_OPERATION_IMPORT.to_string(),
                SOURCE_OPERATION_FETCH.to_string(),
                SOURCE_OPERATION_PUSH.to_string(),
                SOURCE_OPERATION_REF_UPDATE.to_string(),
                SOURCE_OPERATION_STATUS.to_string(),
            ],
        }
    }

    #[test]
    fn validates_source_version_graph_family() {
        let graph = SourceVersionGraph {
            kind: Some(RECORD_SOURCE_VERSION_GRAPH.to_string()),
            source_graph_ref: "source:graph:constitute-git".to_string(),
            owner_ref: "identity:root:aux".to_string(),
            storage_backend_ref: "storage:backend:local".to_string(),
            default_branch_ref: "source:ref:main".to_string(),
            head_snapshot_ref: "source:snapshot:head".to_string(),
            state: SOURCE_GRAPH_STATE_READY.to_string(),
            policy: policy(),
            branch_refs: vec!["source:ref:main".to_string()],
            tag_refs: vec![],
            writer_grant_refs: vec!["source:grant:writer".to_string()],
            release_refs: vec![],
            evidence_refs: vec!["source:evidence:init".to_string()],
            blocked_reasons: vec![],
            issued_at: 1,
            expires_at: Some(10),
        };
        validate_source_version_graph(&graph).expect("valid graph");

        let snapshot = SourceSnapshot {
            kind: Some(RECORD_SOURCE_SNAPSHOT.to_string()),
            source_graph_ref: graph.source_graph_ref.clone(),
            snapshot_ref: graph.head_snapshot_ref.clone(),
            commit_ref: "git:commit:abcd".to_string(),
            tree_ref: "git:tree:efgh".to_string(),
            tree_hash_ref:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            parent_snapshot_refs: vec!["source:snapshot:parent".to_string()],
            file_entries: vec![SourceFileEntry {
                file_ref: "source:file:constitute-git:src/lib.rs".to_string(),
                path_ref: "source:path:constitute-git:src-lib-rs".to_string(),
                virtual_path: "src/lib.rs".to_string(),
                hash_ref: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
                byte_length: 42,
                storage_object_ref: None,
                evidence_refs: vec!["source:evidence:file-hash".to_string()],
            }],
            storage_object_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
            author_ref: graph.owner_ref.clone(),
            signature_posture: SOURCE_SIGNATURE_POSTURE_SIGNED.to_string(),
            message_digest_ref: "digest:sha256:message".to_string(),
            branch_refs: vec!["source:ref:main".to_string()],
            candidate_refs: vec![],
            writer_grant_refs: vec!["source:grant:writer".to_string()],
            authority_refs: vec!["authority:source:root".to_string()],
            materialized_projection_refs: vec!["materialized:source-index:head".to_string()],
            dirty_projection_refs: vec![],
            signature_refs: vec!["signature:source:head".to_string()],
            evidence_refs: vec!["source:evidence:pack-import".to_string()],
            issued_at: 2,
        };
        validate_source_snapshot(&snapshot).expect("valid snapshot");

        let mut dirty_without_candidate = snapshot.clone();
        dirty_without_candidate.snapshot_ref = "source:snapshot:dirty-no-candidate".to_string();
        dirty_without_candidate.dirty_projection_refs =
            vec!["materialized:source-index:dirty".to_string()];
        assert!(validate_source_snapshot(&dirty_without_candidate).is_err());

        let mut dev_unsigned = snapshot.clone();
        dev_unsigned.snapshot_ref = "source:snapshot:dev-unsigned".to_string();
        dev_unsigned.signature_posture = SOURCE_SIGNATURE_POSTURE_DEV_UNSIGNED.to_string();
        dev_unsigned.signature_refs.clear();
        dev_unsigned.evidence_refs = vec!["source:evidence:dev-unsigned-explicit".to_string()];
        validate_source_snapshot(&dev_unsigned).expect("valid dev unsigned snapshot");

        let version_entry = SourceVersionIndexEntry {
            kind: Some(RECORD_SOURCE_VERSION_INDEX_ENTRY.to_string()),
            entry_ref: "version-index-entry:native-dev:constitute-protocol".to_string(),
            contract_ref: "contract:module:constitute-protocol".to_string(),
            contract_version_ref: "contract-version:constitute-protocol:0.1.0".to_string(),
            selected_version_ref: "version-selection:native-dev:constitute-protocol:aaaa"
                .to_string(),
            module_ref: "module:native-dev:constitute-protocol".to_string(),
            repo_ref: "repo:constitute-protocol".to_string(),
            role: Some("protocol".to_string()),
            declared_version: Some("0.1.0".to_string()),
            source_snapshot_ref: snapshot.snapshot_ref.clone(),
            content_index_ref: "content-index:native-dev:constitute-protocol".to_string(),
            tree_hash_ref: Some(snapshot.tree_hash_ref.clone()),
            artifact_ref: Some("artifact:native-dev:constitute-protocol:aaaa".to_string()),
            compatibility_ref: Some(
                "compat:contract-version:constitute-protocol:0.1.0".to_string(),
            ),
            selected_by_ref: Some("contract:intention:native-dev:branch-family".to_string()),
            authority_refs: vec!["authority:source:root".to_string()],
            writer_grant_refs: vec!["source:grant:writer".to_string()],
            safe_facts: Value::Null,
        };
        let version_index = SourceVersionIndexProjection {
            kind: Some(RECORD_SOURCE_VERSION_INDEX_PROJECTION.to_string()),
            state: "ready".to_string(),
            version_index_ref: "version-index:native-dev:aaaa".to_string(),
            source_snapshot_ref: snapshot.snapshot_ref.clone(),
            content_index_ref: "content-index:native-dev:root".to_string(),
            entry_count: 1,
            entries: vec![version_entry.clone()],
            selected_version_refs: vec![version_entry.selected_version_ref.clone()],
            contract_version_refs: vec![version_entry.contract_version_ref.clone()],
            module_refs: vec![version_entry.module_ref.clone()],
            evidence_refs: vec!["evidence:native-source:version-index".to_string()],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({
                "versionIndexOwnsSelection": true
            }),
            observed_at: Some("2026-05-24T00:00:00.000Z".to_string()),
        };
        validate_source_version_index_projection(&version_index).expect("valid version index");

        let proof_target = AuthoringProofTarget {
            proof_target_ref: "proof-target:build:native-dev:constitute-protocol".to_string(),
            state: "queued".to_string(),
            action_adapter_ref: Some("cargo:check:constitute-protocol".to_string()),
            latest_evidence_ref: Some("proof-event:cargo:check:constitute-protocol".to_string()),
        };
        let authoring_entry = AuthoringWorkspaceEntry {
            kind: Some(RECORD_SWARM_WORKSPACE_AUTHORING_ENTRY.to_string()),
            entry_ref: "swarm-workspace:authoring-entry:native-dev:constitute-protocol".to_string(),
            state: "candidateAuthoring".to_string(),
            repo_ref: version_entry.repo_ref.clone(),
            module_ref: version_entry.module_ref.clone(),
            role: Some("protocol".to_string()),
            selected_version_ref: version_entry.selected_version_ref.clone(),
            contract_version_ref: Some(version_entry.contract_version_ref.clone()),
            source_snapshot_ref: snapshot.snapshot_ref.clone(),
            content_index_ref: version_entry.content_index_ref.clone(),
            candidate_refs: vec![
                "source:candidate:native-dev:constitute-protocol:aaaa".to_string(),
            ],
            dirty_projection_refs: vec![
                "materialized:source-index:native-dev:constitute-protocol:dirty".to_string(),
            ],
            editable_file_refs: vec!["source:file:constitute-protocol:src-source-rs".to_string()],
            editable_file_count: 1,
            storage_object_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
            availability_refs: vec!["storage-availability:source:constitute-protocol".to_string()],
            candidate_feedback: Some(AuthoringCandidateFeedbackPosture {
                kind: Some(RECORD_SWARM_WORKSPACE_AUTHORING_CANDIDATE_FEEDBACK_POSTURE.to_string()),
                state: "ready".to_string(),
                candidate_snapshot_refs: vec![
                    "source:snapshot:candidate:constitute-protocol:aaaa".to_string(),
                ],
                candidate_refs: vec![
                    "source:candidate:native-dev:constitute-protocol:aaaa".to_string(),
                ],
                source_ref_update_refs: vec![
                    "source:update:native-dev:constitute-protocol:aaaa".to_string(),
                ],
                storage_object_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
                availability_refs: vec![
                    "storage-availability:source:constitute-protocol".to_string(),
                ],
                proof_event_refs: vec![
                    "proof-event:operator:authoring-candidate-fixture".to_string(),
                ],
                promotion_intent_refs: vec![
                    "promotion:intent:source-candidate:constitute-protocol:aaaa".to_string(),
                ],
                lifecycle_request_refs: vec![
                    "lifecycle-request:promote:source:snapshot:candidate:constitute-protocol:aaaa"
                        .to_string(),
                ],
                report_refs: vec![
                    "operator-report:authoring-candidate-fixture:constitute-protocol".to_string(),
                ],
                blocked_reasons: vec![],
                safe_facts: Value::Null,
            }),
            materialized_projection_refs: vec![
                "materialized:source-index:native-dev:constitute-protocol".to_string(),
            ],
            tool_mount_refs: vec!["materialized:path:constitute-protocol:src".to_string()],
            proof_targets: vec![proof_target.clone()],
            proof_target_refs: vec![proof_target.proof_target_ref.clone()],
            blocked_reasons: vec![],
            safe_facts: Value::Null,
        };
        let workspace = AuthoringWorkspaceProjection {
            kind: Some(RECORD_SWARM_WORKSPACE_AUTHORING_PROJECTION.to_string()),
            state: "ready".to_string(),
            workspace_ref: "swarm-workspace:authoring:native-dev:aaaa".to_string(),
            source_snapshot_ref: snapshot.snapshot_ref.clone(),
            content_index_ref: version_index.content_index_ref.clone(),
            version_index_ref: version_index.version_index_ref.clone(),
            resolver_ref: Some("module-resolver:native-dev:aaaa".to_string()),
            entry_count: 1,
            editable_file_count: 1,
            selected_version_refs: version_index.selected_version_refs.clone(),
            candidate_refs: authoring_entry.candidate_refs.clone(),
            dirty_projection_refs: authoring_entry.dirty_projection_refs.clone(),
            tool_mount_refs: authoring_entry.tool_mount_refs.clone(),
            proof_target_refs: authoring_entry.proof_target_refs.clone(),
            promotion_intent_ref: Some("source:promotion-intent:native-dev:aaaa".to_string()),
            lifecycle_manifest_ref: Some("lifecycle:manifest:native-dev:aaaa".to_string()),
            authoring_entries: vec![authoring_entry.clone()],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({
                "typedFlagsArePostureProjection": true
            }),
            observed_at: Some("2026-05-24T00:00:00.000Z".to_string()),
        };
        validate_authoring_workspace_projection(&workspace).expect("valid authoring workspace");

        let candidate = AuthoringCandidateSnapshotPosture {
            kind: Some(RECORD_SWARM_WORKSPACE_AUTHORING_CANDIDATE_SNAPSHOT_POSTURE.to_string()),
            state: "ready".to_string(),
            candidate_snapshot_ref: "source:snapshot:candidate:constitute-protocol:aaaa"
                .to_string(),
            candidate_ref: authoring_entry.candidate_refs[0].clone(),
            edit_intent_ref: "authoring:edit-intent:native-dev:constitute-protocol:aaaa"
                .to_string(),
            workspace_ref: workspace.workspace_ref.clone(),
            entry_ref: authoring_entry.entry_ref.clone(),
            repo_ref: authoring_entry.repo_ref.clone(),
            module_ref: authoring_entry.module_ref.clone(),
            selected_version_ref: authoring_entry.selected_version_ref.clone(),
            parent_source_snapshot_ref: snapshot.snapshot_ref.clone(),
            content_index_ref: authoring_entry.content_index_ref.clone(),
            dirty_projection_refs: authoring_entry.dirty_projection_refs.clone(),
            editable_file_count: 1,
            storage_object_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
            fulfilled_storage_object_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
            availability_refs: authoring_entry.availability_refs.clone(),
            tool_mount_refs: authoring_entry.tool_mount_refs.clone(),
            selected_proof_target: Some(proof_target.clone()),
            proof_target_refs: vec![proof_target.proof_target_ref],
            evidence_refs: vec!["proof-event:operator:authoring-candidate-fixture".to_string()],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({
                "sourceCandidateCliIsActionAdapter": true
            }),
        };
        validate_authoring_candidate_snapshot_posture(&candidate)
            .expect("valid authoring candidate posture");

        let update = SourceRefUpdate {
            kind: Some(RECORD_SOURCE_REF_UPDATE.to_string()),
            update_ref: "source:update:main".to_string(),
            source_graph_ref: graph.source_graph_ref.clone(),
            ref_name: "refs/heads/main".to_string(),
            ref_kind: SOURCE_REF_KIND_BRANCH.to_string(),
            from_snapshot_ref: Some("source:snapshot:parent".to_string()),
            to_snapshot_ref: snapshot.snapshot_ref,
            writer_ref: graph.owner_ref.clone(),
            state: SOURCE_UPDATE_STATE_APPLIED.to_string(),
            grant_refs: vec!["source:grant:writer".to_string()],
            evidence_refs: vec!["source:evidence:fast-forward".to_string()],
            witness_refs: vec!["source:witness:runtime".to_string()],
            blocked_reasons: vec![],
            policy: policy(),
            signed_at: 3,
            valid_until: Some(20),
        };
        validate_source_ref_update(&update).expect("valid ref update");
    }

    #[test]
    fn rejects_source_graph_paths_and_policy_gaps() {
        let mut graph = SourceVersionGraph {
            kind: Some(RECORD_SOURCE_VERSION_GRAPH.to_string()),
            source_graph_ref: "C:\\repos\\bad".to_string(),
            owner_ref: "identity:root:aux".to_string(),
            storage_backend_ref: "storage:backend:local".to_string(),
            default_branch_ref: "source:ref:main".to_string(),
            head_snapshot_ref: "source:snapshot:head".to_string(),
            state: SOURCE_GRAPH_STATE_READY.to_string(),
            policy: policy(),
            branch_refs: vec![],
            tag_refs: vec![],
            writer_grant_refs: vec![],
            release_refs: vec![],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            issued_at: 1,
            expires_at: None,
        };
        assert!(validate_source_version_graph(&graph).is_err());

        graph.source_graph_ref = "source:graph:ok".to_string();
        graph.policy.allowed_operations.clear();
        assert!(validate_source_version_graph(&graph).is_err());
    }

    #[test]
    fn validates_source_writer_grant_and_import_proof() {
        let grant = SourceWriterGrant {
            kind: Some(RECORD_SOURCE_WRITER_GRANT.to_string()),
            grant_ref: "source:grant:writer".to_string(),
            source_graph_ref: "source:graph:constitute-git".to_string(),
            issuer_ref: "identity:root:aux".to_string(),
            subject_ref: "identity:device:agent".to_string(),
            scope_refs: vec!["source:ref:main".to_string()],
            allowed_operations: vec![SOURCE_OPERATION_PUSH.to_string()],
            evidence_refs: vec!["authority:grant:source-writer".to_string()],
            issued_at: 1,
            expires_at: Some(10),
            revoked_at: None,
        };
        validate_source_writer_grant(&grant).expect("valid grant");

        let proof = SourceImportProof {
            kind: Some(RECORD_SOURCE_IMPORT_PROOF.to_string()),
            import_ref: "source:import:initial".to_string(),
            source_graph_ref: grant.source_graph_ref,
            tool_ref: "tool:git:import".to_string(),
            input_ref: "git:pack:input".to_string(),
            output_snapshot_ref: "source:snapshot:head".to_string(),
            state: SOURCE_IMPORT_STATE_IMPORTED.to_string(),
            imported_object_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
            evidence_refs: vec!["source:evidence:hash-check".to_string()],
            blocked_reasons: vec![],
            safe_facts: Value::Null,
            observed_at: 2,
        };
        validate_source_import_proof(&proof).expect("valid import proof");
    }

    #[test]
    fn blocked_fast_forward_update_can_name_missing_base() {
        let update = SourceRefUpdate {
            kind: Some(RECORD_SOURCE_REF_UPDATE.to_string()),
            update_ref: "source:update:main-blocked".to_string(),
            source_graph_ref: "source:graph:constitute-git".to_string(),
            ref_name: "refs/heads/main".to_string(),
            ref_kind: SOURCE_REF_KIND_BRANCH.to_string(),
            from_snapshot_ref: None,
            to_snapshot_ref: "source:snapshot:head".to_string(),
            writer_ref: "identity:device:agent".to_string(),
            state: SOURCE_UPDATE_STATE_BLOCKED.to_string(),
            grant_refs: vec![],
            evidence_refs: vec![],
            witness_refs: vec![],
            blocked_reasons: vec!["source.policy.fastForwardRequired".to_string()],
            policy: policy(),
            signed_at: 3,
            valid_until: Some(20),
        };
        validate_source_ref_update(&update).expect("blocked update can carry missing base posture");
    }

    #[test]
    fn validates_source_project_operation_posture() {
        let operation = SourceProjectOperation {
            kind: Some(RECORD_SOURCE_PROJECT_OPERATION.to_string()),
            operation_ref: "source:operation:release-main".to_string(),
            source_graph_ref: "source:graph:constitute-git".to_string(),
            subject_ref: "source:ref:main".to_string(),
            actor_ref: "identity:device:agent".to_string(),
            operation: SOURCE_OPERATION_RELEASE.to_string(),
            state: SOURCE_PROJECT_OPERATION_STATE_APPLIED.to_string(),
            compatibility_state: SOURCE_PROJECT_COMPATIBILITY_SUPPORTED.to_string(),
            scope_refs: vec!["source:ref:main".to_string()],
            source_snapshot_refs: vec!["source:snapshot:head".to_string()],
            content_index_refs: vec!["content-index:source:constitute-git".to_string()],
            storage_refs: vec![TEST_SOURCE_STORAGE_OBJECT_REF.to_string()],
            branch_refs: vec!["source:ref:main".to_string()],
            tag_refs: vec!["source:tag:v0.1.0".to_string()],
            release_refs: vec!["release:source:v0.1.0".to_string()],
            project_refs: vec!["project:constituency".to_string()],
            work_item_refs: vec!["work-item:git-project-hardening".to_string()],
            build_target_refs: vec!["build:target:web".to_string()],
            build_profile_refs: vec!["build:profile:dev".to_string()],
            build_proof_refs: vec!["build:proof:surface".to_string()],
            compatibility_refs: vec!["compat:git:refs-v1".to_string()],
            proof_refs: vec!["proof:source-release:main".to_string()],
            evidence_refs: vec!["evidence:source-release:main".to_string()],
            rollback_refs: vec!["rollback:source:previous".to_string()],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({
                "operation": "release",
                "branch": "main",
                "compatibility": "supported"
            }),
            issued_at: 3,
            expires_at: Some(20),
        };
        validate_source_project_operation(&operation).expect("valid source project operation");

        let mut unsupported = operation.clone();
        unsupported.operation_ref = "source:operation:git-pack-export".to_string();
        unsupported.operation = SOURCE_OPERATION_EXPORT.to_string();
        unsupported.state = SOURCE_PROJECT_OPERATION_STATE_BLOCKED.to_string();
        unsupported.compatibility_state = SOURCE_PROJECT_COMPATIBILITY_UNSUPPORTED.to_string();
        unsupported.release_refs.clear();
        unsupported.blocked_reasons = vec!["source.compatibility.gitPackUnsupported".to_string()];
        validate_source_project_operation(&unsupported)
            .expect("unsupported compatibility can be explicit posture");

        let mut missing_evidence = operation.clone();
        missing_evidence.proof_refs.clear();
        missing_evidence.evidence_refs.clear();
        assert!(validate_source_project_operation(&missing_evidence).is_err());

        let mut unsafe_facts = operation;
        unsafe_facts.safe_facts = serde_json::json!({ "raw": "secret source bytes" });
        assert!(validate_source_project_operation(&unsafe_facts).is_err());
    }
}
