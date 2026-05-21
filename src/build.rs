use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RECORD_BUILD_CONTRACT: &str = "build.contract";
pub const RECORD_BUILD_RUN: &str = "build.run";
pub const RECORD_BUILD_ARTIFACT: &str = "build.artifact";
pub const RECORD_BUILD_PROOF: &str = "build.proof";

pub const BUILD_CONTRACT_STATE_DRAFT: &str = "draft";
pub const BUILD_CONTRACT_STATE_READY: &str = "ready";
pub const BUILD_CONTRACT_STATE_BLOCKED: &str = "blocked";
pub const BUILD_CONTRACT_STATE_SUPERSEDED: &str = "superseded";

pub const BUILD_RUN_STATE_REQUESTED: &str = "requested";
pub const BUILD_RUN_STATE_ACCEPTED: &str = "accepted";
pub const BUILD_RUN_STATE_RUNNING: &str = "running";
pub const BUILD_RUN_STATE_SUCCEEDED: &str = "succeeded";
pub const BUILD_RUN_STATE_FAILED: &str = "failed";
pub const BUILD_RUN_STATE_BLOCKED: &str = "blocked";
pub const BUILD_RUN_STATE_CANCELLED: &str = "cancelled";

pub const BUILD_ARTIFACT_KIND_MODULE: &str = "module";
pub const BUILD_ARTIFACT_KIND_BUNDLE: &str = "bundle";
pub const BUILD_ARTIFACT_KIND_MANIFEST: &str = "manifest";
pub const BUILD_ARTIFACT_KIND_SOURCE_MAP: &str = "sourceMap";

pub const BUILD_PROOF_STATE_PENDING: &str = "pending";
pub const BUILD_PROOF_STATE_PROVED: &str = "proved";
pub const BUILD_PROOF_STATE_FAILED: &str = "failed";
pub const BUILD_PROOF_STATE_BLOCKED: &str = "blocked";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BuildContract {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub build_contract_ref: String,
    pub app_contract_ref: String,
    pub source_graph_ref: String,
    pub source_snapshot_ref: String,
    pub recipe_ref: String,
    pub state: String,
    #[serde(default)]
    pub runner_role_refs: Vec<String>,
    #[serde(default)]
    pub runner_refs: Vec<String>,
    #[serde(default)]
    pub resource_grant_refs: Vec<String>,
    #[serde(default)]
    pub secret_boundary_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub expected_artifact_refs: Vec<String>,
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
pub struct BuildRun {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub run_ref: String,
    pub build_contract_ref: String,
    pub source_snapshot_ref: String,
    pub recipe_ref: String,
    pub runner_ref: String,
    pub runner_operation_ref: String,
    pub state: String,
    #[serde(default)]
    pub grant_refs: Vec<String>,
    #[serde(default)]
    pub resource_grant_refs: Vec<String>,
    #[serde(default)]
    pub secret_boundary_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub log_refs: Vec<String>,
    #[serde(default)]
    pub proof_refs: Vec<String>,
    #[serde(default)]
    pub metric_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub release_candidate_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub requested_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BuildArtifact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub artifact_ref: String,
    pub run_ref: String,
    pub artifact_kind: String,
    pub storage_object_ref: String,
    pub digest_ref: String,
    pub compatibility_ref: String,
    pub media_type: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BuildProof {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub proof_ref: String,
    pub run_ref: String,
    pub state: String,
    pub source_snapshot_ref: String,
    pub runner_ref: String,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub log_refs: Vec<String>,
    #[serde(default)]
    pub metric_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub observed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

pub fn validate_build_contract(record: &BuildContract) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_BUILD_CONTRACT,
        "build contract",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "build contract")?;
    validate_contract_ref(
        &record.build_contract_ref,
        "build contract buildContractRef",
    )?;
    validate_contract_ref(&record.app_contract_ref, "build contract appContractRef")?;
    validate_contract_ref(&record.source_graph_ref, "build contract sourceGraphRef")?;
    validate_contract_ref(
        &record.source_snapshot_ref,
        "build contract sourceSnapshotRef",
    )?;
    validate_contract_ref(&record.recipe_ref, "build contract recipeRef")?;
    validate_build_contract_state(&record.state)?;
    validate_ref_list(&record.runner_role_refs, "build contract runnerRoleRefs")?;
    validate_ref_list(&record.runner_refs, "build contract runnerRefs")?;
    validate_ref_list(
        &record.resource_grant_refs,
        "build contract resourceGrantRefs",
    )?;
    validate_ref_list(
        &record.secret_boundary_refs,
        "build contract secretBoundaryRefs",
    )?;
    validate_ref_list(
        &record.compatibility_refs,
        "build contract compatibilityRefs",
    )?;
    validate_ref_list(
        &record.expected_artifact_refs,
        "build contract expectedArtifactRefs",
    )?;
    validate_ref_list(&record.evidence_refs, "build contract evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "build contract blockedReasons")?;
    if record.state == BUILD_CONTRACT_STATE_READY
        && (record.runner_role_refs.is_empty() || record.resource_grant_refs.is_empty())
    {
        return Err(anyhow!(
            "ready build contract requires runnerRoleRefs and resourceGrantRefs"
        ));
    }
    if record.state == BUILD_CONTRACT_STATE_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!("blocked build contract requires blockedReasons"));
    }
    validate_time_bounds(record.issued_at, record.expires_at, "build contract")?;
    Ok(())
}

pub fn validate_build_run(record: &BuildRun) -> Result<()> {
    validate_optional_kind(record.kind.as_deref(), RECORD_BUILD_RUN, "build run")?;
    reject_private_fields(&serde_json::to_value(record)?, "build run")?;
    validate_contract_ref(&record.run_ref, "build run runRef")?;
    validate_contract_ref(&record.build_contract_ref, "build run buildContractRef")?;
    validate_contract_ref(&record.source_snapshot_ref, "build run sourceSnapshotRef")?;
    validate_contract_ref(&record.recipe_ref, "build run recipeRef")?;
    validate_contract_ref(&record.runner_ref, "build run runnerRef")?;
    validate_contract_ref(&record.runner_operation_ref, "build run runnerOperationRef")?;
    validate_build_run_state(&record.state)?;
    validate_ref_list(&record.grant_refs, "build run grantRefs")?;
    validate_ref_list(&record.resource_grant_refs, "build run resourceGrantRefs")?;
    validate_ref_list(&record.secret_boundary_refs, "build run secretBoundaryRefs")?;
    validate_ref_list(&record.artifact_refs, "build run artifactRefs")?;
    validate_ref_list(&record.log_refs, "build run logRefs")?;
    validate_ref_list(&record.proof_refs, "build run proofRefs")?;
    validate_ref_list(&record.metric_refs, "build run metricRefs")?;
    validate_ref_list(&record.storage_refs, "build run storageRefs")?;
    validate_ref_list(&record.compatibility_refs, "build run compatibilityRefs")?;
    validate_ref_list(
        &record.release_candidate_refs,
        "build run releaseCandidateRefs",
    )?;
    validate_ref_list(&record.evidence_refs, "build run evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "build run blockedReasons")?;
    reject_private_fields(&record.safe_facts, "build run safeFacts")?;
    if record.requested_at == 0 {
        return Err(anyhow!("build run missing requestedAt"));
    }
    if matches!(record.state.as_str(), BUILD_RUN_STATE_SUCCEEDED)
        && record.artifact_refs.is_empty()
        && record.proof_refs.is_empty()
    {
        return Err(anyhow!(
            "succeeded build run requires artifactRefs or proofRefs"
        ));
    }
    if matches!(record.state.as_str(), BUILD_RUN_STATE_SUCCEEDED)
        && (record.resource_grant_refs.is_empty()
            || record.compatibility_refs.is_empty()
            || record.release_candidate_refs.is_empty())
    {
        return Err(anyhow!(
            "succeeded build run requires resourceGrantRefs, compatibilityRefs, and releaseCandidateRefs"
        ));
    }
    if matches!(
        record.state.as_str(),
        BUILD_RUN_STATE_FAILED | BUILD_RUN_STATE_BLOCKED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "failed or blocked build run requires blockedReasons"
        ));
    }
    if record
        .completed_at
        .is_some_and(|completed_at| completed_at < record.requested_at)
    {
        return Err(anyhow!("build run completedAt before requestedAt"));
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= record.requested_at)
    {
        return Err(anyhow!("build run expiresAt must be after requestedAt"));
    }
    Ok(())
}

pub fn validate_build_artifact(record: &BuildArtifact) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_BUILD_ARTIFACT,
        "build artifact",
    )?;
    validate_contract_ref(&record.artifact_ref, "build artifact artifactRef")?;
    validate_contract_ref(&record.run_ref, "build artifact runRef")?;
    validate_build_artifact_kind(&record.artifact_kind)?;
    validate_contract_ref(
        &record.storage_object_ref,
        "build artifact storageObjectRef",
    )?;
    validate_contract_ref(&record.digest_ref, "build artifact digestRef")?;
    validate_contract_ref(&record.compatibility_ref, "build artifact compatibilityRef")?;
    require_non_empty(&record.media_type, "build artifact missing mediaType")?;
    if record.size_bytes == 0 {
        return Err(anyhow!("build artifact missing sizeBytes"));
    }
    validate_ref_list(&record.evidence_refs, "build artifact evidenceRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("build artifact missing issuedAt"));
    }
    Ok(())
}

pub fn validate_build_proof(record: &BuildProof) -> Result<()> {
    validate_optional_kind(record.kind.as_deref(), RECORD_BUILD_PROOF, "build proof")?;
    validate_contract_ref(&record.proof_ref, "build proof proofRef")?;
    validate_contract_ref(&record.run_ref, "build proof runRef")?;
    validate_build_proof_state(&record.state)?;
    validate_contract_ref(&record.source_snapshot_ref, "build proof sourceSnapshotRef")?;
    validate_contract_ref(&record.runner_ref, "build proof runnerRef")?;
    validate_ref_list(&record.artifact_refs, "build proof artifactRefs")?;
    validate_ref_list(&record.log_refs, "build proof logRefs")?;
    validate_ref_list(&record.metric_refs, "build proof metricRefs")?;
    validate_ref_list(&record.evidence_refs, "build proof evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "build proof blockedReasons")?;
    if record.state == BUILD_PROOF_STATE_PROVED && record.artifact_refs.is_empty() {
        return Err(anyhow!("proved build proof requires artifactRefs"));
    }
    if matches!(
        record.state.as_str(),
        BUILD_PROOF_STATE_FAILED | BUILD_PROOF_STATE_BLOCKED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "failed or blocked build proof requires blockedReasons"
        ));
    }
    validate_time_bounds(record.observed_at, record.expires_at, "build proof")?;
    Ok(())
}

fn validate_build_contract_state(value: &str) -> Result<()> {
    if matches!(
        value,
        BUILD_CONTRACT_STATE_DRAFT
            | BUILD_CONTRACT_STATE_READY
            | BUILD_CONTRACT_STATE_BLOCKED
            | BUILD_CONTRACT_STATE_SUPERSEDED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported build contract state"))
    }
}

fn validate_build_run_state(value: &str) -> Result<()> {
    if matches!(
        value,
        BUILD_RUN_STATE_REQUESTED
            | BUILD_RUN_STATE_ACCEPTED
            | BUILD_RUN_STATE_RUNNING
            | BUILD_RUN_STATE_SUCCEEDED
            | BUILD_RUN_STATE_FAILED
            | BUILD_RUN_STATE_BLOCKED
            | BUILD_RUN_STATE_CANCELLED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported build run state"))
    }
}

fn validate_build_artifact_kind(value: &str) -> Result<()> {
    if matches!(
        value,
        BUILD_ARTIFACT_KIND_MODULE
            | BUILD_ARTIFACT_KIND_BUNDLE
            | BUILD_ARTIFACT_KIND_MANIFEST
            | BUILD_ARTIFACT_KIND_SOURCE_MAP
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported build artifact kind"))
    }
}

fn validate_build_proof_state(value: &str) -> Result<()> {
    if matches!(
        value,
        BUILD_PROOF_STATE_PENDING
            | BUILD_PROOF_STATE_PROVED
            | BUILD_PROOF_STATE_FAILED
            | BUILD_PROOF_STATE_BLOCKED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported build proof state"))
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

fn validate_ref_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        validate_contract_ref(value, context)?;
    }
    Ok(())
}

fn validate_reason_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        validate_reason(value, context)?;
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
        return Err(anyhow!("{context} must be a contract/storage ref"));
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
        return Err(anyhow!("{context} must contain reason codes"));
    }
    Ok(())
}

fn validate_time_bounds(issued_at: u64, expires_at: Option<u64>, context: &str) -> Result<()> {
    if issued_at == 0 {
        return Err(anyhow!("{context} missing time"));
    }
    if expires_at.is_some_and(|expires_at| expires_at <= issued_at) {
        return Err(anyhow!("{context} expiresAt must be after issued time"));
    }
    Ok(())
}

fn require_non_empty(value: &str, message: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(anyhow!(message.to_string()))
    } else {
        Ok(())
    }
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
                | "artifactbytes"
                | "logbytes"
                | "stdout"
                | "stderr"
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

    fn contract() -> BuildContract {
        BuildContract {
            kind: Some(RECORD_BUILD_CONTRACT.to_string()),
            build_contract_ref: "build:contract:cybersec-bootstrap".to_string(),
            app_contract_ref: "app:contract:cybersec@0.1.0".to_string(),
            source_graph_ref: "source:graph:constitute-git".to_string(),
            source_snapshot_ref: "source:snapshot:head".to_string(),
            recipe_ref: "build:recipe:browser-module".to_string(),
            state: BUILD_CONTRACT_STATE_READY.to_string(),
            runner_role_refs: vec!["runner:role:build".to_string()],
            runner_refs: vec!["runner:instance:local".to_string()],
            resource_grant_refs: vec!["resource:grant:build-lite".to_string()],
            secret_boundary_refs: vec!["secret:boundary:not-required".to_string()],
            compatibility_refs: vec!["compat:surface-app:0.1".to_string()],
            expected_artifact_refs: vec!["build:artifact:module".to_string()],
            evidence_refs: vec!["source:update:main".to_string()],
            blocked_reasons: vec![],
            issued_at: 1,
            expires_at: Some(10),
        }
    }

    #[test]
    fn validates_build_contract_run_artifact_and_proof() {
        let contract = contract();
        validate_build_contract(&contract).expect("valid contract");

        let run = BuildRun {
            kind: Some(RECORD_BUILD_RUN.to_string()),
            run_ref: "build:run:1".to_string(),
            build_contract_ref: contract.build_contract_ref.clone(),
            source_snapshot_ref: contract.source_snapshot_ref.clone(),
            recipe_ref: contract.recipe_ref.clone(),
            runner_ref: "runner:instance:local".to_string(),
            runner_operation_ref: "runner:operation:build-1".to_string(),
            state: BUILD_RUN_STATE_SUCCEEDED.to_string(),
            grant_refs: vec!["authority:grant:runner-build".to_string()],
            resource_grant_refs: vec!["resource:grant:build-lite".to_string()],
            secret_boundary_refs: vec!["secret:boundary:not-required".to_string()],
            artifact_refs: vec!["build:artifact:module".to_string()],
            log_refs: vec!["storage:object:build-log".to_string()],
            proof_refs: vec!["build:proof:1".to_string()],
            metric_refs: vec!["metrics:build:1".to_string()],
            storage_refs: vec!["storage:object:artifact-module".to_string()],
            compatibility_refs: vec!["compat:surface-app:0.1".to_string()],
            release_candidate_refs: vec!["release:candidate:module".to_string()],
            evidence_refs: vec!["runner:evidence:build-1".to_string()],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({ "durationMs": 42 }),
            requested_at: 2,
            started_at: Some(3),
            completed_at: Some(4),
            expires_at: Some(20),
        };
        validate_build_run(&run).expect("valid run");

        let artifact = BuildArtifact {
            kind: Some(RECORD_BUILD_ARTIFACT.to_string()),
            artifact_ref: "build:artifact:module".to_string(),
            run_ref: run.run_ref.clone(),
            artifact_kind: BUILD_ARTIFACT_KIND_MODULE.to_string(),
            storage_object_ref: "storage:object:artifact-module".to_string(),
            digest_ref: "digest:sha256:module".to_string(),
            compatibility_ref: "compat:surface-app:0.1".to_string(),
            media_type: "application/javascript".to_string(),
            size_bytes: 1024,
            evidence_refs: vec!["build:evidence:hash".to_string()],
            issued_at: 4,
        };
        validate_build_artifact(&artifact).expect("valid artifact");

        let proof = BuildProof {
            kind: Some(RECORD_BUILD_PROOF.to_string()),
            proof_ref: "build:proof:1".to_string(),
            run_ref: run.run_ref,
            state: BUILD_PROOF_STATE_PROVED.to_string(),
            source_snapshot_ref: contract.source_snapshot_ref,
            runner_ref: "runner:instance:local".to_string(),
            artifact_refs: vec![artifact.artifact_ref],
            log_refs: vec!["storage:object:build-log".to_string()],
            metric_refs: vec!["metrics:build:1".to_string()],
            evidence_refs: vec!["runner:evidence:build-1".to_string()],
            blocked_reasons: vec![],
            observed_at: 5,
            expires_at: Some(20),
        };
        validate_build_proof(&proof).expect("valid proof");
    }

    #[test]
    fn rejects_build_private_payloads_and_missing_runner_grants() {
        let mut contract = contract();
        contract.resource_grant_refs.clear();
        assert!(validate_build_contract(&contract).is_err());

        let run = BuildRun {
            kind: Some(RECORD_BUILD_RUN.to_string()),
            run_ref: "build:run:bad".to_string(),
            build_contract_ref: "build:contract:bad".to_string(),
            source_snapshot_ref: "source:snapshot:head".to_string(),
            recipe_ref: "build:recipe:browser-module".to_string(),
            runner_ref: "runner:instance:local".to_string(),
            runner_operation_ref: "runner:operation:build-bad".to_string(),
            state: BUILD_RUN_STATE_FAILED.to_string(),
            grant_refs: vec!["authority:grant:runner-build".to_string()],
            resource_grant_refs: vec!["resource:grant:build-lite".to_string()],
            secret_boundary_refs: vec!["secret:boundary:not-required".to_string()],
            artifact_refs: vec!["build:artifact:module".to_string()],
            log_refs: vec![],
            proof_refs: vec![],
            metric_refs: vec![],
            storage_refs: vec![],
            compatibility_refs: vec![],
            release_candidate_refs: vec![],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({ "build": "bad-run" }),
            requested_at: 2,
            started_at: None,
            completed_at: Some(3),
            expires_at: None,
        };
        assert!(validate_build_run(&run).is_err());
    }
}
