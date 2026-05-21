use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RECORD_SOURCE_VERSION_GRAPH: &str = "source.version.graph";
pub const RECORD_SOURCE_SNAPSHOT: &str = "source.snapshot";
pub const RECORD_SOURCE_REF_UPDATE: &str = "source.ref.update";
pub const RECORD_SOURCE_WRITER_GRANT: &str = "source.writer.grant";
pub const RECORD_SOURCE_IMPORT_PROOF: &str = "source.import.proof";

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

pub const SOURCE_IMPORT_STATE_PENDING: &str = "pending";
pub const SOURCE_IMPORT_STATE_IMPORTED: &str = "imported";
pub const SOURCE_IMPORT_STATE_BLOCKED: &str = "blocked";
pub const SOURCE_IMPORT_STATE_FAILED: &str = "failed";

pub const SOURCE_OPERATION_IMPORT: &str = "import";
pub const SOURCE_OPERATION_FETCH: &str = "fetch";
pub const SOURCE_OPERATION_PUSH: &str = "push";
pub const SOURCE_OPERATION_STATUS: &str = "status";
pub const SOURCE_OPERATION_REF_UPDATE: &str = "refUpdate";
pub const SOURCE_OPERATION_BRANCH: &str = "branch";
pub const SOURCE_OPERATION_TAG: &str = "tag";

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
pub struct SourceSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub source_graph_ref: String,
    pub snapshot_ref: String,
    pub commit_ref: String,
    pub tree_ref: String,
    #[serde(default)]
    pub parent_snapshot_refs: Vec<String>,
    #[serde(default)]
    pub storage_object_refs: Vec<String>,
    pub author_ref: String,
    pub message_digest_ref: String,
    #[serde(default)]
    pub signature_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub issued_at: u64,
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
    validate_ref_list(
        &record.parent_snapshot_refs,
        "source snapshot parentSnapshotRefs",
    )?;
    validate_ref_list(
        &record.storage_object_refs,
        "source snapshot storageObjectRefs",
    )?;
    if record.storage_object_refs.is_empty() {
        return Err(anyhow!("source snapshot needs storageObjectRefs"));
    }
    validate_contract_ref(&record.author_ref, "source snapshot authorRef")?;
    validate_contract_ref(
        &record.message_digest_ref,
        "source snapshot messageDigestRef",
    )?;
    validate_ref_list(&record.signature_refs, "source snapshot signatureRefs")?;
    validate_ref_list(&record.evidence_refs, "source snapshot evidenceRefs")?;
    if record.issued_at == 0 {
        return Err(anyhow!("source snapshot missing issuedAt"));
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
    validate_ref_list(
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
        if !matches!(
            value.as_str(),
            SOURCE_OPERATION_IMPORT
                | SOURCE_OPERATION_FETCH
                | SOURCE_OPERATION_PUSH
                | SOURCE_OPERATION_STATUS
                | SOURCE_OPERATION_REF_UPDATE
                | SOURCE_OPERATION_BRANCH
                | SOURCE_OPERATION_TAG
        ) {
            return Err(anyhow!("unsupported source operation"));
        }
    }
    Ok(())
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
            parent_snapshot_refs: vec!["source:snapshot:parent".to_string()],
            storage_object_refs: vec!["storage:object:pack-1".to_string()],
            author_ref: graph.owner_ref.clone(),
            message_digest_ref: "digest:sha256:message".to_string(),
            signature_refs: vec!["signature:source:head".to_string()],
            evidence_refs: vec!["source:evidence:pack-import".to_string()],
            issued_at: 2,
        };
        validate_source_snapshot(&snapshot).expect("valid snapshot");

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
            imported_object_refs: vec!["storage:object:pack-1".to_string()],
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
}
