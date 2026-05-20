use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RECORD_APP_CONTRACT: &str = "app.contract";
pub const RECORD_APP_MODULE_ROLE: &str = "app.module.role";
pub const RECORD_APP_ACTIVITY: &str = "app.activity";
pub const RECORD_APP_RELEASE: &str = "app.release";
pub const RECORD_APP_RELEASE_RESOLUTION: &str = "app.release.resolution";

pub const APP_CONTRACT_STATE_DRAFT: &str = "draft";
pub const APP_CONTRACT_STATE_READY: &str = "ready";
pub const APP_CONTRACT_STATE_BLOCKED: &str = "blocked";
pub const APP_CONTRACT_STATE_SUPERSEDED: &str = "superseded";

pub const APP_ACTIVITY_STATE_READY: &str = "ready";
pub const APP_ACTIVITY_STATE_BLOCKED: &str = "blocked";
pub const APP_ACTIVITY_STATE_DEPRECATED: &str = "deprecated";

pub const APP_ACTIVITY_LAUNCH_SURFACE: &str = "surface";
pub const APP_ACTIVITY_LAUNCH_EMBEDDED: &str = "embedded";
pub const APP_ACTIVITY_LAUNCH_NATIVE: &str = "native";
pub const APP_ACTIVITY_LAUNCH_SERVICE: &str = "service";

pub const APP_EMBED_POLICY_ALLOWED: &str = "allowed";
pub const APP_EMBED_POLICY_RESTRICTED: &str = "restricted";
pub const APP_EMBED_POLICY_DENIED: &str = "denied";

pub const APP_MODULE_ROLE_RUNTIME_CLIENT: &str = "runtimeClient";
pub const APP_MODULE_ROLE_PROJECTION_MODEL: &str = "projectionModel";
pub const APP_MODULE_ROLE_PLATFORM_ADAPTER: &str = "platformAdapter";
pub const APP_MODULE_ROLE_SERVICE_SURFACE_ADAPTER: &str = "serviceSurfaceAdapter";
pub const APP_MODULE_ROLE_SERVICE_EDGE_ADAPTER: &str = "serviceEdgeAdapter";
pub const APP_MODULE_ROLE_PRODUCT_VIEW: &str = "productView";
pub const APP_MODULE_ROLE_OPERATOR_HELPER: &str = "operatorHelper";
pub const APP_MODULE_ROLE_RELEASE_HELPER: &str = "releaseHelper";

pub const APP_RELEASE_STATE_PUBLISHED: &str = "published";
pub const APP_RELEASE_STATE_BLOCKED: &str = "blocked";
pub const APP_RELEASE_STATE_SUPERSEDED: &str = "superseded";
pub const APP_RELEASE_STATE_REVOKED: &str = "revoked";

pub const APP_RESOLUTION_STATE_RESOLVED: &str = "resolved";
pub const APP_RESOLUTION_STATE_BLOCKED: &str = "blocked";
pub const APP_RESOLUTION_STATE_DEGRADED: &str = "degraded";
pub const APP_RESOLUTION_STATE_SUPERSEDED: &str = "superseded";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppContract {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub app_contract_ref: String,
    pub app_id: String,
    pub version: String,
    pub author_ref: String,
    pub state: String,
    #[serde(default)]
    pub primitive_refs: Vec<String>,
    #[serde(default)]
    pub activity_refs: Vec<String>,
    #[serde(default)]
    pub module_role_refs: Vec<String>,
    #[serde(default)]
    pub release_refs: Vec<String>,
    #[serde(default)]
    pub permission_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
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
pub struct AppModuleRole {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub module_role_ref: String,
    pub app_contract_ref: String,
    pub role_name: String,
    pub required: bool,
    #[serde(default)]
    pub primitive_refs: Vec<String>,
    #[serde(default)]
    pub platform_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppActivity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub activity_ref: String,
    pub app_contract_ref: String,
    pub activity_id: String,
    pub state: String,
    pub launch_mode: String,
    pub embed_policy: String,
    #[serde(default)]
    pub primitive_refs: Vec<String>,
    #[serde(default)]
    pub module_role_refs: Vec<String>,
    #[serde(default)]
    pub permission_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub materialization_refs: Vec<String>,
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
pub struct AppRelease {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub release_ref: String,
    pub app_contract_ref: String,
    pub version: String,
    pub source_snapshot_ref: String,
    pub build_run_ref: String,
    pub state: String,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub proof_refs: Vec<String>,
    #[serde(default)]
    pub module_role_refs: Vec<String>,
    #[serde(default)]
    pub storage_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
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
pub struct AppReleaseResolution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub resolution_ref: String,
    pub app_intent_ref: String,
    pub app_contract_ref: String,
    pub requested_version: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_release_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_activity_ref: Option<String>,
    #[serde(default)]
    pub selected_artifact_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_snapshot_ref: Option<String>,
    #[serde(default)]
    pub build_proof_refs: Vec<String>,
    #[serde(default)]
    pub compatibility_refs: Vec<String>,
    #[serde(default)]
    pub permission_refs: Vec<String>,
    #[serde(default)]
    pub access_group_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    pub resolved_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

pub fn validate_app_contract(record: &AppContract) -> Result<()> {
    validate_optional_kind(record.kind.as_deref(), RECORD_APP_CONTRACT, "app contract")?;
    reject_private_fields(&serde_json::to_value(record)?, "app contract")?;
    validate_contract_ref(&record.app_contract_ref, "app contract appContractRef")?;
    validate_token(&record.app_id, "app contract appId")?;
    validate_version(&record.version, "app contract version")?;
    validate_contract_ref(&record.author_ref, "app contract authorRef")?;
    validate_app_contract_state(&record.state)?;
    validate_ref_list(&record.primitive_refs, "app contract primitiveRefs")?;
    validate_ref_list(&record.activity_refs, "app contract activityRefs")?;
    validate_ref_list(&record.module_role_refs, "app contract moduleRoleRefs")?;
    validate_ref_list(&record.release_refs, "app contract releaseRefs")?;
    validate_ref_list(&record.permission_refs, "app contract permissionRefs")?;
    validate_ref_list(&record.access_group_refs, "app contract accessGroupRefs")?;
    validate_ref_list(&record.compatibility_refs, "app contract compatibilityRefs")?;
    validate_ref_list(&record.evidence_refs, "app contract evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "app contract blockedReasons")?;
    if record.state == APP_CONTRACT_STATE_READY
        && (record.primitive_refs.is_empty()
            || record.activity_refs.is_empty()
            || record.module_role_refs.is_empty()
            || record.release_refs.is_empty())
    {
        return Err(anyhow!(
            "ready app contract requires primitiveRefs, activityRefs, moduleRoleRefs, and releaseRefs"
        ));
    }
    if record.state == APP_CONTRACT_STATE_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!("blocked app contract requires blockedReasons"));
    }
    validate_time_bounds(record.issued_at, record.expires_at, "app contract")?;
    Ok(())
}

pub fn validate_app_module_role(record: &AppModuleRole) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_APP_MODULE_ROLE,
        "app module role",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "app module role")?;
    validate_contract_ref(&record.module_role_ref, "app module role moduleRoleRef")?;
    validate_contract_ref(&record.app_contract_ref, "app module role appContractRef")?;
    validate_app_module_role_name(&record.role_name)?;
    validate_ref_list(&record.primitive_refs, "app module role primitiveRefs")?;
    validate_ref_list(&record.platform_refs, "app module role platformRefs")?;
    validate_ref_list(&record.artifact_refs, "app module role artifactRefs")?;
    validate_ref_list(
        &record.compatibility_refs,
        "app module role compatibilityRefs",
    )?;
    validate_ref_list(&record.evidence_refs, "app module role evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "app module role blockedReasons")?;
    if record.required && record.primitive_refs.is_empty() {
        return Err(anyhow!("required app module role requires primitiveRefs"));
    }
    Ok(())
}

pub fn validate_app_activity(record: &AppActivity) -> Result<()> {
    validate_optional_kind(record.kind.as_deref(), RECORD_APP_ACTIVITY, "app activity")?;
    reject_private_fields(&serde_json::to_value(record)?, "app activity")?;
    validate_contract_ref(&record.activity_ref, "app activity activityRef")?;
    validate_contract_ref(&record.app_contract_ref, "app activity appContractRef")?;
    validate_token(&record.activity_id, "app activity activityId")?;
    validate_app_activity_state(&record.state)?;
    validate_app_activity_launch_mode(&record.launch_mode)?;
    validate_app_embed_policy(&record.embed_policy)?;
    validate_ref_list(&record.primitive_refs, "app activity primitiveRefs")?;
    validate_ref_list(&record.module_role_refs, "app activity moduleRoleRefs")?;
    validate_ref_list(&record.permission_refs, "app activity permissionRefs")?;
    validate_ref_list(&record.access_group_refs, "app activity accessGroupRefs")?;
    validate_ref_list(
        &record.materialization_refs,
        "app activity materializationRefs",
    )?;
    validate_ref_list(&record.evidence_refs, "app activity evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "app activity blockedReasons")?;
    if record.state == APP_ACTIVITY_STATE_READY
        && (record.primitive_refs.is_empty() || record.module_role_refs.is_empty())
    {
        return Err(anyhow!(
            "ready app activity requires primitiveRefs and moduleRoleRefs"
        ));
    }
    if record.state == APP_ACTIVITY_STATE_BLOCKED && record.blocked_reasons.is_empty() {
        return Err(anyhow!("blocked app activity requires blockedReasons"));
    }
    validate_time_bounds(record.issued_at, record.expires_at, "app activity")?;
    Ok(())
}

pub fn validate_app_release(record: &AppRelease) -> Result<()> {
    validate_optional_kind(record.kind.as_deref(), RECORD_APP_RELEASE, "app release")?;
    reject_private_fields(&serde_json::to_value(record)?, "app release")?;
    validate_contract_ref(&record.release_ref, "app release releaseRef")?;
    validate_contract_ref(&record.app_contract_ref, "app release appContractRef")?;
    validate_version(&record.version, "app release version")?;
    validate_contract_ref(&record.source_snapshot_ref, "app release sourceSnapshotRef")?;
    validate_contract_ref(&record.build_run_ref, "app release buildRunRef")?;
    validate_app_release_state(&record.state)?;
    validate_ref_list(&record.artifact_refs, "app release artifactRefs")?;
    validate_ref_list(&record.proof_refs, "app release proofRefs")?;
    validate_ref_list(&record.module_role_refs, "app release moduleRoleRefs")?;
    validate_ref_list(&record.storage_refs, "app release storageRefs")?;
    validate_ref_list(&record.compatibility_refs, "app release compatibilityRefs")?;
    validate_ref_list(&record.evidence_refs, "app release evidenceRefs")?;
    validate_reason_list(&record.blocked_reasons, "app release blockedReasons")?;
    if record.state == APP_RELEASE_STATE_PUBLISHED
        && (record.artifact_refs.is_empty()
            || record.proof_refs.is_empty()
            || record.storage_refs.is_empty()
            || record.compatibility_refs.is_empty())
    {
        return Err(anyhow!(
            "published app release requires artifactRefs, proofRefs, storageRefs, and compatibilityRefs"
        ));
    }
    if matches!(
        record.state.as_str(),
        APP_RELEASE_STATE_BLOCKED | APP_RELEASE_STATE_REVOKED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "blocked or revoked app release requires blockedReasons"
        ));
    }
    validate_time_bounds(record.issued_at, record.expires_at, "app release")?;
    Ok(())
}

pub fn validate_app_release_resolution(record: &AppReleaseResolution) -> Result<()> {
    validate_optional_kind(
        record.kind.as_deref(),
        RECORD_APP_RELEASE_RESOLUTION,
        "app release resolution",
    )?;
    reject_private_fields(&serde_json::to_value(record)?, "app release resolution")?;
    validate_contract_ref(
        &record.resolution_ref,
        "app release resolution resolutionRef",
    )?;
    validate_contract_ref(
        &record.app_intent_ref,
        "app release resolution appIntentRef",
    )?;
    validate_contract_ref(
        &record.app_contract_ref,
        "app release resolution appContractRef",
    )?;
    validate_version(
        &record.requested_version,
        "app release resolution requestedVersion",
    )?;
    validate_app_resolution_state(&record.state)?;
    validate_optional_ref(
        record.selected_release_ref.as_deref(),
        "app release resolution selectedReleaseRef",
    )?;
    validate_optional_ref(
        record.selected_activity_ref.as_deref(),
        "app release resolution selectedActivityRef",
    )?;
    validate_ref_list(
        &record.selected_artifact_refs,
        "app release resolution selectedArtifactRefs",
    )?;
    validate_optional_ref(
        record.source_snapshot_ref.as_deref(),
        "app release resolution sourceSnapshotRef",
    )?;
    validate_ref_list(
        &record.build_proof_refs,
        "app release resolution buildProofRefs",
    )?;
    validate_ref_list(
        &record.compatibility_refs,
        "app release resolution compatibilityRefs",
    )?;
    validate_ref_list(
        &record.permission_refs,
        "app release resolution permissionRefs",
    )?;
    validate_ref_list(
        &record.access_group_refs,
        "app release resolution accessGroupRefs",
    )?;
    validate_ref_list(&record.evidence_refs, "app release resolution evidenceRefs")?;
    validate_reason_list(
        &record.blocked_reasons,
        "app release resolution blockedReasons",
    )?;
    reject_private_fields(&record.safe_facts, "app release resolution safeFacts")?;
    if record.state == APP_RESOLUTION_STATE_RESOLVED
        && (record.selected_release_ref.is_none()
            || record.selected_activity_ref.is_none()
            || record.selected_artifact_refs.is_empty()
            || record.source_snapshot_ref.is_none()
            || record.build_proof_refs.is_empty()
            || record.compatibility_refs.is_empty())
    {
        return Err(anyhow!(
            "resolved app release requires selected release, activity, artifacts, source snapshot, build proof, and compatibility refs"
        ));
    }
    if matches!(
        record.state.as_str(),
        APP_RESOLUTION_STATE_BLOCKED | APP_RESOLUTION_STATE_DEGRADED
    ) && record.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "blocked or degraded app release resolution requires blockedReasons"
        ));
    }
    validate_time_bounds(
        record.resolved_at,
        record.expires_at,
        "app release resolution",
    )?;
    Ok(())
}

pub fn app_ref(kind: &str, id: &str) -> String {
    format!("app:{kind}:{id}")
}

fn validate_app_contract_state(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_CONTRACT_STATE_DRAFT
            | APP_CONTRACT_STATE_READY
            | APP_CONTRACT_STATE_BLOCKED
            | APP_CONTRACT_STATE_SUPERSEDED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app contract state"))
    }
}

fn validate_app_activity_state(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_ACTIVITY_STATE_READY | APP_ACTIVITY_STATE_BLOCKED | APP_ACTIVITY_STATE_DEPRECATED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app activity state"))
    }
}

fn validate_app_activity_launch_mode(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_ACTIVITY_LAUNCH_SURFACE
            | APP_ACTIVITY_LAUNCH_EMBEDDED
            | APP_ACTIVITY_LAUNCH_NATIVE
            | APP_ACTIVITY_LAUNCH_SERVICE
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app activity launch mode"))
    }
}

fn validate_app_embed_policy(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_EMBED_POLICY_ALLOWED | APP_EMBED_POLICY_RESTRICTED | APP_EMBED_POLICY_DENIED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app embed policy"))
    }
}

fn validate_app_module_role_name(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_MODULE_ROLE_RUNTIME_CLIENT
            | APP_MODULE_ROLE_PROJECTION_MODEL
            | APP_MODULE_ROLE_PLATFORM_ADAPTER
            | APP_MODULE_ROLE_SERVICE_SURFACE_ADAPTER
            | APP_MODULE_ROLE_SERVICE_EDGE_ADAPTER
            | APP_MODULE_ROLE_PRODUCT_VIEW
            | APP_MODULE_ROLE_OPERATOR_HELPER
            | APP_MODULE_ROLE_RELEASE_HELPER
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app module role"))
    }
}

fn validate_app_release_state(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_RELEASE_STATE_PUBLISHED
            | APP_RELEASE_STATE_BLOCKED
            | APP_RELEASE_STATE_SUPERSEDED
            | APP_RELEASE_STATE_REVOKED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app release state"))
    }
}

fn validate_app_resolution_state(value: &str) -> Result<()> {
    if matches!(
        value,
        APP_RESOLUTION_STATE_RESOLVED
            | APP_RESOLUTION_STATE_BLOCKED
            | APP_RESOLUTION_STATE_DEGRADED
            | APP_RESOLUTION_STATE_SUPERSEDED
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported app release resolution state"))
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

fn validate_token(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{context} is empty"));
    }
    if value != value.trim()
        || value.chars().any(char::is_whitespace)
        || value.contains('\\')
        || value.contains('/')
        || value.starts_with("file:")
        || value.starts_with("http:")
        || value.starts_with("https:")
    {
        return Err(anyhow!("{context} must be a logical token"));
    }
    Ok(())
}

fn validate_version(value: &str, context: &str) -> Result<()> {
    validate_token(value, context)?;
    if !value.chars().any(|ch| ch.is_ascii_digit()) {
        return Err(anyhow!("{context} must carry a concrete version"));
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
                | "codebytes"
                | "artifactbytes"
                | "bundlebytes"
                | "ciphertext"
                | "sdp"
                | "candidate"
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

    fn contract() -> AppContract {
        AppContract {
            kind: Some(RECORD_APP_CONTRACT.to_string()),
            app_contract_ref: "app:contract:cybersec@0.1.0".to_string(),
            app_id: "constitute-cybersec".to_string(),
            version: "0.1.0".to_string(),
            author_ref: "identity:root:aux".to_string(),
            state: APP_CONTRACT_STATE_READY.to_string(),
            primitive_refs: vec!["primitive:event:fabric".to_string()],
            activity_refs: vec!["app:activity:cybersec.dashboard".to_string()],
            module_role_refs: vec![
                "app:module-role:runtime-client".to_string(),
                "app:module-role:product-view".to_string(),
            ],
            release_refs: vec!["app:release:cybersec@0.1.0".to_string()],
            permission_refs: vec!["authority:grant:cybersec-read".to_string()],
            access_group_refs: vec!["access:group:cybersec".to_string()],
            compatibility_refs: vec!["compat:surface-app:0.1".to_string()],
            evidence_refs: vec!["source:update:main".to_string()],
            blocked_reasons: vec![],
            issued_at: 1,
            expires_at: Some(10),
        }
    }

    #[test]
    fn validates_app_contract_activity_release_and_resolution() {
        let contract = contract();
        validate_app_contract(&contract).expect("valid app contract");

        let module = AppModuleRole {
            kind: Some(RECORD_APP_MODULE_ROLE.to_string()),
            module_role_ref: "app:module-role:runtime-client".to_string(),
            app_contract_ref: contract.app_contract_ref.clone(),
            role_name: APP_MODULE_ROLE_RUNTIME_CLIENT.to_string(),
            required: true,
            primitive_refs: vec!["primitive:runtime:client".to_string()],
            platform_refs: vec!["platform:browser:window".to_string()],
            artifact_refs: vec!["build:artifact:runtime-client".to_string()],
            compatibility_refs: vec!["compat:surface-app:0.1".to_string()],
            evidence_refs: vec!["build:proof:runtime-client".to_string()],
            blocked_reasons: vec![],
        };
        validate_app_module_role(&module).expect("valid module role");

        let activity = AppActivity {
            kind: Some(RECORD_APP_ACTIVITY.to_string()),
            activity_ref: "app:activity:cybersec.dashboard".to_string(),
            app_contract_ref: contract.app_contract_ref.clone(),
            activity_id: "dashboard".to_string(),
            state: APP_ACTIVITY_STATE_READY.to_string(),
            launch_mode: APP_ACTIVITY_LAUNCH_SURFACE.to_string(),
            embed_policy: APP_EMBED_POLICY_RESTRICTED.to_string(),
            primitive_refs: vec!["primitive:event:fabric".to_string()],
            module_role_refs: vec![module.module_role_ref.clone()],
            permission_refs: contract.permission_refs.clone(),
            access_group_refs: contract.access_group_refs.clone(),
            materialization_refs: vec!["materialization:budget:cybersec-dashboard".to_string()],
            evidence_refs: vec!["app:evidence:activity".to_string()],
            blocked_reasons: vec![],
            issued_at: 2,
            expires_at: Some(10),
        };
        validate_app_activity(&activity).expect("valid activity");

        let release = AppRelease {
            kind: Some(RECORD_APP_RELEASE.to_string()),
            release_ref: "app:release:cybersec@0.1.0".to_string(),
            app_contract_ref: contract.app_contract_ref.clone(),
            version: contract.version.clone(),
            source_snapshot_ref: "source:snapshot:head".to_string(),
            build_run_ref: "build:run:cybersec-bootstrap".to_string(),
            state: APP_RELEASE_STATE_PUBLISHED.to_string(),
            artifact_refs: vec!["build:artifact:module".to_string()],
            proof_refs: vec!["build:proof:cybersec-bootstrap".to_string()],
            module_role_refs: vec![module.module_role_ref],
            storage_refs: vec!["storage:object:cybersec-module".to_string()],
            compatibility_refs: contract.compatibility_refs.clone(),
            evidence_refs: vec!["build:evidence:artifact-hash".to_string()],
            blocked_reasons: vec![],
            issued_at: 3,
            expires_at: Some(10),
        };
        validate_app_release(&release).expect("valid release");

        let resolution = AppReleaseResolution {
            kind: Some(RECORD_APP_RELEASE_RESOLUTION.to_string()),
            resolution_ref: "app:resolution:cybersec-dashboard".to_string(),
            app_intent_ref: "app:intent:cybersec-dashboard".to_string(),
            app_contract_ref: contract.app_contract_ref,
            requested_version: contract.version,
            state: APP_RESOLUTION_STATE_RESOLVED.to_string(),
            selected_release_ref: Some(release.release_ref),
            selected_activity_ref: Some(activity.activity_ref),
            selected_artifact_refs: vec!["build:artifact:module".to_string()],
            source_snapshot_ref: Some(release.source_snapshot_ref),
            build_proof_refs: release.proof_refs,
            compatibility_refs: contract.compatibility_refs,
            permission_refs: contract.permission_refs,
            access_group_refs: contract.access_group_refs,
            evidence_refs: vec!["app:evidence:resolved".to_string()],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({ "activity": "dashboard" }),
            resolved_at: 4,
            expires_at: Some(10),
        };
        validate_app_release_resolution(&resolution).expect("valid resolution");
    }

    #[test]
    fn rejects_app_branch_tables_and_fake_refs() {
        let mut contract = contract();
        contract.release_refs.clear();
        assert!(validate_app_contract(&contract).is_err());

        let resolution = AppReleaseResolution {
            kind: Some(RECORD_APP_RELEASE_RESOLUTION.to_string()),
            resolution_ref: "app:resolution:bad".to_string(),
            app_intent_ref: "app:intent:bad".to_string(),
            app_contract_ref: "app:contract:bad@0.1.0".to_string(),
            requested_version: "0.1.0".to_string(),
            state: APP_RESOLUTION_STATE_RESOLVED.to_string(),
            selected_release_ref: None,
            selected_activity_ref: None,
            selected_artifact_refs: vec![],
            source_snapshot_ref: None,
            build_proof_refs: vec![],
            compatibility_refs: vec![],
            permission_refs: vec![],
            access_group_refs: vec![],
            evidence_refs: vec![],
            blocked_reasons: vec![],
            safe_facts: serde_json::json!({ "activity": "bad-resolution" }),
            resolved_at: 5,
            expires_at: Some(10),
        };
        assert!(validate_app_release_resolution(&resolution).is_err());
    }
}
