use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{canonical_json, sha256_hex};
use crate::storage::EncryptedDetailRef;

pub const LOG_SCHEMA_VERSION: u16 = 1;
pub const LOG_EVENT_ID_PREFIX: &str = "constitute-log-event-v1";
pub const LOG_EVIDENCE_PROFILE_KIND: &str = "logging.evidence.profile";

pub const LOG_EVIDENCE_PROFILE_EVENT_CYBERSEC_AUDIT: &str = "cybersecAudit";
pub const LOG_EVIDENCE_PROFILE_EVENT_RUNTIME_DIAGNOSTIC: &str = "runtimeDiagnostic";
pub const LOG_EVIDENCE_PROFILE_EVENT_SERVICE_EVENT: &str = "serviceEvent";
pub const LOG_EVIDENCE_PROFILE_EVENT_STORAGE_ACCESS: &str = "storageAccess";
pub const LOG_EVIDENCE_PROFILE_EVENT_MEDIA_PATH: &str = "mediaPath";
pub const LOG_EVIDENCE_PROFILE_EVENT_HOST_SECURITY: &str = "hostSecurity";
pub const LOG_EVIDENCE_PROFILE_EVENT_SERVICE_HARDENING: &str = "serviceHardening";
pub const LOG_EVIDENCE_PROFILE_EVENT_NETWORK_EXPOSURE: &str = "networkExposure";
pub const LOG_EVIDENCE_PROFILE_EVENT_EVIDENCE_REQUEST: &str = "evidenceRequest";

pub const LOG_EVIDENCE_DETAIL_CUSTODY_SAFE_FACTS_ONLY: &str = "safeFactsOnly";
pub const LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_DETAIL_REF: &str = "encryptedDetailRef";
pub const LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_RAW_REF: &str = "encryptedRawRef";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogSeverity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogCategory {
    System,
    Capability,
    SwarmEdge,
    HostedService,
    GatewayControl,
    CameraDevice,
    MediaProjection,
    Recording,
    Worker,
    Storage,
    Logging,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogOutcome {
    Observed,
    Succeeded,
    Failed,
    Denied,
    Degraded,
    Recovered,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogRedactionClass {
    Safe,
    Redacted,
    EncryptedDetail,
    SensitiveOmitted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogVerbosityClass {
    Critical,
    Normal,
    Verbose,
    Noise,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogRetentionClass {
    Forever,
    Long,
    Rolling,
    Short,
    Ephemeral,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogEvidenceProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub profile_id: String,
    pub consumer_ref: String,
    pub event_classes: Vec<String>,
    pub retention_window: String,
    pub safe_index_refs: Vec<String>,
    pub detail_custody: String,
    pub encrypted_detail_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access_grant_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_container_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization_budget_ref: Option<String>,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogProducerRef {
    pub service: String,
    pub component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_pk: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogSubjectRef {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogResourceRef {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogCorrelationRef {
    pub correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LogEventEnvelope {
    pub schema_version: u16,
    pub event_id: String,
    pub occurred_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<u64>,
    pub producer: LogProducerRef,
    pub category: LogCategory,
    pub severity: LogSeverity,
    pub outcome: LogOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<LogSubjectRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<LogResourceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<LogCorrelationRef>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_ref: Option<EncryptedDetailRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_detail_refs: Vec<EncryptedDetailRef>,
    #[serde(default)]
    pub redaction: Vec<LogRedactionClass>,
}

pub fn log_event_id(event: &LogEventEnvelope) -> Result<String> {
    let mut value = serde_json::to_value(event)?;
    if let Value::Object(map) = &mut value {
        map.remove("eventId");
        map.remove("receivedAt");
    }
    Ok(sha256_hex(format!(
        "{}|{}",
        LOG_EVENT_ID_PREFIX,
        canonical_json(&value)?
    )))
}

pub fn validate_log_event(event: &LogEventEnvelope) -> Result<()> {
    if event.schema_version != LOG_SCHEMA_VERSION {
        return Err(anyhow!("unsupported log schema version"));
    }
    if event.producer.service.trim().is_empty() {
        return Err(anyhow!("log event missing producer service"));
    }
    if event.producer.component.trim().is_empty() {
        return Err(anyhow!("log event missing producer component"));
    }
    if event.occurred_at == 0 {
        return Err(anyhow!("log event missing occurred timestamp"));
    }
    if !event.safe_facts.is_object() {
        return Err(anyhow!("log safe facts must be an object"));
    }
    reject_sensitive_safe_facts(&event.safe_facts)?;
    if let Some(detail_ref) = &event.detail_ref {
        validate_encrypted_detail_ref(detail_ref, "log detailRef")?;
    }
    for detail_ref in &event.encrypted_detail_refs {
        validate_encrypted_detail_ref(detail_ref, "log encryptedDetailRefs entry")?;
    }
    let expected = log_event_id(event)?;
    if event.event_id != expected {
        return Err(anyhow!("log event id mismatch"));
    }
    Ok(())
}

pub fn validate_encrypted_detail_ref(detail_ref: &EncryptedDetailRef, context: &str) -> Result<()> {
    if detail_ref.object_id.trim().is_empty() {
        return Err(anyhow!("{} missing objectId", context));
    }
    if detail_ref.container_id.trim().is_empty() {
        return Err(anyhow!("{} missing containerId", context));
    }
    if detail_ref.key_ref.trim().is_empty() {
        return Err(anyhow!("{} missing keyRef", context));
    }
    if detail_ref.manifest_hash.trim().is_empty() {
        return Err(anyhow!("{} missing manifestHash", context));
    }
    if detail_ref
        .summary_tags
        .iter()
        .any(|tag| tag.trim().is_empty())
    {
        return Err(anyhow!("{} summaryTags must be non-empty strings", context));
    }
    Ok(())
}

pub fn validate_log_evidence_profile(profile: &LogEvidenceProfile) -> Result<()> {
    if let Some(kind) = &profile.kind
        && kind != LOG_EVIDENCE_PROFILE_KIND
    {
        return Err(anyhow!(
            "log evidence profile kind must be {}",
            LOG_EVIDENCE_PROFILE_KIND
        ));
    }
    require_non_empty(&profile.profile_id, "log evidence profile profileId")?;
    require_non_empty(&profile.consumer_ref, "log evidence profile consumerRef")?;
    require_non_empty(
        &profile.retention_window,
        "log evidence profile retentionWindow",
    )?;
    require_non_empty(
        &profile.detail_custody,
        "log evidence profile detailCustody",
    )?;
    if profile.event_classes.is_empty() {
        return Err(anyhow!(
            "log evidence profile eventClasses must not be empty"
        ));
    }
    for event_class in &profile.event_classes {
        require_non_empty(event_class, "log evidence profile eventClass")?;
        if !LOG_EVIDENCE_PROFILE_EVENT_CLASSES.contains(&event_class.as_str()) {
            return Err(anyhow!("invalid log evidence profile eventClass"));
        }
    }
    if profile.safe_index_refs.is_empty() {
        return Err(anyhow!(
            "log evidence profile safeIndexRefs must not be empty"
        ));
    }
    for safe_index_ref in &profile.safe_index_refs {
        require_non_empty(safe_index_ref, "log evidence profile safeIndexRef")?;
    }
    if !LOG_EVIDENCE_DETAIL_CUSTODIES.contains(&profile.detail_custody.as_str()) {
        return Err(anyhow!("invalid log evidence profile detailCustody"));
    }
    for access_grant_ref in &profile.access_grant_refs {
        require_non_empty(access_grant_ref, "log evidence profile accessGrantRef")?;
    }
    for storage_container_ref in &profile.storage_container_refs {
        require_non_empty(
            storage_container_ref,
            "log evidence profile storageContainerRef",
        )?;
    }
    if profile.encrypted_detail_required && profile.access_grant_refs.is_empty() {
        return Err(anyhow!(
            "encrypted log evidence profile requires accessGrantRefs"
        ));
    }
    if profile.encrypted_detail_required && profile.storage_container_refs.is_empty() {
        return Err(anyhow!(
            "encrypted log evidence profile requires storageContainerRefs"
        ));
    }
    if let Some(materialization_budget_ref) = &profile.materialization_budget_ref {
        require_non_empty(
            materialization_budget_ref,
            "log evidence profile materializationBudgetRef",
        )?;
    }
    if profile.issued_at == 0 {
        return Err(anyhow!("log evidence profile missing issuedAt"));
    }
    if let Some(expires_at) = profile.expires_at
        && expires_at <= profile.issued_at
    {
        return Err(anyhow!(
            "log evidence profile expiresAt must be after issuedAt"
        ));
    }
    Ok(())
}

pub fn reject_sensitive_safe_facts(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, next) in map {
                let lowered = key.to_ascii_lowercase();
                if SENSITIVE_SAFE_FACT_KEY_FRAGMENTS
                    .iter()
                    .any(|fragment| lowered.contains(fragment))
                {
                    return Err(anyhow!("unsafe log safe fact key: {}", key));
                }
                reject_sensitive_safe_facts(next)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_sensitive_safe_facts(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

const SENSITIVE_SAFE_FACT_KEY_FRAGMENTS: &[&str] = &[
    "argv",
    "body",
    "caac",
    "capabilitygrant",
    "credential",
    "decrypted",
    "password",
    "payload",
    "private",
    "raw",
    "rtsp",
    "secret",
    "servicecapability",
    "token",
];

const LOG_EVIDENCE_PROFILE_EVENT_CLASSES: &[&str] = &[
    LOG_EVIDENCE_PROFILE_EVENT_CYBERSEC_AUDIT,
    LOG_EVIDENCE_PROFILE_EVENT_RUNTIME_DIAGNOSTIC,
    LOG_EVIDENCE_PROFILE_EVENT_SERVICE_EVENT,
    LOG_EVIDENCE_PROFILE_EVENT_STORAGE_ACCESS,
    LOG_EVIDENCE_PROFILE_EVENT_MEDIA_PATH,
    LOG_EVIDENCE_PROFILE_EVENT_HOST_SECURITY,
    LOG_EVIDENCE_PROFILE_EVENT_SERVICE_HARDENING,
    LOG_EVIDENCE_PROFILE_EVENT_NETWORK_EXPOSURE,
    LOG_EVIDENCE_PROFILE_EVENT_EVIDENCE_REQUEST,
];

const LOG_EVIDENCE_DETAIL_CUSTODIES: &[&str] = &[
    LOG_EVIDENCE_DETAIL_CUSTODY_SAFE_FACTS_ONLY,
    LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_DETAIL_REF,
    LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_RAW_REF,
];

fn require_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{} is required", name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(safe_facts: Value) -> LogEventEnvelope {
        let mut event = LogEventEnvelope {
            schema_version: LOG_SCHEMA_VERSION,
            event_id: String::new(),
            occurred_at: 1_700_000_000,
            received_at: None,
            producer: LogProducerRef {
                service: "gateway".to_string(),
                component: "managed".to_string(),
                instance_id: Some("gateway-1".to_string()),
                gateway_pk: None,
                service_pk: None,
            },
            category: LogCategory::Capability,
            severity: LogSeverity::Info,
            outcome: LogOutcome::Succeeded,
            subject: Some(LogSubjectRef {
                kind: "service".to_string(),
                id: Some("nvr".to_string()),
                display: Some("Security Cameras".to_string()),
            }),
            resource: None,
            correlation: Some(LogCorrelationRef {
                correlation_id: "corr-1".to_string(),
                causation_id: None,
                trace_id: None,
            }),
            tags: vec!["capability".to_string()],
            safe_facts,
            detail_ref: None,
            encrypted_detail_refs: Vec::new(),
            redaction: vec![LogRedactionClass::Safe],
        };
        event.event_id = log_event_id(&event).expect("event id");
        event
    }

    #[test]
    fn validates_log_event() {
        let event = event(json!({
            "service": "nvr",
            "capabilityRef": "media.stream.preview",
            "operation": "request",
            "result": "accepted"
        }));
        validate_log_event(&event).expect("valid log event");
    }

    #[test]
    fn rejects_sensitive_safe_fact_keys() {
        let token_event = event(json!({
            "service": "nvr",
            "privateToken": "secret"
        }));
        assert!(validate_log_event(&token_event).is_err());

        let grant_event = event(json!({
            "service": "nvr",
            "capabilityGrant": "delegatedAuthorityGrant"
        }));
        assert!(validate_log_event(&grant_event).is_err());
    }

    #[test]
    fn rejects_log_event_id_mismatch() {
        let mut event = event(json!({ "operation": "request" }));
        event.event_id = "bad".to_string();
        assert!(validate_log_event(&event).is_err());
    }

    #[test]
    fn validates_encrypted_detail_refs() {
        let mut event = event(json!({ "operation": "request" }));
        event.encrypted_detail_refs = vec![EncryptedDetailRef {
            object_id: "object-log-detail-1".to_string(),
            container_id: "container-log-detail".to_string(),
            key_ref: "container-log-detail:key".to_string(),
            manifest_hash: "sha256:manifest-log-detail".to_string(),
            summary_tags: vec!["debug-detail".to_string()],
        }];
        event.redaction = vec![LogRedactionClass::Safe, LogRedactionClass::EncryptedDetail];
        event.event_id = log_event_id(&event).expect("event id");
        validate_log_event(&event).expect("valid detail ref");

        let mut bad = event;
        bad.encrypted_detail_refs[0].container_id = String::new();
        bad.event_id = log_event_id(&bad).expect("event id");
        assert!(validate_log_event(&bad).is_err());
    }

    #[test]
    fn validates_log_evidence_profile() {
        let profile = LogEvidenceProfile {
            kind: Some(LOG_EVIDENCE_PROFILE_KIND.to_string()),
            profile_id: "logging.cybersec.default".to_string(),
            consumer_ref: "constitute-cybersec".to_string(),
            event_classes: vec![
                LOG_EVIDENCE_PROFILE_EVENT_CYBERSEC_AUDIT.to_string(),
                LOG_EVIDENCE_PROFILE_EVENT_RUNTIME_DIAGNOSTIC.to_string(),
                LOG_EVIDENCE_PROFILE_EVENT_SERVICE_EVENT.to_string(),
                LOG_EVIDENCE_PROFILE_EVENT_HOST_SECURITY.to_string(),
                LOG_EVIDENCE_PROFILE_EVENT_SERVICE_HARDENING.to_string(),
                LOG_EVIDENCE_PROFILE_EVENT_NETWORK_EXPOSURE.to_string(),
                LOG_EVIDENCE_PROFILE_EVENT_EVIDENCE_REQUEST.to_string(),
            ],
            retention_window: "90d".to_string(),
            safe_index_refs: vec![
                "logging.events.safeIndex".to_string(),
                "logging.dashboard.cybersecSummary".to_string(),
            ],
            detail_custody: LOG_EVIDENCE_DETAIL_CUSTODY_ENCRYPTED_DETAIL_REF.to_string(),
            encrypted_detail_required: true,
            access_grant_refs: vec!["grant:logging.cybersec.default".to_string()],
            storage_container_refs: vec!["logging-archive".to_string()],
            materialization_budget_ref: Some("logging.cybersec.default.90d".to_string()),
            issued_at: 1_700_000_000,
            expires_at: Some(1_707_776_000),
        };
        validate_log_evidence_profile(&profile).expect("valid profile");

        let mut missing_grant = profile.clone();
        missing_grant.access_grant_refs = Vec::new();
        assert!(validate_log_evidence_profile(&missing_grant).is_err());

        let mut invalid_class = profile;
        invalid_class.event_classes = vec!["debugEverything".to_string()];
        assert!(validate_log_evidence_profile(&invalid_class).is_err());
    }
}
