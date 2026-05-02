use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{canonical_json, sha256_hex};
use crate::storage::EncryptedDetailRef;

pub const LOG_SCHEMA_VERSION: u16 = 1;
pub const LOG_EVENT_ID_PREFIX: &str = "constitute-log-event-v1";

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
    ServiceAccess,
    ServiceSignal,
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
    let expected = log_event_id(event)?;
    if event.event_id != expected {
        return Err(anyhow!("log event id mismatch"));
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
    "capability",
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
            category: LogCategory::ServiceAccess,
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
            tags: vec!["service-access".to_string()],
            safe_facts,
            detail_ref: None,
            redaction: vec![LogRedactionClass::Safe],
        };
        event.event_id = log_event_id(&event).expect("event id");
        event
    }

    #[test]
    fn validates_log_event() {
        let event = event(json!({
            "service": "nvr",
            "operation": "request",
            "result": "accepted"
        }));
        validate_log_event(&event).expect("valid log event");
    }

    #[test]
    fn rejects_sensitive_safe_fact_keys() {
        let event = event(json!({
            "service": "nvr",
            "serviceCapability": "secret"
        }));
        assert!(validate_log_event(&event).is_err());
    }

    #[test]
    fn rejects_log_event_id_mismatch() {
        let mut event = event(json!({ "operation": "request" }));
        event.event_id = "bad".to_string();
        assert!(validate_log_event(&event).is_err());
    }
}
