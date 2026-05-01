use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::caac::CaacEnvelope;

pub const EVENT_GATEWAY_SERVICE_ACCESS_REQUEST: &str = "gateway_service_access_request";
pub const EVENT_GATEWAY_SERVICE_ACCESS_STATUS: &str = "gateway_service_access_status";
pub const EVENT_GATEWAY_SERVICE_SIGNAL_REQUEST: &str = "gateway_service_signal_request";
pub const EVENT_GATEWAY_SERVICE_SIGNAL_STATUS: &str = "gateway_service_signal_status";
pub const EVENT_GATEWAY_SERVICE_SIGNAL: &str = "gateway_service_signal";
pub const GRANT_GATEWAY_SERVICE_ACCESS: &str = "gateway.service_access";

pub const CAAC_KIND_SERVICE_ACCESS_CAPABILITY: &str = "service_access.capability";
pub const CAAC_KIND_SERVICE_ACCESS_STATUS: &str = "service_access.status";
pub const CAAC_KIND_SERVICE_ACCESS_REQUEST: &str = "service_access.request";
pub const CAAC_KIND_SERVICE_ACCESS_SIGNAL: &str = "service_access.signal";
pub const CAAC_KIND_SERVICE_ACCESS_INVOCATION: &str = "service_access.invocation";
pub const CAAC_KIND_SERVICE_ACCESS_ADMIN: &str = "service_access.admin";
pub const CAAC_KIND_SERVICE_ACCESS_CONTROL: &str = "service_access.control";
pub const CAAC_KIND_SERVICE_ACCESS_CLOSE: &str = "service_access.close";

pub const DEFAULT_CAPABILITY_TTL_SECONDS: u64 = 15 * 60;
pub const MAX_CAPABILITY_TTL_SECONDS: u64 = 30 * 60;
pub const DEFAULT_REQUEST_TTL_SECONDS: u64 = 90;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccessCapabilityClaims {
    pub capability_id: String,
    pub gateway_pk: String,
    pub service_pk: String,
    pub service: String,
    pub identity_id: String,
    pub device_pk: String,
    pub capability: String,
    #[serde(default)]
    pub owner: bool,
    #[serde(default)]
    pub view_sources: Vec<String>,
    #[serde(default)]
    pub control_sources: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccessStatusClaims {
    pub request_id: String,
    pub status: String,
    pub gateway_pk: String,
    pub service_pk: String,
    pub service: String,
    #[serde(default)]
    pub display: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_capability: Option<CaacEnvelope>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccessContext {
    pub context_id: String,
    pub service: String,
    pub gateway_pk: String,
    pub service_pk: String,
    #[serde(default)]
    pub identity_id: String,
    #[serde(default)]
    pub device_pk: String,
    #[serde(default)]
    pub display: Value,
    pub service_capability: CaacEnvelope,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSignalRequest {
    pub gateway_pk: String,
    pub service_pk: String,
    pub service: String,
    pub signal_type: String,
    pub service_capability: CaacEnvelope,
    pub payload: CaacEnvelope,
}

pub fn service_access_routing_tags(
    gateway_pk: &str,
    service_pk: &str,
    service: &str,
    envelope_kind: &str,
) -> Vec<Vec<String>> {
    let mut tags = vec![
        vec!["t".to_string(), "constitute".to_string()],
        vec!["t".to_string(), "service_access".to_string()],
    ];
    if !gateway_pk.is_empty() {
        tags.push(vec!["p".to_string(), gateway_pk.to_string()]);
    }
    if !service_pk.is_empty() {
        tags.push(vec!["service_pk".to_string(), service_pk.to_string()]);
    }
    if !service.is_empty() {
        tags.push(vec!["service".to_string(), service.to_string()]);
    }
    if !envelope_kind.is_empty() {
        tags.push(vec!["caac_kind".to_string(), envelope_kind.to_string()]);
    }
    tags
}
