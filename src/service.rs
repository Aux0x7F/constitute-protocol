use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SERVICE_FRAME_DESCRIBE_REQUEST: &str = "service.describe.request";
pub const SERVICE_FRAME_DESCRIBE_RESPONSE: &str = "service.describe.response";
pub const SERVICE_FRAME_PROJECTION_REQUEST: &str = "service.projection.request";
pub const SERVICE_FRAME_PROJECTION_RESPONSE: &str = "service.projection.response";
pub const SERVICE_FRAME_CONTROL_REQUEST: &str = "service.control.request";
pub const SERVICE_FRAME_CONTROL_RESPONSE: &str = "service.control.response";
pub const SERVICE_FRAME_INVOKE_REQUEST: &str = "service.invoke.request";
pub const SERVICE_FRAME_INVOKE_RESPONSE: &str = "service.invoke.response";
pub const SERVICE_FRAME_WATCH_REQUEST: &str = "service.watch.request";
pub const SERVICE_FRAME_WATCH_EVENT: &str = "service.watch.event";
pub const SERVICE_FRAME_CLOSE: &str = "service.close";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostedServiceDescriptor {
    pub service: String,
    pub service_pk: String,
    pub host_gateway_pk: String,
    #[serde(default)]
    pub display: Value,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub projection_channels: Vec<String>,
    #[serde(default)]
    pub invocation_kinds: Vec<String>,
    #[serde(default)]
    pub transport_hints: Value,
    #[serde(default)]
    pub health_summary: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceExchangeFrame {
    pub frame_id: String,
    pub schema_version: u32,
    pub kind: String,
    pub issuer_pk: String,
    pub recipient_service_pk: String,
    pub host_gateway_pk: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub route_hint: Value,
    #[serde(default)]
    pub sealed_payload: Value,
    pub signature: String,
}

pub fn is_service_exchange_kind(kind: &str) -> bool {
    matches!(
        kind,
        SERVICE_FRAME_DESCRIBE_REQUEST
            | SERVICE_FRAME_DESCRIBE_RESPONSE
            | SERVICE_FRAME_PROJECTION_REQUEST
            | SERVICE_FRAME_PROJECTION_RESPONSE
            | SERVICE_FRAME_CONTROL_REQUEST
            | SERVICE_FRAME_CONTROL_RESPONSE
            | SERVICE_FRAME_INVOKE_REQUEST
            | SERVICE_FRAME_INVOKE_RESPONSE
            | SERVICE_FRAME_WATCH_REQUEST
            | SERVICE_FRAME_WATCH_EVENT
            | SERVICE_FRAME_CLOSE
    )
}

pub fn validate_hosted_service_descriptor(descriptor: &HostedServiceDescriptor) -> Result<()> {
    if descriptor.service.trim().is_empty() {
        return Err(anyhow!("service descriptor missing service"));
    }
    if descriptor.service_pk.trim().is_empty() {
        return Err(anyhow!("service descriptor missing servicePk"));
    }
    if descriptor.host_gateway_pk.trim().is_empty() {
        return Err(anyhow!("service descriptor missing hostGatewayPk"));
    }
    for channel in &descriptor.projection_channels {
        if channel.trim().is_empty() {
            return Err(anyhow!(
                "service descriptor contains empty projection channel"
            ));
        }
    }
    Ok(())
}

pub fn validate_service_exchange_frame(frame: &ServiceExchangeFrame) -> Result<()> {
    if frame.frame_id.trim().is_empty() {
        return Err(anyhow!("service exchange missing frameId"));
    }
    if frame.schema_version == 0 {
        return Err(anyhow!("service exchange missing schemaVersion"));
    }
    if !is_service_exchange_kind(frame.kind.trim()) {
        return Err(anyhow!("unsupported service exchange kind"));
    }
    if frame.issuer_pk.trim().is_empty() {
        return Err(anyhow!("service exchange missing issuerPk"));
    }
    if frame.recipient_service_pk.trim().is_empty() {
        return Err(anyhow!("service exchange missing recipientServicePk"));
    }
    if frame.host_gateway_pk.trim().is_empty() {
        return Err(anyhow!("service exchange missing hostGatewayPk"));
    }
    if frame.issued_at == 0 || frame.expires_at == 0 || frame.expires_at <= frame.issued_at {
        return Err(anyhow!("service exchange invalid time bounds"));
    }
    if frame.signature.trim().is_empty() {
        return Err(anyhow!("service exchange missing signature"));
    }
    Ok(())
}

pub fn reject_unsafe_safe_facts(value: &Value) -> Result<()> {
    fn walk(path: &str, value: &Value) -> Result<()> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let lowered = key.to_ascii_lowercase();
                    let banned = [
                        "password",
                        "credential",
                        "secret",
                        "token",
                        "capability",
                        "servicecapability",
                        "privatekey",
                        "secretkey",
                        "rtspurl",
                        "authorization",
                        "rawpayload",
                        "requestbody",
                    ];
                    if banned.iter().any(|needle| lowered.contains(needle)) {
                        return Err(anyhow!("unsafe safe fact key: {path}{key}"));
                    }
                    walk(&format!("{path}{key}."), child)?;
                }
            }
            Value::String(text) => {
                let lowered = text.to_ascii_lowercase();
                if lowered.contains("rtsp://")
                    || lowered.contains("authorization:")
                    || lowered.contains("servicecapability")
                    || lowered.contains("-----begin")
                {
                    return Err(anyhow!("unsafe safe fact value"));
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(path, item)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk("", value)
}
