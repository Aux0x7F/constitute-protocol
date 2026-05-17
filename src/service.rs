use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::projection::ProjectionFreshness;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceLocationRef {
    pub location_id: String,
    pub label: String,
    pub gateway_pk: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostedServiceDescriptor {
    pub service: String,
    pub service_pk: String,
    pub host_gateway_pk: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ServiceLocationRef>,
    pub surface_channel: String,
    #[serde(default)]
    pub display: Value,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub health: Value,
    #[serde(default)]
    pub nodes: Vec<String>,
    #[serde(default)]
    pub retired: Value,
    #[serde(default)]
    pub transport_hints: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ServiceNodeFieldCapability {
    Read,
    Observe,
    Set,
    Attach,
    Invoke,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceNodeFieldDescriptor {
    pub field_id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub value_kind: String,
    #[serde(default)]
    pub capabilities: Vec<ServiceNodeFieldCapability>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub schema: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceNodeDescriptor {
    pub node_id: String,
    pub path: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub backing_channel: String,
    #[serde(default)]
    pub children: Vec<String>,
    #[serde(default)]
    pub fields: Vec<ServiceNodeFieldDescriptor>,
    #[serde(default)]
    pub terminal_operation: bool,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSurfaceProjection {
    pub surface_id: String,
    pub schema_version: u32,
    pub service: String,
    pub service_pk: String,
    pub host_gateway_pk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ServiceLocationRef>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    pub health_node: String,
    #[serde(default)]
    pub nodes: Vec<ServiceNodeDescriptor>,
    #[serde(default)]
    pub diagnostics: Vec<Value>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAttachDescriptor {
    pub attach_id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub attach_kind: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub endpoint: Value,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceNodeProjectionRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub node_path: String,
    pub service: String,
    pub service_pk: String,
    #[serde(default)]
    pub producer: Value,
    pub freshness: ProjectionFreshness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_schema: Option<String>,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub fields: Value,
    #[serde(default)]
    pub desired: Value,
    #[serde(default)]
    pub status: Value,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub attaches: Vec<ServiceAttachDescriptor>,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub diagnostics: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceNodeSetRequest {
    pub request_id: String,
    pub service: String,
    pub node_path: String,
    #[serde(default)]
    pub desired: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceNodeObserverUpdate {
    pub node_key: String,
    pub node_path: String,
    pub service: String,
    pub freshness: ProjectionFreshness,
    #[serde(default)]
    pub changed_fields: Vec<String>,
    #[serde(default)]
    pub projection: Value,
    #[serde(default)]
    pub diagnostics: Vec<Value>,
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
    if descriptor.surface_channel.trim().is_empty() {
        return Err(anyhow!("service descriptor missing surfaceChannel"));
    }
    if let Some(location) = &descriptor.location {
        validate_service_location_ref(location)?;
    }
    Ok(())
}

pub fn validate_service_location_ref(location: &ServiceLocationRef) -> Result<()> {
    if location.location_id.trim().is_empty() {
        return Err(anyhow!("service location missing locationId"));
    }
    if location.label.trim().is_empty() {
        return Err(anyhow!("service location missing label"));
    }
    if location.gateway_pk.trim().is_empty() {
        return Err(anyhow!("service location missing gatewayPk"));
    }
    Ok(())
}

pub fn validate_service_surface(surface: &ServiceSurfaceProjection) -> Result<()> {
    if surface.surface_id.trim().is_empty() {
        return Err(anyhow!("service surface missing surfaceId"));
    }
    if surface.schema_version == 0 {
        return Err(anyhow!("service surface missing schemaVersion"));
    }
    if surface.service.trim().is_empty() {
        return Err(anyhow!("service surface missing service"));
    }
    if surface.service_pk.trim().is_empty() {
        return Err(anyhow!("service surface missing servicePk"));
    }
    if surface.host_gateway_pk.trim().is_empty() {
        return Err(anyhow!("service surface missing hostGatewayPk"));
    }
    if let Some(location) = &surface.location {
        validate_service_location_ref(location)?;
    }
    if surface.summary.trim().is_empty() {
        return Err(anyhow!("service surface missing summary"));
    }
    if surface.health_node.trim().is_empty() {
        return Err(anyhow!("service surface missing healthNode"));
    }
    if surface.updated_at == 0 {
        return Err(anyhow!("service surface missing updatedAt"));
    }
    if surface.nodes.is_empty() {
        return Err(anyhow!("service surface must describe at least one node"));
    }
    for node in &surface.nodes {
        validate_service_node_descriptor(node)?;
    }
    if find_service_node(surface, &surface.health_node).is_none() {
        return Err(anyhow!("service surface healthNode does not match a node"));
    }
    Ok(())
}

pub fn validate_service_node_descriptor(node: &ServiceNodeDescriptor) -> Result<()> {
    if node.node_id.trim().is_empty() {
        return Err(anyhow!("service node missing nodeId"));
    }
    if node.path.trim().is_empty() {
        return Err(anyhow!("service node missing path"));
    }
    if node.label.trim().is_empty() {
        return Err(anyhow!("service node missing label"));
    }
    for field in &node.fields {
        validate_service_node_field_descriptor(field)?;
    }
    Ok(())
}

pub fn validate_service_node_field_descriptor(field: &ServiceNodeFieldDescriptor) -> Result<()> {
    if field.field_id.trim().is_empty() {
        return Err(anyhow!("service node field missing fieldId"));
    }
    if field.label.trim().is_empty() {
        return Err(anyhow!("service node field missing label"));
    }
    if field.capabilities.is_empty() {
        return Err(anyhow!("service node field missing capabilities"));
    }
    if !field.schema.is_null() && !field.schema.is_object() {
        return Err(anyhow!("service node field schema must be an object"));
    }
    Ok(())
}

pub fn validate_service_attach_descriptor(attach: &ServiceAttachDescriptor) -> Result<()> {
    if attach.attach_id.trim().is_empty() {
        return Err(anyhow!("service attach descriptor missing attachId"));
    }
    if attach.label.trim().is_empty() {
        return Err(anyhow!("service attach descriptor missing label"));
    }
    if attach.attach_kind.trim().is_empty() {
        return Err(anyhow!("service attach descriptor missing attachKind"));
    }
    Ok(())
}

pub fn validate_service_node_projection_record(
    record: &ServiceNodeProjectionRecord,
    surface: &ServiceSurfaceProjection,
) -> Result<()> {
    validate_service_surface(surface)?;
    if record.service.trim() != surface.service.trim() {
        return Err(anyhow!("service node projection service mismatch"));
    }
    if record.service_pk.trim() != surface.service_pk.trim() {
        return Err(anyhow!("service node projection servicePk mismatch"));
    }
    if find_service_node(surface, &record.node_path).is_none() {
        return Err(anyhow!("service node projection targets unknown node"));
    }
    if !record.payload.is_object() {
        return Err(anyhow!("service node projection payload must be an object"));
    }
    if !record.fields.is_null() && !record.fields.is_object() {
        return Err(anyhow!("service node projection fields must be an object"));
    }
    if !record.desired.is_null() && !record.desired.is_object() {
        return Err(anyhow!("service node projection desired must be an object"));
    }
    if !record.status.is_null() && !record.status.is_object() {
        return Err(anyhow!("service node projection status must be an object"));
    }
    if !record.result.is_null() && !record.result.is_object() {
        return Err(anyhow!("service node projection result must be an object"));
    }
    for attach in &record.attaches {
        validate_service_attach_descriptor(attach)?;
    }
    reject_unsafe_safe_facts(&record.safe_facts)?;
    Ok(())
}

pub fn validate_service_node_set_request(
    request: &ServiceNodeSetRequest,
    surface: &ServiceSurfaceProjection,
) -> Result<()> {
    validate_service_surface(surface)?;
    if request.request_id.trim().is_empty() {
        return Err(anyhow!("service node set missing requestId"));
    }
    if request.service.trim() != surface.service.trim() {
        return Err(anyhow!("service node set service mismatch"));
    }
    let node = find_service_node(surface, &request.node_path)
        .ok_or_else(|| anyhow!("service node set targets unknown node"))?;
    let desired = request
        .desired
        .as_object()
        .ok_or_else(|| anyhow!("service node set desired must be an object"))?;
    for field_id in desired.keys() {
        let field = node
            .fields
            .iter()
            .find(|field| field.field_id == *field_id)
            .ok_or_else(|| anyhow!("service node set targets unknown field"))?;
        if !field
            .capabilities
            .iter()
            .any(|capability| matches!(capability, ServiceNodeFieldCapability::Set))
        {
            return Err(anyhow!("service node field is not settable"));
        }
    }
    Ok(())
}

pub fn validate_service_node_observer_update(update: &ServiceNodeObserverUpdate) -> Result<()> {
    if update.node_key.trim().is_empty() {
        return Err(anyhow!("service node observer missing nodeKey"));
    }
    if update.node_path.trim().is_empty() {
        return Err(anyhow!("service node observer missing nodePath"));
    }
    if update.service.trim().is_empty() {
        return Err(anyhow!("service node observer missing service"));
    }
    if update.freshness.updated_at == 0 {
        return Err(anyhow!("service node observer missing freshness timestamp"));
    }
    Ok(())
}

pub fn find_service_node<'a>(
    surface: &'a ServiceSurfaceProjection,
    node_path: &str,
) -> Option<&'a ServiceNodeDescriptor> {
    let normalized = node_path.trim();
    surface.nodes.iter().find(|node| {
        node.path.trim() == normalized
            || node.aliases.iter().any(|alias| alias.trim() == normalized)
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::{ProjectionFreshness, ProjectionFreshnessState};
    use serde_json::json;

    fn surface() -> ServiceSurfaceProjection {
        ServiceSurfaceProjection {
            surface_id: "logging.surface".to_string(),
            schema_version: 1,
            service: "logging".to_string(),
            service_pk: "logging-service-pk".to_string(),
            host_gateway_pk: "gateway-pk".to_string(),
            location: Some(ServiceLocationRef {
                location_id: "lab-gateway".to_string(),
                label: "Lab Gateway".to_string(),
                gateway_pk: "gateway-pk".to_string(),
            }),
            aliases: vec!["Logging".to_string()],
            summary: "Structured safe event observation.".to_string(),
            health_node: "health".to_string(),
            nodes: vec![
                ServiceNodeDescriptor {
                    node_id: "logging.health".to_string(),
                    path: "health".to_string(),
                    label: "Health".to_string(),
                    description: "Current service health.".to_string(),
                    aliases: vec![],
                    backing_channel: "logging.health".to_string(),
                    children: vec![],
                    fields: vec![ServiceNodeFieldDescriptor {
                        field_id: "status".to_string(),
                        label: "Status".to_string(),
                        description: "One-line health state.".to_string(),
                        value_kind: "string".to_string(),
                        capabilities: vec![
                            ServiceNodeFieldCapability::Read,
                            ServiceNodeFieldCapability::Observe,
                        ],
                        required: true,
                        schema: json!({ "type": "string" }),
                    }],
                    terminal_operation: false,
                    metadata: json!({}),
                },
                ServiceNodeDescriptor {
                    node_id: "logging.settings".to_string(),
                    path: "settings".to_string(),
                    label: "Settings".to_string(),
                    description: "Operator-facing logging policy controls.".to_string(),
                    aliases: vec![],
                    backing_channel: "logging.settings".to_string(),
                    children: vec![],
                    fields: vec![ServiceNodeFieldDescriptor {
                        field_id: "verbosity".to_string(),
                        label: "Verbosity".to_string(),
                        description: "Maximum materialized event verbosity.".to_string(),
                        value_kind: "string".to_string(),
                        capabilities: vec![
                            ServiceNodeFieldCapability::Read,
                            ServiceNodeFieldCapability::Observe,
                            ServiceNodeFieldCapability::Set,
                        ],
                        required: false,
                        schema: json!({ "enum": ["normal", "verbose"] }),
                    }],
                    terminal_operation: false,
                    metadata: json!({}),
                },
            ],
            diagnostics: vec![],
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn validates_service_surface_and_node_projection() {
        let surface = surface();
        validate_service_surface(&surface).expect("surface is valid");

        let descriptor = HostedServiceDescriptor {
            service: "logging".to_string(),
            service_pk: "logging-service-pk".to_string(),
            host_gateway_pk: "gateway-pk".to_string(),
            aliases: vec!["Logging".to_string()],
            location: surface.location.clone(),
            surface_channel: "logging.surface".to_string(),
            display: json!({ "name": "Constitute Logging" }),
            summary: surface.summary.clone(),
            health: json!({ "status": "ok" }),
            nodes: surface.nodes.iter().map(|node| node.path.clone()).collect(),
            retired: json!({}),
            transport_hints: json!({}),
        };
        validate_hosted_service_descriptor(&descriptor).expect("descriptor is valid");

        let record = ServiceNodeProjectionRecord {
            request_id: Some("node-1".to_string()),
            node_path: "health".to_string(),
            service: "logging".to_string(),
            service_pk: "logging-service-pk".to_string(),
            producer: json!({ "service": "logging" }),
            freshness: ProjectionFreshness {
                state: ProjectionFreshnessState::Fresh,
                updated_at: 1_700_000_001,
                stale_after: Some(1_700_000_031),
                reason: None,
            },
            payload_schema: Some("constitute.service.node.health.v1".to_string()),
            payload: json!({ "status": "ok" }),
            fields: json!({ "status": "ok" }),
            desired: json!({}),
            status: json!({ "state": "ok" }),
            result: json!({}),
            attaches: vec![],
            safe_facts: json!({ "status": "ok" }),
            diagnostics: vec![],
        };
        validate_service_node_projection_record(&record, &surface)
            .expect("node projection is valid");
    }

    #[test]
    fn rejects_unknown_or_unsettable_service_node_fields() {
        let surface = surface();
        let valid = ServiceNodeSetRequest {
            request_id: "set-1".to_string(),
            service: "logging".to_string(),
            node_path: "settings".to_string(),
            desired: json!({ "verbosity": "verbose" }),
        };
        validate_service_node_set_request(&valid, &surface).expect("settable field accepted");

        let unknown = ServiceNodeSetRequest {
            desired: json!({ "missing": true }),
            ..valid.clone()
        };
        assert!(validate_service_node_set_request(&unknown, &surface).is_err());

        let readonly = ServiceNodeSetRequest {
            node_path: "health".to_string(),
            desired: json!({ "status": "ok" }),
            ..valid
        };
        assert!(validate_service_node_set_request(&readonly, &surface).is_err());
    }
}
