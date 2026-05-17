pub const BROKER_PROJECTION_GET: &str = "projection.get";
pub const BROKER_PROJECTION_PUT: &str = "projection.put";
pub const BROKER_SERVICE_CATALOG_GET: &str = "service.catalog.get";
pub const BROKER_SERVICE_NODE_GET: &str = "service.node.get";
pub const BROKER_SERVICE_NODE_POLICY_PUT: &str = "service.node.policy.put";

pub fn is_protocol_broker_message(name: &str) -> bool {
    matches!(
        name,
        BROKER_PROJECTION_GET
            | BROKER_PROJECTION_PUT
            | BROKER_SERVICE_CATALOG_GET
            | BROKER_SERVICE_NODE_GET
            | BROKER_SERVICE_NODE_POLICY_PUT
    )
}
