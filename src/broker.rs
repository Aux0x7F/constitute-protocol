pub const BROKER_SERVICE_ACCESS_REQUEST: &str = "gateway.serviceAccess.request";
pub const BROKER_SERVICE_ACCESS_RESPONSE: &str = "gateway.serviceAccess.response";
pub const BROKER_SERVICE_SIGNAL_REQUEST: &str = "gateway.serviceSignal.request";
pub const BROKER_SERVICE_SIGNAL_RESPONSE: &str = "gateway.serviceSignal.response";
pub const BROKER_SERVICE_ACCESS_CONTEXT_GET: &str = "serviceAccessContext.get";
pub const BROKER_SERVICE_ACCESS_CONTEXT_PUT: &str = "serviceAccessContext.put";
pub const BROKER_SERVICE_ACCESS_CONTEXT_DELETE: &str = "serviceAccessContext.delete";

pub fn is_protocol_broker_message(name: &str) -> bool {
    matches!(
        name,
        BROKER_SERVICE_ACCESS_REQUEST
            | BROKER_SERVICE_ACCESS_RESPONSE
            | BROKER_SERVICE_SIGNAL_REQUEST
            | BROKER_SERVICE_SIGNAL_RESPONSE
            | BROKER_SERVICE_ACCESS_CONTEXT_GET
            | BROKER_SERVICE_ACCESS_CONTEXT_PUT
            | BROKER_SERVICE_ACCESS_CONTEXT_DELETE
    )
}
