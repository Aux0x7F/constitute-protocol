use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRecord {
    pub identity_id: String,
    #[serde(default)]
    pub handle: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRecord {
    pub gateway_pk: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub freshness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostedServiceRecord {
    pub service_pk: String,
    pub service: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub gateway_pk: String,
}
