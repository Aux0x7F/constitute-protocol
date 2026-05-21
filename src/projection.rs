use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROJECTION_CHANNEL_LOGGING_EVENTS: &str = "logging.events";
pub const PROJECTION_CHANNEL_LOGGING_HEALTH: &str = "logging.health";
pub const PROJECTION_CHANNEL_LOGGING_DASHBOARD: &str = "logging.dashboard";
pub const PROJECTION_CHANNEL_DIAGNOSTICS_EVENTS: &str = "diagnostics.events";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionFreshnessState {
    Fresh,
    Stale,
    Missing,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionCursor {
    pub value: String,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionFreshness {
    pub state: ProjectionFreshnessState,
    pub updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_after: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionChannel {
    pub channel_id: String,
    pub service: String,
    pub projection_kind: String,
    pub capability_scope: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProjectionSyncState {
    Idle,
    Syncing,
    Degraded,
    Stale,
    Blocked,
    CompleteEnough,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionPolicy {
    pub policy_id: String,
    pub channel_id: String,
    pub service: String,
    #[serde(default)]
    pub scope: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rolling_window_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_verbosity_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub excluded_verbosity_classes: Vec<String>,
    #[serde(default)]
    pub sync_depth_target: Value,
    #[serde(default)]
    pub retention_target: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionCoverage {
    pub materialized_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_count: Option<u64>,
    pub completion_ratio: f64,
    #[serde(default)]
    pub complete_severity_bands: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_observed_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_observed_at: Option<u64>,
    pub sync_state: ProjectionSyncState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionObserverUpdate {
    pub projection_key: String,
    pub changed_count: u64,
    pub coverage: ProjectionCoverage,
    pub freshness: ProjectionFreshness,
    #[serde(default)]
    pub diagnostics: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProjectionRequest {
    pub request_id: String,
    pub channel_id: String,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default)]
    pub filters: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<ProjectionPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionRecord {
    pub channel_id: String,
    pub service: String,
    pub service_pk: String,
    #[serde(default)]
    pub producer: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<ProjectionCursor>,
    pub freshness: ProjectionFreshness,
    #[serde(default)]
    pub scope: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization_budget_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_floor_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_schema: Option<String>,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub safe_facts: Value,
    #[serde(default)]
    pub encrypted_detail_refs: Vec<Value>,
    #[serde(default)]
    pub diagnostics: Vec<Value>,
}

pub fn validate_projection_channel_id_with_allowed(
    channel_id: &str,
    allowed: &[String],
) -> Result<()> {
    let trimmed = channel_id.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("projection missing channel id"));
    }
    if !allowed.is_empty() {
        return allowed
            .iter()
            .any(|channel| channel == trimmed)
            .then_some(())
            .ok_or_else(|| anyhow!("unsupported projection channel"));
    }
    Ok(())
}

pub fn validate_projection_channel_id(channel_id: &str) -> Result<()> {
    validate_projection_channel_id_with_allowed(channel_id, &[])
}

pub fn validate_service_projection_request(req: &ServiceProjectionRequest) -> Result<()> {
    if req.request_id.trim().is_empty() {
        return Err(anyhow!("service projection missing request id"));
    }
    validate_projection_channel_id(&req.channel_id)?;
    if req.service.trim().is_empty() {
        return Err(anyhow!("service projection missing service"));
    }
    if !req.filters.is_object() {
        return Err(anyhow!("service projection filters must be an object"));
    }
    if let Some(policy) = &req.policy {
        validate_projection_policy(policy)?;
        if policy.channel_id != req.channel_id {
            return Err(anyhow!("projection policy channel mismatch"));
        }
        if policy.service != req.service {
            return Err(anyhow!("projection policy service mismatch"));
        }
    }
    Ok(())
}

pub fn validate_projection_policy(policy: &ProjectionPolicy) -> Result<()> {
    if policy.policy_id.trim().is_empty() {
        return Err(anyhow!("projection policy missing policyId"));
    }
    validate_projection_channel_id(&policy.channel_id)?;
    if policy.service.trim().is_empty() {
        return Err(anyhow!("projection policy missing service"));
    }
    if !policy.scope.is_object() {
        return Err(anyhow!("projection policy scope must be an object"));
    }
    if policy.rolling_window_hours == Some(0) {
        return Err(anyhow!("projection policy rolling window must be positive"));
    }
    if !policy.sync_depth_target.is_null() && !policy.sync_depth_target.is_object() {
        return Err(anyhow!(
            "projection policy sync depth target must be an object"
        ));
    }
    if !policy.retention_target.is_null() && !policy.retention_target.is_object() {
        return Err(anyhow!(
            "projection policy retention target must be an object"
        ));
    }
    Ok(())
}

pub fn validate_projection_coverage(coverage: &ProjectionCoverage) -> Result<()> {
    if !coverage.completion_ratio.is_finite()
        || coverage.completion_ratio < 0.0
        || coverage.completion_ratio > 1.0
    {
        return Err(anyhow!("projection coverage completion ratio must be 0..1"));
    }
    if let Some(target_count) = coverage.target_count {
        if coverage.materialized_count > target_count && target_count > 0 {
            return Err(anyhow!(
                "projection coverage materialized count exceeds target"
            ));
        }
    }
    Ok(())
}

pub fn validate_projection_observer_update(update: &ProjectionObserverUpdate) -> Result<()> {
    if update.projection_key.trim().is_empty() {
        return Err(anyhow!("projection observer update missing projection key"));
    }
    validate_projection_coverage(&update.coverage)?;
    if update.freshness.updated_at == 0 {
        return Err(anyhow!(
            "projection observer update missing freshness timestamp"
        ));
    }
    Ok(())
}

pub fn validate_projection_record(record: &ProjectionRecord, allowed: &[String]) -> Result<()> {
    validate_projection_channel_id_with_allowed(&record.channel_id, allowed)?;
    if record.service.trim().is_empty() {
        return Err(anyhow!("projection record missing service"));
    }
    if record.service_pk.trim().is_empty() {
        return Err(anyhow!("projection record missing servicePk"));
    }
    if record
        .materialization_budget_ref
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(anyhow!(
            "projection record materializationBudgetRef is empty"
        ));
    }
    if record
        .consumer_floor_ref
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(anyhow!("projection record consumerFloorRef is empty"));
    }
    if !record.payload.is_object() {
        return Err(anyhow!("projection record payload must be an object"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_service_projection_records() {
        let req = ServiceProjectionRequest {
            request_id: "projection-1".to_string(),
            channel_id: PROJECTION_CHANNEL_LOGGING_EVENTS.to_string(),
            service: "logging".to_string(),
            cursor: None,
            limit: Some(100),
            filters: json!({ "severity": "error" }),
            policy: Some(ProjectionPolicy {
                policy_id: "logging.default.72h.low".to_string(),
                channel_id: PROJECTION_CHANNEL_LOGGING_EVENTS.to_string(),
                service: "logging".to_string(),
                scope: json!({ "rolling": "72h" }),
                rolling_window_hours: Some(72),
                max_verbosity_class: Some("normal".to_string()),
                min_severity: Some("debug".to_string()),
                excluded_verbosity_classes: vec!["noise".to_string()],
                sync_depth_target: json!({ "mode": "policyComplete" }),
                retention_target: json!({ "mode": "loggingDefault" }),
            }),
        };
        validate_service_projection_request(&req).expect("valid request");

        let result = ProjectionRecord {
            channel_id: req.channel_id,
            service: req.service,
            service_pk: "logging-service-pk".to_string(),
            producer: json!({ "service": "logging" }),
            cursor: Some(ProjectionCursor {
                value: "cursor-1".to_string(),
                updated_at: 1_700_000_000,
            }),
            freshness: ProjectionFreshness {
                state: ProjectionFreshnessState::Fresh,
                updated_at: 1_700_000_000,
                stale_after: Some(1_700_000_030),
                reason: None,
            },
            scope: json!({}),
            materialization_budget_ref: Some("logging.default.72h.low".to_string()),
            consumer_floor_ref: Some("logging-ui.events.floor".to_string()),
            payload_schema: Some("constitute.logging.events.v1".to_string()),
            payload: json!({ "events": [] }),
            safe_facts: json!({}),
            encrypted_detail_refs: vec![],
            diagnostics: vec![],
        };
        validate_projection_record(&result, &[]).expect("valid result");
        assert!(
            validate_projection_record(&result, &[PROJECTION_CHANNEL_LOGGING_HEALTH.to_string()])
                .is_err()
        );
    }

    #[test]
    fn rejects_unknown_projection_channel() {
        let req = ServiceProjectionRequest {
            request_id: "projection-1".to_string(),
            channel_id: "logging.raw".to_string(),
            service: "logging".to_string(),
            cursor: None,
            limit: None,
            filters: json!({}),
            policy: None,
        };
        validate_service_projection_request(&req)
            .expect("generic projection requests validate shape without service surface context");
        assert!(
            validate_projection_channel_id_with_allowed(
                &req.channel_id,
                &["logging.health".to_string()]
            )
            .is_err()
        );
    }

    #[test]
    fn validates_projection_policy_coverage_and_observer_update() {
        let policy = ProjectionPolicy {
            policy_id: "logging.default.72h.low".to_string(),
            channel_id: PROJECTION_CHANNEL_LOGGING_EVENTS.to_string(),
            service: "logging".to_string(),
            scope: json!({ "range": "rolling" }),
            rolling_window_hours: Some(72),
            max_verbosity_class: Some("normal".to_string()),
            min_severity: Some("debug".to_string()),
            excluded_verbosity_classes: vec!["noise".to_string()],
            sync_depth_target: json!({ "mode": "policyComplete" }),
            retention_target: json!({ "normalInfo": "48h" }),
        };
        validate_projection_policy(&policy).expect("valid policy");

        let coverage = ProjectionCoverage {
            materialized_count: 100,
            target_count: Some(200),
            completion_ratio: 0.5,
            complete_severity_bands: vec!["critical".to_string(), "error".to_string()],
            oldest_observed_at: Some(1_700_000_000),
            newest_observed_at: Some(1_700_000_100),
            sync_state: ProjectionSyncState::Syncing,
        };
        validate_projection_coverage(&coverage).expect("valid coverage");

        let update = ProjectionObserverUpdate {
            projection_key: "logging:service-pk:logging.events:logging.default.72h.low".to_string(),
            changed_count: 20,
            coverage,
            freshness: ProjectionFreshness {
                state: ProjectionFreshnessState::Fresh,
                updated_at: 1_700_000_100,
                stale_after: Some(1_700_000_160),
                reason: None,
            },
            diagnostics: vec![],
        };
        validate_projection_observer_update(&update).expect("valid observer update");
    }
}
