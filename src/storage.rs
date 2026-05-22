use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;

pub const RECORD_STORAGE_BACKEND_POSTURE: &str = "storage.backend.posture";
pub const RECORD_STORAGE_BACKEND_SNAPSHOT: &str = "storage.backend.snapshot";
pub const RECORD_STORAGE_FILESYSTEM_VIEW: &str = "storage.filesystem.view";
pub const STORAGE_OBJECT_HASH_ALG: &str = "sha256-ciphertext-v1";
pub const STORAGE_CHUNK_HASH_ALG: &str = "sha256-ciphertext-v1";
pub const STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305: &str = "xchacha20poly1305";
pub const CAAC_KIND_STORAGE_KEY_GRANT: &str = "storage.key_grant";
pub const STORAGE_BACKEND_KIND_LOCAL_FS_SQLITE: &str = "localFsSqlite";
pub const STORAGE_BACKEND_STATE_READY: &str = "ready";
pub const STORAGE_BACKEND_STATE_DEGRADED: &str = "degraded";
pub const STORAGE_BACKEND_STATE_BLOCKED: &str = "blocked";
pub const STORAGE_BACKEND_STATE_UNAVAILABLE: &str = "unavailable";
pub const STORAGE_FILESYSTEM_VIEW_READY: &str = "ready";
pub const STORAGE_FILESYSTEM_VIEW_DEGRADED: &str = "degraded";
pub const STORAGE_FILESYSTEM_VIEW_BLOCKED: &str = "blocked";
pub const STORAGE_FILESYSTEM_VIEW_UNAVAILABLE: &str = "unavailable";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StorageKeyGranularity {
    Container,
    Shard,
    Entry,
    FieldFamily,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageContainer {
    pub container_id: String,
    pub owner_pk: String,
    pub created_at: u64,
    #[serde(default)]
    pub key_granularity: Vec<StorageKeyGranularity>,
    #[serde(default)]
    pub default_retention_class: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageChunkRef {
    pub chunk_id: String,
    pub hash: String,
    pub hash_alg: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageObjectManifest {
    pub object_id: String,
    pub container_id: String,
    pub content_hash: String,
    pub hash_alg: String,
    pub encryption_alg: String,
    pub key_ref: String,
    pub chunks: Vec<StorageChunkRef>,
    pub created_at: u64,
    #[serde(default)]
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_deleted_at: Option<u64>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageGraphEdge {
    pub edge_id: String,
    pub container_id: String,
    pub from_ref: String,
    pub relation: String,
    pub to_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_ref: Option<EncryptedDetailRef>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageIndexShard {
    pub shard_id: String,
    pub container_id: String,
    pub shard_type: String,
    pub key_ref: String,
    pub ciphertext_hash: String,
    pub hash_alg: String,
    pub chunks: Vec<StorageChunkRef>,
    #[serde(default)]
    pub object_refs: Vec<String>,
    #[serde(default)]
    pub graph_edges: Vec<StorageGraphEdge>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageKeyGrant {
    pub grant_id: String,
    pub container_id: String,
    pub key_ref: String,
    pub scope: String,
    pub recipient_pk: String,
    pub issuer_pk: String,
    pub wrapping_alg: String,
    pub wrapped_key: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinLease {
    pub pin_id: String,
    pub container_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_hash: Option<String>,
    pub pinned_by: String,
    pub retention_class: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_accessed_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageAvailabilityRef {
    pub availability_id: String,
    pub storage_host_id: String,
    pub retention_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_hash: Option<String>,
    pub exported_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageBackendPosture {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub posture_id: String,
    pub backend_id: String,
    pub storage_member_ref: String,
    pub backend_kind: String,
    pub state: String,
    pub root_ref: String,
    pub object_count: u64,
    pub chunk_count: u64,
    pub stored_bytes: u64,
    pub index_shard_count: u64,
    pub key_grant_count: u64,
    pub pin_lease_count: u64,
    pub pin_intent_count: u64,
    pub pin_attestation_count: u64,
    pub materialized_entry_count: u64,
    pub logical_deleted_object_count: u64,
    pub missing_chunk_count: u64,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub sampled_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageBackendSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub snapshot_id: String,
    pub backend_id: String,
    pub storage_member_ref: String,
    pub posture_ref: String,
    pub object_count: u64,
    pub chunk_count: u64,
    pub pin_lease_count: u64,
    pub pin_intent_count: u64,
    pub pin_attestation_count: u64,
    pub materialized_entry_count: u64,
    #[serde(default)]
    pub object_refs: Vec<String>,
    #[serde(default)]
    pub chunk_refs: Vec<String>,
    #[serde(default)]
    pub pin_lease_refs: Vec<String>,
    #[serde(default)]
    pub pin_intent_refs: Vec<String>,
    #[serde(default)]
    pub pin_projection_refs: Vec<String>,
    pub capped_at: u64,
    pub captured_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageFilesystemEntry {
    pub entry_ref: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_ref: Option<String>,
    #[serde(default)]
    pub media_type: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_deleted_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageFilesystemView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub view_id: String,
    pub backend_id: String,
    pub storage_member_ref: String,
    pub root_ref: String,
    pub state: String,
    pub view_mode: String,
    pub materialization_ref: String,
    pub object_count: u64,
    pub chunk_count: u64,
    pub entry_count: u64,
    #[serde(default)]
    pub entries: Vec<StorageFilesystemEntry>,
    pub capped_at: u64,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    pub captured_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedDetailRef {
    pub object_id: String,
    pub container_id: String,
    pub key_ref: String,
    pub manifest_hash: String,
    #[serde(default)]
    pub summary_tags: Vec<String>,
}

pub fn storage_ciphertext_hash(bytes: impl AsRef<[u8]>) -> String {
    sha256_hex(bytes)
}

pub fn storage_object_id(container_id: &str, content_hash: &str) -> String {
    sha256_hex(format!(
        "constitute-storage-object-v1|{}|{}",
        container_id.trim(),
        content_hash.trim()
    ))
}

pub fn storage_chunk_id(hash: &str) -> String {
    sha256_hex(format!("constitute-storage-chunk-v1|{}", hash.trim()))
}

pub fn validate_storage_chunk_ref(chunk: &StorageChunkRef, bytes: &[u8]) -> Result<()> {
    if chunk.hash_alg != STORAGE_CHUNK_HASH_ALG {
        return Err(anyhow!("unsupported storage chunk hash algorithm"));
    }
    if chunk.size != bytes.len() as u64 {
        return Err(anyhow!("storage chunk size mismatch"));
    }
    let actual = storage_ciphertext_hash(bytes);
    if chunk.hash != actual {
        return Err(anyhow!("storage chunk hash mismatch"));
    }
    if chunk.chunk_id != storage_chunk_id(&chunk.hash) {
        return Err(anyhow!("storage chunk id mismatch"));
    }
    Ok(())
}

pub fn validate_storage_manifest(manifest: &StorageObjectManifest) -> Result<()> {
    if manifest.container_id.trim().is_empty() {
        return Err(anyhow!("storage manifest missing container id"));
    }
    if manifest.content_hash.trim().is_empty() {
        return Err(anyhow!("storage manifest missing content hash"));
    }
    if manifest.hash_alg != STORAGE_OBJECT_HASH_ALG {
        return Err(anyhow!("unsupported storage object hash algorithm"));
    }
    if manifest.encryption_alg != STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305 {
        return Err(anyhow!("unsupported storage object encryption algorithm"));
    }
    if manifest.key_ref.trim().is_empty() {
        return Err(anyhow!("storage manifest missing key ref"));
    }
    if manifest.chunks.is_empty() {
        return Err(anyhow!("storage manifest has no chunks"));
    }
    if manifest.object_id != storage_object_id(&manifest.container_id, &manifest.content_hash) {
        return Err(anyhow!("storage object id mismatch"));
    }
    Ok(())
}

pub fn validate_storage_backend_posture(posture: &StorageBackendPosture) -> Result<()> {
    validate_optional_kind(
        posture.kind.as_deref(),
        RECORD_STORAGE_BACKEND_POSTURE,
        "storage backend posture",
    )?;
    require_non_empty(
        &posture.posture_id,
        "storage backend posture missing postureId",
    )?;
    require_non_empty(
        &posture.backend_id,
        "storage backend posture missing backendId",
    )?;
    require_non_empty(
        &posture.storage_member_ref,
        "storage backend posture missing storageMemberRef",
    )?;
    require_non_empty(&posture.root_ref, "storage backend posture missing rootRef")?;
    if posture.backend_kind != STORAGE_BACKEND_KIND_LOCAL_FS_SQLITE {
        return Err(anyhow!("unsupported storage backend kind"));
    }
    validate_storage_backend_state(&posture.state)?;
    if posture.state == STORAGE_BACKEND_STATE_READY && posture.missing_chunk_count > 0 {
        return Err(anyhow!("ready storage backend cannot have missing chunks"));
    }
    if matches!(
        posture.state.as_str(),
        STORAGE_BACKEND_STATE_DEGRADED | STORAGE_BACKEND_STATE_BLOCKED
    ) && posture.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "degraded or blocked storage backend posture requires blockedReasons"
        ));
    }
    validate_ref_list(
        &posture.evidence_refs,
        "storage backend posture evidenceRefs",
    )?;
    validate_ref_list(
        &posture.blocked_reasons,
        "storage backend posture blockedReasons",
    )?;
    if posture.sampled_at == 0 {
        return Err(anyhow!("storage backend posture missing sampledAt"));
    }
    if posture
        .expires_at
        .is_some_and(|expires_at| expires_at <= posture.sampled_at)
    {
        return Err(anyhow!(
            "storage backend posture expiresAt must be after sampledAt"
        ));
    }
    Ok(())
}

pub fn validate_storage_backend_snapshot(snapshot: &StorageBackendSnapshot) -> Result<()> {
    validate_optional_kind(
        snapshot.kind.as_deref(),
        RECORD_STORAGE_BACKEND_SNAPSHOT,
        "storage backend snapshot",
    )?;
    require_non_empty(
        &snapshot.snapshot_id,
        "storage backend snapshot missing snapshotId",
    )?;
    require_non_empty(
        &snapshot.backend_id,
        "storage backend snapshot missing backendId",
    )?;
    require_non_empty(
        &snapshot.storage_member_ref,
        "storage backend snapshot missing storageMemberRef",
    )?;
    require_non_empty(
        &snapshot.posture_ref,
        "storage backend snapshot missing postureRef",
    )?;
    validate_ref_list(&snapshot.object_refs, "storage backend snapshot objectRefs")?;
    validate_ref_list(&snapshot.chunk_refs, "storage backend snapshot chunkRefs")?;
    validate_ref_list(
        &snapshot.pin_lease_refs,
        "storage backend snapshot pinLeaseRefs",
    )?;
    validate_ref_list(
        &snapshot.pin_intent_refs,
        "storage backend snapshot pinIntentRefs",
    )?;
    validate_ref_list(
        &snapshot.pin_projection_refs,
        "storage backend snapshot pinProjectionRefs",
    )?;
    if snapshot.captured_at == 0 {
        return Err(anyhow!("storage backend snapshot missing capturedAt"));
    }
    if snapshot
        .expires_at
        .is_some_and(|expires_at| expires_at <= snapshot.captured_at)
    {
        return Err(anyhow!(
            "storage backend snapshot expiresAt must be after capturedAt"
        ));
    }
    Ok(())
}

pub fn validate_storage_graph_edge(edge: &StorageGraphEdge) -> Result<()> {
    require_non_empty(&edge.edge_id, "storage graph edge missing edgeId")?;
    require_non_empty(&edge.container_id, "storage graph edge missing containerId")?;
    require_non_empty(&edge.from_ref, "storage graph edge missing fromRef")?;
    require_non_empty(&edge.relation, "storage graph edge missing relation")?;
    require_non_empty(&edge.to_ref, "storage graph edge missing toRef")?;
    if edge.created_at == 0 {
        return Err(anyhow!("storage graph edge missing createdAt"));
    }
    let refs = [
        edge.edge_id.as_str(),
        edge.container_id.as_str(),
        edge.from_ref.as_str(),
        edge.to_ref.as_str(),
    ];
    if refs.iter().any(|value| {
        value.chars().any(char::is_whitespace)
            || value.contains('\\')
            || value.starts_with('/')
            || value.starts_with("file:")
            || value.starts_with("http:")
            || value.starts_with("https:")
    }) {
        return Err(anyhow!("storage graph edge refs must be virtual refs"));
    }
    Ok(())
}

pub fn validate_storage_filesystem_view(view: &StorageFilesystemView) -> Result<()> {
    validate_optional_kind(
        view.kind.as_deref(),
        RECORD_STORAGE_FILESYSTEM_VIEW,
        "storage filesystem view",
    )?;
    require_non_empty(&view.view_id, "storage filesystem view missing viewId")?;
    require_non_empty(
        &view.backend_id,
        "storage filesystem view missing backendId",
    )?;
    require_non_empty(
        &view.storage_member_ref,
        "storage filesystem view missing storageMemberRef",
    )?;
    require_non_empty(&view.root_ref, "storage filesystem view missing rootRef")?;
    validate_storage_filesystem_view_state(&view.state)?;
    require_non_empty(&view.view_mode, "storage filesystem view missing viewMode")?;
    require_non_empty(
        &view.materialization_ref,
        "storage filesystem view missing materializationRef",
    )?;
    if matches!(
        view.state.as_str(),
        STORAGE_FILESYSTEM_VIEW_DEGRADED | STORAGE_FILESYSTEM_VIEW_BLOCKED
    ) && view.blocked_reasons.is_empty()
    {
        return Err(anyhow!(
            "degraded or blocked storage filesystem view requires blockedReasons"
        ));
    }
    if view.entry_count != view.entries.len() as u64 {
        return Err(anyhow!("storage filesystem view entryCount mismatch"));
    }
    for entry in &view.entries {
        validate_storage_filesystem_entry(entry)?;
    }
    validate_ref_list(&view.evidence_refs, "storage filesystem view evidenceRefs")?;
    validate_ref_list(
        &view.blocked_reasons,
        "storage filesystem view blockedReasons",
    )?;
    if view.captured_at == 0 {
        return Err(anyhow!("storage filesystem view missing capturedAt"));
    }
    if view
        .expires_at
        .is_some_and(|expires_at| expires_at <= view.captured_at)
    {
        return Err(anyhow!(
            "storage filesystem view expiresAt must be after capturedAt"
        ));
    }
    Ok(())
}

fn validate_storage_filesystem_entry(entry: &StorageFilesystemEntry) -> Result<()> {
    require_non_empty(
        &entry.entry_ref,
        "storage filesystem entry missing entryRef",
    )?;
    require_non_empty(&entry.path, "storage filesystem entry missing path")?;
    if entry.object_ref.is_none() && entry.chunk_ref.is_none() {
        return Err(anyhow!(
            "storage filesystem entry missing objectRef or chunkRef"
        ));
    }
    if let Some(object_ref) = &entry.object_ref {
        require_non_empty(object_ref, "storage filesystem entry missing objectRef")?;
    }
    if let Some(chunk_ref) = &entry.chunk_ref {
        require_non_empty(chunk_ref, "storage filesystem entry missing chunkRef")?;
    }
    validate_storage_virtual_path(&entry.path)?;
    Ok(())
}

pub fn validate_storage_index_shard(shard: &StorageIndexShard) -> Result<()> {
    if shard.shard_id.trim().is_empty() {
        return Err(anyhow!("storage index shard missing id"));
    }
    if shard.container_id.trim().is_empty() {
        return Err(anyhow!("storage index shard missing container id"));
    }
    if shard.key_ref.trim().is_empty() {
        return Err(anyhow!("storage index shard missing key ref"));
    }
    if shard.hash_alg != STORAGE_OBJECT_HASH_ALG {
        return Err(anyhow!("unsupported storage index shard hash algorithm"));
    }
    if shard.ciphertext_hash.trim().is_empty() {
        return Err(anyhow!("storage index shard missing ciphertext hash"));
    }
    if shard.chunks.is_empty() {
        return Err(anyhow!("storage index shard has no chunks"));
    }
    for edge in &shard.graph_edges {
        validate_storage_graph_edge(edge)?;
    }
    Ok(())
}

fn validate_optional_kind(kind: Option<&str>, expected: &str, context: &str) -> Result<()> {
    if let Some(kind) = kind {
        if kind != expected {
            return Err(anyhow!("{context} kind mismatch"));
        }
    }
    Ok(())
}

fn validate_storage_backend_state(state: &str) -> Result<()> {
    if matches!(
        state,
        STORAGE_BACKEND_STATE_READY
            | STORAGE_BACKEND_STATE_DEGRADED
            | STORAGE_BACKEND_STATE_BLOCKED
            | STORAGE_BACKEND_STATE_UNAVAILABLE
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported storage backend state"))
    }
}

fn validate_storage_filesystem_view_state(state: &str) -> Result<()> {
    if matches!(
        state,
        STORAGE_FILESYSTEM_VIEW_READY
            | STORAGE_FILESYSTEM_VIEW_DEGRADED
            | STORAGE_FILESYSTEM_VIEW_BLOCKED
            | STORAGE_FILESYSTEM_VIEW_UNAVAILABLE
    ) {
        Ok(())
    } else {
        Err(anyhow!("unsupported storage filesystem view state"))
    }
}

fn validate_storage_virtual_path(path: &str) -> Result<()> {
    if path.starts_with('/') || path.starts_with('\\') || path.contains(':') {
        return Err(anyhow!("storage filesystem path must be virtual relative"));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(anyhow!("storage filesystem path contains invalid segment"));
    }
    if path.contains('\\') {
        return Err(anyhow!("storage filesystem path must use slash separators"));
    }
    Ok(())
}

fn require_non_empty(value: &str, message: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(anyhow!(message.to_string()))
    } else {
        Ok(())
    }
}

fn validate_ref_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        require_non_empty(value, context)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ciphertext_chunk_and_manifest() {
        let bytes = b"encrypted bytes";
        let hash = storage_ciphertext_hash(bytes);
        let chunk = StorageChunkRef {
            chunk_id: storage_chunk_id(&hash),
            hash: hash.clone(),
            hash_alg: STORAGE_CHUNK_HASH_ALG.to_string(),
            size: bytes.len() as u64,
        };
        validate_storage_chunk_ref(&chunk, bytes).expect("valid chunk");
        let manifest = StorageObjectManifest {
            object_id: storage_object_id("container-a", &hash),
            container_id: "container-a".to_string(),
            content_hash: hash,
            hash_alg: STORAGE_OBJECT_HASH_ALG.to_string(),
            encryption_alg: STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305.to_string(),
            key_ref: "container-a:key".to_string(),
            chunks: vec![chunk],
            created_at: 1_700_000_000,
            media_type: "application/octet-stream".to_string(),
            logical_deleted_at: None,
            tags: vec!["proof".to_string()],
        };
        validate_storage_manifest(&manifest).expect("valid manifest");
    }

    #[test]
    fn rejects_bad_chunk_hash() {
        let mut chunk = StorageChunkRef {
            chunk_id: storage_chunk_id("bad"),
            hash: "bad".to_string(),
            hash_alg: STORAGE_CHUNK_HASH_ALG.to_string(),
            size: 3,
        };
        assert!(validate_storage_chunk_ref(&chunk, b"abc").is_err());
        let hash = storage_ciphertext_hash(b"abc");
        chunk.hash = hash;
        assert!(validate_storage_chunk_ref(&chunk, b"abc").is_err());
    }

    #[test]
    fn validates_storage_backend_posture_and_snapshot() {
        let posture = StorageBackendPosture {
            kind: Some(RECORD_STORAGE_BACKEND_POSTURE.to_string()),
            posture_id: "storage-backend-posture:local:1".to_string(),
            backend_id: "storage-backend:local".to_string(),
            storage_member_ref: "service:storage:local".to_string(),
            backend_kind: STORAGE_BACKEND_KIND_LOCAL_FS_SQLITE.to_string(),
            state: STORAGE_BACKEND_STATE_READY.to_string(),
            root_ref: "storage-root:local".to_string(),
            object_count: 1,
            chunk_count: 1,
            stored_bytes: 16,
            index_shard_count: 0,
            key_grant_count: 0,
            pin_lease_count: 1,
            pin_intent_count: 1,
            pin_attestation_count: 1,
            materialized_entry_count: 0,
            logical_deleted_object_count: 0,
            missing_chunk_count: 0,
            evidence_refs: vec!["storage:sqlite:local".to_string()],
            blocked_reasons: vec![],
            sampled_at: 1,
            expires_at: Some(10),
        };
        validate_storage_backend_posture(&posture).expect("valid storage posture");

        let snapshot = StorageBackendSnapshot {
            kind: Some(RECORD_STORAGE_BACKEND_SNAPSHOT.to_string()),
            snapshot_id: "storage-backend-snapshot:local:1".to_string(),
            backend_id: posture.backend_id.clone(),
            storage_member_ref: posture.storage_member_ref.clone(),
            posture_ref: posture.posture_id.clone(),
            object_count: posture.object_count,
            chunk_count: posture.chunk_count,
            pin_lease_count: posture.pin_lease_count,
            pin_intent_count: posture.pin_intent_count,
            pin_attestation_count: posture.pin_attestation_count,
            materialized_entry_count: posture.materialized_entry_count,
            object_refs: vec!["storage:object:object-1".to_string()],
            chunk_refs: vec!["storage:chunk:chunk-1".to_string()],
            pin_lease_refs: vec!["storage:pin-lease:pin-1".to_string()],
            pin_intent_refs: vec!["storage:pin-intent:intent-1".to_string()],
            pin_projection_refs: vec!["storage:pin-projection:intent-1".to_string()],
            capped_at: 64,
            captured_at: 1,
            expires_at: Some(10),
        };
        validate_storage_backend_snapshot(&snapshot).expect("valid storage snapshot");

        let mut bad_posture = posture;
        bad_posture.state = STORAGE_BACKEND_STATE_READY.to_string();
        bad_posture.missing_chunk_count = 1;
        assert!(validate_storage_backend_posture(&bad_posture).is_err());
    }

    #[test]
    fn validates_storage_graph_edge_and_index_shard_refs() {
        let bytes = b"encrypted source graph";
        let hash = storage_ciphertext_hash(bytes);
        let chunk = StorageChunkRef {
            chunk_id: storage_chunk_id(&hash),
            hash: hash.clone(),
            hash_alg: STORAGE_CHUNK_HASH_ALG.to_string(),
            size: bytes.len() as u64,
        };
        let edge = StorageGraphEdge {
            edge_id: "storage-graph-edge:source:root:module".to_string(),
            container_id: "container-source".to_string(),
            from_ref: "source:graph:root".to_string(),
            relation: "contains".to_string(),
            to_ref: "source:module:nvr-preview".to_string(),
            detail_ref: None,
            created_at: 1_700_000_000,
        };
        validate_storage_graph_edge(&edge).expect("valid storage graph edge");

        let shard = StorageIndexShard {
            shard_id: "storage-index-shard:source:1".to_string(),
            container_id: "container-source".to_string(),
            shard_type: "sourceGraph".to_string(),
            key_ref: "container-source:key".to_string(),
            ciphertext_hash: hash,
            hash_alg: STORAGE_CHUNK_HASH_ALG.to_string(),
            chunks: vec![chunk],
            object_refs: vec!["storage:object:source-root".to_string()],
            graph_edges: vec![edge.clone()],
            created_at: 1_700_000_000,
        };
        validate_storage_index_shard(&shard).expect("valid storage index shard");

        let mut filesystem_ref = edge.clone();
        filesystem_ref.to_ref = "file:C:/secrets/source".to_string();
        assert!(validate_storage_graph_edge(&filesystem_ref).is_err());

        let mut absolute_ref = shard;
        absolute_ref.graph_edges[0].from_ref = "/source/root".to_string();
        assert!(validate_storage_index_shard(&absolute_ref).is_err());
    }

    #[test]
    fn validates_storage_filesystem_view_as_virtual_materialization() {
        let view = StorageFilesystemView {
            kind: Some(RECORD_STORAGE_FILESYSTEM_VIEW.to_string()),
            view_id: "storage-filesystem-view:local:1".to_string(),
            backend_id: "storage-backend:local".to_string(),
            storage_member_ref: "service:storage:local".to_string(),
            root_ref: "storage-root:local".to_string(),
            state: STORAGE_FILESYSTEM_VIEW_READY.to_string(),
            view_mode: "virtualReadOnly".to_string(),
            materialization_ref: "materialization:storage:filesystem-view:local".to_string(),
            object_count: 1,
            chunk_count: 1,
            entry_count: 2,
            entries: vec![
                StorageFilesystemEntry {
                    entry_ref: "storage-filesystem-entry:object:one".to_string(),
                    path: "objects/container-a/object-one.manifest.json".to_string(),
                    object_ref: Some("storage:object:object-one".to_string()),
                    chunk_ref: None,
                    media_type: "application/json".to_string(),
                    size: 128,
                    logical_deleted_at: None,
                },
                StorageFilesystemEntry {
                    entry_ref: "storage-filesystem-entry:chunk:abc".to_string(),
                    path: "chunks/ab/abcdef.bin".to_string(),
                    object_ref: None,
                    chunk_ref: Some("storage:chunk:abcdef".to_string()),
                    media_type: "application/octet-stream".to_string(),
                    size: 64,
                    logical_deleted_at: None,
                },
            ],
            capped_at: 64,
            evidence_refs: vec!["storage:backend:snapshot".to_string()],
            blocked_reasons: vec![],
            captured_at: 1_700_000_000,
            expires_at: Some(1_700_000_060),
        };
        validate_storage_filesystem_view(&view).expect("valid filesystem view");

        let mut absolute_path = view.clone();
        absolute_path.entries[0].path = "C:/storage/object-one".to_string();
        assert!(validate_storage_filesystem_view(&absolute_path).is_err());

        let mut traversal_path = view;
        traversal_path.entries[0].path = "objects/../secret".to_string();
        assert!(validate_storage_filesystem_view(&traversal_path).is_err());
    }
}
