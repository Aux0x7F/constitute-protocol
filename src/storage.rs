use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::crypto::sha256_hex;

pub const STORAGE_OBJECT_HASH_ALG: &str = "sha256-ciphertext-v1";
pub const STORAGE_CHUNK_HASH_ALG: &str = "sha256-ciphertext-v1";
pub const STORAGE_ENCRYPTION_ALG_XCHACHA20POLY1305: &str = "xchacha20poly1305";
pub const CAAC_KIND_STORAGE_KEY_GRANT: &str = "storage.key_grant";

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
}
