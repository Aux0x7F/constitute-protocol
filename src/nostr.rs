use anyhow::{Result, anyhow};
use secp256k1::rand::thread_rng;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::crypto::{bytes_to_hex, hex_to_bytes};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrUnsignedEvent {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct NostrFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u32>>,
    #[serde(rename = "#t", skip_serializing_if = "Option::is_none")]
    pub t: Option<Vec<String>>,
    #[serde(rename = "#z", skip_serializing_if = "Option::is_none")]
    pub z: Option<Vec<String>>,
}

pub fn generate_keypair() -> (String, String) {
    let secp = Secp256k1::new();
    let (sk, _pk) = secp.generate_keypair(&mut thread_rng());
    let sk_hex = bytes_to_hex(&sk.secret_bytes());
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let pk_hex = xonly_pk_hex(&keypair);
    (pk_hex, sk_hex)
}

pub fn pubkey_from_sk_hex(sk_hex: &str) -> Result<String> {
    let sk_bytes = hex_to_bytes(sk_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid nostr sk"))?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &sk);
    Ok(xonly_pk_hex(&keypair))
}

pub fn build_unsigned_event(
    pubkey: &str,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    created_at: u64,
) -> NostrUnsignedEvent {
    NostrUnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at,
        kind,
        tags,
        content,
    }
}

pub fn sign_event(unsigned: &NostrUnsignedEvent, sk_hex: &str) -> Result<NostrEvent> {
    let id = event_id_hex(unsigned)?;
    let hash = hex_to_bytes(&id)?;
    let msg = Message::from_digest_slice(&hash).map_err(|_| anyhow!("invalid message digest"))?;
    let secp = Secp256k1::new();
    let sk_bytes = hex_to_bytes(sk_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid nostr sk"))?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    Ok(NostrEvent {
        id,
        pubkey: unsigned.pubkey.clone(),
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags.clone(),
        content: unsigned.content.clone(),
        sig: bytes_to_hex(sig.as_ref()),
    })
}

pub fn verify_event(ev: &NostrEvent) -> Result<bool> {
    let unsigned = NostrUnsignedEvent {
        pubkey: ev.pubkey.clone(),
        created_at: ev.created_at,
        kind: ev.kind,
        tags: ev.tags.clone(),
        content: ev.content.clone(),
    };
    if event_id_hex(&unsigned)? != ev.id {
        return Ok(false);
    }
    let hash = hex_to_bytes(&ev.id)?;
    let msg = Message::from_digest_slice(&hash).map_err(|_| anyhow!("invalid message digest"))?;
    let sig_bytes = hex_to_bytes(&ev.sig)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("invalid signature"))?;
    let pk_bytes = hex_to_bytes(&ev.pubkey)?;
    let pk = XOnlyPublicKey::from_slice(&pk_bytes).map_err(|_| anyhow!("invalid pubkey"))?;
    let secp = Secp256k1::new();
    Ok(secp.verify_schnorr(&sig, &msg, &pk).is_ok())
}

pub fn event_id_hex(unsigned: &NostrUnsignedEvent) -> Result<String> {
    let payload = json!([
        0,
        unsigned.pubkey,
        unsigned.created_at,
        unsigned.kind,
        unsigned.tags,
        unsigned.content,
    ]);
    let raw = serde_json::to_string(&payload).map_err(|_| anyhow!("event serialize failed"))?;
    Ok(bytes_to_hex(&Sha256::digest(raw.as_bytes())))
}

pub fn frame_event(ev: &NostrEvent) -> String {
    serde_json::to_string(&json!(["EVENT", ev])).unwrap_or_else(|_| "[]".to_string())
}

pub fn frame_req(sub_id: &str, filters: Vec<NostrFilter>) -> String {
    serde_json::to_string(&json!(["REQ", sub_id, filters])).unwrap_or_else(|_| "[]".to_string())
}

pub fn parse_xonly_as_public_key(pk_hex: &str) -> Result<PublicKey> {
    let xonly = hex_to_bytes(pk_hex)?;
    if xonly.len() != 32 {
        return Err(anyhow!("invalid secp256k1 xonly pubkey"));
    }
    let mut compressed = Vec::with_capacity(33);
    compressed.push(0x02);
    compressed.extend_from_slice(&xonly);
    PublicKey::from_slice(&compressed).map_err(|_| anyhow!("invalid secp256k1 pubkey"))
}

fn xonly_pk_hex(keypair: &Keypair) -> String {
    let (pk, _) = XOnlyPublicKey::from_keypair(keypair);
    bytes_to_hex(&pk.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = "0000000000000000000000000000000000000000000000000000000000000001";
        let pk = pubkey_from_sk_hex(sk).expect("pk");
        let unsigned = build_unsigned_event(
            &pk,
            1111,
            vec![vec!["t".into(), "constitute".into()]],
            "{\"ok\":true}".into(),
            1_700_000_000,
        );
        let ev = sign_event(&unsigned, sk).expect("sign");
        assert!(verify_event(&ev).expect("verify"));
        assert_eq!(
            ev.id,
            "79893099e8d1dae52109e57cd6fa2c4eef5257d6779dad8107c708a64ef0e9ad"
        );
    }
}
