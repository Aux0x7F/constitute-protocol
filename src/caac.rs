use std::collections::HashSet;

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use secp256k1::ecdh;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::crypto::{bytes_to_hex, canonical_json, canonical_json_bytes, hex_to_bytes};
use crate::nostr::{parse_xonly_as_public_key, pubkey_from_sk_hex};

pub const CAAC_VERSION: u8 = 1;
pub const CAAC_ALG_V1: &str = "caac-v1-secp256k1-hkdf-sha256-xchacha20poly1305";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaacRecipient {
    pub recipient_pk: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaacEnvelope {
    pub version: u8,
    pub kind: String,
    pub envelope_id: String,
    pub issuer_pk: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub alg: String,
    pub recipients: Vec<CaacRecipient>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCaacEnvelope {
    pub alg: String,
    pub envelope_id: String,
    pub expires_at: u64,
    pub issued_at: u64,
    pub issuer_pk: String,
    pub kind: String,
    pub recipients: Vec<CaacRecipient>,
    pub version: u8,
}

#[derive(Default, Debug)]
pub struct ReplayCache {
    seen: HashSet<String>,
}

impl ReplayCache {
    pub fn check_and_insert(&mut self, id: &str) -> Result<()> {
        if self.seen.contains(id) {
            return Err(anyhow!("caac envelope replayed"));
        }
        self.seen.insert(id.to_string());
        Ok(())
    }
}

pub fn seal_envelope(
    kind: &str,
    claims: &Value,
    issuer_sk: &str,
    recipient_pks: &[String],
    issued_at: u64,
    expires_at: u64,
) -> Result<CaacEnvelope> {
    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);
    let envelope_id = bytes_to_hex(&random);
    seal_envelope_with_options(
        kind,
        claims,
        issuer_sk,
        recipient_pks,
        issued_at,
        expires_at,
        envelope_id,
        vec![],
    )
}

pub fn seal_envelope_with_options(
    kind: &str,
    claims: &Value,
    issuer_sk: &str,
    recipient_pks: &[String],
    issued_at: u64,
    expires_at: u64,
    envelope_id: String,
    nonce_hexes: Vec<String>,
) -> Result<CaacEnvelope> {
    let issuer_pk = pubkey_from_sk_hex(issuer_sk)?;
    let plaintext = canonical_json_bytes(claims)?;
    let mut recipients = Vec::new();
    let mut unique = HashSet::new();
    for (index, recipient_pk) in recipient_pks.iter().enumerate() {
        if !unique.insert(recipient_pk.clone()) {
            continue;
        }
        let nonce = if let Some(hex) = nonce_hexes.get(index) {
            hex_to_bytes(hex)?
        } else {
            let mut random = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut random);
            random.to_vec()
        };
        if nonce.len() != 24 {
            return Err(anyhow!("invalid caac nonce length"));
        }
        let key = derive_recipient_key(issuer_sk, recipient_pk, kind, &envelope_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let aad = recipient_aad(kind, &envelope_id, &issuer_pk, recipient_pk);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("caac encrypt failed"))?;
        recipients.push(CaacRecipient {
            recipient_pk: recipient_pk.clone(),
            nonce: bytes_to_hex(&nonce),
            ciphertext: bytes_to_hex(&ciphertext),
        });
    }

    let mut envelope = CaacEnvelope {
        version: CAAC_VERSION,
        kind: kind.to_string(),
        envelope_id,
        issuer_pk,
        issued_at,
        expires_at,
        alg: CAAC_ALG_V1.to_string(),
        recipients,
        signature: String::new(),
    };
    envelope.signature = sign_envelope(&envelope, issuer_sk)?;
    Ok(envelope)
}

pub fn open_envelope(
    envelope: &CaacEnvelope,
    recipient_sk: &str,
    now: u64,
    replay_cache: Option<&mut ReplayCache>,
) -> Result<Value> {
    if envelope.version != CAAC_VERSION {
        return Err(anyhow!("unsupported caac envelope version"));
    }
    if envelope.alg != CAAC_ALG_V1 {
        return Err(anyhow!("unsupported caac envelope algorithm"));
    }
    if envelope.expires_at <= now {
        return Err(anyhow!("caac envelope expired"));
    }
    if !verify_envelope_signature(envelope)? {
        return Err(anyhow!("invalid caac envelope signature"));
    }
    if let Some(cache) = replay_cache {
        cache.check_and_insert(&envelope.envelope_id)?;
    }

    let recipient_pk = pubkey_from_sk_hex(recipient_sk)?;
    let recipient = envelope
        .recipients
        .iter()
        .find(|entry| entry.recipient_pk == recipient_pk)
        .ok_or_else(|| anyhow!("caac envelope recipient mismatch"))?;
    let key = derive_open_key(
        recipient_sk,
        &envelope.issuer_pk,
        &recipient_pk,
        &envelope.kind,
        &envelope.envelope_id,
    )?;
    let nonce = hex_to_bytes(&recipient.nonce)?;
    let ciphertext = hex_to_bytes(&recipient.ciphertext)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let aad = recipient_aad(
        &envelope.kind,
        &envelope.envelope_id,
        &envelope.issuer_pk,
        &recipient_pk,
    );
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("caac decrypt failed"))?;
    serde_json::from_slice(&plaintext).map_err(|_| anyhow!("caac plaintext is not json"))
}

pub fn unsigned_envelope(envelope: &CaacEnvelope) -> UnsignedCaacEnvelope {
    UnsignedCaacEnvelope {
        alg: envelope.alg.clone(),
        envelope_id: envelope.envelope_id.clone(),
        expires_at: envelope.expires_at,
        issued_at: envelope.issued_at,
        issuer_pk: envelope.issuer_pk.clone(),
        kind: envelope.kind.clone(),
        recipients: envelope.recipients.clone(),
        version: envelope.version,
    }
}

pub fn envelope_signing_digest(envelope: &CaacEnvelope) -> Result<Vec<u8>> {
    let value = serde_json::to_value(unsigned_envelope(envelope))
        .map_err(|_| anyhow!("caac envelope serialize failed"))?;
    Ok(Sha256::digest(canonical_json(&value)?.as_bytes()).to_vec())
}

pub fn sign_envelope(envelope: &CaacEnvelope, issuer_sk: &str) -> Result<String> {
    let digest = envelope_signing_digest(envelope)?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| anyhow!("invalid caac digest"))?;
    let secp = Secp256k1::new();
    let sk_bytes = hex_to_bytes(issuer_sk)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid caac issuer sk"))?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    Ok(bytes_to_hex(sig.as_ref()))
}

pub fn verify_envelope_signature(envelope: &CaacEnvelope) -> Result<bool> {
    let digest = envelope_signing_digest(envelope)?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| anyhow!("invalid caac digest"))?;
    let sig_bytes = hex_to_bytes(&envelope.signature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("invalid caac signature"))?;
    let pk_bytes = hex_to_bytes(&envelope.issuer_pk)?;
    let pk = XOnlyPublicKey::from_slice(&pk_bytes).map_err(|_| anyhow!("invalid caac issuer pk"))?;
    let secp = Secp256k1::new();
    Ok(secp.verify_schnorr(&sig, &msg, &pk).is_ok())
}

pub fn encode_envelope_base64(envelope: &CaacEnvelope) -> Result<String> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| anyhow!("caac envelope serialize failed"))?;
    Ok(B64.encode(bytes))
}

pub fn decode_envelope_base64(encoded: &str) -> Result<CaacEnvelope> {
    let bytes = B64
        .decode(encoded.trim())
        .map_err(|_| anyhow!("invalid caac envelope base64"))?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid caac envelope json"))
}

fn derive_recipient_key(
    issuer_sk: &str,
    recipient_pk: &str,
    kind: &str,
    envelope_id: &str,
) -> Result<[u8; 32]> {
    let issuer_pk = pubkey_from_sk_hex(issuer_sk)?;
    let sk_bytes = hex_to_bytes(issuer_sk)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid caac issuer sk"))?;
    let recipient_public = parse_xonly_as_public_key(recipient_pk)?;
    let shared_point = ecdh::shared_secret_point(&recipient_public, &sk);
    hkdf_key(&shared_point[..32], kind, envelope_id, &issuer_pk, recipient_pk)
}

fn derive_open_key(
    recipient_sk: &str,
    issuer_pk: &str,
    recipient_pk: &str,
    kind: &str,
    envelope_id: &str,
) -> Result<[u8; 32]> {
    let sk_bytes = hex_to_bytes(recipient_sk)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid caac recipient sk"))?;
    let issuer_public = parse_xonly_as_public_key(issuer_pk)?;
    let shared_point = ecdh::shared_secret_point(&issuer_public, &sk);
    hkdf_key(&shared_point[..32], kind, envelope_id, issuer_pk, recipient_pk)
}

fn hkdf_key(
    shared: &[u8],
    kind: &str,
    envelope_id: &str,
    issuer_pk: &str,
    recipient_pk: &str,
) -> Result<[u8; 32]> {
    let info = format!("constitute-caac-v1|{kind}|{envelope_id}|{issuer_pk}|{recipient_pk}");
    let hk = Hkdf::<Sha256>::new(Some(b"constitute-caac-v1"), shared);
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|_| anyhow!("caac hkdf failed"))?;
    Ok(out)
}

fn recipient_aad(kind: &str, envelope_id: &str, issuer_pk: &str, recipient_pk: &str) -> Vec<u8> {
    format!("caac-v1|{kind}|{envelope_id}|{issuer_pk}|{recipient_pk}").into_bytes()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::nostr::pubkey_from_sk_hex;

    const ISSUER_SK: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const GATEWAY_SK: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const SERVICE_SK: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const BROWSER_SK: &str = "0000000000000000000000000000000000000000000000000000000000000004";

    #[test]
    fn sealed_envelope_roundtrip_for_multiple_recipients() {
        let gateway_pk = pubkey_from_sk_hex(GATEWAY_SK).expect("gateway pk");
        let service_pk = pubkey_from_sk_hex(SERVICE_SK).expect("service pk");
        let browser_pk = pubkey_from_sk_hex(BROWSER_SK).expect("browser pk");
        let claims = json!({
            "identityId": "id-secret",
            "service": "nvr",
            "sourceIds": ["front-door"],
        });
        let envelope = seal_envelope_with_options(
            "service_access.capability",
            &claims,
            ISSUER_SK,
            &[gateway_pk, service_pk],
            1_700_000_000,
            1_700_000_900,
            "capability-001".to_string(),
            vec![
                "000102030405060708090a0b0c0d0e0f1011121314151617".to_string(),
                "17161514131211100f0e0d0c0b0a09080706050403020100".to_string(),
            ],
        )
        .expect("seal");
        assert!(verify_envelope_signature(&envelope).expect("verify sig"));
        assert_eq!(
            open_envelope(&envelope, GATEWAY_SK, 1_700_000_001, None).expect("open gateway"),
            claims
        );
        assert_eq!(
            open_envelope(&envelope, SERVICE_SK, 1_700_000_001, None).expect("open service"),
            claims
        );
        assert!(open_envelope(&envelope, BROWSER_SK, 1_700_000_001, None).is_err());
        assert_eq!(browser_pk.len(), 64);
    }

    #[test]
    fn rejects_tamper_expiry_and_replay() {
        let gateway_pk = pubkey_from_sk_hex(GATEWAY_SK).expect("gateway pk");
        let envelope = seal_envelope(
            "service_access.request",
            &json!({"requestId": "req-1"}),
            ISSUER_SK,
            &[gateway_pk],
            10,
            20,
        )
        .expect("seal");
        assert!(open_envelope(&envelope, GATEWAY_SK, 21, None).is_err());

        let mut tampered = envelope.clone();
        tampered.recipients[0].ciphertext.push('0');
        assert!(open_envelope(&tampered, GATEWAY_SK, 11, None).is_err());

        let mut replay = ReplayCache::default();
        assert!(open_envelope(&envelope, GATEWAY_SK, 11, Some(&mut replay)).is_ok());
        assert!(open_envelope(&envelope, GATEWAY_SK, 11, Some(&mut replay)).is_err());
    }
}
