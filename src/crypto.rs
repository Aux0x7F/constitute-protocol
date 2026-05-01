use anyhow::{Result, anyhow};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let h = hex.trim();
    if !h.len().is_multiple_of(2) {
        return Err(anyhow!("invalid hex"));
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for i in (0..h.len()).step_by(2) {
        let b = u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| anyhow!("invalid hex"))?;
        out.push(b);
    }
    Ok(out)
}

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    bytes_to_hex(&Sha256::digest(input.as_ref()))
}

pub fn canonical_json(value: &Value) -> Result<String> {
    let sorted = sort_value(value);
    serde_json::to_string(&sorted).map_err(|_| anyhow!("canonical json serialize failed"))
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(canonical_json(value)?.into_bytes())
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                if let Some(next) = map.get(&key) {
                    out.insert(key, sort_value(next));
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}
