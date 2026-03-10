use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct RipleyGuardOptions {
    pub node_rpc_url: String,
    pub wallet_address: String,
    pub amount_piconero: u64,
    pub server_secret: String,
    pub expire_window_ms: u64,
}

#[derive(Deserialize)]
struct RpcResult {
    good: bool,
    received: u64,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: RpcResult,
}

pub struct NonceContext<'a> {
    pub client_ip: &'a str,
    pub url: &'a str,
    pub payload_hash: &'a str,
    pub window: u64,
}

/// Generates a stateless, intent-bound nonce for XMR402 v2.0
pub fn generate_nonce(secret: &str, ctx: NonceContext) -> String {
    let mut hasher = Sha256::new();
    let raw_data = format!("{}:{}:{}:{}:{}", ctx.client_ip, ctx.url, ctx.payload_hash, ctx.window, secret);
    hasher.update(raw_data.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8]) // 16 characters
}

/// Validates a Monero TX Proof via JSON-RPC
pub async fn verify_payment(
    rpc_url: &str,
    wallet_address: &str,
    min_amount: u64,
    txid: &str,
    proof: &str,
    message: &str,
) -> Result<bool, String> {
    let mut clean_rpc_url = rpc_url.to_string();
    if !clean_rpc_url.ends_with("/json_rpc") {
        clean_rpc_url = format!("{}/json_rpc", clean_rpc_url.trim_end_matches('/'));
    }

    let client = reqwest::Client::new();
    let res = client
        .post(&clean_rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "xmr402-core-rust",
            "method": "check_tx_proof",
            "params": {
                "txid": txid,
                "address": wallet_address,
                "message": message,
                "signature": proof
            }
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let data = res.json::<RpcResponse>().await.map_err(|e| e.to_string())?;
    
    Ok(data.result.good && data.result.received >= min_amount)
}

/// Helper to get current time window
pub fn get_time_window(expire_ms: u64) -> u64 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    timestamp / expire_ms
}

/// Helper to hash payload
pub fn hash_payload(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}
