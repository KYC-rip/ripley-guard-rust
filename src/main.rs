use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct RipleyGuardOptions {
    node_rpc_url: String,
    wallet_address: String,
    amount_piconero: u64,
    server_secret: String,
    expire_window_ms: u64,
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

#[tokio::main]
async fn main() {
    let options = Arc::new(RipleyGuardOptions {
        node_rpc_url: "http://127.0.0.1:18081/json_rpc".to_string(),
        wallet_address: "888tNkbaB65ad3hgE9R916PP56bdz1c9v...".to_string(),
        amount_piconero: 3000000,
        server_secret: "rust-tactical-secret".to_string(),
        expire_window_ms: 300000, // 5 minutes
    });

    let app = Router::new()
        .route("/protected", get(handle_protected))
        .with_state(options);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    println!("Ripley Guard (Rust) - IETF Standard - Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn verify_proof_on_chain(
    options: &RipleyGuardOptions,
    txid: &str,
    proof: &str,
    message: &str,
) -> bool {
    let client = reqwest::Client::new();
    let res = client
        .post(&options.node_rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "ripley-guard-rust",
            "method": "check_tx_proof",
            "params": {
                "txid": txid,
                "address": options.wallet_address,
                "message": message,
                "signature": proof
            }
        }))
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<RpcResponse>().await {
                data.result.good && data.result.received >= options.amount_piconero
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

async fn handle_protected(
    State(options): State<Arc<RipleyGuardOptions>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION);
    
    let client_ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()))
        .unwrap_or("unknown-ip");

    // Generate stateless nonce
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let time_window = timestamp / options.expire_window_ms;
    
    let generate_nonce = |window: u64| {
        let mut hasher = Sha256::new();
        let raw_data = format!("{}:{}:{}", client_ip, window, options.server_secret);
        hasher.update(raw_data.as_bytes());
        hex::encode(&hasher.finalize()[..8]) // 16 chars
    };

    let expected_nonce = generate_nonce(time_window);
    let prev_nonce = generate_nonce(time_window.saturating_sub(1));

    // 1. Challenge: Issue XMR402 challenge
    if auth_header.is_none() || !auth_header.unwrap().to_str().unwrap_or("").starts_with("XMR402") {
        return (
            StatusCode::PAYMENT_REQUIRED,
            [
                (header::WWW_AUTHENTICATE, format!(
                    r#"XMR402 address="{}", amount="{}", message="{}""#,
                    options.wallet_address, options.amount_piconero, expected_nonce
                )),
            ],
            Json(json!({ "error": "TACTICAL_PAYMENT_REQUIRED", "protocol": "XMR402" })),
        ).into_response();
    }

    // 2. Parse Authorization
    let auth_str = auth_header.unwrap().to_str().unwrap_or("");
    let re = regex::Regex::new(r#"^XMR402\s+txid="([^"]+)",\s*proof="([^"]+)"$"#).unwrap();
    
    if let Some(caps) = re.captures(auth_str) {
        let txid = &caps[1];
        let proof = &caps[2];

        // 3. Verify Proof
        if verify_proof_on_chain(&options, txid, proof, &expected_nonce).await ||
           verify_proof_on_chain(&options, txid, proof, &prev_nonce).await {
            (
                StatusCode::OK,
                Json(json!({ 
                    "message": "Access Granted! XMR402 IETF flow verified.", 
                    "implementation": "Rust" 
                })),
            ).into_response()
        } else {
            (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "INVALID_PROOF_OR_FUNDS_MISSING" })),
            ).into_response()
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "INVALID_XMR402_FORMAT" })),
        ).into_response()
    }
}
