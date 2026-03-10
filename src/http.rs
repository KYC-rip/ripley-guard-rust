use axum::{
    extract::{connect_info::ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use crate::core::{self, RipleyGuardOptions, NonceContext};

pub async fn handle_protected(
    State(options): State<Arc<RipleyGuardOptions>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION);
    
    let client_ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()))
        .unwrap_or_else(|| addr.ip().to_string().leak()); // Leak is safe for static demo IP

    let url = "/protected"; // In a real app, extract from request
    let payload_hash = core::hash_payload(&body);
    
    let time_window = core::get_time_window(options.expire_window_ms);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let nonce_ctx = NonceContext {
        client_ip,
        url,
        payload_hash: &payload_hash,
        window: time_window,
    };

    let expected_nonce = core::generate_nonce(&options.server_secret, nonce_ctx);
    let prev_nonce = core::generate_nonce(&options.server_secret, NonceContext { window: time_window.saturating_sub(1), ..nonce_ctx });

    // 1. Challenge
    if auth_header.is_none() || !auth_header.unwrap().to_str().unwrap_or("").starts_with("XMR402") {
        return (
            StatusCode::PAYMENT_REQUIRED,
            [
                (header::WWW_AUTHENTICATE, format!(
                    r#"XMR402 address="{}", amount="{}", message="{}", timestamp="{}""#,
                    options.wallet_address, options.amount_piconero, expected_nonce, timestamp
                )),
            ],
            Json(json!({ "error": "TACTICAL_PAYMENT_REQUIRED", "protocol": "XMR402" })),
        ).into_response();
    }

    // 2. Parse & Verify
    let auth_str = auth_header.unwrap().to_str().unwrap_or("");
    let re = regex::Regex::new(r#"^XMR402\s+txid="([^"]+)",\s*proof="([^"]+)"$"#).unwrap();
    
    if let Some(caps) = re.captures(auth_str) {
        let txid = &caps[1];
        let proof = &caps[2];

        let is_valid = core::verify_payment(&options.node_rpc_url, &options.wallet_address, options.amount_piconero, txid, proof, &expected_nonce).await.unwrap_or(false) ||
                       core::verify_payment(&options.node_rpc_url, &options.wallet_address, options.amount_piconero, txid, proof, &prev_nonce).await.unwrap_or(false);

        if is_valid {
            (
                StatusCode::OK,
                Json(json!({ "message": "Access Granted! XMR402 v2.0 flow verified.", "implementation": "Rust" })),
            ).into_response()
        } else {
            (StatusCode::FORBIDDEN, Json(json!({ "error": "INVALID_PROOF" }))).into_response()
        }
    } else {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": "INVALID_XMR402_FORMAT" }))).into_response()
    }
}
