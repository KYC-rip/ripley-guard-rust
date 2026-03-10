mod core;
mod http;
mod ws;

use ax_ws::extract::State;
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::core::RipleyGuardOptions;

#[tokio::main]
async fn main() {
    let options = Arc::new(RipleyGuardOptions {
        node_rpc_url: "http://127.0.0.1:18081".to_string(),
        wallet_address: "888tNkbaB65ad3hgE9R916PP56bdz1c9v...".to_string(), // Replace with your subaddress
        amount_piconero: 1000,
        server_secret: "v2-tactical-secret".to_string(),
        expire_window_ms: 300000, // 5 minutes
    });

    let app = Router::new()
        // HTTP 402 Flow
        .route("/protected", post(http::handle_protected))
        // WebSocket Relay Flow
        .route("/relay", get(ws::handler))
        .with_state(options);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    println!("XMR402 Guard (Rust v2.0) - Transport Agnostic");
    println!("HTTP Gateway: http://{}/protected", addr);
    println!("WS Relay: ws://{}/relay", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
