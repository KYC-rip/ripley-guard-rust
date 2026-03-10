use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::core::{self, RipleyGuardOptions, NonceContext};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum XMR402Frame {
    #[serde(rename = "PAYMENT_CHALLENGE")]
    PaymentChallenge {
        address: String,
        amount: String,
        message: String,
        timestamp: String,
    },
    #[serde(rename = "PAYMENT_PROOF")]
    PaymentProof {
        txid: String,
        proof: String,
        message: String, // Client must return the nonce it signed
    },
}

pub async fn handler(
    ws: WebSocketUpgrade,
    State(options): State<Arc<RipleyGuardOptions>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, options))
}

async fn handle_socket(mut socket: WebSocket, options: Arc<RipleyGuardOptions>) {
    println!("[XMR402-WS] New persistent relay connection established.");
    
    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(text) = msg {
            // Simplified: Assume every text message is a resource demand frame
            // In v2.0, we respond with a PAYMENT_CHALLENGE
            
            let time_window = core::get_time_window(options.expire_window_ms);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            let nonce_ctx = NonceContext {
                client_ip: "ws-relay",
                url: "ws://relay",
                payload_hash: &text, // Intent binding to the message content
                window: time_window,
            };

            let message = core::generate_nonce(&options.server_secret, nonce_ctx);

            let challenge = XMR402Frame::PaymentChallenge {
                address: options.wallet_address.clone(),
                amount: options.amount_piconero.to_string(),
                message,
                timestamp: timestamp.to_string(),
            };

            if let Ok(json_challenge) = serde_json::to_string(&challenge) {
                let _ = socket.send(Message::Text(json_challenge)).await;
            }
        }
    }
}
