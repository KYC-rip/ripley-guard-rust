# 🛡️ Ripley Guard (Rust)

> **XMR402 v2.0**: High-performance, transport-agnostic Monero payment gating.

Refactored for the v2.0 decoupled architecture, `ripley-guard-rust` provides a lightning-fast implementation of the XMR402 protocol for Axum and other asynchronous Rust web frameworks.

## ⚡ Features

* **Modular Design**: Separate `core`, `http`, and `ws` modules for maximum flexibility.
* **Axum Native**: First-class support for Axum middlewares and WebSocket upgrades.
* **Payload Binding**: Intent-bound nonces (HMAC) to prevent instruction replacement.
* **0-Conf Verification**: Direct Monero RPC integration for instant resource unlocking.

## 🚀 Usage

### HTTP Gating (Axum)

```rust
use axum::{routing::post, Router};
mod http;

let app = Router::new()
    .route("/protected", post(http::handle_protected))
    .with_state(options);
```

### WebSocket Relay

```rust
use axum::{routing::get, Router};
mod ws;

let app = Router::new()
    .route("/relay", get(ws::handler))
    .with_state(options);
```

## ⚙️ Configuration

Requires a Monero RPC node and a server secret for stateless nonce generation.

```rust
let options = RipleyGuardOptions {
    node_rpc_url: "http://127.0.0.1:18081".to_string(),
    wallet_address: "888t...".to_string(),
    amount_piconero: 1000,
    server_secret: "v2-tactical-secret".to_string(),
    expire_window_ms: 300000,
};
```

## License

MIT © [XBToshi](https://x.com/xbtoshi) / [KYC.rip](https://kyc.rip)
