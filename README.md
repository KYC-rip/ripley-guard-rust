# Ripley Guard (Rust)

Industrial-grade Monero payment gating for modern APIs. IETF-compliant, 0-conf enabled, and built for the sovereign internet.

## Overview

`ripley-guard-rust` is a lightning-fast asynchronous middleware for the Axum and Tower ecosystems. It implements the **XMR402 Protocol**, providing a tactical solution for monetizing API resources with absolute Monero privacy.

## Features

- **Instruction Binding**: Cryptographically binds nonces to request bodies to prevent instruction replacement.
- **XMR402 Compliance**: Strict adherence to the IETF HTTP 402 standard with `timestamp` synchronization.
- **0-Conf Verification**: Fast-path resource unlocking via transaction proofs.
- **Async Execution**: Non-blocking RPC verification using `reqwest` and `tokio`.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ripley-guard = { git = "https://github.com/KYC-rip/ripley-guard-rust" }
```

## Quick Start (Axum)

```rust
use axum::{routing::get, Router};
use ripley_guard::{RipleyGuard, RipleyGuardOptions};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let options = Arc::new(RipleyGuardOptions {
        node_rpc_url: "http://127.0.0.1:18081/json_rpc".to_string(),
        wallet_address: "888tNkbaB65ad3hgE9R916PP56bdz1c9v...".to_string(),
        amount_piconero: 3000000,
        server_secret: "rust-tactical-secret".to_string(),
        expire_window_ms: 300000,
    });

    let app = Router::new()
        .route("/api/resource", get(protected_handler))
        .layer(RipleyGuard::new(options));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn protected_handler() -> &'static str {
    "Sovereign Content Unlocked"
}
```

## Protocol

For a detailed protocol specification, visit [XMR402.org](https://xmr402.org).

## License

MIT © [KYC.rip](https://kyc.rip)
