# alterion-enc-pipeline

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/alterion-enc-pipeline.svg)](https://crates.io/crates/alterion-enc-pipeline)

A full end-to-end encryption pipeline for Actix-web applications, developed by **Alterion Software**.

The primary entry point is the [`Interceptor`] middleware. Mount it on your Actix-web app and every request/response is transparently encrypted — no per-handler boilerplate required.

---

## What it does

Each request from the client is packaged as a `WrappedPacket`:

```
Client → [AES-256-GCM encrypted body] + [RSA-OAEP-SHA256 encrypted AES key] + [key_id]
```

The `Interceptor` middleware:

1. **Decrypts the request** — RSA-unwraps the AES key using the active key-store entry, then AES-decrypts the payload. The raw bytes are injected into request extensions as `DecryptedBody` for your handlers to read.
2. **Encrypts the response** — Takes the JSON response body and pipes it through: `Deflate → MessagePack → AES-256-GCM → HMAC-SHA256`, returning a `SignedResponse` packet.

The RSA key pair rotates automatically on a configurable interval with a grace window so in-flight requests using the previous key still succeed.

---

## Crate layout

```
alterion_enc_pipeline
├── keystore       RSA-2048 key store with timed rotation and grace-window overlap
├── interceptor    Actix-web middleware — the main public API
└── tools
    ├── crypt      AES-256-GCM encrypt/decrypt, Argon2id password hashing, Argon2id KDF
    ├── serializer MessagePack serialisation, Deflate compression, signed-response builder
    └── helper
        ├── hmac   HMAC-SHA256 sign / constant-time verify
        ├── sha2   SHA-256 — raw bytes, hex string, file hash
        └── pstore Versioned pepper store via OS native keyring (cross-platform)
```

---

## Quick start

### 1. Add the dependency

```toml
[dependencies]
alterion-enc-pipeline = { git = "https://github.com/Alterion-Software/alterion-enc-pipeline" }
```

### 2. Initialise the key store and mount the interceptor

```rust
use alterion_enc_pipeline::{
    interceptor::Interceptor,
    keystore::{init_key_store, start_rotation},
};
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Rotate RSA keys every hour; keep the previous key live for 5 minutes (grace window).
    let store = init_key_store(3600);
    start_rotation(store.clone(), 3600);

    HttpServer::new(move || {
        App::new()
            .wrap(Interceptor { key_store: store.clone() })
            // your routes here
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

### 3. Read the decrypted body in a handler

```rust
use actix_web::{post, web, HttpRequest, HttpMessage, HttpResponse};
use alterion_enc_pipeline::interceptor::DecryptedBody;

#[post("/api/example")]
async fn example_handler(req: HttpRequest) -> HttpResponse {
    let body = match req.extensions().get::<DecryptedBody>().cloned() {
        Some(b) => b,
        None    => return HttpResponse::BadRequest().body("missing encrypted body"),
    };
    // body.0 is the raw decrypted bytes — deserialise however you like
    HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}
```

### 4. Expose the current public key to clients

Clients need the RSA public key to encrypt their requests. Expose it from an unprotected endpoint:

```rust
use actix_web::{get, web, HttpResponse};
use alterion_enc_pipeline::keystore::{KeyStore, get_current_public_key};
use std::sync::Arc;
use tokio::sync::RwLock;

#[get("/api/pubkey")]
async fn public_key_handler(
    store: web::Data<Arc<RwLock<KeyStore>>>,
) -> HttpResponse {
    let (key_id, pem) = get_current_public_key(&store).await;
    HttpResponse::Ok().json(serde_json::json!({ "key_id": key_id, "public_key": pem }))
}
```

---

## Key store

| Function | Description |
|---|---|
| `init_key_store(interval_secs)` | Generates the initial RSA-2048 key pair and wraps it in an `Arc<RwLock<KeyStore>>` |
| `start_rotation(store, interval_secs)` | Spawns a background task that rotates the key every `interval_secs` seconds |
| `get_current_public_key(store)` | Returns `(key_id, pem)` for the active key |
| `decrypt(store, key_id, cdata)` | RSA-OAEP-SHA256 decrypts `cdata` using the matching key (falls back to the previous key within its grace window) |

The grace window is fixed at **300 seconds** (5 minutes). This means the previous key remains valid for 5 minutes after rotation, so any request that was encrypted just before a rotation still decrypts successfully.

> **Frontend note:** Pre-fetch a new public key at `rotation_interval − 300` seconds so the cached key is never stale when a rotation occurs.

---

## Tools

### `tools::crypt`

```rust
use alterion_enc_pipeline::tools::crypt;

// AES-256-GCM (nonce prepended to output)
let key = [0u8; 32];
let ct  = crypt::aes_encrypt(b"hello", &key)?;
let pt  = crypt::aes_decrypt(&ct, &key)?;

// Argon2id password hashing with HMAC-pepper
let (hash, pepper_version) = crypt::hash_password("my-password")?;
let valid = crypt::verify_password("my-password", &hash, pepper_version)?;

// Argon2id KDF — encrypt/decrypt a secret string with a password
let blob    = crypt::key_encrypt("secret value", "master-password")?;
let secret  = crypt::key_decrypt(&blob, "master-password")?;
```

### `tools::serializer`

```rust
use alterion_enc_pipeline::tools::serializer;

// Build an AES+HMAC signed response from any Serialize type
let bytes = serializer::build_signed_response(&my_struct, &aes_key)?;

// Decode an incoming request payload (msgpack → deflate → JSON)
let payload: MyStruct = serializer::decode_request_payload(&decrypted_bytes)?;
```

### `tools::helper::sha2`

```rust
use alterion_enc_pipeline::tools::helper::sha2;

let hex  = sha2::hash_hex(b"some data");         // → 64-char lowercase hex
let raw  = sha2::hash(b"some data");              // → [u8; 32]
let file = sha2::hash_file(Path::new("a.bin"))?; // → hex string
```

### `tools::helper::hmac`

```rust
use alterion_enc_pipeline::tools::helper::hmac;

let sig   = hmac::sign(b"data", &key);
let valid = hmac::verify(b"data", &key, &sig); // constant-time
```

### `tools::helper::pstore`

Pepper versions are stored in the OS native keyring under service `"alterion-enc-pipeline"`.
Peppers are 32 random bytes, hex-encoded at rest.

| Platform | Backend |
|---|---|
| Linux | Secret Service (e.g. GNOME Keyring, KWallet) |
| macOS | Keychain |
| Windows | Credential Manager |

```rust
use alterion_enc_pipeline::tools::helper::pstore;

let (pepper, version) = pstore::get_current_pepper()?;
let new_version       = pstore::rotate_pepper()?;
```

---

## Response pipeline (detail)

```
Handler returns JSON bytes
        │
        ▼
  Deflate compress
        │
        ▼
  MessagePack encode  ──→  ByteBuf
        │
        ▼
  AES-256-GCM encrypt  (nonce prepended)
        │
        ▼
  HMAC-SHA256 sign  (over the ciphertext)
        │
        ▼
  SignedResponse { payload: ByteBuf, hmac: ByteBuf }
        │
        ▼
  MessagePack encode  ──→  sent to client
```

The client verifies the HMAC before decrypting. If verification fails, the response must be discarded.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

© Alterion Software
