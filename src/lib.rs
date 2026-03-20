// SPDX-License-Identifier: GPL-3.0
//! # alterion-enc-pipeline
//!
//! The primary entry point is [`interceptor::Interceptor`]: mount it as an Actix-web middleware
//! and every encrypted request is transparently decrypted, and every response re-encrypted,
//! using the RSA + AES-256-GCM + HMAC-SHA256 pipeline.
//!
//! ## Layout
//! ```text
//! alterion_enc_pipeline
//! ├── keystore      — RSA-2048 key store with timed rotation and grace-window overlap
//! ├── interceptor   — Actix-web middleware (main public API)
//! └── tools
//!     ├── crypt     — AES-256-GCM, Argon2id password hashing, Argon2id KDF
//!     ├── serializer— MessagePack serialisation, Deflate compression, signed-response builder
//!     └── helper
//!         ├── hmac  — HMAC-SHA256 sign / constant-time verify
//!         ├── sha2  — SHA-256 raw bytes, hex, string, and file helpers
//!         └── pstore— Pepper versioning via the Linux user-session keyring
//! ```

pub mod interceptor;
pub mod keystore;
pub mod tools;
