// SPDX-License-Identifier: GPL-3.0
//! Cross-platform pepper store backed by the OS native keyring (Secret Service on Linux,
//! Keychain on macOS, Credential Manager on Windows) via the [`keyring`] crate.
//!
//! Peppers are 32 random bytes stored as lowercase hex strings under the service name
//! `"alterion-enc-pipeline"` and a versioned key name such as `"alterion_pepper_v1"`.

use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE:           &str = "alterion-enc-pipeline";
const PEPPER_KEY_PREFIX: &str = "alterion_pepper_v";
const CURRENT_VERSION:   i16  = 1;

#[derive(Debug, thiserror::Error)]
pub enum PstoreError {
    #[error("keyring error: {0}")]
    KeyringError(String),
    #[error("invalid pepper encoding")]
    InvalidEncoding,
    #[error("invalid pepper length — expected 32 bytes")]
    InvalidLength,
}

fn key_name(version: i16) -> String {
    format!("{}{}", PEPPER_KEY_PREFIX, version)
}

fn entry(version: i16) -> Result<Entry, PstoreError> {
    Entry::new(SERVICE, &key_name(version))
        .map_err(|e| PstoreError::KeyringError(e.to_string()))
}

/// Returns the current pepper bytes and version number, generating and storing one if absent.
pub fn get_current_pepper() -> Result<([u8; 32], i16), PstoreError> {
    get_pepper(CURRENT_VERSION).map(|p| (p, CURRENT_VERSION))
}

/// Retrieves a specific pepper version from the OS keyring, generating and storing one if absent.
pub fn get_pepper(version: i16) -> Result<[u8; 32], PstoreError> {
    let e = entry(version)?;
    match e.get_password() {
        Ok(hex_str) => {
            let raw = Zeroizing::new(
                hex::decode(&hex_str).map_err(|_| PstoreError::InvalidEncoding)?
            );
            if raw.len() != 32 {
                return Err(PstoreError::InvalidLength);
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            Ok(out)
        }
        Err(_) => {
            let pepper = generate_pepper();
            store_pepper(version, &pepper)?;
            Ok(pepper)
        }
    }
}

fn generate_pepper() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

fn store_pepper(version: i16, pepper: &[u8; 32]) -> Result<(), PstoreError> {
    entry(version)?
        .set_password(&hex::encode(pepper))
        .map_err(|e| PstoreError::KeyringError(e.to_string()))
}

/// Generates and stores a new pepper at the next version, returning the new version number.
pub fn rotate_pepper() -> Result<i16, PstoreError> {
    let new_version = CURRENT_VERSION + 1;
    store_pepper(new_version, &generate_pepper())?;
    Ok(new_version)
}
