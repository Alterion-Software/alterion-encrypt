// SPDX-License-Identifier: GPL-3.0
//! OS-keyring pepper store for the Argon2id password hasher.
//!
//! ## What is a pepper?
//! A pepper is a 32-byte random secret stored **outside** the database (in the OS keyring) and
//! mixed into the password hash via HMAC-SHA256 before Argon2id runs. If the database is
//! exfiltrated without the keyring, offline brute-force attacks are infeasible even for weak
//! passwords.
//!
//! ## Storage layout (OS keyring)
//! | Key name | Value |
//! |----------|-------|
//! | `alterion_pepper_v1` | Lowercase hex of 32 random bytes |
//! | `alterion_pepper_v2` | … next version after rotation … |
//! | `alterion_pepper_current_v` | Version number of the active pepper (e.g. `"1"`) |
//!
//! The service name used for all keyring entries is `"alterion-enc-pipeline"`.
//!
//! ## Pepper rotation
//! Call [`rotate_pepper`] to generate a new pepper at `current_version + 1` and advance the
//! version pointer. Old pepper versions are **not deleted** — [`verify_password`](crate::tools::crypt::verify_password)
//! accepts a `pepper_version` argument so existing hashes remain verifiable indefinitely.
//! Re-hash on next successful login to migrate users to the new pepper.

use keyring::Entry;
use rand_core::RngCore;
use zeroize::Zeroizing;

const SERVICE:              &str = "alterion-enc-pipeline";
const PEPPER_KEY_PREFIX:    &str = "alterion_pepper_v";
const VERSION_POINTER_KEY:  &str = "alterion_pepper_current_v";

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

fn version_pointer_entry() -> Result<Entry, PstoreError> {
    Entry::new(SERVICE, VERSION_POINTER_KEY)
        .map_err(|e| PstoreError::KeyringError(e.to_string()))
}

/// Reads the current active pepper version from the keyring.
/// Initialises to v1 and stores the pointer if no pointer exists yet.
fn read_current_version() -> Result<i16, PstoreError> {
    let e = version_pointer_entry()?;
    match e.get_password() {
        Ok(s) => s.trim().parse::<i16>().map_err(|_| PstoreError::InvalidEncoding),
        Err(_) => {
            set_current_version(1)?;
            Ok(1)
        }
    }
}

fn set_current_version(version: i16) -> Result<(), PstoreError> {
    version_pointer_entry()?
        .set_password(&version.to_string())
        .map_err(|e| PstoreError::KeyringError(e.to_string()))
}

/// Returns `(pepper_bytes, version)` for the currently active pepper, lazily creating v1 if none exists.
///
/// This is the function [`crate::tools::crypt::hash_password`] calls. The returned `version` must
/// be persisted alongside the password hash so the correct pepper can be fetched at verify time.
pub fn get_current_pepper() -> Result<([u8; 32], i16), PstoreError> {
    let version = read_current_version()?;
    get_pepper(version).map(|p| (p, version))
}

/// Retrieves the pepper at `version` from the OS keyring, generating and persisting it if absent.
///
/// Called by [`crate::tools::crypt::verify_password`] with the version stored at hash time.
/// Old versions are kept indefinitely — rotation does not delete them.
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
    rand_core::OsRng.fill_bytes(&mut buf);
    buf
}

fn store_pepper(version: i16, pepper: &[u8; 32]) -> Result<(), PstoreError> {
    entry(version)?
        .set_password(&hex::encode(pepper))
        .map_err(|e| PstoreError::KeyringError(e.to_string()))
}

/// Rotates to a new pepper: generates 32 random bytes, stores them at `current_version + 1`,
/// advances the version pointer, and returns the new version number.
///
/// Existing hashes are **not invalidated** — they still reference their original version, which
/// remains in the keyring. To fully migrate, re-hash users' passwords on their next successful
/// login using [`crate::tools::crypt::hash_password`] (which will pick up the new active version).
pub fn rotate_pepper() -> Result<i16, PstoreError> {
    let current     = read_current_version()?;
    let new_version = current + 1;
    store_pepper(new_version, &generate_pepper())?;
    set_current_version(new_version)?;
    Ok(new_version)
}
