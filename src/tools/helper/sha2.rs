// SPDX-License-Identifier: GPL-3.0
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Debug, thiserror::Error)]
pub enum Sha2Error {
    #[error("io error: {0}")]
    IoError(String),
}

/// Returns the raw 32-byte SHA-256 digest of `data`.
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Returns the lowercase hex-encoded SHA-256 digest of `data`.
pub fn hash_hex(data: &[u8]) -> String {
    bytes_to_hex(&hash(data))
}

/// Returns the lowercase hex-encoded SHA-256 digest of a UTF-8 string.
pub fn hash_string(s: &str) -> String {
    hash_hex(s.as_bytes())
}

/// Streams a file from `path` and returns its SHA-256 digest as a lowercase hex string.
pub fn hash_file(path: &std::path::Path) -> Result<String, Sha2Error> {
    let mut file   = std::fs::File::open(path).map_err(|e| Sha2Error::IoError(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf    = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| Sha2Error::IoError(e.to_string()))?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(bytes_to_hex(&hasher.finalize()))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{:02x}", b);
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_empty_input() {
        let h = hash_hex(&[]);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("e3b0c44298fc1c14"));
    }

    #[test]
    fn hash_is_deterministic() {
        let data = b"alterion-enc-pipeline test vector";
        assert_eq!(hash_hex(data), hash_hex(data));
    }

    #[test]
    fn hash_string_matches_hash_hex() {
        assert_eq!(hash_string("alterion"), hash_hex("alterion".as_bytes()));
    }

    #[test]
    fn hash_output_is_lowercase_hex() {
        let h = hash_hex(b"abc");
        assert!(h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        assert_ne!(hash_hex(b"a"), hash_hex(b"b"));
    }

    #[test]
    fn hash_file_nonexistent_returns_error() {
        assert!(hash_file(std::path::Path::new("/nonexistent/path/file.bin")).is_err());
    }
}
