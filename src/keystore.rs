// SPDX-License-Identifier: GPL-3.0
use std::sync::Arc;
use tokio::sync::RwLock;
use rsa::{RsaPrivateKey, Oaep};
use rsa::pkcs8::EncodePublicKey;
use sha2::Sha256;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct KeyEntry {
    pub key_id:         String,
    pub public_key_pem: String,
    pub private_key:    RsaPrivateKey,
    pub created_at:     DateTime<Utc>,
    pub expires_at:     DateTime<Utc>,
}

pub struct KeyStore {
    pub current:  KeyEntry,
    pub previous: Option<KeyEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum RsaError {
    #[error("key_expired")]
    KeyExpired,
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),
}

impl From<RsaError> for actix_web::Error {
    fn from(e: RsaError) -> Self {
        match e {
            RsaError::KeyExpired => actix_web::error::ErrorUnauthorized("KEY_EXPIRED"),
            _                    => actix_web::error::ErrorInternalServerError(e.to_string()),
        }
    }
}

const KEY_GRACE_SECS: u64 = 300;

#[cfg(test)]
const KEY_BITS: usize = 1024;
#[cfg(not(test))]
const KEY_BITS: usize = 2048;

fn generate_entry(interval_secs: u64) -> Result<KeyEntry, RsaError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, KEY_BITS)
        .map_err(|e| RsaError::KeyGenerationFailed(e.to_string()))?;
    let public_key = private_key.to_public_key();
    let public_key_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| RsaError::KeyGenerationFailed(e.to_string()))?;
    let now  = Utc::now();
    let secs = i64::try_from(interval_secs + KEY_GRACE_SECS)
        .map_err(|_| RsaError::KeyGenerationFailed("interval overflow".into()))?;
    Ok(KeyEntry {
        key_id:         Uuid::new_v4().to_string(),
        public_key_pem,
        private_key,
        created_at:     now,
        expires_at:     now + Duration::seconds(secs),
    })
}

/// Generates an initial RSA key pair and wraps it in a shared, RwLock-guarded `KeyStore`.
pub fn init_key_store(interval_secs: u64) -> Arc<RwLock<KeyStore>> {
    let entry = generate_entry(interval_secs).expect("RSA key generation failed at startup");
    Arc::new(RwLock::new(KeyStore { current: entry, previous: None }))
}

/// Spawns a background task that rotates the active key every `interval_secs` seconds and
/// prunes the previous key once its grace window expires.
pub fn start_rotation(store: Arc<RwLock<KeyStore>>, interval_secs: u64) {
    tokio::spawn(async move {
        let mut rotation_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(interval_secs),
            tokio::time::Duration::from_secs(interval_secs),
        );
        let mut cleanup_interval = tokio::time::interval(
            tokio::time::Duration::from_secs(30),
        );
        loop {
            tokio::select! {
                _ = rotation_interval.tick() => {
                    match generate_entry(interval_secs) {
                        Ok(new_entry) => {
                            let mut w = store.write().await;
                            let old = std::mem::replace(&mut w.current, new_entry);
                            w.previous = Some(old);
                        }
                        Err(e) => tracing::error!("RSA rotation failed: {e}"),
                    }
                }
                _ = cleanup_interval.tick() => {
                    let needs_cleanup = {
                        let r = store.read().await;
                        r.previous.as_ref().map_or(false, |p| Utc::now() > p.expires_at)
                    };
                    if needs_cleanup {
                        store.write().await.previous = None;
                    }
                }
            }
        }
    });
}

/// Returns the key-id and PEM-encoded public key for the currently active key.
pub async fn get_current_public_key(store: &Arc<RwLock<KeyStore>>) -> (String, String) {
    let guard = store.read().await;
    (guard.current.key_id.clone(), guard.current.public_key_pem.clone())
}

/// Decrypts `cdata` (RSA-OAEP-SHA256) using the key identified by `key_id`.
/// Falls back to the previous key within its grace window; returns `KeyExpired` otherwise.
pub async fn decrypt(
    store:  &Arc<RwLock<KeyStore>>,
    key_id: &str,
    cdata:  &[u8],
) -> Result<Zeroizing<Vec<u8>>, RsaError> {
    let guard = store.read().await;
    let key = if guard.current.key_id == key_id {
        &guard.current.private_key
    } else if let Some(prev) = &guard.previous {
        if prev.key_id == key_id {
            if Utc::now() > prev.expires_at {
                return Err(RsaError::KeyExpired);
            }
            &prev.private_key
        } else {
            return Err(RsaError::KeyExpired);
        }
    } else {
        return Err(RsaError::KeyExpired);
    };

    let padding   = Oaep::new::<Sha256>();
    let plaintext = key.decrypt(padding, cdata)
        .map_err(|e| RsaError::DecryptionFailed(e.to_string()))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, LineEnding};

    const KEYPAIR_PATH: &str = "/tmp/alterion_test_keypair.json";

    fn client_encrypt(pem: &str, plaintext: &[u8]) -> Vec<u8> {
        let pub_key = rsa::RsaPublicKey::from_public_key_pem(pem).expect("parse public key PEM");
        let padding = rsa::Oaep::new::<sha2::Sha256>();
        pub_key.encrypt(&mut rand::thread_rng(), padding, plaintext)
            .expect("client-side RSA encrypt")
    }

    #[tokio::test]
    async fn init_key_store_produces_valid_key_pair() {
        let store        = init_key_store(3600);
        let (key_id, pem) = get_current_public_key(&store).await;
        assert!(!key_id.is_empty());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[tokio::test]
    async fn decrypt_current_key_roundtrip() {
        let store         = init_key_store(3600);
        let (key_id, pem) = get_current_public_key(&store).await;
        let plaintext     = b"aes-key-32-bytes-test-payload!@@";
        let cdata         = client_encrypt(&pem, plaintext);
        let decrypted     = decrypt(&store, &key_id, &cdata).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn decrypt_unknown_key_id_returns_expired() {
        let store  = init_key_store(3600);
        let dummy  = vec![0u8; 128];
        let result = decrypt(&store, "nonexistent-key-id", &dummy).await;
        assert!(matches!(result, Err(RsaError::KeyExpired)));
    }

    #[tokio::test]
    async fn decrypt_with_corrupted_cdata_returns_error() {
        let store        = init_key_store(3600);
        let (key_id, _)  = get_current_public_key(&store).await;
        let bad_cdata    = vec![0xFFu8; 128];
        let result       = decrypt(&store, &key_id, &bad_cdata).await;
        assert!(matches!(result, Err(RsaError::DecryptionFailed(_))));
    }

    #[tokio::test]
    async fn key_pair_matches() {
        let store  = init_key_store(3600);
        let guard  = store.read().await;
        let entry  = &guard.current;
        let derived_public = entry.private_key.to_public_key();
        let derived_pem    = derived_public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let plaintext = b"keypair-match-probe";
        let cdata     = client_encrypt(&entry.public_key_pem, plaintext);
        let padding   = rsa::Oaep::new::<sha2::Sha256>();
        let decrypted = entry.private_key.decrypt(padding, &cdata).unwrap();
        assert_eq!(entry.public_key_pem, derived_pem);
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// Step 1 of the cross-crate e2e pipeline.
    /// Writes the private key to `/tmp/alterion_test_keypair.json` and prints
    /// the public PEM + key_id to paste into the frontend test.
    #[tokio::test]
    async fn generate_test_keypair() {
        let store  = init_key_store(3600);
        let guard  = store.read().await;
        let entry  = &guard.current;
        let private_key_pem = entry.private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to serialize private key");
        let json = format!(
            r#"{{ "key_id": "{}", "private_key_pem": "{}" }}"#,
            entry.key_id,
            private_key_pem.as_str().replace('\n', "\\n")
        );
        std::fs::write(KEYPAIR_PATH, &json).expect("failed to write keypair file");
        println!("\n========= PASTE INTO FRONTEND TEST =========");
        println!("const TEST_KEY_ID = \"{}\";", entry.key_id);
        println!("const TEST_PEM = `{}`;", entry.public_key_pem);
        println!("============================================");
        println!("private key written to: {}", KEYPAIR_PATH);
    }
}
