// SPDX-License-Identifier: GPL-3.0
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_bytes::ByteBuf;
use flate2::write::DeflateEncoder;
use flate2::read::DeflateDecoder;
use flate2::Compression;
use std::io::{Write, Read};
use crate::tools::helper::hmac;
use crate::tools::crypt::aes_encrypt;

#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedPacket {
    pub data:   ByteBuf,
    pub cdata:  ByteBuf,
    pub key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedResponse {
    pub payload: ByteBuf,
    pub hmac:    ByteBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SerializerError {
    #[error("serialize error: {0}")]
    Serialize(String),
    #[error("deserialize error: {0}")]
    Deserialize(String),
    #[error("compress error: {0}")]
    Compress(String),
    #[error("decompress error: {0}")]
    Decompress(String),
}

impl From<SerializerError> for actix_web::Error {
    fn from(e: SerializerError) -> Self {
        actix_web::error::ErrorInternalServerError(e.to_string())
    }
}

/// Encodes a value to MessagePack bytes using named fields.
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, SerializerError> {
    rmp_serde::to_vec_named(value)
        .map_err(|e| SerializerError::Serialize(e.to_string()))
}

/// Decodes MessagePack bytes into the target type.
pub fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T, SerializerError> {
    rmp_serde::from_slice(data)
        .map_err(|e| SerializerError::Deserialize(e.to_string()))
}

/// Deflate-compresses `data` and returns the compressed bytes.
pub fn compress(data: &[u8]) -> Result<Vec<u8>, SerializerError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)
        .map_err(|e: std::io::Error| SerializerError::Compress(e.to_string()))?;
    encoder.finish()
        .map_err(|e: std::io::Error| SerializerError::Compress(e.to_string()))
}

/// Deflate-decompresses `data` and returns the original bytes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, SerializerError> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out     = Vec::new();
    decoder.read_to_end(&mut out)
        .map_err(|e: std::io::Error| SerializerError::Decompress(e.to_string()))?;
    Ok(out)
}

/// Deserialises raw bytes as a `WrappedPacket` (RSA-encrypted AES key + AES-encrypted payload).
pub fn deserialize_packet(data: &[u8]) -> Result<WrappedPacket, SerializerError> {
    deserialize::<WrappedPacket>(data)
}

/// Decodes a request payload from AES-decrypted bytes:
/// msgpack decode → deflate decompress → JSON deserialise.
pub fn decode_request_payload<T: DeserializeOwned>(
    decrypted_data: &[u8],
) -> Result<T, SerializerError> {
    let compressed: ByteBuf = deserialize(decrypted_data)?;
    let json_bytes          = decompress(&compressed)?;
    serde_json::from_slice(&json_bytes)
        .map_err(|e| SerializerError::Deserialize(e.to_string()))
}

/// Serialises `value` to JSON then passes it through `build_signed_response_raw`.
pub fn build_signed_response<T: Serialize>(
    value:   &T,
    aes_key: &[u8; 32],
) -> Result<Vec<u8>, SerializerError> {
    let json_bytes = serde_json::to_vec(value)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    build_signed_response_raw(&json_bytes, aes_key)
}

/// Builds a signed response from raw JSON bytes:
/// deflate compress → msgpack → AES-256-GCM encrypt → HMAC-SHA256 → `SignedResponse` → msgpack.
pub fn build_signed_response_raw(
    json_bytes: &[u8],
    aes_key:    &[u8; 32],
) -> Result<Vec<u8>, SerializerError> {
    let compressed = compress(json_bytes)?;
    let msgpacked  = serialize(&ByteBuf::from(compressed))?;
    let encrypted  = aes_encrypt(&msgpacked, aes_key)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    let sig        = hmac::sign(&encrypted, aes_key);
    let response   = SignedResponse {
        payload: ByteBuf::from(encrypted),
        hmac:    ByteBuf::from(sig),
    };
    serialize(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use crate::tools::crypt::aes_decrypt;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestPayload { id: u32, name: String, flag: bool }

    fn sample() -> TestPayload { TestPayload { id: 42, name: "alterion".into(), flag: true } }

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"hello alterion enc pipeline payload";
        assert_eq!(decompress(&compress(data).unwrap()).unwrap(), data);
    }

    #[test]
    fn decode_request_payload_roundtrip() {
        let original   = sample();
        let json_bytes = serde_json::to_vec(&original).unwrap();
        let compressed = compress(&json_bytes).unwrap();
        let msgpacked  = serialize(&ByteBuf::from(compressed)).unwrap();
        let decoded: TestPayload = decode_request_payload(&msgpacked).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn build_signed_response_roundtrip() {
        let aes_key = [0xABu8; 32];
        let payload = sample();
        let bytes   = build_signed_response(&payload, &aes_key).unwrap();
        let signed: SignedResponse = deserialize(&bytes).unwrap();

        assert_eq!(signed.hmac.as_ref(), hmac::sign(&signed.payload, &aes_key).as_slice());

        let decrypted: Vec<u8>   = aes_decrypt(&signed.payload, &aes_key).unwrap();
        let compressed: ByteBuf  = deserialize(&decrypted).unwrap();
        let json_bytes           = decompress(&compressed).unwrap();
        let decoded: TestPayload = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn build_signed_response_raw_matches_typed() {
        let aes_key    = [0xCDu8; 32];
        let payload    = sample();
        let json_bytes = serde_json::to_vec(&payload).unwrap();
        let from_typed = build_signed_response(&payload, &aes_key).unwrap();
        let from_raw   = build_signed_response_raw(&json_bytes, &aes_key).unwrap();
        let s1: SignedResponse = deserialize(&from_typed).unwrap();
        let s2: SignedResponse = deserialize(&from_raw).unwrap();
        let c1: ByteBuf = deserialize(&aes_decrypt(&s1.payload, &aes_key).unwrap()).unwrap();
        let c2: ByteBuf = deserialize(&aes_decrypt(&s2.payload, &aes_key).unwrap()).unwrap();
        assert_eq!(decompress(&c1).unwrap(), decompress(&c2).unwrap());
    }

    #[test]
    fn decompress_garbage_returns_error() {
        assert!(decompress(b"not compressed").is_err());
    }
}
