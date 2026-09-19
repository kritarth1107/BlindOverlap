//! Session freshness primitives for replay protection and TTL enforcement.
//!
//! Provides:
//! - `SessionNonce`: Cryptographic nonce for session binding
//! - `SessionDeadline`: TTL enforcement with issued_at/expires_at timestamps
//! - `TranscriptDigest`: Domain-separated hash over wire messages for binding
//!
//! # Security Note
//!
//! These are **best-effort freshness aids under the semi-honest model**.
//! They help prevent accidental replay and provide session timeouts, but do NOT
//! provide protection against active adversaries who can manipulate clocks or
//! forge messages.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Domain separation tag for transcript hashing.
const TRANSCRIPT_DOMAIN: &[u8] = b"BlindOverlap:TranscriptDigest:v1";

/// Default session TTL in seconds (5 minutes).
pub const DEFAULT_TTL_SECS: u64 = 300;

/// Errors that can occur during freshness operations.
#[derive(Debug, Error)]
pub enum FreshnessError {
    /// Session has expired.
    #[error("session expired: issued_at={issued_at}, expires_at={expires_at}, now={now}")]
    SessionExpired {
        /// When session was issued (unix seconds).
        issued_at: u64,
        /// When session expires (unix seconds).
        expires_at: u64,
        /// Current time (unix seconds).
        now: u64,
    },
    /// Nonce mismatch between messages.
    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch {
        /// Expected nonce (hex).
        expected: String,
        /// Received nonce (hex).
        got: String,
    },
    /// Message was replayed (seen before).
    #[error("message replay detected: {0}")]
    ReplayDetected(String),
    /// Invalid timestamp.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
    /// Missing freshness fields in message.
    #[error("missing freshness fields: {0}")]
    MissingFields(String),
}

/// A cryptographic nonce for session binding (32 bytes).
///
/// Generated randomly and used to bind protocol messages to a specific session.
/// Each party generates their own nonce; messages include both initiator and
/// responder nonces for mutual binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionNonce(#[serde(with = "hex_bytes_32")] [u8; 32]);

impl SessionNonce {
    /// Generate a new random nonce.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a nonce from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl Default for SessionNonce {
    fn default() -> Self {
        Self::generate()
    }
}

impl std::fmt::Display for SessionNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Session deadline with issued_at and expires_at timestamps.
///
/// Used to enforce TTL (time-to-live) on sessions. Messages with expired
/// deadlines should be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDeadline {
    /// Unix timestamp when session was issued (seconds since epoch).
    pub issued_at: u64,
    /// Unix timestamp when session expires (seconds since epoch).
    pub expires_at: u64,
}

impl SessionDeadline {
    /// Create a new deadline with given TTL from now.
    pub fn new(ttl_secs: u64) -> Self {
        let now = current_unix_time();
        Self {
            issued_at: now,
            expires_at: now.saturating_add(ttl_secs),
        }
    }

    /// Create a deadline with the default TTL.
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_TTL_SECS)
    }

    /// Create from explicit timestamps.
    pub fn from_timestamps(issued_at: u64, expires_at: u64) -> Self {
        Self {
            issued_at,
            expires_at,
        }
    }

    /// Check if this deadline has expired.
    pub fn is_expired(&self) -> bool {
        let now = current_unix_time();
        now >= self.expires_at
    }

    /// Validate this deadline hasn't expired and timestamps are sensible.
    pub fn validate(&self) -> Result<(), FreshnessError> {
        let now = current_unix_time();

        if self.expires_at <= self.issued_at {
            return Err(FreshnessError::InvalidTimestamp(
                "expires_at must be after issued_at".to_string(),
            ));
        }

        if now >= self.expires_at {
            return Err(FreshnessError::SessionExpired {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                now,
            });
        }

        Ok(())
    }

    /// Get the remaining time until expiry.
    pub fn remaining(&self) -> Option<Duration> {
        let now = current_unix_time();
        if now >= self.expires_at {
            None
        } else {
            Some(Duration::from_secs(self.expires_at - now))
        }
    }

    /// Get the TTL duration.
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.expires_at.saturating_sub(self.issued_at))
    }
}

impl Default for SessionDeadline {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

/// A digest of the wire protocol transcript for binding.
///
/// Used to cryptographically bind receipts to the actual messages exchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TranscriptDigest(#[serde(with = "hex_bytes_32")] [u8; 32]);

impl TranscriptDigest {
    /// Create a new transcript digest from message components.
    ///
    /// Hashes the session_id, nonces, and all masked elements in a
    /// domain-separated manner.
    pub fn compute(
        session_id: &str,
        initiator_nonce: &SessionNonce,
        responder_nonce: Option<&SessionNonce>,
        offer_elements: &[[u8; 32]],
        reply_responder_masked: Option<&[[u8; 32]]>,
        reply_initiator_doubly_masked: Option<&[[u8; 32]]>,
    ) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(b":session:");
        hasher.update(session_id.as_bytes());

        hasher.update(b":initiator_nonce:");
        hasher.update(initiator_nonce.as_bytes());

        if let Some(resp_nonce) = responder_nonce {
            hasher.update(b":responder_nonce:");
            hasher.update(resp_nonce.as_bytes());
        }

        hasher.update(b":offer_elements:");
        hasher.update(&(offer_elements.len() as u64).to_le_bytes());
        for elem in offer_elements {
            hasher.update(elem);
        }

        if let Some(resp_masked) = reply_responder_masked {
            hasher.update(b":reply_responder_masked:");
            hasher.update(&(resp_masked.len() as u64).to_le_bytes());
            for elem in resp_masked {
                hasher.update(elem);
            }
        }

        if let Some(init_doubly) = reply_initiator_doubly_masked {
            hasher.update(b":reply_initiator_doubly_masked:");
            hasher.update(&(init_doubly.len() as u64).to_le_bytes());
            for elem in init_doubly {
                hasher.update(elem);
            }
        }

        Self(hasher.finalize().into())
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl std::fmt::Display for TranscriptDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Get the current Unix time in seconds.
pub fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let nonce1 = SessionNonce::generate();
        let nonce2 = SessionNonce::generate();

        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.as_bytes().len(), 32);
    }

    #[test]
    fn test_nonce_hex_roundtrip() {
        let nonce = SessionNonce::generate();
        let hex = nonce.to_hex();
        let parsed = SessionNonce::from_hex(&hex).unwrap();

        assert_eq!(nonce, parsed);
    }

    #[test]
    fn test_nonce_serde_roundtrip() {
        let nonce = SessionNonce::generate();
        let json = serde_json::to_string(&nonce).unwrap();
        let parsed: SessionNonce = serde_json::from_str(&json).unwrap();

        assert_eq!(nonce, parsed);
    }

    #[test]
    fn test_deadline_creation() {
        let deadline = SessionDeadline::new(300);

        assert!(deadline.expires_at > deadline.issued_at);
        assert!(!deadline.is_expired());
        assert!(deadline.validate().is_ok());
    }

    #[test]
    fn test_deadline_expiry() {
        let deadline = SessionDeadline::from_timestamps(1000, 1001);

        assert!(deadline.is_expired());
        assert!(deadline.validate().is_err());
    }

    #[test]
    fn test_deadline_remaining() {
        let deadline = SessionDeadline::new(300);
        let remaining = deadline.remaining();

        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_secs() <= 300);
    }

    #[test]
    fn test_deadline_ttl() {
        let deadline = SessionDeadline::new(300);

        assert_eq!(deadline.ttl().as_secs(), 300);
    }

    #[test]
    fn test_deadline_serde_roundtrip() {
        let deadline = SessionDeadline::new(300);
        let json = serde_json::to_string(&deadline).unwrap();
        let parsed: SessionDeadline = serde_json::from_str(&json).unwrap();

        assert_eq!(deadline.issued_at, parsed.issued_at);
        assert_eq!(deadline.expires_at, parsed.expires_at);
    }

    #[test]
    fn test_transcript_digest_deterministic() {
        let nonce = SessionNonce::from_bytes([1u8; 32]);
        let elements = vec![[2u8; 32], [3u8; 32]];

        let digest1 = TranscriptDigest::compute("session-1", &nonce, None, &elements, None, None);
        let digest2 = TranscriptDigest::compute("session-1", &nonce, None, &elements, None, None);

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_transcript_digest_different_sessions() {
        let nonce = SessionNonce::from_bytes([1u8; 32]);
        let elements = vec![[2u8; 32]];

        let digest1 = TranscriptDigest::compute("session-a", &nonce, None, &elements, None, None);
        let digest2 = TranscriptDigest::compute("session-b", &nonce, None, &elements, None, None);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_transcript_digest_different_nonces() {
        let nonce1 = SessionNonce::from_bytes([1u8; 32]);
        let nonce2 = SessionNonce::from_bytes([2u8; 32]);
        let elements = vec![[3u8; 32]];

        let digest1 = TranscriptDigest::compute("session", &nonce1, None, &elements, None, None);
        let digest2 = TranscriptDigest::compute("session", &nonce2, None, &elements, None, None);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_transcript_digest_with_responder_nonce() {
        let init_nonce = SessionNonce::from_bytes([1u8; 32]);
        let resp_nonce = SessionNonce::from_bytes([2u8; 32]);
        let elements = vec![[3u8; 32]];

        let digest1 =
            TranscriptDigest::compute("session", &init_nonce, Some(&resp_nonce), &elements, None, None);
        let digest2 = TranscriptDigest::compute("session", &init_nonce, None, &elements, None, None);

        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_transcript_digest_hex_roundtrip() {
        let nonce = SessionNonce::generate();
        let digest = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

        let hex = digest.to_hex();
        let parsed = TranscriptDigest::from_hex(&hex).unwrap();

        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_current_unix_time() {
        let now = current_unix_time();

        assert!(now > 1_700_000_000);
    }
}
