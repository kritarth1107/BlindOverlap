//! Abort receipts for mid-protocol cancellation.
//!
//! An `AbortReceipt` is a signed record of session cancellation that provides
//! an audit trail when a party aborts a PSI session before completion.
//!
//! ## Security Note
//!
//! **Abort receipts are audit aids, not security guarantees.**
//!
//! - They provide a tamper-evident record of WHO aborted and WHY
//! - They do NOT force the other party to accept the abort
//! - They do NOT upgrade PSI security from semi-honest to malicious
//! - A malicious party could claim abort without actually sending one
//!
//! ## Domain Separation
//!
//! All signatures use the domain tag `BlindOverlap:AbortReceipt:v1` to prevent
//! cross-protocol signature reuse.

use crate::freshness::{current_unix_time, TranscriptDigest};
use crate::identity::{IdentityError, PartyIdentity, PublicIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separation tag for abort receipt signatures.
pub const ABORT_RECEIPT_DOMAIN: &[u8] = b"BlindOverlap:AbortReceipt:v1";

/// Standard abort reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    /// User requested cancellation.
    UserCancelled,
    /// Session timed out.
    Timeout,
    /// Protocol error (malformed message, validation failure).
    ProtocolError,
    /// Network error.
    NetworkError,
    /// Resource exhaustion (memory, connections).
    ResourceExhaustion,
    /// Policy violation (trust check failed).
    PolicyViolation,
    /// Unknown or unspecified reason.
    #[default]
    Unknown,
    /// Custom reason (check reason_text for details).
    Custom,
}

impl AbortReason {
    /// Convert to a short code string.
    pub fn code(&self) -> &'static str {
        match self {
            AbortReason::UserCancelled => "user_cancelled",
            AbortReason::Timeout => "timeout",
            AbortReason::ProtocolError => "protocol_error",
            AbortReason::NetworkError => "network_error",
            AbortReason::ResourceExhaustion => "resource_exhaustion",
            AbortReason::PolicyViolation => "policy_violation",
            AbortReason::Unknown => "unknown",
            AbortReason::Custom => "custom",
        }
    }
}

impl std::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// Errors that can occur during abort receipt operations.
#[derive(Debug, Error)]
pub enum AbortError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,
    /// Issuer mismatch.
    #[error("issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch {
        /// Expected issuer public key (hex).
        expected: String,
        /// Actual issuer public key (hex).
        got: String,
    },
    /// Session ID mismatch.
    #[error("session ID mismatch: expected {expected}, got {got}")]
    SessionMismatch {
        /// Expected session ID.
        expected: String,
        /// Actual session ID.
        got: String,
    },
    /// Transcript digest mismatch.
    #[error("transcript digest mismatch")]
    TranscriptMismatch,
    /// Identity error.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A signed abort receipt for mid-protocol cancellation.
///
/// When a party needs to abort a PSI session before completion, they can
/// create an abort receipt to document the cancellation with a reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbortReceipt {
    /// Protocol version for abort receipts.
    pub version: u8,
    /// Session ID of the aborted session.
    pub session_id: String,
    /// Public key of the party issuing the abort.
    pub issuer_pubkey: PublicIdentity,
    /// Abort reason code.
    pub reason: AbortReason,
    /// Optional reason text (short description).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    /// Unix timestamp when abort was issued.
    pub issued_at: u64,
    /// Optional transcript digest (if available at abort time).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_digest: Option<TranscriptDigest>,
    /// Ed25519 signature over the abort payload.
    #[serde(with = "hex_signature")]
    pub signature: [u8; 64],
}

impl AbortReceipt {
    /// Create a new abort receipt.
    pub fn new(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        reason: AbortReason,
        reason_text: Option<String>,
        transcript_digest: Option<TranscriptDigest>,
    ) -> Self {
        let session_id = session_id.into();
        let issued_at = current_unix_time();

        let payload = Self::compute_payload(
            &session_id,
            &issuer.public(),
            reason,
            reason_text.as_deref(),
            issued_at,
            transcript_digest.as_ref(),
        );

        let signature = issuer.sign(&payload);

        Self {
            version: 1,
            session_id,
            issuer_pubkey: issuer.public(),
            reason,
            reason_text,
            issued_at,
            transcript_digest,
            signature,
        }
    }

    /// Create a simple abort receipt with just a reason code.
    pub fn simple(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        reason: AbortReason,
    ) -> Self {
        Self::new(issuer, session_id, reason, None, None)
    }

    /// Create an abort receipt with a custom reason text.
    pub fn with_reason(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        reason_text: impl Into<String>,
    ) -> Self {
        Self::new(
            issuer,
            session_id,
            AbortReason::Custom,
            Some(reason_text.into()),
            None,
        )
    }

    /// Create an abort receipt with transcript binding.
    pub fn with_transcript(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        reason: AbortReason,
        transcript_digest: TranscriptDigest,
    ) -> Self {
        Self::new(issuer, session_id, reason, None, Some(transcript_digest))
    }

    /// Verify the receipt's signature.
    pub fn verify(&self) -> Result<(), AbortError> {
        let payload = Self::compute_payload(
            &self.session_id,
            &self.issuer_pubkey,
            self.reason,
            self.reason_text.as_deref(),
            self.issued_at,
            self.transcript_digest.as_ref(),
        );

        self.issuer_pubkey
            .verify(&payload, &self.signature)
            .map_err(|_| AbortError::InvalidSignature)?;

        Ok(())
    }

    /// Verify the receipt was issued by the expected party.
    pub fn verify_issuer(&self, expected_issuer: &PublicIdentity) -> Result<(), AbortError> {
        self.verify()?;

        if &self.issuer_pubkey != expected_issuer {
            return Err(AbortError::IssuerMismatch {
                expected: expected_issuer.to_hex(),
                got: self.issuer_pubkey.to_hex(),
            });
        }

        Ok(())
    }

    /// Verify the receipt is for the expected session.
    pub fn verify_for_session(&self, session_id: &str) -> Result<(), AbortError> {
        self.verify()?;

        if self.session_id != session_id {
            return Err(AbortError::SessionMismatch {
                expected: self.session_id.clone(),
                got: session_id.to_string(),
            });
        }

        Ok(())
    }

    /// Verify the receipt matches the expected transcript.
    pub fn verify_transcript(&self, expected: &TranscriptDigest) -> Result<(), AbortError> {
        self.verify()?;

        if let Some(digest) = &self.transcript_digest {
            if digest != expected {
                return Err(AbortError::TranscriptMismatch);
            }
        }

        Ok(())
    }

    /// Compute the receipt ID (hash of signature).
    pub fn receipt_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, AbortError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, AbortError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    pub fn from_json(json: &str) -> Result<Self, AbortError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load from file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, AbortError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Save to file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), AbortError> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn compute_payload(
        session_id: &str,
        issuer: &PublicIdentity,
        reason: AbortReason,
        reason_text: Option<&str>,
        issued_at: u64,
        transcript_digest: Option<&TranscriptDigest>,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(256);
        payload.extend_from_slice(ABORT_RECEIPT_DOMAIN);
        payload.push(0); // null separator
        payload.extend_from_slice(session_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(issuer.as_bytes());
        payload.extend_from_slice(reason.code().as_bytes());
        payload.push(0);
        if let Some(text) = reason_text {
            payload.push(1);
            payload.extend_from_slice(text.as_bytes());
        } else {
            payload.push(0);
        }
        payload.extend_from_slice(&issued_at.to_le_bytes());
        if let Some(digest) = transcript_digest {
            payload.push(1);
            payload.extend_from_slice(digest.as_bytes());
        } else {
            payload.push(0);
        }
        payload
    }
}

mod hex_signature {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::freshness::SessionNonce;

    #[test]
    fn test_abort_receipt_simple() {
        let issuer = PartyIdentity::generate();

        let receipt = AbortReceipt::simple(&issuer, "test-session", AbortReason::UserCancelled);

        assert!(receipt.verify().is_ok());
        assert_eq!(receipt.reason, AbortReason::UserCancelled);
        assert!(receipt.reason_text.is_none());
    }

    #[test]
    fn test_abort_receipt_with_reason_text() {
        let issuer = PartyIdentity::generate();

        let receipt =
            AbortReceipt::with_reason(&issuer, "test-session", "Connection lost unexpectedly");

        assert!(receipt.verify().is_ok());
        assert_eq!(receipt.reason, AbortReason::Custom);
        assert_eq!(
            receipt.reason_text,
            Some("Connection lost unexpectedly".to_string())
        );
    }

    #[test]
    fn test_abort_receipt_with_transcript() {
        let issuer = PartyIdentity::generate();
        let nonce = SessionNonce::generate();
        let digest = TranscriptDigest::compute("test-session", &nonce, None, &[], None, None);

        let receipt =
            AbortReceipt::with_transcript(&issuer, "test-session", AbortReason::Timeout, digest);

        assert!(receipt.verify().is_ok());
        assert_eq!(receipt.transcript_digest, Some(digest));
    }

    #[test]
    fn test_abort_receipt_verify_issuer() {
        let issuer = PartyIdentity::generate();
        let other = PartyIdentity::generate();

        let receipt = AbortReceipt::simple(&issuer, "test-session", AbortReason::NetworkError);

        assert!(receipt.verify_issuer(&issuer.public()).is_ok());
        assert!(receipt.verify_issuer(&other.public()).is_err());
    }

    #[test]
    fn test_abort_receipt_verify_session() {
        let issuer = PartyIdentity::generate();

        let receipt = AbortReceipt::simple(&issuer, "session-1", AbortReason::ProtocolError);

        assert!(receipt.verify_for_session("session-1").is_ok());
        assert!(receipt.verify_for_session("session-2").is_err());
    }

    #[test]
    fn test_abort_receipt_json_roundtrip() {
        let issuer = PartyIdentity::generate();

        let receipt = AbortReceipt::with_reason(&issuer, "json-test", "Testing JSON");
        let json = receipt.to_json_pretty().unwrap();
        let parsed = AbortReceipt::from_json(&json).unwrap();

        assert_eq!(receipt.session_id, parsed.session_id);
        assert_eq!(receipt.reason, parsed.reason);
        assert_eq!(receipt.reason_text, parsed.reason_text);
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn test_abort_receipt_tampered_rejected() {
        let issuer = PartyIdentity::generate();

        let mut receipt = AbortReceipt::simple(&issuer, "tamper-test", AbortReason::Unknown);
        receipt.signature[0] ^= 0xFF;

        assert!(matches!(
            receipt.verify(),
            Err(AbortError::InvalidSignature)
        ));
    }

    #[test]
    fn test_abort_receipt_id_uniqueness() {
        let issuer = PartyIdentity::generate();

        let receipt1 = AbortReceipt::simple(&issuer, "session-1", AbortReason::Timeout);
        let receipt2 = AbortReceipt::simple(&issuer, "session-2", AbortReason::Timeout);

        assert_ne!(receipt1.receipt_id(), receipt2.receipt_id());
    }

    #[test]
    fn test_abort_reason_display() {
        assert_eq!(AbortReason::UserCancelled.to_string(), "user_cancelled");
        assert_eq!(AbortReason::Timeout.to_string(), "timeout");
        assert_eq!(AbortReason::Custom.to_string(), "custom");
    }
}
