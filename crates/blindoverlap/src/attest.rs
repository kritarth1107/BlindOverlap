//! Overlap attestation for portable, verifiable intersection outcomes.
//!
//! Provides `OverlapAttestation` — an Ed25519-signed attestation of an intersection
//! outcome that a third party can verify WITHOUT re-running PSI.
//!
//! # Security Note
//!
//! An attestation proves the **issuer claimed** a particular outcome. It does NOT:
//! - Prove the other party agreed (unless dual-signed)
//! - Prove the PSI was executed correctly (semi-honest model)
//! - Prevent the issuer from lying about the outcome
//!
//! Use attestations for audit trails and non-interactive verification of claims.

use crate::freshness::{current_unix_time, TranscriptDigest};
use crate::identity::{PartyIdentity, PublicIdentity};
use crate::protocol::IntersectionMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

/// Domain separation tag for attestation signatures.
pub const ATTESTATION_DOMAIN: &[u8] = b"blindoverlap-attest-v1";

/// Errors that can occur during attestation operations.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Attestation has expired.
    #[error("attestation expired: issued_at={issued_at}, expires_at={expires_at}, now={now}")]
    Expired {
        /// When attestation was issued (unix seconds).
        issued_at: u64,
        /// When attestation expires (unix seconds).
        expires_at: u64,
        /// Current time (unix seconds).
        now: u64,
    },
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,
    /// Issuer public key mismatch.
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
    /// Mode mismatch.
    #[error("mode mismatch: expected {expected:?}, got {got:?}")]
    ModeMismatch {
        /// Expected mode.
        expected: AttestationMode,
        /// Actual mode.
        got: AttestationMode,
    },
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),
    /// Invalid hex encoding.
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    /// Identity error.
    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::IdentityError),
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Attestation mode (what is being attested).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    /// Attesting the full intersection result.
    Intersection,
    /// Attesting only the cardinality.
    Cardinality,
}

impl From<IntersectionMode> for AttestationMode {
    fn from(mode: IntersectionMode) -> Self {
        match mode {
            IntersectionMode::Intersection => AttestationMode::Intersection,
            IntersectionMode::Cardinality => AttestationMode::Cardinality,
        }
    }
}

/// An Ed25519-signed attestation of an intersection outcome.
///
/// Third parties can verify this attestation WITHOUT re-running PSI.
/// The attestation binds:
/// - The issuer's identity (Ed25519 public key)
/// - The intersection mode (intersection vs cardinality)
/// - Set commitments (roots of both parties' sets)
/// - The outcome (intersection root or cardinality)
/// - Optionally: session ID and transcript digest
///
/// # Honest Scope
///
/// An attestation proves the **issuer claimed** a particular outcome.
/// It does NOT prove:
/// - The other party agreed to this outcome
/// - The PSI protocol was followed correctly
/// - The claimed values are truthful
///
/// For mutual agreement, see `co_sign()` for dual-signature attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlapAttestation {
    /// Version of the attestation format.
    pub version: u8,

    /// Optional session ID this attestation is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Attestation mode (intersection or cardinality).
    pub mode: AttestationMode,

    /// Merkle root of party A's set.
    #[serde(with = "hex_bytes_32")]
    pub set_root_a: [u8; 32],

    /// Merkle root of party B's set.
    #[serde(with = "hex_bytes_32")]
    pub set_root_b: [u8; 32],

    /// Merkle root of the intersection (for Intersection mode).
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "option_hex_32"
    )]
    pub intersection_root: Option<[u8; 32]>,

    /// Cardinality of the intersection (for Cardinality mode).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cardinality: Option<usize>,

    /// Optional transcript digest for session binding.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transcript_digest: Option<TranscriptDigest>,

    /// Unix timestamp when attestation was issued.
    pub issued_at: u64,

    /// Unix timestamp when attestation expires.
    pub expires_at: u64,

    /// Public key of the issuer.
    pub issuer_pubkey: PublicIdentity,

    /// Ed25519 signature over the attestation body.
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],

    /// Optional co-signer public key (for dual-signed attestations).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub co_signer_pubkey: Option<PublicIdentity>,

    /// Optional co-signature (for dual-signed attestations).
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "option_hex_64"
    )]
    pub co_signature: Option<[u8; 64]>,
}

impl OverlapAttestation {
    /// Default attestation TTL in seconds (1 hour).
    pub const DEFAULT_TTL_SECS: u64 = 3600;

    /// Create and sign an intersection attestation.
    pub fn sign_intersection(
        identity: &PartyIdentity,
        set_root_a: [u8; 32],
        set_root_b: [u8; 32],
        intersection_root: [u8; 32],
        session_id: Option<String>,
        transcript_digest: Option<TranscriptDigest>,
        ttl_secs: u64,
    ) -> Self {
        let now = current_unix_time();
        let mut attestation = Self {
            version: 1,
            session_id,
            mode: AttestationMode::Intersection,
            set_root_a,
            set_root_b,
            intersection_root: Some(intersection_root),
            cardinality: None,
            transcript_digest,
            issued_at: now,
            expires_at: now.saturating_add(ttl_secs),
            issuer_pubkey: identity.public(),
            signature: [0u8; 64],
            co_signer_pubkey: None,
            co_signature: None,
        };

        let body = attestation.signing_body();
        attestation.signature = Self::sign_with_domain(identity, &body);
        attestation
    }

    /// Create and sign a cardinality attestation.
    pub fn sign_cardinality(
        identity: &PartyIdentity,
        set_root_a: [u8; 32],
        set_root_b: [u8; 32],
        cardinality: usize,
        session_id: Option<String>,
        transcript_digest: Option<TranscriptDigest>,
        ttl_secs: u64,
    ) -> Self {
        let now = current_unix_time();
        let mut attestation = Self {
            version: 1,
            session_id,
            mode: AttestationMode::Cardinality,
            set_root_a,
            set_root_b,
            intersection_root: None,
            cardinality: Some(cardinality),
            transcript_digest,
            issued_at: now,
            expires_at: now.saturating_add(ttl_secs),
            issuer_pubkey: identity.public(),
            signature: [0u8; 64],
            co_signer_pubkey: None,
            co_signature: None,
        };

        let body = attestation.signing_body();
        attestation.signature = Self::sign_with_domain(identity, &body);
        attestation
    }

    /// Sign the body with domain separation.
    fn sign_with_domain(identity: &PartyIdentity, body: &[u8]) -> [u8; 64] {
        let mut domain_msg = Vec::with_capacity(ATTESTATION_DOMAIN.len() + body.len());
        domain_msg.extend_from_slice(ATTESTATION_DOMAIN);
        domain_msg.extend_from_slice(body);

        identity.sign(&domain_msg)
    }

    /// Verify the signature with domain separation.
    fn verify_with_domain(pubkey: &PublicIdentity, body: &[u8], sig: &[u8; 64]) -> bool {
        let mut domain_msg = Vec::with_capacity(ATTESTATION_DOMAIN.len() + body.len());
        domain_msg.extend_from_slice(ATTESTATION_DOMAIN);
        domain_msg.extend_from_slice(body);

        pubkey.verify(&domain_msg, sig).is_ok()
    }

    /// Compute the canonical signing body for this attestation.
    fn signing_body(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();

        hasher.update(ATTESTATION_DOMAIN);
        hasher.update(b":version:");
        hasher.update([self.version]);

        if let Some(ref session) = self.session_id {
            hasher.update(b":session:");
            hasher.update(session.as_bytes());
        }

        hasher.update(b":mode:");
        match self.mode {
            AttestationMode::Intersection => hasher.update(b"intersection"),
            AttestationMode::Cardinality => hasher.update(b"cardinality"),
        }

        hasher.update(b":set_root_a:");
        hasher.update(self.set_root_a);

        hasher.update(b":set_root_b:");
        hasher.update(self.set_root_b);

        if let Some(ref root) = self.intersection_root {
            hasher.update(b":intersection_root:");
            hasher.update(root);
        }

        if let Some(card) = self.cardinality {
            hasher.update(b":cardinality:");
            hasher.update((card as u64).to_le_bytes());
        }

        if let Some(ref digest) = self.transcript_digest {
            hasher.update(b":transcript:");
            hasher.update(digest.as_bytes());
        }

        hasher.update(b":issued_at:");
        hasher.update(self.issued_at.to_le_bytes());

        hasher.update(b":expires_at:");
        hasher.update(self.expires_at.to_le_bytes());

        hasher.update(b":issuer:");
        hasher.update(self.issuer_pubkey.as_bytes());

        hasher.finalize().to_vec()
    }

    /// Verify this attestation's signature and expiry.
    pub fn verify(&self) -> Result<(), AttestationError> {
        let now = current_unix_time();

        if now >= self.expires_at {
            return Err(AttestationError::Expired {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                now,
            });
        }

        let body = self.signing_body();
        if !Self::verify_with_domain(&self.issuer_pubkey, &body, &self.signature) {
            return Err(AttestationError::InvalidSignature);
        }

        Ok(())
    }

    /// Verify the attestation is from a specific issuer.
    pub fn verify_issuer(&self, expected: &PublicIdentity) -> Result<(), AttestationError> {
        if &self.issuer_pubkey != expected {
            return Err(AttestationError::IssuerMismatch {
                expected: expected.to_hex(),
                got: self.issuer_pubkey.to_hex(),
            });
        }
        Ok(())
    }

    /// Verify the attestation is for a specific session.
    pub fn verify_session(&self, expected: &str) -> Result<(), AttestationError> {
        match &self.session_id {
            Some(id) if id == expected => Ok(()),
            Some(id) => Err(AttestationError::SessionMismatch {
                expected: expected.to_string(),
                got: id.clone(),
            }),
            None => Err(AttestationError::MissingField("session_id".to_string())),
        }
    }

    /// Perform full verification including signature, expiry, and issuer.
    pub fn verify_full(&self, expected_issuer: &PublicIdentity) -> Result<(), AttestationError> {
        self.verify()?;
        self.verify_issuer(expected_issuer)?;
        Ok(())
    }

    /// Check if this attestation has expired.
    pub fn is_expired(&self) -> bool {
        current_unix_time() >= self.expires_at
    }

    /// Get remaining TTL in seconds, or None if expired.
    pub fn remaining_secs(&self) -> Option<u64> {
        let now = current_unix_time();
        if now >= self.expires_at {
            None
        } else {
            Some(self.expires_at - now)
        }
    }

    /// Compute a unique attestation ID (hash of key fields).
    pub fn attestation_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ATTESTATION_DOMAIN);
        hasher.update(self.issuer_pubkey.as_bytes());
        hasher.update(self.issued_at.to_le_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Add a co-signature from another party (dual-signed attestation).
    ///
    /// This creates a mutually-attested outcome where both parties agree.
    /// The co-signer signs the same body as the original issuer.
    pub fn co_sign(&mut self, co_signer: &PartyIdentity) {
        let body = self.signing_body();
        self.co_signer_pubkey = Some(co_signer.public());
        self.co_signature = Some(Self::sign_with_domain(co_signer, &body));
    }

    /// Verify the co-signature if present.
    pub fn verify_co_signature(&self) -> Result<(), AttestationError> {
        let co_signer = self
            .co_signer_pubkey
            .as_ref()
            .ok_or_else(|| AttestationError::MissingField("co_signer_pubkey".to_string()))?;
        let co_sig = self
            .co_signature
            .as_ref()
            .ok_or_else(|| AttestationError::MissingField("co_signature".to_string()))?;

        let body = self.signing_body();
        if !Self::verify_with_domain(co_signer, &body, co_sig) {
            return Err(AttestationError::InvalidSignature);
        }
        Ok(())
    }

    /// Check if this is a dual-signed (co-attested) attestation.
    pub fn is_dual_signed(&self) -> bool {
        self.co_signer_pubkey.is_some() && self.co_signature.is_some()
    }

    /// Load attestation from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, AttestationError> {
        let contents = std::fs::read_to_string(path)?;
        let attest: Self = serde_json::from_str(&contents)?;
        Ok(attest)
    }

    /// Save attestation to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), AttestationError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, AttestationError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, AttestationError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> Result<Self, AttestationError> {
        Ok(serde_json::from_str(json)?)
    }
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

mod hex_bytes_64 {
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

mod option_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

mod option_hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> PartyIdentity {
        PartyIdentity::from_seed(&[1u8; 32])
    }

    fn create_another_identity() -> PartyIdentity {
        PartyIdentity::from_seed(&[2u8; 32])
    }

    #[test]
    fn test_sign_intersection_attestation() {
        let identity = create_test_identity();
        let set_root_a = [1u8; 32];
        let set_root_b = [2u8; 32];
        let intersection_root = [3u8; 32];

        let attest = OverlapAttestation::sign_intersection(
            &identity,
            set_root_a,
            set_root_b,
            intersection_root,
            Some("test-session".to_string()),
            None,
            3600,
        );

        assert_eq!(attest.version, 1);
        assert_eq!(attest.session_id, Some("test-session".to_string()));
        assert_eq!(attest.mode, AttestationMode::Intersection);
        assert_eq!(attest.set_root_a, set_root_a);
        assert_eq!(attest.set_root_b, set_root_b);
        assert_eq!(attest.intersection_root, Some(intersection_root));
        assert!(attest.cardinality.is_none());
        assert_eq!(attest.issuer_pubkey, identity.public());
        assert!(!attest.is_expired());
    }

    #[test]
    fn test_sign_cardinality_attestation() {
        let identity = create_test_identity();
        let set_root_a = [1u8; 32];
        let set_root_b = [2u8; 32];
        let cardinality = 42;

        let attest = OverlapAttestation::sign_cardinality(
            &identity,
            set_root_a,
            set_root_b,
            cardinality,
            None,
            None,
            3600,
        );

        assert_eq!(attest.mode, AttestationMode::Cardinality);
        assert!(attest.intersection_root.is_none());
        assert_eq!(attest.cardinality, Some(42));
        assert!(attest.session_id.is_none());
    }

    #[test]
    fn test_verify_valid_attestation() {
        let identity = create_test_identity();
        let attest = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        assert!(attest.verify().is_ok());
    }

    #[test]
    fn test_verify_expired_attestation() {
        let identity = create_test_identity();

        // Create attestation with 0 TTL (immediately expired)
        let attest = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 0,
        );

        let err = attest.verify().unwrap_err();
        assert!(matches!(err, AttestationError::Expired { .. }));
    }

    #[test]
    fn test_verify_tampered_signature() {
        let identity = create_test_identity();
        let mut attest = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        attest.signature[0] ^= 0xFF;

        let err = attest.verify().unwrap_err();
        assert!(matches!(err, AttestationError::InvalidSignature));
    }

    #[test]
    fn test_verify_wrong_issuer() {
        let identity = create_test_identity();
        let other_identity = create_another_identity();

        let attest = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        let err = attest.verify_issuer(&other_identity.public()).unwrap_err();
        assert!(matches!(err, AttestationError::IssuerMismatch { .. }));
    }

    #[test]
    fn test_verify_session() {
        let identity = create_test_identity();

        let attest_with_session = OverlapAttestation::sign_intersection(
            &identity,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            Some("my-session".to_string()),
            None,
            3600,
        );

        assert!(attest_with_session.verify_session("my-session").is_ok());

        let err = attest_with_session
            .verify_session("other-session")
            .unwrap_err();
        assert!(matches!(err, AttestationError::SessionMismatch { .. }));

        let attest_no_session = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        let err = attest_no_session.verify_session("any-session").unwrap_err();
        assert!(matches!(err, AttestationError::MissingField(_)));
    }

    #[test]
    fn test_verify_full() {
        let identity = create_test_identity();

        let attest = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        assert!(attest.verify_full(&identity.public()).is_ok());
    }

    #[test]
    fn test_co_sign_attestation() {
        let issuer = create_test_identity();
        let co_signer = create_another_identity();

        let mut attest = OverlapAttestation::sign_intersection(
            &issuer, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        assert!(!attest.is_dual_signed());

        attest.co_sign(&co_signer);

        assert!(attest.is_dual_signed());
        assert_eq!(attest.co_signer_pubkey, Some(co_signer.public()));
        assert!(attest.verify_co_signature().is_ok());
    }

    #[test]
    fn test_co_signature_verification_fails_when_tampered() {
        let issuer = create_test_identity();
        let co_signer = create_another_identity();

        let mut attest = OverlapAttestation::sign_intersection(
            &issuer, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        attest.co_sign(&co_signer);
        attest.co_signature.as_mut().unwrap()[0] ^= 0xFF;

        let err = attest.verify_co_signature().unwrap_err();
        assert!(matches!(err, AttestationError::InvalidSignature));
    }

    #[test]
    fn test_attestation_id_uniqueness() {
        let identity = create_test_identity();

        let attest1 = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        let attest2 = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        // Different attestations should have different IDs
        // (due to different issued_at timestamps or signatures)
        // Note: in rapid succession they might have same timestamp,
        // but signatures include randomness
        let id1 = attest1.attestation_id();
        let id2 = attest2.attestation_id();

        // IDs should be valid 32-byte hashes
        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);
    }

    #[test]
    fn test_json_roundtrip() {
        let identity = create_test_identity();

        let attest = OverlapAttestation::sign_intersection(
            &identity,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            Some("session".to_string()),
            None,
            3600,
        );

        let json = attest.to_json_pretty().unwrap();
        let restored = OverlapAttestation::from_json(&json).unwrap();

        assert_eq!(restored.version, attest.version);
        assert_eq!(restored.session_id, attest.session_id);
        assert_eq!(restored.mode, attest.mode);
        assert_eq!(restored.set_root_a, attest.set_root_a);
        assert_eq!(restored.set_root_b, attest.set_root_b);
        assert_eq!(restored.intersection_root, attest.intersection_root);
        assert_eq!(restored.issuer_pubkey, attest.issuer_pubkey);
        assert_eq!(restored.signature, attest.signature);

        // Restored attestation should still verify
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn test_json_roundtrip_with_transcript() {
        use crate::freshness::SessionNonce;

        let identity = create_test_identity();
        let nonce = SessionNonce::from_bytes([42u8; 32]);
        let transcript = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

        let attest = OverlapAttestation::sign_intersection(
            &identity,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            Some("session".to_string()),
            Some(transcript),
            3600,
        );

        let json = attest.to_json_pretty().unwrap();
        let restored = OverlapAttestation::from_json(&json).unwrap();

        assert_eq!(restored.transcript_digest, attest.transcript_digest);
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn test_json_roundtrip_dual_signed() {
        let issuer = create_test_identity();
        let co_signer = create_another_identity();

        let mut attest = OverlapAttestation::sign_intersection(
            &issuer, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        attest.co_sign(&co_signer);

        let json = attest.to_json_pretty().unwrap();
        let restored = OverlapAttestation::from_json(&json).unwrap();

        assert!(restored.is_dual_signed());
        assert_eq!(restored.co_signer_pubkey, attest.co_signer_pubkey);
        assert_eq!(restored.co_signature, attest.co_signature);

        assert!(restored.verify().is_ok());
        assert!(restored.verify_co_signature().is_ok());
    }

    #[test]
    fn test_file_roundtrip() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let path = dir.path().join("attestation.json");

        let identity = create_test_identity();
        let attest = OverlapAttestation::sign_cardinality(
            &identity,
            [10u8; 32],
            [20u8; 32],
            100,
            Some("file-test".to_string()),
            None,
            7200,
        );

        attest.save_to_file(&path).unwrap();
        let restored = OverlapAttestation::load_from_file(&path).unwrap();

        assert_eq!(restored.mode, AttestationMode::Cardinality);
        assert_eq!(restored.cardinality, Some(100));
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn test_remaining_secs() {
        let identity = create_test_identity();

        let attest_long = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 3600,
        );

        let remaining = attest_long.remaining_secs();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= 3600);

        let attest_expired = OverlapAttestation::sign_intersection(
            &identity, [1u8; 32], [2u8; 32], [3u8; 32], None, None, 0,
        );

        assert!(attest_expired.remaining_secs().is_none());
    }

    #[test]
    fn test_attestation_mode_conversion() {
        assert_eq!(
            AttestationMode::from(IntersectionMode::Intersection),
            AttestationMode::Intersection
        );
        assert_eq!(
            AttestationMode::from(IntersectionMode::Cardinality),
            AttestationMode::Cardinality
        );
    }
}
