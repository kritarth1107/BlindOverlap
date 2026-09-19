//! Intersection receipt signing and verification.
//!
//! A receipt provides cryptographic proof that a PSI execution occurred between
//! two parties with specific set commitments and produced a specific result.
//!
//! ## Receipt Types
//!
//! - `IntersectionReceipt`: Basic receipt binding set roots and result (v0.1.0+)
//! - `WireBoundReceipt`: Enhanced receipt binding to a specific online session
//!   and wire transcript (v0.3.0+)
//!
//! Wire-bound receipts provide stronger binding to a specific protocol execution
//! by including session_id and transcript_digest in the signed data.

use crate::freshness::{SessionNonce, TranscriptDigest};
use crate::protocol::{IntersectionMode, PsiResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during receipt operations.
#[derive(Debug, Error)]
pub enum ReceiptError {
    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,
    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),
    /// Invalid public key format.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Commitment mismatch.
    #[error("commitment mismatch: expected {expected}, got {actual}")]
    CommitmentMismatch {
        /// Expected commitment (hex).
        expected: String,
        /// Actual commitment (hex).
        actual: String,
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
}

/// A signed intersection receipt.
///
/// This attests that a PSI execution occurred with the given parameters
/// and produced the given result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntersectionReceipt {
    /// Protocol version.
    pub version: u8,
    /// Set root commitment from party A (hex encoded for serde).
    #[serde(with = "hex_bytes_32")]
    pub set_root_a: [u8; 32],
    /// Set root commitment from party B (hex encoded for serde).
    #[serde(with = "hex_bytes_32")]
    pub set_root_b: [u8; 32],
    /// Result commitment (intersection root or cardinality hash).
    #[serde(with = "hex_bytes_32")]
    pub result_commitment: [u8; 32],
    /// Intersection mode used.
    pub mode: ReceiptMode,
    /// Ed25519 signature over the receipt data (hex encoded for serde).
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
    /// Public key of the signer (hex encoded for serde).
    #[serde(with = "hex_bytes_32")]
    pub signer_public_key: [u8; 32],
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

/// Receipt mode matching IntersectionMode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptMode {
    /// Full intersection was computed.
    Intersection,
    /// Only cardinality was revealed.
    Cardinality,
}

impl From<IntersectionMode> for ReceiptMode {
    fn from(mode: IntersectionMode) -> Self {
        match mode {
            IntersectionMode::Intersection => ReceiptMode::Intersection,
            IntersectionMode::Cardinality => ReceiptMode::Cardinality,
        }
    }
}

/// A wire-bound intersection receipt (v0.3.0+).
///
/// Unlike the basic `IntersectionReceipt`, this receipt binds to a specific
/// online PSI session and wire transcript, providing stronger assurance that
/// the receipt corresponds to a particular protocol execution.
///
/// # Binding Components
///
/// The receipt binds:
/// - Session ID: identifies the specific PSI session
/// - Transcript digest: hash of all wire messages exchanged
/// - Set roots: commitments to both parties' input sets
/// - Result commitment: hash of the intersection result
/// - Both parties' nonces: proves freshness and mutual participation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireBoundReceipt {
    /// Receipt format version.
    pub version: u8,
    /// Session identifier this receipt is bound to.
    pub session_id: String,
    /// Digest of the wire protocol transcript.
    pub transcript_digest: TranscriptDigest,
    /// Initiator's session nonce.
    pub initiator_nonce: SessionNonce,
    /// Responder's session nonce.
    pub responder_nonce: SessionNonce,
    /// Set root commitment from party A.
    #[serde(with = "hex_bytes_32")]
    pub set_root_a: [u8; 32],
    /// Set root commitment from party B.
    #[serde(with = "hex_bytes_32")]
    pub set_root_b: [u8; 32],
    /// Result commitment (intersection root or cardinality hash).
    #[serde(with = "hex_bytes_32")]
    pub result_commitment: [u8; 32],
    /// Intersection mode used.
    pub mode: ReceiptMode,
    /// Ed25519 signature over the receipt data.
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
    /// Public key of the signer.
    #[serde(with = "hex_bytes_32")]
    pub signer_public_key: [u8; 32],
}

impl WireBoundReceipt {
    /// Domain tag for wire-bound receipt signing.
    const DOMAIN: &'static [u8] = b"BlindOverlap:WireBoundReceipt:v1";

    /// Compute the message bytes that are signed.
    fn message_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        msg.extend_from_slice(Self::DOMAIN);
        msg.push(self.version);
        msg.extend_from_slice(self.session_id.as_bytes());
        msg.push(0); // null separator
        msg.extend_from_slice(self.transcript_digest.as_bytes());
        msg.extend_from_slice(self.initiator_nonce.as_bytes());
        msg.extend_from_slice(self.responder_nonce.as_bytes());
        msg.extend_from_slice(&self.set_root_a);
        msg.extend_from_slice(&self.set_root_b);
        msg.extend_from_slice(&self.result_commitment);
        msg.push(match self.mode {
            ReceiptMode::Intersection => 0,
            ReceiptMode::Cardinality => 1,
        });
        msg
    }

    /// Verify the receipt signature.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        let public_key = VerifyingKey::from_bytes(&self.signer_public_key)
            .map_err(|e| ReceiptError::InvalidPublicKey(e.to_string()))?;

        let signature = Signature::from_bytes(&self.signature);

        let message = self.message_bytes();
        public_key
            .verify(&message, &signature)
            .map_err(|e| ReceiptError::VerificationFailed(e.to_string()))
    }

    /// Verify the receipt against expected bindings.
    pub fn verify_with_bindings(
        &self,
        expected_session_id: &str,
        expected_transcript: &TranscriptDigest,
        expected_root_a: &[u8; 32],
        expected_root_b: &[u8; 32],
    ) -> Result<(), ReceiptError> {
        self.verify()?;

        if self.session_id != expected_session_id {
            return Err(ReceiptError::SessionMismatch {
                expected: expected_session_id.to_string(),
                got: self.session_id.clone(),
            });
        }

        if &self.transcript_digest != expected_transcript {
            return Err(ReceiptError::TranscriptMismatch);
        }

        if &self.set_root_a != expected_root_a {
            return Err(ReceiptError::CommitmentMismatch {
                expected: hex::encode(expected_root_a),
                actual: hex::encode(self.set_root_a),
            });
        }

        if &self.set_root_b != expected_root_b {
            return Err(ReceiptError::CommitmentMismatch {
                expected: hex::encode(expected_root_b),
                actual: hex::encode(self.set_root_b),
            });
        }

        Ok(())
    }

    /// Get the receipt ID (hash of the receipt for reference).
    pub fn receipt_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BlindOverlap:WireBoundReceiptId:v1");
        hasher.update(self.message_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }
}

impl IntersectionReceipt {
    /// Compute the message bytes that are signed.
    fn message_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 32 + 32 + 32 + 1);
        msg.push(self.version);
        msg.extend_from_slice(&self.set_root_a);
        msg.extend_from_slice(&self.set_root_b);
        msg.extend_from_slice(&self.result_commitment);
        msg.push(match self.mode {
            ReceiptMode::Intersection => 0,
            ReceiptMode::Cardinality => 1,
        });
        msg
    }

    /// Verify the receipt signature.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        let public_key = VerifyingKey::from_bytes(&self.signer_public_key)
            .map_err(|e| ReceiptError::InvalidPublicKey(e.to_string()))?;

        let signature = Signature::from_bytes(&self.signature);

        let message = self.message_bytes();
        public_key
            .verify(&message, &signature)
            .map_err(|e| ReceiptError::VerificationFailed(e.to_string()))
    }

    /// Verify the receipt against expected set roots.
    pub fn verify_with_roots(
        &self,
        expected_root_a: &[u8; 32],
        expected_root_b: &[u8; 32],
    ) -> Result<(), ReceiptError> {
        self.verify()?;

        if &self.set_root_a != expected_root_a {
            return Err(ReceiptError::CommitmentMismatch {
                expected: hex::encode(expected_root_a),
                actual: hex::encode(self.set_root_a),
            });
        }

        if &self.set_root_b != expected_root_b {
            return Err(ReceiptError::CommitmentMismatch {
                expected: hex::encode(expected_root_b),
                actual: hex::encode(self.set_root_b),
            });
        }

        Ok(())
    }

    /// Get the receipt ID (hash of the receipt for reference).
    pub fn receipt_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BlindOverlap:ReceiptId:v1");
        hasher.update(self.message_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }
}

/// Receipt signer with an Ed25519 signing key.
pub struct ReceiptSigner {
    signing_key: SigningKey,
}

impl ReceiptSigner {
    /// Create a new signer with a random key.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        Self { signing_key }
    }

    /// Create a signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a PSI result and create a receipt.
    pub fn sign(
        &self,
        set_root_a: &[u8; 32],
        set_root_b: &[u8; 32],
        result: &PsiResult,
        mode: IntersectionMode,
    ) -> IntersectionReceipt {
        let result_commitment = result.commitment();

        let mut receipt = IntersectionReceipt {
            version: 1,
            set_root_a: *set_root_a,
            set_root_b: *set_root_b,
            result_commitment,
            mode: mode.into(),
            signature: [0u8; 64],
            signer_public_key: self.public_key(),
        };

        let message = receipt.message_bytes();
        let signature = self.signing_key.sign(&message);
        receipt.signature = signature.to_bytes();

        receipt
    }

    /// Sign a wire-bound receipt that binds to a specific session and transcript.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_wire_bound(
        &self,
        session_id: impl Into<String>,
        transcript_digest: TranscriptDigest,
        initiator_nonce: SessionNonce,
        responder_nonce: SessionNonce,
        set_root_a: &[u8; 32],
        set_root_b: &[u8; 32],
        result: &PsiResult,
        mode: IntersectionMode,
    ) -> WireBoundReceipt {
        let result_commitment = result.commitment();

        let mut receipt = WireBoundReceipt {
            version: 1,
            session_id: session_id.into(),
            transcript_digest,
            initiator_nonce,
            responder_nonce,
            set_root_a: *set_root_a,
            set_root_b: *set_root_b,
            result_commitment,
            mode: mode.into(),
            signature: [0u8; 64],
            signer_public_key: self.public_key(),
        };

        let message = receipt.message_bytes();
        let signature = self.signing_key.sign(&message);
        receipt.signature = signature.to_bytes();

        receipt
    }
}

impl Default for ReceiptSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Receipt verifier (convenience wrapper around IntersectionReceipt::verify).
pub struct ReceiptVerifier;

impl ReceiptVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify a receipt's signature.
    pub fn verify(&self, receipt: &IntersectionReceipt) -> Result<(), ReceiptError> {
        receipt.verify()
    }

    /// Verify a receipt against expected set roots.
    pub fn verify_with_roots(
        &self,
        receipt: &IntersectionReceipt,
        expected_root_a: &[u8; 32],
        expected_root_b: &[u8; 32],
    ) -> Result<(), ReceiptError> {
        receipt.verify_with_roots(expected_root_a, expected_root_b)
    }

    /// Verify a wire-bound receipt's signature.
    pub fn verify_wire_bound(&self, receipt: &WireBoundReceipt) -> Result<(), ReceiptError> {
        receipt.verify()
    }

    /// Verify a wire-bound receipt against expected bindings.
    pub fn verify_wire_bound_with_bindings(
        &self,
        receipt: &WireBoundReceipt,
        expected_session_id: &str,
        expected_transcript: &TranscriptDigest,
        expected_root_a: &[u8; 32],
        expected_root_b: &[u8; 32],
    ) -> Result<(), ReceiptError> {
        receipt.verify_with_bindings(
            expected_session_id,
            expected_transcript,
            expected_root_a,
            expected_root_b,
        )
    }
}

impl Default for ReceiptVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_id::{fact_id_from_json, FactSet};
    use crate::protocol::PsiProtocol;
    use serde_json::json;

    #[test]
    fn test_receipt_roundtrip() {
        let set_a = FactSet::from_ids([
            fact_id_from_json(&json!({"a": 1})),
            fact_id_from_json(&json!({"a": 2})),
        ]);
        let set_b = FactSet::from_ids([
            fact_id_from_json(&json!({"a": 2})),
            fact_id_from_json(&json!({"b": 1})),
        ]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let signer = ReceiptSigner::new();
        let receipt = signer.sign(
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        let verifier = ReceiptVerifier::new();
        assert!(verifier.verify(&receipt).is_ok());
        assert!(verifier
            .verify_with_roots(&receipt, set_a.root(), set_b.root())
            .is_ok());
    }

    #[test]
    fn test_receipt_tampered_signature() {
        let set_a = FactSet::from_ids([fact_id_from_json(&json!({"a": 1}))]);
        let set_b = FactSet::from_ids([fact_id_from_json(&json!({"b": 1}))]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Cardinality)
            .unwrap();

        let signer = ReceiptSigner::new();
        let mut receipt = signer.sign(
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Cardinality,
        );

        receipt.signature[0] ^= 0xFF;

        let verifier = ReceiptVerifier::new();
        assert!(matches!(
            verifier.verify(&receipt),
            Err(ReceiptError::VerificationFailed(_))
        ));
    }

    #[test]
    fn test_receipt_wrong_roots() {
        let set_a = FactSet::from_ids([fact_id_from_json(&json!({"a": 1}))]);
        let set_b = FactSet::from_ids([fact_id_from_json(&json!({"b": 1}))]);
        let wrong_set = FactSet::from_ids([fact_id_from_json(&json!({"c": 1}))]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let signer = ReceiptSigner::new();
        let receipt = signer.sign(
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        let verifier = ReceiptVerifier::new();
        assert!(matches!(
            verifier.verify_with_roots(&receipt, wrong_set.root(), set_b.root()),
            Err(ReceiptError::CommitmentMismatch { .. })
        ));
    }

    #[test]
    fn test_receipt_deterministic_from_seed() {
        let seed = [42u8; 32];
        let signer1 = ReceiptSigner::from_seed(&seed);
        let signer2 = ReceiptSigner::from_seed(&seed);

        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn test_wire_bound_receipt_roundtrip() {
        use crate::freshness::{SessionNonce, TranscriptDigest};

        let set_a = FactSet::from_ids([
            fact_id_from_json(&json!({"a": 1})),
            fact_id_from_json(&json!({"a": 2})),
        ]);
        let set_b = FactSet::from_ids([
            fact_id_from_json(&json!({"a": 2})),
            fact_id_from_json(&json!({"b": 1})),
        ]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();
        let transcript = TranscriptDigest::compute(
            "test-session",
            &init_nonce,
            Some(&resp_nonce),
            &[[1u8; 32]],
            Some(&[[2u8; 32]]),
            Some(&[[3u8; 32]]),
        );

        let signer = ReceiptSigner::new();
        let receipt = signer.sign_wire_bound(
            "test-session",
            transcript,
            init_nonce,
            resp_nonce,
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        let verifier = ReceiptVerifier::new();
        assert!(verifier.verify_wire_bound(&receipt).is_ok());
        assert!(verifier
            .verify_wire_bound_with_bindings(
                &receipt,
                "test-session",
                &transcript,
                set_a.root(),
                set_b.root()
            )
            .is_ok());
    }

    #[test]
    fn test_wire_bound_receipt_tampered() {
        use crate::freshness::{SessionNonce, TranscriptDigest};

        let set_a = FactSet::from_ids([fact_id_from_json(&json!({"a": 1}))]);
        let set_b = FactSet::from_ids([fact_id_from_json(&json!({"b": 1}))]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();
        let transcript = TranscriptDigest::compute("session", &init_nonce, None, &[], None, None);

        let signer = ReceiptSigner::new();
        let mut receipt = signer.sign_wire_bound(
            "session",
            transcript,
            init_nonce,
            resp_nonce,
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        receipt.signature[0] ^= 0xFF;

        let verifier = ReceiptVerifier::new();
        assert!(verifier.verify_wire_bound(&receipt).is_err());
    }

    #[test]
    fn test_wire_bound_receipt_session_mismatch() {
        use crate::freshness::{SessionNonce, TranscriptDigest};

        let set_a = FactSet::from_ids([fact_id_from_json(&json!({"a": 1}))]);
        let set_b = FactSet::from_ids([fact_id_from_json(&json!({"b": 1}))]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();
        let transcript = TranscriptDigest::compute("session-1", &init_nonce, None, &[], None, None);

        let signer = ReceiptSigner::new();
        let receipt = signer.sign_wire_bound(
            "session-1",
            transcript,
            init_nonce,
            resp_nonce,
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        let verifier = ReceiptVerifier::new();
        let result = verifier.verify_wire_bound_with_bindings(
            &receipt,
            "session-WRONG",
            &transcript,
            set_a.root(),
            set_b.root(),
        );
        assert!(matches!(result, Err(ReceiptError::SessionMismatch { .. })));
    }

    #[test]
    fn test_wire_bound_receipt_transcript_mismatch() {
        use crate::freshness::{SessionNonce, TranscriptDigest};

        let set_a = FactSet::from_ids([fact_id_from_json(&json!({"a": 1}))]);
        let set_b = FactSet::from_ids([fact_id_from_json(&json!({"b": 1}))]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();
        let transcript = TranscriptDigest::compute("session", &init_nonce, None, &[], None, None);
        let wrong_transcript =
            TranscriptDigest::compute("session", &resp_nonce, None, &[], None, None);

        let signer = ReceiptSigner::new();
        let receipt = signer.sign_wire_bound(
            "session",
            transcript,
            init_nonce,
            resp_nonce,
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        let verifier = ReceiptVerifier::new();
        let result = verifier.verify_wire_bound_with_bindings(
            &receipt,
            "session",
            &wrong_transcript,
            set_a.root(),
            set_b.root(),
        );
        assert!(matches!(result, Err(ReceiptError::TranscriptMismatch)));
    }

    #[test]
    fn test_wire_bound_receipt_json_roundtrip() {
        use crate::freshness::{SessionNonce, TranscriptDigest};

        let set_a = FactSet::from_ids([fact_id_from_json(&json!({"a": 1}))]);
        let set_b = FactSet::from_ids([fact_id_from_json(&json!({"b": 1}))]);

        let protocol = PsiProtocol::new();
        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();
        let transcript = TranscriptDigest::compute("session", &init_nonce, None, &[], None, None);

        let signer = ReceiptSigner::new();
        let receipt = signer.sign_wire_bound(
            "session",
            transcript,
            init_nonce,
            resp_nonce,
            set_a.root(),
            set_b.root(),
            &result,
            IntersectionMode::Intersection,
        );

        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let parsed: WireBoundReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.session_id, parsed.session_id);
        assert_eq!(receipt.transcript_digest, parsed.transcript_digest);
        assert_eq!(receipt.initiator_nonce, parsed.initiator_nonce);
        assert_eq!(receipt.responder_nonce, parsed.responder_nonce);
        assert_eq!(receipt.signature, parsed.signature);
    }
}
