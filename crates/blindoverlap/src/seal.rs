//! Sealed session records for audit and export.
//!
//! A `SealedSessionRecord` is a JSON export of a completed (or in-progress)
//! online PSI session for audit purposes. It captures session metadata,
//! wire messages, and optionally a transcript digest and Ed25519 seal.
//!
//! ## Security Note
//!
//! **Sealed records are an audit aid only.**
//!
//! - They do NOT claim stronger PSI security
//! - They provide a tamper-evident record of what happened
//! - A sealed record can prove a session occurred as recorded
//! - It does NOT prove parties followed the protocol correctly
//!
//! ## Domain Separation
//!
//! Records are integrity-protected via a domain-separated hash commitment.
//! Optional Ed25519 seals use the `BlindOverlap:SealedRecord:v1` tag.

use crate::freshness::{current_unix_time, SessionNonce, TranscriptDigest};
use crate::identity::{IdentityError, PartyIdentity, PublicIdentity};
use crate::protocol::MaskedElement;
use crate::receipt::WireBoundReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separation tag for sealed record signatures.
pub const SEALED_RECORD_DOMAIN: &[u8] = b"BlindOverlap:SealedRecord:v1";

/// Errors that can occur during seal operations.
#[derive(Debug, Error)]
pub enum SealError {
    /// Record integrity check failed.
    #[error("integrity check failed: computed {computed}, expected {expected}")]
    IntegrityFailed {
        /// Computed digest (hex).
        computed: String,
        /// Expected digest (hex).
        expected: String,
    },
    /// Seal signature verification failed.
    #[error("seal verification failed")]
    SealVerificationFailed,
    /// Signer mismatch.
    #[error("signer mismatch: expected {expected}, got {got}")]
    SignerMismatch {
        /// Expected signer (hex).
        expected: String,
        /// Actual signer (hex).
        got: String,
    },
    /// Missing seal when verification requires it.
    #[error("record is not sealed (no signature)")]
    NotSealed,
    /// Missing data required for operation.
    #[error("missing required data: {0}")]
    MissingData(String),
    /// Identity error.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A wire message entry in the session record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireMessageEntry {
    /// Sequence number (0-indexed).
    pub sequence: u32,
    /// Message direction.
    pub direction: MessageDirection,
    /// Message type (offer, reply, reveal).
    pub message_type: String,
    /// Unix timestamp when message was recorded.
    pub timestamp: u64,
    /// Message size in bytes (JSON length).
    pub size_bytes: usize,
    /// SHA-256 hash of the message JSON.
    #[serde(with = "hex_bytes")]
    pub message_hash: [u8; 32],
    /// Optional: full message content (can be omitted for compact records).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Direction of a wire message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    /// Message sent by local party.
    Sent,
    /// Message received from peer.
    Received,
}

/// Session status at time of export.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session is still in progress.
    #[default]
    InProgress,
    /// Session completed successfully.
    Completed,
    /// Session failed (protocol error, validation failure).
    Failed,
    /// Session was explicitly aborted by a party.
    Aborted,
}

/// A sealed session record for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSessionRecord {
    /// Record format version.
    pub version: u8,
    /// Session identifier.
    pub session_id: String,
    /// Protocol version used (1 or 2).
    pub protocol_version: u8,
    /// Session status at export time.
    pub status: SessionStatus,
    /// Unix timestamp when session started.
    pub started_at: u64,
    /// Unix timestamp when record was exported.
    pub exported_at: u64,
    /// Local party's public identity (if bound).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_pubkey: Option<PublicIdentity>,
    /// Peer's public identity (if bound).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_pubkey: Option<PublicIdentity>,
    /// Ordered wire message entries.
    pub messages: Vec<WireMessageEntry>,
    /// Transcript digest (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_digest: Option<TranscriptDigest>,
    /// Initiator nonce (if v2 protocol).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_nonce: Option<SessionNonce>,
    /// Responder nonce (if v2 protocol).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_nonce: Option<SessionNonce>,
    /// Optional wire-bound receipt (if session issued one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<WireBoundReceipt>,
    /// Record body digest for integrity (hash of canonical body).
    #[serde(with = "hex_bytes")]
    pub body_digest: [u8; 32],
    /// Optional Ed25519 seal by local identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<RecordSeal>,
}

/// Ed25519 seal over the record body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordSeal {
    /// Public key of the sealer.
    pub sealer_pubkey: PublicIdentity,
    /// Unix timestamp when sealed.
    pub sealed_at: u64,
    /// Signature over (DOMAIN || body_digest).
    #[serde(with = "hex_signature")]
    pub signature: [u8; 64],
}

/// Builder for creating sealed session records.
#[derive(Debug, Default)]
pub struct SealedSessionBuilder {
    session_id: Option<String>,
    protocol_version: u8,
    status: SessionStatus,
    started_at: Option<u64>,
    local_pubkey: Option<PublicIdentity>,
    peer_pubkey: Option<PublicIdentity>,
    messages: Vec<WireMessageEntry>,
    initiator_nonce: Option<SessionNonce>,
    responder_nonce: Option<SessionNonce>,
    receipt: Option<WireBoundReceipt>,
}

impl SealedSessionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            protocol_version: 2,
            status: SessionStatus::InProgress,
            ..Default::default()
        }
    }

    /// Set the session ID.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the protocol version.
    pub fn protocol_version(mut self, version: u8) -> Self {
        self.protocol_version = version;
        self
    }

    /// Set the session status.
    pub fn status(mut self, status: SessionStatus) -> Self {
        self.status = status;
        self
    }

    /// Set the start timestamp.
    pub fn started_at(mut self, ts: u64) -> Self {
        self.started_at = Some(ts);
        self
    }

    /// Set the local identity.
    pub fn local_pubkey(mut self, pubkey: PublicIdentity) -> Self {
        self.local_pubkey = Some(pubkey);
        self
    }

    /// Set the peer identity.
    pub fn peer_pubkey(mut self, pubkey: PublicIdentity) -> Self {
        self.peer_pubkey = Some(pubkey);
        self
    }

    /// Set the initiator nonce.
    pub fn initiator_nonce(mut self, nonce: SessionNonce) -> Self {
        self.initiator_nonce = Some(nonce);
        self
    }

    /// Set the responder nonce.
    pub fn responder_nonce(mut self, nonce: SessionNonce) -> Self {
        self.responder_nonce = Some(nonce);
        self
    }

    /// Attach a wire-bound receipt.
    pub fn receipt(mut self, receipt: WireBoundReceipt) -> Self {
        self.receipt = Some(receipt);
        self
    }

    /// Add a sent message entry.
    pub fn add_sent_message(mut self, message_type: &str, json: &str) -> Self {
        let entry = create_message_entry(
            self.messages.len() as u32,
            MessageDirection::Sent,
            message_type,
            json,
            true,
        );
        self.messages.push(entry);
        self
    }

    /// Add a received message entry.
    pub fn add_received_message(mut self, message_type: &str, json: &str) -> Self {
        let entry = create_message_entry(
            self.messages.len() as u32,
            MessageDirection::Received,
            message_type,
            json,
            true,
        );
        self.messages.push(entry);
        self
    }

    /// Add a message entry (hash only, no content).
    pub fn add_message_hash(
        mut self,
        direction: MessageDirection,
        message_type: &str,
        json: &str,
    ) -> Self {
        let entry = create_message_entry(
            self.messages.len() as u32,
            direction,
            message_type,
            json,
            false,
        );
        self.messages.push(entry);
        self
    }

    /// Build the sealed record (unsigned).
    pub fn build(self) -> Result<SealedSessionRecord, SealError> {
        let session_id = self
            .session_id
            .ok_or_else(|| SealError::MissingData("session_id".to_string()))?;

        let started_at = self.started_at.unwrap_or_else(current_unix_time);
        let exported_at = current_unix_time();

        let transcript_digest = compute_transcript_digest(
            &session_id,
            self.initiator_nonce.as_ref(),
            self.responder_nonce.as_ref(),
            &self.messages,
        );

        let body_digest = compute_body_digest(
            &session_id,
            self.protocol_version,
            self.status,
            started_at,
            self.local_pubkey.as_ref(),
            self.peer_pubkey.as_ref(),
            &self.messages,
            transcript_digest.as_ref(),
        );

        Ok(SealedSessionRecord {
            version: 1,
            session_id,
            protocol_version: self.protocol_version,
            status: self.status,
            started_at,
            exported_at,
            local_pubkey: self.local_pubkey,
            peer_pubkey: self.peer_pubkey,
            messages: self.messages,
            transcript_digest,
            initiator_nonce: self.initiator_nonce,
            responder_nonce: self.responder_nonce,
            receipt: self.receipt,
            body_digest,
            seal: None,
        })
    }

    /// Build and seal the record with the given identity.
    pub fn build_sealed(self, identity: &PartyIdentity) -> Result<SealedSessionRecord, SealError> {
        let mut record = self.build()?;
        record.seal(identity)?;
        Ok(record)
    }
}

impl SealedSessionRecord {
    /// Create a new builder.
    pub fn builder() -> SealedSessionBuilder {
        SealedSessionBuilder::new()
    }

    /// Seal the record with the given identity.
    pub fn seal(&mut self, identity: &PartyIdentity) -> Result<(), SealError> {
        let payload = self.seal_payload();
        let signature = identity.sign(&payload);
        let sealed_at = current_unix_time();

        self.seal = Some(RecordSeal {
            sealer_pubkey: identity.public(),
            sealed_at,
            signature,
        });

        Ok(())
    }

    /// Verify the record's body digest.
    pub fn verify_integrity(&self) -> Result<(), SealError> {
        let computed = compute_body_digest(
            &self.session_id,
            self.protocol_version,
            self.status,
            self.started_at,
            self.local_pubkey.as_ref(),
            self.peer_pubkey.as_ref(),
            &self.messages,
            self.transcript_digest.as_ref(),
        );

        if computed != self.body_digest {
            return Err(SealError::IntegrityFailed {
                computed: hex::encode(computed),
                expected: hex::encode(self.body_digest),
            });
        }

        Ok(())
    }

    /// Verify the record's seal signature.
    pub fn verify_seal(&self) -> Result<(), SealError> {
        let seal = self.seal.as_ref().ok_or(SealError::NotSealed)?;

        self.verify_integrity()?;

        let payload = self.seal_payload();
        seal.sealer_pubkey
            .verify(&payload, &seal.signature)
            .map_err(|_| SealError::SealVerificationFailed)?;

        Ok(())
    }

    /// Verify the seal was made by the expected signer.
    pub fn verify_seal_from(&self, expected_signer: &PublicIdentity) -> Result<(), SealError> {
        let seal = self.seal.as_ref().ok_or(SealError::NotSealed)?;

        if &seal.sealer_pubkey != expected_signer {
            return Err(SealError::SignerMismatch {
                expected: expected_signer.to_hex(),
                got: seal.sealer_pubkey.to_hex(),
            });
        }

        self.verify_seal()
    }

    /// Check if the record is sealed.
    pub fn is_sealed(&self) -> bool {
        self.seal.is_some()
    }

    /// Get the sealer's public key, if sealed.
    pub fn sealer(&self) -> Option<&PublicIdentity> {
        self.seal.as_ref().map(|s| &s.sealer_pubkey)
    }

    /// Compute the record ID (hash of body_digest).
    pub fn record_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.body_digest);
        hasher.finalize().into()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, SealError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, SealError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    pub fn from_json(json: &str) -> Result<Self, SealError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load from file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, SealError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Save to file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), SealError> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn seal_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(SEALED_RECORD_DOMAIN);
        payload.extend_from_slice(&self.body_digest);
        payload
    }
}

fn create_message_entry(
    sequence: u32,
    direction: MessageDirection,
    message_type: &str,
    json: &str,
    include_content: bool,
) -> WireMessageEntry {
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let message_hash: [u8; 32] = hasher.finalize().into();

    WireMessageEntry {
        sequence,
        direction,
        message_type: message_type.to_string(),
        timestamp: current_unix_time(),
        size_bytes: json.len(),
        message_hash,
        content: if include_content {
            Some(json.to_string())
        } else {
            None
        },
    }
}

fn compute_transcript_digest(
    session_id: &str,
    initiator_nonce: Option<&SessionNonce>,
    responder_nonce: Option<&SessionNonce>,
    messages: &[WireMessageEntry],
) -> Option<TranscriptDigest> {
    let init_nonce = initiator_nonce?;

    // Extract masked elements from message hashes for transcript computation
    // This is a simplified version; in practice we'd use actual wire data
    let dummy_elements: Vec<MaskedElement> = messages.iter().map(|m| m.message_hash).collect();

    Some(TranscriptDigest::compute(
        session_id,
        init_nonce,
        responder_nonce,
        &dummy_elements,
        None,
        None,
    ))
}

#[allow(clippy::too_many_arguments)]
fn compute_body_digest(
    session_id: &str,
    protocol_version: u8,
    status: SessionStatus,
    started_at: u64,
    local_pubkey: Option<&PublicIdentity>,
    peer_pubkey: Option<&PublicIdentity>,
    messages: &[WireMessageEntry],
    transcript_digest: Option<&TranscriptDigest>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(SEALED_RECORD_DOMAIN);
    hasher.update(session_id.as_bytes());
    hasher.update([protocol_version]);
    hasher.update([status_byte(status)]);
    hasher.update(started_at.to_le_bytes());

    if let Some(pk) = local_pubkey {
        hasher.update([1]);
        hasher.update(pk.as_bytes());
    } else {
        hasher.update([0]);
    }

    if let Some(pk) = peer_pubkey {
        hasher.update([1]);
        hasher.update(pk.as_bytes());
    } else {
        hasher.update([0]);
    }

    hasher.update((messages.len() as u32).to_le_bytes());
    for msg in messages {
        hasher.update(msg.sequence.to_le_bytes());
        hasher.update([direction_byte(msg.direction)]);
        hasher.update(msg.message_hash);
    }

    if let Some(td) = transcript_digest {
        hasher.update([1]);
        hasher.update(td.as_bytes());
    } else {
        hasher.update([0]);
    }

    hasher.finalize().into()
}

fn status_byte(status: SessionStatus) -> u8 {
    match status {
        SessionStatus::InProgress => 0,
        SessionStatus::Completed => 1,
        SessionStatus::Failed => 2,
        SessionStatus::Aborted => 3,
    }
}

fn direction_byte(direction: MessageDirection) -> u8 {
    match direction {
        MessageDirection::Sent => 0,
        MessageDirection::Received => 1,
    }
}

mod hex_bytes {
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

    #[test]
    fn test_build_unsigned_record() {
        let record = SealedSessionRecord::builder()
            .session_id("test-session")
            .protocol_version(2)
            .status(SessionStatus::Completed)
            .add_sent_message("offer", r#"{"type":"offer"}"#)
            .add_received_message("reply", r#"{"type":"reply"}"#)
            .build()
            .unwrap();

        assert_eq!(record.session_id, "test-session");
        assert_eq!(record.messages.len(), 2);
        assert!(!record.is_sealed());
    }

    #[test]
    fn test_build_and_seal_record() {
        let identity = PartyIdentity::generate();

        let record = SealedSessionRecord::builder()
            .session_id("sealed-session")
            .local_pubkey(identity.public())
            .build_sealed(&identity)
            .unwrap();

        assert!(record.is_sealed());
        assert_eq!(record.sealer(), Some(&identity.public()));
        assert!(record.verify_seal().is_ok());
    }

    #[test]
    fn test_verify_integrity() {
        let record = SealedSessionRecord::builder()
            .session_id("integrity-test")
            .add_sent_message("offer", r#"{"data":"test"}"#)
            .build()
            .unwrap();

        assert!(record.verify_integrity().is_ok());
    }

    #[test]
    fn test_tampered_record_fails_integrity() {
        let mut record = SealedSessionRecord::builder()
            .session_id("tamper-test")
            .build()
            .unwrap();

        record.session_id = "different-session".to_string();

        assert!(record.verify_integrity().is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        let identity = PartyIdentity::generate();

        let record = SealedSessionRecord::builder()
            .session_id("json-test")
            .local_pubkey(identity.public())
            .status(SessionStatus::Completed)
            .add_sent_message("offer", r#"{"type":"offer"}"#)
            .build_sealed(&identity)
            .unwrap();

        let json = record.to_json_pretty().unwrap();
        let parsed = SealedSessionRecord::from_json(&json).unwrap();

        assert_eq!(record.session_id, parsed.session_id);
        assert_eq!(record.body_digest, parsed.body_digest);
        assert!(parsed.verify_seal().is_ok());
    }

    #[test]
    fn test_seal_from_wrong_signer_rejected() {
        let alice = PartyIdentity::generate();
        let bob = PartyIdentity::generate();

        let record = SealedSessionRecord::builder()
            .session_id("signer-test")
            .build_sealed(&alice)
            .unwrap();

        assert!(record.verify_seal().is_ok());
        assert!(record.verify_seal_from(&alice.public()).is_ok());
        assert!(record.verify_seal_from(&bob.public()).is_err());
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let identity = PartyIdentity::generate();

        let mut record = SealedSessionRecord::builder()
            .session_id("sig-test")
            .build_sealed(&identity)
            .unwrap();

        if let Some(ref mut seal) = record.seal {
            seal.signature[0] ^= 0xFF;
        }

        assert!(record.verify_seal().is_err());
    }

    #[test]
    fn test_record_id_uniqueness() {
        let r1 = SealedSessionRecord::builder()
            .session_id("session-1")
            .build()
            .unwrap();

        let r2 = SealedSessionRecord::builder()
            .session_id("session-2")
            .build()
            .unwrap();

        assert_ne!(r1.record_id(), r2.record_id());
    }

    #[test]
    fn test_message_hash_only() {
        let record = SealedSessionRecord::builder()
            .session_id("hash-only")
            .add_message_hash(MessageDirection::Sent, "offer", r#"{"large":"data"}"#)
            .build()
            .unwrap();

        assert!(record.messages[0].content.is_none());
        assert_eq!(record.messages[0].size_bytes, r#"{"large":"data"}"#.len());
    }

    #[test]
    fn test_with_nonces() {
        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();

        let record = SealedSessionRecord::builder()
            .session_id("nonce-test")
            .initiator_nonce(init_nonce)
            .responder_nonce(resp_nonce)
            .build()
            .unwrap();

        assert!(record.initiator_nonce.is_some());
        assert!(record.responder_nonce.is_some());
        assert!(record.transcript_digest.is_some());
    }

    #[test]
    fn test_with_identities() {
        let local = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let record = SealedSessionRecord::builder()
            .session_id("identity-test")
            .local_pubkey(local.public())
            .peer_pubkey(peer.public())
            .build()
            .unwrap();

        assert_eq!(record.local_pubkey, Some(local.public()));
        assert_eq!(record.peer_pubkey, Some(peer.public()));
    }
}
