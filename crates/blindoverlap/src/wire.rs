//! Wire protocol codec for network-based PSI exchange.
//!
//! Defines JSON-serializable message types for the multi-round DH-PSI protocol:
//! - `MaskedSetOffer`: Party sends their masked set to initiate exchange
//! - `MaskedSetReply`: Receiving party responds with their masked set + doubly-masked received set
//! - `IntersectionReveal`: Optional final reveal (for intersection mode only)
//!
//! Each message type has a domain-separated tag for unambiguous parsing.
//!
//! ## Protocol Versions
//!
//! - **v1**: Basic wire protocol (v0.1.0-v0.2.0)
//! - **v2**: Adds freshness fields for replay protection (v0.3.0+)
//!   - `nonce`: Cryptographic nonce for session binding
//!   - `issued_at`: Unix timestamp when message was created
//!   - `expires_at`: Unix timestamp when message expires

use crate::freshness::{SessionDeadline, SessionNonce};
use crate::identity::{IdentityError, PartyIdentity, PublicIdentity};
use crate::protocol::MaskedElement;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation tags for wire messages.
pub mod tags {
    /// Tag for MaskedSetOffer messages (v1, legacy).
    pub const MASKED_SET_OFFER_V1: &str = "BlindOverlap:MaskedSetOffer:v1";
    /// Tag for MaskedSetReply messages (v1, legacy).
    pub const MASKED_SET_REPLY_V1: &str = "BlindOverlap:MaskedSetReply:v1";
    /// Tag for IntersectionReveal messages (v1, legacy).
    pub const INTERSECTION_REVEAL_V1: &str = "BlindOverlap:IntersectionReveal:v1";

    /// Tag for MaskedSetOffer messages (v2, with freshness).
    pub const MASKED_SET_OFFER_V2: &str = "BlindOverlap:MaskedSetOffer:v2";
    /// Tag for MaskedSetReply messages (v2, with freshness).
    pub const MASKED_SET_REPLY_V2: &str = "BlindOverlap:MaskedSetReply:v2";
    /// Tag for IntersectionReveal messages (v2, with freshness).
    pub const INTERSECTION_REVEAL_V2: &str = "BlindOverlap:IntersectionReveal:v2";

    /// Tag for MaskedSetOffer messages (v3, signed).
    pub const MASKED_SET_OFFER_V3: &str = "BlindOverlap:MaskedSetOffer:v3";
    /// Tag for MaskedSetReply messages (v3, signed).
    pub const MASKED_SET_REPLY_V3: &str = "BlindOverlap:MaskedSetReply:v3";
    /// Tag for IntersectionReveal messages (v3, signed).
    pub const INTERSECTION_REVEAL_V3: &str = "BlindOverlap:IntersectionReveal:v3";

    /// Tag for AbortMessage messages (v1).
    pub const ABORT_MESSAGE_V1: &str = "BlindOverlap:AbortMessage:v1";

    /// Current default tag for MaskedSetOffer (v2).
    pub const MASKED_SET_OFFER: &str = MASKED_SET_OFFER_V2;
    /// Current default tag for MaskedSetReply (v2).
    pub const MASKED_SET_REPLY: &str = MASKED_SET_REPLY_V2;
    /// Current default tag for IntersectionReveal (v2).
    pub const INTERSECTION_REVEAL: &str = INTERSECTION_REVEAL_V2;
    /// Current default tag for AbortMessage (v1).
    pub const ABORT_MESSAGE: &str = ABORT_MESSAGE_V1;

    /// Domain tag for signed wire messages.
    pub const SIGNED_MESSAGE_DOMAIN: &str = "BlindOverlap:SignedWireMessage:v1";
}

/// First message: initiator sends their masked set.
///
/// Contains the initiator's elements, each masked with their secret scalar.
/// The recipient will apply their secret to these elements.
///
/// ## Protocol Versions
/// - v1: Basic fields (version, tag, session_id, masked_elements)
/// - v2: Adds freshness fields (nonce, issued_at, expires_at)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaskedSetOffer {
    /// Protocol version (1 or 2).
    pub version: u8,
    /// Domain-separated message tag.
    pub tag: String,
    /// Session identifier for correlating messages.
    pub session_id: String,
    /// Masked elements (hex-encoded 32-byte values).
    #[serde(with = "hex_vec")]
    pub masked_elements: Vec<MaskedElement>,
    /// Initiator's nonce for session binding (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<SessionNonce>,
    /// Unix timestamp when offer was created (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    /// Unix timestamp when offer expires (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl MaskedSetOffer {
    /// Create a new v1 MaskedSetOffer (legacy, no freshness).
    pub fn new(session_id: impl Into<String>, masked_elements: Vec<MaskedElement>) -> Self {
        Self {
            version: 1,
            tag: tags::MASKED_SET_OFFER_V1.to_string(),
            session_id: session_id.into(),
            masked_elements,
            nonce: None,
            issued_at: None,
            expires_at: None,
        }
    }

    /// Create a new v2 MaskedSetOffer with freshness fields.
    pub fn new_v2(
        session_id: impl Into<String>,
        masked_elements: Vec<MaskedElement>,
        nonce: SessionNonce,
        deadline: SessionDeadline,
    ) -> Self {
        Self {
            version: 2,
            tag: tags::MASKED_SET_OFFER_V2.to_string(),
            session_id: session_id.into(),
            masked_elements,
            nonce: Some(nonce),
            issued_at: Some(deadline.issued_at),
            expires_at: Some(deadline.expires_at),
        }
    }

    /// Get the deadline if freshness fields are present.
    pub fn deadline(&self) -> Option<SessionDeadline> {
        match (self.issued_at, self.expires_at) {
            (Some(issued), Some(expires)) => {
                Some(SessionDeadline::from_timestamps(issued, expires))
            }
            _ => None,
        }
    }

    /// Check if this is a v2 message with freshness fields.
    pub fn has_freshness(&self) -> bool {
        self.version >= 2
            && self.nonce.is_some()
            && self.issued_at.is_some()
            && self.expires_at.is_some()
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        let valid_tags = [tags::MASKED_SET_OFFER_V1, tags::MASKED_SET_OFFER_V2];
        if !valid_tags.contains(&self.tag.as_str()) {
            return Err(WireError::InvalidTag {
                expected: tags::MASKED_SET_OFFER.to_string(),
                got: self.tag.clone(),
            });
        }
        if self.version < 1 || self.version > 2 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        if self.version == 2 {
            if self.nonce.is_none() {
                return Err(WireError::MissingFreshness("nonce".to_string()));
            }
            if self.issued_at.is_none() {
                return Err(WireError::MissingFreshness("issued_at".to_string()));
            }
            if self.expires_at.is_none() {
                return Err(WireError::MissingFreshness("expires_at".to_string()));
            }
        }
        Ok(())
    }
}

/// Second message: responder sends their masked set plus doubly-masked initiator elements.
///
/// Contains:
/// - The responder's own elements masked with their secret
/// - The initiator's elements after being masked by the responder's secret
///
/// ## Protocol Versions
/// - v1: Basic fields
/// - v2: Adds freshness fields (initiator_nonce echo, responder_nonce, timestamps)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaskedSetReply {
    /// Protocol version (1 or 2).
    pub version: u8,
    /// Domain-separated message tag.
    pub tag: String,
    /// Session identifier (must match the offer).
    pub session_id: String,
    /// Responder's masked elements (hex-encoded).
    #[serde(with = "hex_vec")]
    pub responder_masked: Vec<MaskedElement>,
    /// Initiator's elements after responder applied their mask (hex-encoded).
    #[serde(with = "hex_vec")]
    pub initiator_doubly_masked: Vec<MaskedElement>,
    /// Initiator's nonce echoed back (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_nonce: Option<SessionNonce>,
    /// Responder's own nonce for binding (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_nonce: Option<SessionNonce>,
    /// Unix timestamp when reply was created (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    /// Unix timestamp when reply expires (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl MaskedSetReply {
    /// Create a new v1 MaskedSetReply (legacy, no freshness).
    pub fn new(
        session_id: impl Into<String>,
        responder_masked: Vec<MaskedElement>,
        initiator_doubly_masked: Vec<MaskedElement>,
    ) -> Self {
        Self {
            version: 1,
            tag: tags::MASKED_SET_REPLY_V1.to_string(),
            session_id: session_id.into(),
            responder_masked,
            initiator_doubly_masked,
            initiator_nonce: None,
            responder_nonce: None,
            issued_at: None,
            expires_at: None,
        }
    }

    /// Create a new v2 MaskedSetReply with freshness fields.
    pub fn new_v2(
        session_id: impl Into<String>,
        responder_masked: Vec<MaskedElement>,
        initiator_doubly_masked: Vec<MaskedElement>,
        initiator_nonce: SessionNonce,
        responder_nonce: SessionNonce,
        deadline: SessionDeadline,
    ) -> Self {
        Self {
            version: 2,
            tag: tags::MASKED_SET_REPLY_V2.to_string(),
            session_id: session_id.into(),
            responder_masked,
            initiator_doubly_masked,
            initiator_nonce: Some(initiator_nonce),
            responder_nonce: Some(responder_nonce),
            issued_at: Some(deadline.issued_at),
            expires_at: Some(deadline.expires_at),
        }
    }

    /// Get the deadline if freshness fields are present.
    pub fn deadline(&self) -> Option<SessionDeadline> {
        match (self.issued_at, self.expires_at) {
            (Some(issued), Some(expires)) => {
                Some(SessionDeadline::from_timestamps(issued, expires))
            }
            _ => None,
        }
    }

    /// Check if this is a v2 message with freshness fields.
    pub fn has_freshness(&self) -> bool {
        self.version >= 2
            && self.initiator_nonce.is_some()
            && self.responder_nonce.is_some()
            && self.issued_at.is_some()
            && self.expires_at.is_some()
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        let valid_tags = [tags::MASKED_SET_REPLY_V1, tags::MASKED_SET_REPLY_V2];
        if !valid_tags.contains(&self.tag.as_str()) {
            return Err(WireError::InvalidTag {
                expected: tags::MASKED_SET_REPLY.to_string(),
                got: self.tag.clone(),
            });
        }
        if self.version < 1 || self.version > 2 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        if self.version == 2 {
            if self.initiator_nonce.is_none() {
                return Err(WireError::MissingFreshness("initiator_nonce".to_string()));
            }
            if self.responder_nonce.is_none() {
                return Err(WireError::MissingFreshness("responder_nonce".to_string()));
            }
            if self.issued_at.is_none() {
                return Err(WireError::MissingFreshness("issued_at".to_string()));
            }
            if self.expires_at.is_none() {
                return Err(WireError::MissingFreshness("expires_at".to_string()));
            }
        }
        Ok(())
    }
}

/// Third message (optional): initiator reveals doubly-masked responder elements.
///
/// Sent only in intersection mode. Allows responder to also learn the intersection.
///
/// ## Protocol Versions
/// - v1: Basic fields
/// - v2: Adds freshness fields (nonces, timestamps)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntersectionReveal {
    /// Protocol version (1 or 2).
    pub version: u8,
    /// Domain-separated message tag.
    pub tag: String,
    /// Session identifier.
    pub session_id: String,
    /// Responder's elements after initiator applied their mask (hex-encoded).
    #[serde(with = "hex_vec")]
    pub responder_doubly_masked: Vec<MaskedElement>,
    /// Initiator's nonce (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_nonce: Option<SessionNonce>,
    /// Responder's nonce echoed back (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_nonce: Option<SessionNonce>,
    /// Unix timestamp when reveal was created (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    /// Unix timestamp when reveal expires (v2+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl IntersectionReveal {
    /// Create a new v1 IntersectionReveal (legacy, no freshness).
    pub fn new(session_id: impl Into<String>, responder_doubly_masked: Vec<MaskedElement>) -> Self {
        Self {
            version: 1,
            tag: tags::INTERSECTION_REVEAL_V1.to_string(),
            session_id: session_id.into(),
            responder_doubly_masked,
            initiator_nonce: None,
            responder_nonce: None,
            issued_at: None,
            expires_at: None,
        }
    }

    /// Create a new v2 IntersectionReveal with freshness fields.
    pub fn new_v2(
        session_id: impl Into<String>,
        responder_doubly_masked: Vec<MaskedElement>,
        initiator_nonce: SessionNonce,
        responder_nonce: SessionNonce,
        deadline: SessionDeadline,
    ) -> Self {
        Self {
            version: 2,
            tag: tags::INTERSECTION_REVEAL_V2.to_string(),
            session_id: session_id.into(),
            responder_doubly_masked,
            initiator_nonce: Some(initiator_nonce),
            responder_nonce: Some(responder_nonce),
            issued_at: Some(deadline.issued_at),
            expires_at: Some(deadline.expires_at),
        }
    }

    /// Get the deadline if freshness fields are present.
    pub fn deadline(&self) -> Option<SessionDeadline> {
        match (self.issued_at, self.expires_at) {
            (Some(issued), Some(expires)) => {
                Some(SessionDeadline::from_timestamps(issued, expires))
            }
            _ => None,
        }
    }

    /// Check if this is a v2 message with freshness fields.
    pub fn has_freshness(&self) -> bool {
        self.version >= 2
            && self.initiator_nonce.is_some()
            && self.responder_nonce.is_some()
            && self.issued_at.is_some()
            && self.expires_at.is_some()
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        let valid_tags = [tags::INTERSECTION_REVEAL_V1, tags::INTERSECTION_REVEAL_V2];
        if !valid_tags.contains(&self.tag.as_str()) {
            return Err(WireError::InvalidTag {
                expected: tags::INTERSECTION_REVEAL.to_string(),
                got: self.tag.clone(),
            });
        }
        if self.version < 1 || self.version > 2 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        if self.version == 2 {
            if self.initiator_nonce.is_none() {
                return Err(WireError::MissingFreshness("initiator_nonce".to_string()));
            }
            if self.responder_nonce.is_none() {
                return Err(WireError::MissingFreshness("responder_nonce".to_string()));
            }
            if self.issued_at.is_none() {
                return Err(WireError::MissingFreshness("issued_at".to_string()));
            }
            if self.expires_at.is_none() {
                return Err(WireError::MissingFreshness("expires_at".to_string()));
            }
        }
        Ok(())
    }
}

/// Abort message for mid-protocol cancellation (v0.6.0+).
///
/// Allows a party to signal session abort with a reason code.
/// This is a wire message variant, not a signed receipt.
/// For signed abort records, use `AbortReceipt` from the `abort` module.
///
/// ## Backward Compatibility
///
/// Older peers (pre-v0.6.0) may reject unknown message types.
/// Document this clearly in protocol negotiation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbortMessage {
    /// Protocol version (1).
    pub version: u8,
    /// Domain-separated message tag.
    pub tag: String,
    /// Session identifier.
    pub session_id: String,
    /// Abort reason code.
    pub reason_code: String,
    /// Optional reason text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    /// Unix timestamp when abort was issued.
    pub issued_at: u64,
}

impl AbortMessage {
    /// Create a new abort message.
    pub fn new(session_id: impl Into<String>, reason_code: impl Into<String>) -> Self {
        Self {
            version: 1,
            tag: tags::ABORT_MESSAGE_V1.to_string(),
            session_id: session_id.into(),
            reason_code: reason_code.into(),
            reason_text: None,
            issued_at: crate::freshness::current_unix_time(),
        }
    }

    /// Create an abort message with reason text.
    pub fn with_reason(
        session_id: impl Into<String>,
        reason_code: impl Into<String>,
        reason_text: impl Into<String>,
    ) -> Self {
        Self {
            version: 1,
            tag: tags::ABORT_MESSAGE_V1.to_string(),
            session_id: session_id.into(),
            reason_code: reason_code.into(),
            reason_text: Some(reason_text.into()),
            issued_at: crate::freshness::current_unix_time(),
        }
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.tag != tags::ABORT_MESSAGE_V1 {
            return Err(WireError::InvalidTag {
                expected: tags::ABORT_MESSAGE.to_string(),
                got: self.tag.clone(),
            });
        }
        if self.version != 1 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

/// Envelope type for any wire message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "message_type")]
pub enum WireMessage {
    /// MaskedSetOffer message.
    #[serde(rename = "offer")]
    Offer(MaskedSetOffer),
    /// MaskedSetReply message.
    #[serde(rename = "reply")]
    Reply(MaskedSetReply),
    /// IntersectionReveal message.
    #[serde(rename = "reveal")]
    Reveal(IntersectionReveal),
    /// AbortMessage for mid-protocol cancellation (v0.6.0+).
    #[serde(rename = "abort")]
    Abort(AbortMessage),
}

impl WireMessage {
    /// Get the session ID from any message type.
    pub fn session_id(&self) -> &str {
        match self {
            WireMessage::Offer(m) => &m.session_id,
            WireMessage::Reply(m) => &m.session_id,
            WireMessage::Reveal(m) => &m.session_id,
            WireMessage::Abort(m) => &m.session_id,
        }
    }

    /// Validate the message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            WireMessage::Offer(m) => m.validate(),
            WireMessage::Reply(m) => m.validate(),
            WireMessage::Reveal(m) => m.validate(),
            WireMessage::Abort(m) => m.validate(),
        }
    }

    /// Compute the canonical signing payload for this message.
    ///
    /// The payload includes the session ID, protocol tag, and message body hash
    /// to ensure the signature covers a stable representation.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(256);
        payload.extend_from_slice(tags::SIGNED_MESSAGE_DOMAIN.as_bytes());
        payload.push(0); // null separator
        payload.extend_from_slice(self.session_id().as_bytes());
        payload.push(0); // null separator
        payload.extend_from_slice(self.tag().as_bytes());
        payload.push(0); // null separator
        let body_json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(body_json.as_bytes());
        let body_hash: [u8; 32] = hasher.finalize().into();
        payload.extend_from_slice(&body_hash);
        payload
    }

    /// Get the message tag.
    pub fn tag(&self) -> &str {
        match self {
            WireMessage::Offer(m) => &m.tag,
            WireMessage::Reply(m) => &m.tag,
            WireMessage::Reveal(m) => &m.tag,
            WireMessage::Abort(m) => &m.tag,
        }
    }

    /// Check if this is an abort message.
    pub fn is_abort(&self) -> bool {
        matches!(self, WireMessage::Abort(_))
    }
}

/// A signed wire message envelope.
///
/// Wraps any `WireMessage` with a signer's public key and signature.
/// This provides channel authentication - the recipient can verify
/// the message came from the expected peer.
///
/// ## Backward Compatibility
///
/// - v1/v2 unsigned messages can still be decoded using `decode()`
/// - `SignedWireMessage` is a separate type for explicitly signed messages
/// - When identity is required, use `decode_signed()` which validates signatures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedWireMessage {
    /// Protocol version for signed envelope (1 = initial).
    pub envelope_version: u8,
    /// The inner wire message.
    pub message: WireMessage,
    /// Public key of the signer (hex-encoded).
    pub signer_pubkey: PublicIdentity,
    /// Ed25519 signature over the signing payload (hex-encoded).
    #[serde(with = "hex_signature")]
    pub signature: [u8; 64],
}

impl SignedWireMessage {
    /// Create a signed message from a wire message and identity.
    pub fn sign(message: WireMessage, identity: &PartyIdentity) -> Self {
        let payload = message.signing_payload();
        let signature = identity.sign(&payload);
        Self {
            envelope_version: 1,
            message,
            signer_pubkey: identity.public(),
            signature,
        }
    }

    /// Verify the signature on this message.
    pub fn verify_signature(&self) -> Result<(), WireError> {
        let payload = self.message.signing_payload();
        self.signer_pubkey
            .verify(&payload, &self.signature)
            .map_err(WireError::Identity)
    }

    /// Verify the signature and check the signer matches expected peer.
    pub fn verify_peer(&self, expected_peer: &PublicIdentity) -> Result<(), WireError> {
        if &self.signer_pubkey != expected_peer {
            return Err(WireError::PeerMismatch {
                expected: expected_peer.to_hex(),
                got: self.signer_pubkey.to_hex(),
            });
        }
        self.verify_signature()
    }

    /// Get the session ID from the inner message.
    pub fn session_id(&self) -> &str {
        self.message.session_id()
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

/// Encode a signed wire message to JSON.
pub fn encode_signed(message: &SignedWireMessage) -> Result<String, WireError> {
    Ok(serde_json::to_string(message)?)
}

/// Encode a signed wire message to pretty-printed JSON.
pub fn encode_signed_pretty(message: &SignedWireMessage) -> Result<String, WireError> {
    Ok(serde_json::to_string_pretty(message)?)
}

/// Decode a signed wire message from JSON.
///
/// Validates both the message structure and the signature.
pub fn decode_signed(json: &str) -> Result<SignedWireMessage, WireError> {
    let signed: SignedWireMessage = serde_json::from_str(json)?;
    signed.message.validate()?;
    signed.verify_signature()?;
    Ok(signed)
}

/// Decode a signed wire message and verify it came from the expected peer.
pub fn decode_signed_from_peer(
    json: &str,
    expected_peer: &PublicIdentity,
) -> Result<SignedWireMessage, WireError> {
    let signed = decode_signed(json)?;
    signed.verify_peer(expected_peer)?;
    Ok(signed)
}

/// Errors that can occur during wire encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Invalid message tag.
    #[error("invalid message tag: expected {expected}, got {got}")]
    InvalidTag {
        /// Expected tag.
        expected: String,
        /// Actual tag.
        got: String,
    },
    /// Unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// Missing freshness field in v2 message.
    #[error("missing freshness field for v2 message: {0}")]
    MissingFreshness(String),
    /// Identity error (signature verification failed, invalid key, etc.)
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// Peer public key mismatch.
    #[error("peer mismatch: expected {expected}, got {got}")]
    PeerMismatch {
        /// Expected peer public key (hex).
        expected: String,
        /// Actual peer public key (hex).
        got: String,
    },
    /// Missing signature on message that requires one.
    #[error("missing signature: message requires identity verification")]
    MissingSignature,
}

/// Encode a wire message to JSON.
pub fn encode(message: &WireMessage) -> Result<String, WireError> {
    Ok(serde_json::to_string(message)?)
}

/// Encode a wire message to pretty-printed JSON.
pub fn encode_pretty(message: &WireMessage) -> Result<String, WireError> {
    Ok(serde_json::to_string_pretty(message)?)
}

/// Decode a wire message from JSON.
pub fn decode(json: &str) -> Result<WireMessage, WireError> {
    let message: WireMessage = serde_json::from_str(json)?;
    message.validate()?;
    Ok(message)
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(elements: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(elements.len()))?;
        for elem in elements {
            seq.serialize_element(&hex::encode(elem))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_elements(n: usize) -> Vec<MaskedElement> {
        (0..n)
            .map(|i| {
                let mut elem = [0u8; 32];
                elem[0] = i as u8;
                elem
            })
            .collect()
    }

    #[test]
    fn test_masked_set_offer_roundtrip() {
        let offer = MaskedSetOffer::new("session-123", dummy_elements(3));
        let message = WireMessage::Offer(offer.clone());

        let json = encode(&message).unwrap();
        let decoded = decode(&json).unwrap();

        assert_eq!(WireMessage::Offer(offer), decoded);
    }

    #[test]
    fn test_masked_set_reply_roundtrip() {
        let reply = MaskedSetReply::new("session-456", dummy_elements(2), dummy_elements(4));
        let message = WireMessage::Reply(reply.clone());

        let json = encode(&message).unwrap();
        let decoded = decode(&json).unwrap();

        assert_eq!(WireMessage::Reply(reply), decoded);
    }

    #[test]
    fn test_intersection_reveal_roundtrip() {
        let reveal = IntersectionReveal::new("session-789", dummy_elements(5));
        let message = WireMessage::Reveal(reveal.clone());

        let json = encode(&message).unwrap();
        let decoded = decode(&json).unwrap();

        assert_eq!(WireMessage::Reveal(reveal), decoded);
    }

    #[test]
    fn test_session_id_accessor() {
        let offer = WireMessage::Offer(MaskedSetOffer::new("offer-session", vec![]));
        assert_eq!(offer.session_id(), "offer-session");

        let reply = WireMessage::Reply(MaskedSetReply::new("reply-session", vec![], vec![]));
        assert_eq!(reply.session_id(), "reply-session");

        let reveal = WireMessage::Reveal(IntersectionReveal::new("reveal-session", vec![]));
        assert_eq!(reveal.session_id(), "reveal-session");
    }

    #[test]
    fn test_invalid_tag_rejected() {
        let mut offer = MaskedSetOffer::new("session", vec![]);
        offer.tag = "wrong-tag".to_string();

        let err = offer.validate().unwrap_err();
        assert!(matches!(err, WireError::InvalidTag { .. }));
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let mut offer = MaskedSetOffer::new("session", vec![]);
        offer.version = 99;

        let err = offer.validate().unwrap_err();
        assert!(matches!(err, WireError::UnsupportedVersion(99)));
    }

    #[test]
    fn test_v2_offer_with_freshness() {
        use crate::freshness::{SessionDeadline, SessionNonce};

        let nonce = SessionNonce::generate();
        let deadline = SessionDeadline::new(300);
        let offer = MaskedSetOffer::new_v2("session-v2", dummy_elements(3), nonce, deadline);

        assert_eq!(offer.version, 2);
        assert!(offer.has_freshness());
        assert!(offer.validate().is_ok());

        let message = WireMessage::Offer(offer.clone());
        let json = encode(&message).unwrap();
        let decoded = decode(&json).unwrap();

        if let WireMessage::Offer(decoded_offer) = decoded {
            assert_eq!(decoded_offer.version, 2);
            assert_eq!(decoded_offer.nonce, offer.nonce);
            assert_eq!(decoded_offer.issued_at, offer.issued_at);
            assert_eq!(decoded_offer.expires_at, offer.expires_at);
        } else {
            panic!("expected offer");
        }
    }

    #[test]
    fn test_v2_reply_with_freshness() {
        use crate::freshness::{SessionDeadline, SessionNonce};

        let init_nonce = SessionNonce::generate();
        let resp_nonce = SessionNonce::generate();
        let deadline = SessionDeadline::new(300);
        let reply = MaskedSetReply::new_v2(
            "session-v2",
            dummy_elements(2),
            dummy_elements(3),
            init_nonce,
            resp_nonce,
            deadline,
        );

        assert_eq!(reply.version, 2);
        assert!(reply.has_freshness());
        assert!(reply.validate().is_ok());

        let message = WireMessage::Reply(reply.clone());
        let json = encode(&message).unwrap();
        let decoded = decode(&json).unwrap();

        if let WireMessage::Reply(decoded_reply) = decoded {
            assert_eq!(decoded_reply.version, 2);
            assert_eq!(decoded_reply.initiator_nonce, reply.initiator_nonce);
            assert_eq!(decoded_reply.responder_nonce, reply.responder_nonce);
        } else {
            panic!("expected reply");
        }
    }

    #[test]
    fn test_v2_missing_freshness_rejected() {
        let mut offer = MaskedSetOffer::new("session", vec![]);
        offer.version = 2;
        offer.tag = tags::MASKED_SET_OFFER_V2.to_string();

        let err = offer.validate().unwrap_err();
        assert!(matches!(err, WireError::MissingFreshness(_)));
    }

    #[test]
    fn test_pretty_encoding() {
        let offer = MaskedSetOffer::new("session", dummy_elements(1));
        let message = WireMessage::Offer(offer);

        let pretty = encode_pretty(&message).unwrap();
        assert!(pretty.contains('\n'));

        let decoded = decode(&pretty).unwrap();
        assert_eq!(message, decoded);
    }

    #[test]
    fn test_empty_elements() {
        let offer = MaskedSetOffer::new("empty-session", vec![]);
        let message = WireMessage::Offer(offer.clone());

        let json = encode(&message).unwrap();
        let decoded = decode(&json).unwrap();

        assert_eq!(WireMessage::Offer(offer), decoded);
    }

    #[test]
    fn test_json_structure() {
        let offer = MaskedSetOffer::new("test", dummy_elements(1));
        let message = WireMessage::Offer(offer);

        let json = encode(&message).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["message_type"], "offer");
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["tag"], tags::MASKED_SET_OFFER_V1);
        assert!(parsed["masked_elements"].is_array());
    }

    #[test]
    fn test_signed_message_roundtrip() {
        let identity = PartyIdentity::generate();
        let offer = MaskedSetOffer::new("signed-session", dummy_elements(3));
        let message = WireMessage::Offer(offer);

        let signed = SignedWireMessage::sign(message.clone(), &identity);

        let json = encode_signed(&signed).unwrap();
        let decoded = decode_signed(&json).unwrap();

        assert_eq!(decoded.message, message);
        assert_eq!(decoded.signer_pubkey, identity.public());
    }

    #[test]
    fn test_signed_message_wrong_signature_rejected() {
        let identity = PartyIdentity::generate();
        let offer = MaskedSetOffer::new("test", dummy_elements(1));
        let message = WireMessage::Offer(offer);

        let mut signed = SignedWireMessage::sign(message, &identity);
        signed.signature[0] ^= 0xFF;

        let json = encode_signed(&signed).unwrap();
        let result = decode_signed(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_message_peer_verification() {
        let alice = PartyIdentity::generate();
        let bob = PartyIdentity::generate();

        let offer = MaskedSetOffer::new("test", dummy_elements(1));
        let message = WireMessage::Offer(offer);

        let signed = SignedWireMessage::sign(message, &alice);
        let json = encode_signed(&signed).unwrap();

        assert!(decode_signed_from_peer(&json, &alice.public()).is_ok());
        assert!(decode_signed_from_peer(&json, &bob.public()).is_err());
    }

    #[test]
    fn test_signed_reply_roundtrip() {
        let identity = PartyIdentity::generate();
        let reply = MaskedSetReply::new("signed-reply", dummy_elements(2), dummy_elements(3));
        let message = WireMessage::Reply(reply);

        let signed = SignedWireMessage::sign(message.clone(), &identity);
        assert!(signed.verify_signature().is_ok());

        let json = encode_signed_pretty(&signed).unwrap();
        let decoded = decode_signed(&json).unwrap();

        assert_eq!(decoded.message, message);
    }

    #[test]
    fn test_signing_payload_stability() {
        let offer = MaskedSetOffer::new("stable-session", dummy_elements(2));
        let message = WireMessage::Offer(offer);

        let payload1 = message.signing_payload();
        let payload2 = message.signing_payload();

        assert_eq!(payload1, payload2);
    }

    #[test]
    fn test_different_sessions_different_payloads() {
        let offer1 = MaskedSetOffer::new("session-1", dummy_elements(1));
        let offer2 = MaskedSetOffer::new("session-2", dummy_elements(1));

        let message1 = WireMessage::Offer(offer1);
        let message2 = WireMessage::Offer(offer2);

        assert_ne!(message1.signing_payload(), message2.signing_payload());
    }
}
