//! Wire protocol codec for network-based PSI exchange.
//!
//! Defines JSON-serializable message types for the multi-round DH-PSI protocol:
//! - `MaskedSetOffer`: Party sends their masked set to initiate exchange
//! - `MaskedSetReply`: Receiving party responds with their masked set + doubly-masked received set
//! - `IntersectionReveal`: Optional final reveal (for intersection mode only)
//!
//! Each message type has a domain-separated tag for unambiguous parsing.

use crate::protocol::MaskedElement;
use serde::{Deserialize, Serialize};

/// Domain separation tags for wire messages.
pub mod tags {
    /// Tag for MaskedSetOffer messages.
    pub const MASKED_SET_OFFER: &str = "BlindOverlap:MaskedSetOffer:v1";
    /// Tag for MaskedSetReply messages.
    pub const MASKED_SET_REPLY: &str = "BlindOverlap:MaskedSetReply:v1";
    /// Tag for IntersectionReveal messages.
    pub const INTERSECTION_REVEAL: &str = "BlindOverlap:IntersectionReveal:v1";
}

/// First message: initiator sends their masked set.
///
/// Contains the initiator's elements, each masked with their secret scalar.
/// The recipient will apply their secret to these elements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaskedSetOffer {
    /// Protocol version.
    pub version: u8,
    /// Domain-separated message tag.
    pub tag: String,
    /// Session identifier for correlating messages.
    pub session_id: String,
    /// Masked elements (hex-encoded 32-byte values).
    #[serde(with = "hex_vec")]
    pub masked_elements: Vec<MaskedElement>,
}

impl MaskedSetOffer {
    /// Create a new MaskedSetOffer.
    pub fn new(session_id: impl Into<String>, masked_elements: Vec<MaskedElement>) -> Self {
        Self {
            version: 1,
            tag: tags::MASKED_SET_OFFER.to_string(),
            session_id: session_id.into(),
            masked_elements,
        }
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.tag != tags::MASKED_SET_OFFER {
            return Err(WireError::InvalidTag {
                expected: tags::MASKED_SET_OFFER.to_string(),
                got: self.tag.clone(),
            });
        }
        if self.version != 1 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

/// Second message: responder sends their masked set plus doubly-masked initiator elements.
///
/// Contains:
/// - The responder's own elements masked with their secret
/// - The initiator's elements after being masked by the responder's secret
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaskedSetReply {
    /// Protocol version.
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
}

impl MaskedSetReply {
    /// Create a new MaskedSetReply.
    pub fn new(
        session_id: impl Into<String>,
        responder_masked: Vec<MaskedElement>,
        initiator_doubly_masked: Vec<MaskedElement>,
    ) -> Self {
        Self {
            version: 1,
            tag: tags::MASKED_SET_REPLY.to_string(),
            session_id: session_id.into(),
            responder_masked,
            initiator_doubly_masked,
        }
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.tag != tags::MASKED_SET_REPLY {
            return Err(WireError::InvalidTag {
                expected: tags::MASKED_SET_REPLY.to_string(),
                got: self.tag.clone(),
            });
        }
        if self.version != 1 {
            return Err(WireError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

/// Third message (optional): initiator reveals doubly-masked responder elements.
///
/// Sent only in intersection mode. Allows responder to also learn the intersection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntersectionReveal {
    /// Protocol version.
    pub version: u8,
    /// Domain-separated message tag.
    pub tag: String,
    /// Session identifier.
    pub session_id: String,
    /// Responder's elements after initiator applied their mask (hex-encoded).
    #[serde(with = "hex_vec")]
    pub responder_doubly_masked: Vec<MaskedElement>,
}

impl IntersectionReveal {
    /// Create a new IntersectionReveal.
    pub fn new(session_id: impl Into<String>, responder_doubly_masked: Vec<MaskedElement>) -> Self {
        Self {
            version: 1,
            tag: tags::INTERSECTION_REVEAL.to_string(),
            session_id: session_id.into(),
            responder_doubly_masked,
        }
    }

    /// Validate message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.tag != tags::INTERSECTION_REVEAL {
            return Err(WireError::InvalidTag {
                expected: tags::INTERSECTION_REVEAL.to_string(),
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
}

impl WireMessage {
    /// Get the session ID from any message type.
    pub fn session_id(&self) -> &str {
        match self {
            WireMessage::Offer(m) => &m.session_id,
            WireMessage::Reply(m) => &m.session_id,
            WireMessage::Reveal(m) => &m.session_id,
        }
    }

    /// Validate the message structure.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            WireMessage::Offer(m) => m.validate(),
            WireMessage::Reply(m) => m.validate(),
            WireMessage::Reveal(m) => m.validate(),
        }
    }
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

        let reply =
            WireMessage::Reply(MaskedSetReply::new("reply-session", vec![], vec![]));
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
        assert_eq!(parsed["tag"], tags::MASKED_SET_OFFER);
        assert!(parsed["masked_elements"].is_array());
    }
}
