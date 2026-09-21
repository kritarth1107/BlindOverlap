//! Invite tickets for bootstrapping channel-bound PSI sessions.
//!
//! An `InviteTicket` is a short-lived signed capability that authenticates
//! who may initiate or join a specific PSI session. The issuer signs the
//! ticket with their Ed25519 identity, binding it to a session ID and
//! optionally to a specific peer.
//!
//! ## Security Note
//!
//! **Invite tickets provide session bootstrapping authentication only.**
//!
//! - They authenticate WHO may start a session
//! - They do NOT upgrade PSI security from semi-honest to malicious
//! - A valid ticket proves the issuer authorized the session
//! - It does NOT prove the peer will follow the protocol correctly
//!
//! ## Domain Separation
//!
//! All signatures use the domain tag `BlindOverlap:InviteTicket:v1` to prevent
//! cross-protocol signature reuse.

use crate::identity::{IdentityError, PartyIdentity, PublicIdentity};
use crate::protocol::IntersectionMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separation tag for invite ticket signatures.
pub const INVITE_TICKET_DOMAIN: &[u8] = b"BlindOverlap:InviteTicket:v1";

/// Default ticket validity duration in seconds (5 minutes).
pub const DEFAULT_TICKET_TTL_SECS: u64 = 300;

/// Errors that can occur during invite ticket operations.
#[derive(Debug, Error)]
pub enum InviteError {
    /// Ticket has expired.
    #[error("ticket expired at {expires_at}, current time is {current_time}")]
    Expired {
        /// When the ticket expired (unix timestamp).
        expires_at: u64,
        /// Current time (unix timestamp).
        current_time: u64,
    },
    /// Ticket is not yet valid.
    #[error("ticket not valid until {issued_at}, current time is {current_time}")]
    NotYetValid {
        /// When the ticket becomes valid (unix timestamp).
        issued_at: u64,
        /// Current time (unix timestamp).
        current_time: u64,
    },
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
    /// Peer mismatch - ticket is for a different peer.
    #[error("peer mismatch: ticket is for {expected}, but {got} is trying to use it")]
    PeerMismatch {
        /// Expected peer public key (hex).
        expected: String,
        /// Actual peer public key (hex).
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
    #[error("mode mismatch: ticket allows {allowed:?}, but {requested:?} was requested")]
    ModeMismatch {
        /// Allowed mode(s).
        allowed: AllowedMode,
        /// Requested mode.
        requested: IntersectionMode,
    },
    /// Identity error (invalid key, etc.)
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Allowed intersection modes for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedMode {
    /// Only intersection mode is allowed.
    Intersection,
    /// Only cardinality mode is allowed.
    Cardinality,
    /// Either mode is allowed.
    Any,
}

impl AllowedMode {
    /// Check if this allowed mode permits the given intersection mode.
    pub fn permits(&self, mode: IntersectionMode) -> bool {
        match self {
            AllowedMode::Intersection => mode == IntersectionMode::Intersection,
            AllowedMode::Cardinality => mode == IntersectionMode::Cardinality,
            AllowedMode::Any => true,
        }
    }
}

impl Default for AllowedMode {
    fn default() -> Self {
        AllowedMode::Any
    }
}

/// A signed invite ticket for bootstrapping a PSI session.
///
/// The issuer creates this ticket and shares it with the intended peer.
/// The peer presents the ticket when starting a session to prove they
/// are authorized by the issuer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteTicket {
    /// Protocol version for invite tickets.
    pub version: u8,
    /// Session ID this ticket authorizes.
    pub session_id: String,
    /// Public key of the ticket issuer.
    pub issuer_pubkey: PublicIdentity,
    /// Optional expected peer public key (if present, only this peer can use the ticket).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_pubkey: Option<PublicIdentity>,
    /// Allowed intersection mode(s).
    pub allowed_mode: AllowedMode,
    /// Unix timestamp when ticket was issued.
    pub issued_at: u64,
    /// Unix timestamp when ticket expires.
    pub expires_at: u64,
    /// Ed25519 signature over the ticket payload.
    #[serde(with = "hex_signature")]
    pub signature: [u8; 64],
}

impl InviteTicket {
    /// Issue a new invite ticket.
    ///
    /// The ticket is signed with the issuer's identity and can optionally
    /// be bound to a specific peer. If `peer_pubkey` is None, anyone who
    /// obtains the ticket can use it.
    pub fn issue(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        peer_pubkey: Option<PublicIdentity>,
        allowed_mode: AllowedMode,
        ttl_secs: u64,
    ) -> Self {
        let session_id = session_id.into();
        let now = crate::freshness::current_unix_time();
        let issued_at = now;
        let expires_at = now + ttl_secs;

        let payload = Self::compute_payload(
            &session_id,
            &issuer.public(),
            peer_pubkey.as_ref(),
            allowed_mode,
            issued_at,
            expires_at,
        );

        let signature = issuer.sign(&payload);

        Self {
            version: 1,
            session_id,
            issuer_pubkey: issuer.public(),
            peer_pubkey,
            allowed_mode,
            issued_at,
            expires_at,
            signature,
        }
    }

    /// Issue a ticket with default TTL (5 minutes).
    pub fn issue_default(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        peer_pubkey: Option<PublicIdentity>,
        allowed_mode: AllowedMode,
    ) -> Self {
        Self::issue(issuer, session_id, peer_pubkey, allowed_mode, DEFAULT_TICKET_TTL_SECS)
    }

    /// Verify the ticket's signature and check it hasn't expired.
    ///
    /// Returns `Ok(())` if the ticket is valid.
    pub fn verify(&self) -> Result<(), InviteError> {
        let payload = Self::compute_payload(
            &self.session_id,
            &self.issuer_pubkey,
            self.peer_pubkey.as_ref(),
            self.allowed_mode,
            self.issued_at,
            self.expires_at,
        );

        self.issuer_pubkey
            .verify(&payload, &self.signature)
            .map_err(|_| InviteError::InvalidSignature)?;

        self.check_validity_window()?;

        Ok(())
    }

    /// Verify the ticket was issued by the expected issuer.
    pub fn verify_issuer(&self, expected_issuer: &PublicIdentity) -> Result<(), InviteError> {
        self.verify()?;

        if &self.issuer_pubkey != expected_issuer {
            return Err(InviteError::IssuerMismatch {
                expected: expected_issuer.to_hex(),
                got: self.issuer_pubkey.to_hex(),
            });
        }

        Ok(())
    }

    /// Verify the ticket and check if the given peer is authorized to use it.
    pub fn verify_for_peer(&self, peer: &PublicIdentity) -> Result<(), InviteError> {
        self.verify()?;

        if let Some(expected_peer) = &self.peer_pubkey {
            if expected_peer != peer {
                return Err(InviteError::PeerMismatch {
                    expected: expected_peer.to_hex(),
                    got: peer.to_hex(),
                });
            }
        }

        Ok(())
    }

    /// Verify the ticket for a specific session and mode.
    pub fn verify_for_session(
        &self,
        session_id: &str,
        mode: IntersectionMode,
    ) -> Result<(), InviteError> {
        self.verify()?;

        if self.session_id != session_id {
            return Err(InviteError::SessionMismatch {
                expected: self.session_id.clone(),
                got: session_id.to_string(),
            });
        }

        if !self.allowed_mode.permits(mode) {
            return Err(InviteError::ModeMismatch {
                allowed: self.allowed_mode,
                requested: mode,
            });
        }

        Ok(())
    }

    /// Full verification: check signature, expiry, issuer, peer, session, and mode.
    pub fn verify_full(
        &self,
        expected_issuer: &PublicIdentity,
        peer: &PublicIdentity,
        session_id: &str,
        mode: IntersectionMode,
    ) -> Result<(), InviteError> {
        self.verify_issuer(expected_issuer)?;
        self.verify_for_peer(peer)?;
        self.verify_for_session(session_id, mode)?;
        Ok(())
    }

    /// Check if the ticket is currently within its validity window.
    pub fn check_validity_window(&self) -> Result<(), InviteError> {
        let now = crate::freshness::current_unix_time();

        if now < self.issued_at {
            return Err(InviteError::NotYetValid {
                issued_at: self.issued_at,
                current_time: now,
            });
        }

        if now > self.expires_at {
            return Err(InviteError::Expired {
                expires_at: self.expires_at,
                current_time: now,
            });
        }

        Ok(())
    }

    /// Check if the ticket has expired.
    pub fn is_expired(&self) -> bool {
        let now = crate::freshness::current_unix_time();
        now > self.expires_at
    }

    /// Get the remaining validity time in seconds, or None if expired.
    pub fn remaining_secs(&self) -> Option<u64> {
        let now = crate::freshness::current_unix_time();
        if now > self.expires_at {
            None
        } else {
            Some(self.expires_at - now)
        }
    }

    /// Compute the ticket ID (hash of signature).
    pub fn ticket_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.signature);
        hasher.finalize().into()
    }

    /// Serialize the ticket to JSON.
    pub fn to_json(&self) -> Result<String, InviteError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize the ticket to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, InviteError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a ticket from JSON.
    pub fn from_json(json: &str) -> Result<Self, InviteError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load a ticket from a file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, InviteError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Save the ticket to a file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), InviteError> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn compute_payload(
        session_id: &str,
        issuer: &PublicIdentity,
        peer: Option<&PublicIdentity>,
        allowed_mode: AllowedMode,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(256);
        payload.extend_from_slice(INVITE_TICKET_DOMAIN);
        payload.push(0); // null separator
        payload.extend_from_slice(session_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(issuer.as_bytes());
        if let Some(p) = peer {
            payload.push(1); // peer present marker
            payload.extend_from_slice(p.as_bytes());
        } else {
            payload.push(0); // no peer marker
        }
        let mode_byte = match allowed_mode {
            AllowedMode::Intersection => 1,
            AllowedMode::Cardinality => 2,
            AllowedMode::Any => 3,
        };
        payload.push(mode_byte);
        payload.extend_from_slice(&issued_at.to_le_bytes());
        payload.extend_from_slice(&expires_at.to_le_bytes());
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

    #[test]
    fn test_issue_and_verify() {
        let issuer = PartyIdentity::generate();
        let ticket = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Any,
        );

        assert!(ticket.verify().is_ok());
        assert!(!ticket.is_expired());
    }

    #[test]
    fn test_verify_issuer() {
        let issuer = PartyIdentity::generate();
        let other = PartyIdentity::generate();

        let ticket = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Any,
        );

        assert!(ticket.verify_issuer(&issuer.public()).is_ok());
        assert!(ticket.verify_issuer(&other.public()).is_err());
    }

    #[test]
    fn test_peer_binding() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();
        let wrong_peer = PartyIdentity::generate();

        let ticket = InviteTicket::issue_default(
            &issuer,
            "test-session",
            Some(peer.public()),
            AllowedMode::Any,
        );

        assert!(ticket.verify_for_peer(&peer.public()).is_ok());
        assert!(ticket.verify_for_peer(&wrong_peer.public()).is_err());
    }

    #[test]
    fn test_unbound_ticket_accepts_any_peer() {
        let issuer = PartyIdentity::generate();
        let peer1 = PartyIdentity::generate();
        let peer2 = PartyIdentity::generate();

        let ticket = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Any,
        );

        assert!(ticket.verify_for_peer(&peer1.public()).is_ok());
        assert!(ticket.verify_for_peer(&peer2.public()).is_ok());
    }

    #[test]
    fn test_mode_restriction() {
        let issuer = PartyIdentity::generate();

        let intersection_only = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Intersection,
        );

        assert!(intersection_only.verify_for_session("test-session", IntersectionMode::Intersection).is_ok());
        assert!(intersection_only.verify_for_session("test-session", IntersectionMode::Cardinality).is_err());

        let cardinality_only = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Cardinality,
        );

        assert!(cardinality_only.verify_for_session("test-session", IntersectionMode::Cardinality).is_ok());
        assert!(cardinality_only.verify_for_session("test-session", IntersectionMode::Intersection).is_err());

        let any_mode = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Any,
        );

        assert!(any_mode.verify_for_session("test-session", IntersectionMode::Intersection).is_ok());
        assert!(any_mode.verify_for_session("test-session", IntersectionMode::Cardinality).is_ok());
    }

    #[test]
    fn test_session_mismatch() {
        let issuer = PartyIdentity::generate();
        let ticket = InviteTicket::issue_default(
            &issuer,
            "session-1",
            None,
            AllowedMode::Any,
        );

        assert!(ticket.verify_for_session("session-1", IntersectionMode::Intersection).is_ok());
        assert!(ticket.verify_for_session("session-2", IntersectionMode::Intersection).is_err());
    }

    #[test]
    fn test_expired_ticket() {
        let issuer = PartyIdentity::generate();

        // Create a ticket that's already expired by setting timestamps in the past
        let payload = InviteTicket::compute_payload(
            "test-session",
            &issuer.public(),
            None,
            AllowedMode::Any,
            1000,  // issued in the past
            1001,  // expired in the past
        );
        let signature = issuer.sign(&payload);

        let ticket = InviteTicket {
            version: 1,
            session_id: "test-session".to_string(),
            issuer_pubkey: issuer.public(),
            peer_pubkey: None,
            allowed_mode: AllowedMode::Any,
            issued_at: 1000,
            expires_at: 1001,
            signature,
        };

        assert!(ticket.is_expired());
        let result = ticket.verify();
        assert!(matches!(result, Err(InviteError::Expired { .. })));
    }

    #[test]
    fn test_json_roundtrip() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let ticket = InviteTicket::issue_default(
            &issuer,
            "test-session",
            Some(peer.public()),
            AllowedMode::Intersection,
        );

        let json = ticket.to_json_pretty().unwrap();
        let parsed = InviteTicket::from_json(&json).unwrap();

        assert_eq!(ticket, parsed);
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let issuer = PartyIdentity::generate();
        let mut ticket = InviteTicket::issue_default(
            &issuer,
            "test-session",
            None,
            AllowedMode::Any,
        );

        ticket.signature[0] ^= 0xFF;

        assert!(ticket.verify().is_err());
    }

    #[test]
    fn test_ticket_id_uniqueness() {
        let issuer = PartyIdentity::generate();

        let ticket1 = InviteTicket::issue_default(&issuer, "session-1", None, AllowedMode::Any);
        let ticket2 = InviteTicket::issue_default(&issuer, "session-2", None, AllowedMode::Any);

        assert_ne!(ticket1.ticket_id(), ticket2.ticket_id());
    }

    #[test]
    fn test_full_verification() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let ticket = InviteTicket::issue_default(
            &issuer,
            "full-test",
            Some(peer.public()),
            AllowedMode::Intersection,
        );

        assert!(ticket.verify_full(
            &issuer.public(),
            &peer.public(),
            "full-test",
            IntersectionMode::Intersection
        ).is_ok());

        // Wrong issuer
        let wrong_issuer = PartyIdentity::generate();
        assert!(ticket.verify_full(
            &wrong_issuer.public(),
            &peer.public(),
            "full-test",
            IntersectionMode::Intersection
        ).is_err());

        // Wrong peer
        let wrong_peer = PartyIdentity::generate();
        assert!(ticket.verify_full(
            &issuer.public(),
            &wrong_peer.public(),
            "full-test",
            IntersectionMode::Intersection
        ).is_err());

        // Wrong session
        assert!(ticket.verify_full(
            &issuer.public(),
            &peer.public(),
            "wrong-session",
            IntersectionMode::Intersection
        ).is_err());

        // Wrong mode
        assert!(ticket.verify_full(
            &issuer.public(),
            &peer.public(),
            "full-test",
            IntersectionMode::Cardinality
        ).is_err());
    }
}
