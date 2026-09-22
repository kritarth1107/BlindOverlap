//! Session leases for extending session authority beyond invite TTL.
//!
//! A `SessionLease` is a signed time-bounded lease that extends session authority
//! beyond the initial invite ticket TTL. Leases can be renewed to form a chain,
//! allowing long-running sessions while maintaining signed authorization.
//!
//! ## Security Note
//!
//! **Session leases provide session continuation authentication only.**
//!
//! - Leases extend WHO may continue a session, not protocol security
//! - They do NOT upgrade PSI security from semi-honest to malicious
//! - A valid lease proves the issuer authorized continued participation
//! - It does NOT prove the peer will follow the protocol correctly
//!
//! ## Domain Separation
//!
//! All signatures use the domain tag `BlindOverlap:SessionLease:v1` to prevent
//! cross-protocol signature reuse.

use crate::freshness::current_unix_time;
use crate::identity::{IdentityError, PartyIdentity, PublicIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separation tag for session lease signatures.
pub const SESSION_LEASE_DOMAIN: &[u8] = b"BlindOverlap:SessionLease:v1";

/// Default lease validity duration in seconds (30 minutes).
pub const DEFAULT_LEASE_TTL_SECS: u64 = 1800;

/// Errors that can occur during session lease operations.
#[derive(Debug, Error)]
pub enum LeaseError {
    /// Lease has expired.
    #[error("lease expired at {expires_at}, current time is {current_time}")]
    Expired {
        /// When the lease expired (unix timestamp).
        expires_at: u64,
        /// Current time (unix timestamp).
        current_time: u64,
    },
    /// Lease is not yet valid.
    #[error("lease not valid until {issued_at}, current time is {current_time}")]
    NotYetValid {
        /// When the lease becomes valid (unix timestamp).
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
    /// Peer mismatch.
    #[error("peer mismatch: lease is for {expected}, but {got} is trying to use it")]
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
    /// Cannot renew - lease chain broken.
    #[error("cannot renew: lease chain broken or invalid parent")]
    RenewalChainBroken,
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

/// A signed session lease extending session authority.
///
/// The issuer creates this lease to authorize a peer to continue participating
/// in a session. Leases can be renewed to form a chain, with each new lease
/// referencing its parent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionLease {
    /// Protocol version for session leases.
    pub version: u8,
    /// Session ID this lease authorizes.
    pub session_id: String,
    /// Public key of the lease issuer.
    pub issuer_pubkey: PublicIdentity,
    /// Public key of the authorized peer.
    pub peer_pubkey: PublicIdentity,
    /// Unix timestamp when lease was issued.
    pub issued_at: u64,
    /// Unix timestamp when lease expires.
    pub expires_at: u64,
    /// Renewal count (0 for initial lease, increments with each renewal).
    #[serde(default)]
    pub renew_count: u32,
    /// Parent lease ID (hash of parent signature, if this is a renewal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_lease_id: Option<[u8; 32]>,
    /// Ed25519 signature over the lease payload.
    #[serde(with = "hex_signature")]
    pub signature: [u8; 64],
}

impl SessionLease {
    /// Issue a new session lease.
    ///
    /// The lease is signed with the issuer's identity and bound to a specific
    /// peer and session.
    pub fn issue(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        peer_pubkey: PublicIdentity,
        ttl_secs: u64,
    ) -> Self {
        let session_id = session_id.into();
        let now = current_unix_time();
        let issued_at = now;
        let expires_at = now + ttl_secs;

        let payload = Self::compute_payload(
            &session_id,
            &issuer.public(),
            &peer_pubkey,
            issued_at,
            expires_at,
            0,
            None,
        );

        let signature = issuer.sign(&payload);

        Self {
            version: 1,
            session_id,
            issuer_pubkey: issuer.public(),
            peer_pubkey,
            issued_at,
            expires_at,
            renew_count: 0,
            parent_lease_id: None,
            signature,
        }
    }

    /// Issue a lease with default TTL (30 minutes).
    pub fn issue_default(
        issuer: &PartyIdentity,
        session_id: impl Into<String>,
        peer_pubkey: PublicIdentity,
    ) -> Self {
        Self::issue(issuer, session_id, peer_pubkey, DEFAULT_LEASE_TTL_SECS)
    }

    /// Renew an existing lease with a new expiry time.
    ///
    /// The issuer signs a new lease referencing the old lease as parent.
    /// The renew_count is incremented and the parent_lease_id is set.
    pub fn renew(&self, issuer: &PartyIdentity, ttl_secs: u64) -> Result<Self, LeaseError> {
        if &self.issuer_pubkey != &issuer.public() {
            return Err(LeaseError::IssuerMismatch {
                expected: self.issuer_pubkey.to_hex(),
                got: issuer.public().to_hex(),
            });
        }

        let now = current_unix_time();
        let issued_at = now;
        let expires_at = now + ttl_secs;
        let renew_count = self.renew_count + 1;
        let parent_lease_id = Some(self.lease_id());

        let payload = Self::compute_payload(
            &self.session_id,
            &self.issuer_pubkey,
            &self.peer_pubkey,
            issued_at,
            expires_at,
            renew_count,
            parent_lease_id.as_ref(),
        );

        let signature = issuer.sign(&payload);

        Ok(Self {
            version: 1,
            session_id: self.session_id.clone(),
            issuer_pubkey: self.issuer_pubkey,
            peer_pubkey: self.peer_pubkey,
            issued_at,
            expires_at,
            renew_count,
            parent_lease_id,
            signature,
        })
    }

    /// Renew with default TTL.
    pub fn renew_default(&self, issuer: &PartyIdentity) -> Result<Self, LeaseError> {
        self.renew(issuer, DEFAULT_LEASE_TTL_SECS)
    }

    /// Verify the lease's signature and check it hasn't expired.
    pub fn verify(&self) -> Result<(), LeaseError> {
        let payload = Self::compute_payload(
            &self.session_id,
            &self.issuer_pubkey,
            &self.peer_pubkey,
            self.issued_at,
            self.expires_at,
            self.renew_count,
            self.parent_lease_id.as_ref(),
        );

        self.issuer_pubkey
            .verify(&payload, &self.signature)
            .map_err(|_| LeaseError::InvalidSignature)?;

        self.check_validity_window()?;

        Ok(())
    }

    /// Verify the lease was issued by the expected issuer.
    pub fn verify_issuer(&self, expected_issuer: &PublicIdentity) -> Result<(), LeaseError> {
        self.verify()?;

        if &self.issuer_pubkey != expected_issuer {
            return Err(LeaseError::IssuerMismatch {
                expected: expected_issuer.to_hex(),
                got: self.issuer_pubkey.to_hex(),
            });
        }

        Ok(())
    }

    /// Verify the lease authorizes the given peer.
    pub fn verify_for_peer(&self, peer: &PublicIdentity) -> Result<(), LeaseError> {
        self.verify()?;

        if &self.peer_pubkey != peer {
            return Err(LeaseError::PeerMismatch {
                expected: self.peer_pubkey.to_hex(),
                got: peer.to_hex(),
            });
        }

        Ok(())
    }

    /// Verify the lease is for a specific session.
    pub fn verify_for_session(&self, session_id: &str) -> Result<(), LeaseError> {
        self.verify()?;

        if self.session_id != session_id {
            return Err(LeaseError::SessionMismatch {
                expected: self.session_id.clone(),
                got: session_id.to_string(),
            });
        }

        Ok(())
    }

    /// Full verification: check signature, expiry, issuer, peer, and session.
    pub fn verify_full(
        &self,
        expected_issuer: &PublicIdentity,
        peer: &PublicIdentity,
        session_id: &str,
    ) -> Result<(), LeaseError> {
        self.verify_issuer(expected_issuer)?;
        self.verify_for_peer(peer)?;
        self.verify_for_session(session_id)?;
        Ok(())
    }

    /// Check if the lease is currently within its validity window.
    pub fn check_validity_window(&self) -> Result<(), LeaseError> {
        let now = current_unix_time();

        if now < self.issued_at {
            return Err(LeaseError::NotYetValid {
                issued_at: self.issued_at,
                current_time: now,
            });
        }

        if now > self.expires_at {
            return Err(LeaseError::Expired {
                expires_at: self.expires_at,
                current_time: now,
            });
        }

        Ok(())
    }

    /// Check if the lease has expired.
    pub fn is_expired(&self) -> bool {
        let now = current_unix_time();
        now > self.expires_at
    }

    /// Get the remaining validity time in seconds, or None if expired.
    pub fn remaining_secs(&self) -> Option<u64> {
        let now = current_unix_time();
        if now > self.expires_at {
            None
        } else {
            Some(self.expires_at - now)
        }
    }

    /// Check if this is a renewal (has a parent lease).
    pub fn is_renewal(&self) -> bool {
        self.parent_lease_id.is_some()
    }

    /// Compute the lease ID (hash of signature).
    pub fn lease_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Serialize the lease to JSON.
    pub fn to_json(&self) -> Result<String, LeaseError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize the lease to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, LeaseError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a lease from JSON.
    pub fn from_json(json: &str) -> Result<Self, LeaseError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Load a lease from a file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, LeaseError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Save the lease to a file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), LeaseError> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn compute_payload(
        session_id: &str,
        issuer: &PublicIdentity,
        peer: &PublicIdentity,
        issued_at: u64,
        expires_at: u64,
        renew_count: u32,
        parent_lease_id: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(256);
        payload.extend_from_slice(SESSION_LEASE_DOMAIN);
        payload.push(0); // null separator
        payload.extend_from_slice(session_id.as_bytes());
        payload.push(0);
        payload.extend_from_slice(issuer.as_bytes());
        payload.extend_from_slice(peer.as_bytes());
        payload.extend_from_slice(&issued_at.to_le_bytes());
        payload.extend_from_slice(&expires_at.to_le_bytes());
        payload.extend_from_slice(&renew_count.to_le_bytes());
        if let Some(parent_id) = parent_lease_id {
            payload.push(1);
            payload.extend_from_slice(parent_id);
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

    #[test]
    fn test_lease_issue_verify() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "test-session", peer.public());

        assert!(lease.verify().is_ok());
        assert!(!lease.is_expired());
        assert!(!lease.is_renewal());
        assert_eq!(lease.renew_count, 0);
    }

    #[test]
    fn test_lease_verify_issuer() {
        let issuer = PartyIdentity::generate();
        let other = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "test-session", peer.public());

        assert!(lease.verify_issuer(&issuer.public()).is_ok());
        assert!(lease.verify_issuer(&other.public()).is_err());
    }

    #[test]
    fn test_lease_verify_peer() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();
        let other = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "test-session", peer.public());

        assert!(lease.verify_for_peer(&peer.public()).is_ok());
        assert!(lease.verify_for_peer(&other.public()).is_err());
    }

    #[test]
    fn test_lease_verify_session() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "session-1", peer.public());

        assert!(lease.verify_for_session("session-1").is_ok());
        assert!(lease.verify_for_session("session-2").is_err());
    }

    #[test]
    fn test_lease_renew() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease1 = SessionLease::issue_default(&issuer, "test-session", peer.public());
        let lease2 = lease1.renew_default(&issuer).unwrap();

        assert!(lease2.verify().is_ok());
        assert!(lease2.is_renewal());
        assert_eq!(lease2.renew_count, 1);
        assert_eq!(lease2.parent_lease_id, Some(lease1.lease_id()));
    }

    #[test]
    fn test_lease_renew_chain() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease1 = SessionLease::issue_default(&issuer, "chain-session", peer.public());
        let lease2 = lease1.renew_default(&issuer).unwrap();
        let lease3 = lease2.renew_default(&issuer).unwrap();

        assert_eq!(lease3.renew_count, 2);
        assert_eq!(lease3.parent_lease_id, Some(lease2.lease_id()));
        assert!(lease3.verify().is_ok());
    }

    #[test]
    fn test_lease_renew_wrong_issuer_rejected() {
        let issuer = PartyIdentity::generate();
        let other = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "test-session", peer.public());
        let result = lease.renew_default(&other);

        assert!(matches!(result, Err(LeaseError::IssuerMismatch { .. })));
    }

    #[test]
    fn test_lease_json_roundtrip() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "json-test", peer.public());
        let json = lease.to_json_pretty().unwrap();
        let parsed = SessionLease::from_json(&json).unwrap();

        assert_eq!(lease.session_id, parsed.session_id);
        assert_eq!(lease.issuer_pubkey, parsed.issuer_pubkey);
        assert_eq!(lease.peer_pubkey, parsed.peer_pubkey);
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn test_lease_tampered_signature_rejected() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let mut lease = SessionLease::issue_default(&issuer, "tamper-test", peer.public());
        lease.signature[0] ^= 0xFF;

        assert!(matches!(lease.verify(), Err(LeaseError::InvalidSignature)));
    }

    #[test]
    fn test_lease_id_uniqueness() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease1 = SessionLease::issue_default(&issuer, "session-1", peer.public());
        let lease2 = SessionLease::issue_default(&issuer, "session-2", peer.public());

        assert_ne!(lease1.lease_id(), lease2.lease_id());
    }

    #[test]
    fn test_lease_full_verification() {
        let issuer = PartyIdentity::generate();
        let peer = PartyIdentity::generate();

        let lease = SessionLease::issue_default(&issuer, "full-test", peer.public());

        assert!(lease
            .verify_full(&issuer.public(), &peer.public(), "full-test")
            .is_ok());

        let wrong_issuer = PartyIdentity::generate();
        assert!(lease
            .verify_full(&wrong_issuer.public(), &peer.public(), "full-test")
            .is_err());

        let wrong_peer = PartyIdentity::generate();
        assert!(lease
            .verify_full(&issuer.public(), &wrong_peer.public(), "full-test")
            .is_err());

        assert!(lease
            .verify_full(&issuer.public(), &peer.public(), "wrong-session")
            .is_err());
    }
}
