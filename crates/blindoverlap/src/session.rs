//! Online PSI session API for two-party protocol over wire messages.
//!
//! Provides a state machine for executing the DH-PSI protocol when parties
//! only have access to their own FactSet and exchanged wire messages.
//!
//! # Protocol Flow
//!
//! 1. **Initiator** creates session, calls `generate_offer()` → sends `MaskedSetOffer`
//! 2. **Responder** creates session, processes offer, calls `generate_reply()` → sends `MaskedSetReply`
//! 3. **Initiator** processes reply, can compute intersection
//! 4. **Initiator** optionally calls `generate_reveal()` → sends `IntersectionReveal`
//! 5. **Responder** processes reveal, can compute intersection
//!
//! # Protocol Versions
//!
//! - **v1 sessions**: No freshness enforcement (backward compatible)
//! - **v2 sessions**: TTL and nonce validation for replay protection
//!
//! # Channel Binding (v0.4.0+)
//!
//! Sessions can optionally bind to party identities:
//! - Local identity: Ed25519 keypair used to sign outgoing messages
//! - Expected peer: Public key to verify incoming messages came from the expected peer
//!
//! Channel binding provides **party authentication only**. It does NOT upgrade PSI
//! security from semi-honest to malicious. A bound session rejects messages from
//! unexpected peers but cannot prevent a semi-honest peer from deviating.
//!
//! # Security Note
//!
//! This is semi-honest secure only. TTL and nonce validation are best-effort
//! aids against accidental replay, not protection against active adversaries.
//! See THREAT_MODEL.md.

use crate::fact_id::{FactId, FactSet};
use crate::freshness::{FreshnessError, SessionDeadline, SessionNonce, DEFAULT_TTL_SECS};
use crate::identity::{PartyIdentity, PublicIdentity};
use crate::invite::{InviteError, InviteTicket};
use crate::protocol::{IntersectionMode, MaskedElement, PsiResult, MAX_SET_SIZE};
use crate::wire::{
    IntersectionReveal, MaskedSetOffer, MaskedSetReply, SignedWireMessage, WireMessage,
};
use std::collections::BTreeSet;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// Errors that can occur during session operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Set exceeds maximum allowed size.
    #[error("set size {0} exceeds maximum {MAX_SET_SIZE}")]
    SetTooLarge(usize),
    /// Session is in wrong state for this operation.
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state.
        expected: &'static str,
        /// Actual state.
        actual: &'static str,
    },
    /// Session ID mismatch.
    #[error("session ID mismatch: expected {expected}, got {got}")]
    SessionIdMismatch {
        /// Expected session ID.
        expected: String,
        /// Actual session ID.
        got: String,
    },
    /// Array length mismatch in received message.
    #[error("element count mismatch: expected {expected}, got {got}")]
    ElementCountMismatch {
        /// Expected count.
        expected: usize,
        /// Actual count.
        got: usize,
    },
    /// Freshness validation error.
    #[error("freshness error: {0}")]
    Freshness(#[from] FreshnessError),
    /// Nonce mismatch in received message.
    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch {
        /// Expected nonce (hex).
        expected: String,
        /// Received nonce (hex).
        got: String,
    },
    /// Protocol version mismatch.
    #[error(
        "protocol version mismatch: session is v{session_version}, message is v{message_version}"
    )]
    VersionMismatch {
        /// Session protocol version.
        session_version: u8,
        /// Message protocol version.
        message_version: u8,
    },
    /// Peer identity mismatch - message signed by unexpected party.
    #[error("identity mismatch: expected peer {expected}, got {got}")]
    IdentityMismatch {
        /// Expected peer public key (hex).
        expected: String,
        /// Actual signer public key (hex).
        got: String,
    },
    /// Signature verification failed.
    #[error("bad signature: message signature verification failed")]
    BadSignature,
    /// Missing identity when channel binding is required.
    #[error("missing identity: session requires signed messages but none provided")]
    MissingIdentity,
    /// Wire error during message processing.
    #[error("wire error: {0}")]
    Wire(#[from] crate::wire::WireError),
    /// Invite ticket verification failed.
    #[error("invite error: {0}")]
    Invite(#[from] InviteError),
}

/// Session state for the initiator (party A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorState {
    /// Session created, ready to generate offer.
    Created,
    /// Offer sent, waiting for reply.
    AwaitingReply,
    /// Reply received, intersection computed.
    Complete,
}

/// Session state for the responder (party B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderState {
    /// Session created, ready to process offer.
    Created,
    /// Offer processed, reply sent.
    ReplySent,
    /// Reveal received, intersection computed.
    Complete,
}

/// Hash a fact ID to a public key point on Curve25519.
fn hash_to_public_key(id: &FactId) -> PublicKey {
    let secret = StaticSecret::from(*id);
    PublicKey::from(&secret)
}

/// Configuration for session freshness and identity binding.
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    /// TTL in seconds (default: 300).
    pub ttl_secs: u64,
    /// Whether to use v2 protocol with freshness fields.
    pub use_freshness: bool,
    /// Whether to require signed messages (channel binding).
    pub require_signatures: bool,
}

impl SessionConfig {
    /// Create a default session config (v2 with freshness, no identity).
    pub fn new() -> Self {
        Self {
            ttl_secs: DEFAULT_TTL_SECS,
            use_freshness: true,
            require_signatures: false,
        }
    }

    /// Create a v1-compatible session (no freshness enforcement).
    pub fn v1_compatible() -> Self {
        Self {
            ttl_secs: DEFAULT_TTL_SECS,
            use_freshness: false,
            require_signatures: false,
        }
    }

    /// Create a session with custom TTL.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            use_freshness: true,
            require_signatures: false,
        }
    }

    /// Create a session that requires signed messages for channel binding.
    pub fn with_identity_binding(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            use_freshness: true,
            require_signatures: true,
        }
    }
}

/// Channel binding information for a session.
///
/// When set, the session will sign outgoing messages and verify
/// that incoming messages are signed by the expected peer.
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    /// Local party's public identity (for outbound message verification).
    pub local_pubkey: PublicIdentity,
    /// Expected peer's public identity.
    pub peer_pubkey: PublicIdentity,
}

impl ChannelBinding {
    /// Create a new channel binding configuration.
    pub fn new(local_pubkey: PublicIdentity, peer_pubkey: PublicIdentity) -> Self {
        Self {
            local_pubkey,
            peer_pubkey,
        }
    }
}

/// PSI session for the initiator (party who starts the exchange).
pub struct InitiatorSession {
    session_id: String,
    secret: StaticSecret,
    fact_set: FactSet,
    original_ids: Vec<FactId>,
    mode: IntersectionMode,
    state: InitiatorState,
    config: SessionConfig,
    nonce: SessionNonce,
    deadline: SessionDeadline,
    masked_elements: Option<Vec<MaskedElement>>,
    responder_masked: Option<Vec<MaskedElement>>,
    responder_nonce: Option<SessionNonce>,
    our_doubly_masked: Option<Vec<MaskedElement>>,
    channel_binding: Option<ChannelBinding>,
    verified_peer: Option<PublicIdentity>,
}

impl InitiatorSession {
    /// Create a new initiator session with default configuration.
    pub fn new(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
    ) -> Result<Self, SessionError> {
        Self::with_config(session_id, fact_set, mode, SessionConfig::default())
    }

    /// Create a new initiator session with custom configuration.
    pub fn with_config(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(SessionError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let original_ids = fact_set.ids();
        let nonce = SessionNonce::generate();
        let deadline = SessionDeadline::new(config.ttl_secs);

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: InitiatorState::Created,
            config,
            nonce,
            deadline,
            masked_elements: None,
            responder_masked: None,
            responder_nonce: None,
            our_doubly_masked: None,
            channel_binding: None,
            verified_peer: None,
        })
    }

    /// Create a new initiator session with channel binding (identity verification).
    ///
    /// When channel binding is set:
    /// - The session binds to (local_pubkey, peer_pubkey, session_id)
    /// - Incoming messages must be signed by the expected peer
    /// - Use `generate_offer_signed()` to produce signed outgoing messages
    pub fn with_channel_binding(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
        local_identity: &PartyIdentity,
        expected_peer: PublicIdentity,
    ) -> Result<Self, SessionError> {
        let config = SessionConfig::with_identity_binding(DEFAULT_TTL_SECS);
        let mut session = Self::with_config(session_id, fact_set, mode, config)?;
        session.channel_binding = Some(ChannelBinding::new(local_identity.public(), expected_peer));
        Ok(session)
    }

    /// Create an initiator session from an invite ticket.
    ///
    /// The ticket is verified before creating the session:
    /// - Signature and expiry are validated
    /// - Session ID must match the ticket
    /// - Mode must be permitted by the ticket
    /// - If ticket has a peer_pubkey, it becomes the expected peer
    ///
    /// This is a convenience method that combines ticket verification with
    /// channel-bound session creation. The ticket issuer becomes the expected peer.
    pub fn from_invite(
        ticket: &InviteTicket,
        fact_set: FactSet,
        mode: IntersectionMode,
        local_identity: &PartyIdentity,
    ) -> Result<Self, SessionError> {
        // Verify the ticket
        ticket.verify_for_session(&ticket.session_id, mode)?;

        // Create channel-bound session with issuer as expected peer
        let session = Self::with_channel_binding(
            &ticket.session_id,
            fact_set,
            mode,
            local_identity,
            ticket.issuer_pubkey,
        )?;

        Ok(session)
    }

    /// Create session with a specific secret (for testing).
    pub fn with_secret(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
        secret: [u8; 32],
    ) -> Result<Self, SessionError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(SessionError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::from(secret);
        let original_ids = fact_set.ids();
        let nonce = SessionNonce::generate();
        let config = SessionConfig::v1_compatible();
        let deadline = SessionDeadline::new(config.ttl_secs);

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: InitiatorState::Created,
            config,
            nonce,
            deadline,
            masked_elements: None,
            responder_masked: None,
            responder_nonce: None,
            our_doubly_masked: None,
            channel_binding: None,
            verified_peer: None,
        })
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the current state.
    pub fn state(&self) -> InitiatorState {
        self.state
    }

    /// Get the fact set.
    pub fn fact_set(&self) -> &FactSet {
        &self.fact_set
    }

    /// Get the intersection mode.
    pub fn mode(&self) -> IntersectionMode {
        self.mode
    }

    /// Get the initiator's nonce.
    pub fn nonce(&self) -> &SessionNonce {
        &self.nonce
    }

    /// Get the session deadline.
    pub fn deadline(&self) -> &SessionDeadline {
        &self.deadline
    }

    /// Get the responder's nonce (available after processing reply).
    pub fn responder_nonce(&self) -> Option<&SessionNonce> {
        self.responder_nonce.as_ref()
    }

    /// Check if this session uses freshness (v2 protocol).
    pub fn uses_freshness(&self) -> bool {
        self.config.use_freshness
    }

    /// Check if this session has channel binding (identity verification).
    pub fn has_channel_binding(&self) -> bool {
        self.channel_binding.is_some()
    }

    /// Get the channel binding configuration, if set.
    pub fn channel_binding(&self) -> Option<&ChannelBinding> {
        self.channel_binding.as_ref()
    }

    /// Get the verified peer identity (set after successful signature verification).
    pub fn verified_peer(&self) -> Option<&PublicIdentity> {
        self.verified_peer.as_ref()
    }

    /// Generate a signed offer message using the provided identity.
    ///
    /// The offer will be signed with the provided identity's private key.
    /// The peer should verify the signature against our public key.
    pub fn generate_offer_signed(
        &mut self,
        identity: &PartyIdentity,
    ) -> Result<SignedWireMessage, SessionError> {
        let offer = self.generate_offer()?;
        let message = WireMessage::Offer(offer);
        Ok(SignedWireMessage::sign(message, identity))
    }

    /// Process a signed reply message with peer verification.
    ///
    /// Verifies that the reply is signed by the expected peer before processing.
    /// Returns an error if signature verification fails or if the signer doesn't
    /// match the expected peer.
    pub fn process_reply_signed(
        &mut self,
        signed_reply: &SignedWireMessage,
    ) -> Result<PsiResult, SessionError> {
        if let Some(binding) = &self.channel_binding {
            signed_reply
                .verify_peer(&binding.peer_pubkey)
                .map_err(|e| match e {
                    crate::wire::WireError::PeerMismatch { expected, got } => {
                        SessionError::IdentityMismatch { expected, got }
                    }
                    crate::wire::WireError::Identity(_) => SessionError::BadSignature,
                    other => SessionError::Wire(other),
                })?;
            self.verified_peer = Some(signed_reply.signer_pubkey);
        } else if self.config.require_signatures {
            return Err(SessionError::MissingIdentity);
        }

        let reply = match &signed_reply.message {
            WireMessage::Reply(r) => r,
            _ => {
                return Err(SessionError::InvalidState {
                    expected: "Reply message",
                    actual: "non-reply message type",
                })
            }
        };

        self.process_reply(reply)
    }

    /// Generate the initial offer message.
    ///
    /// Must be called in Created state.
    pub fn generate_offer(&mut self) -> Result<MaskedSetOffer, SessionError> {
        if self.state != InitiatorState::Created {
            return Err(SessionError::InvalidState {
                expected: "Created",
                actual: state_name(self.state),
            });
        }

        let masked: Vec<MaskedElement> = self
            .original_ids
            .iter()
            .map(|id| {
                let point = hash_to_public_key(id);
                self.secret.diffie_hellman(&point).to_bytes()
            })
            .collect();

        self.masked_elements = Some(masked.clone());
        self.state = InitiatorState::AwaitingReply;

        if self.config.use_freshness {
            Ok(MaskedSetOffer::new_v2(
                &self.session_id,
                masked,
                self.nonce,
                self.deadline,
            ))
        } else {
            Ok(MaskedSetOffer::new(&self.session_id, masked))
        }
    }

    /// Process the reply message and compute the intersection.
    ///
    /// Must be called in AwaitingReply state.
    /// For v2 sessions, validates freshness fields and rejects expired messages.
    pub fn process_reply(&mut self, reply: &MaskedSetReply) -> Result<PsiResult, SessionError> {
        if self.state != InitiatorState::AwaitingReply {
            return Err(SessionError::InvalidState {
                expected: "AwaitingReply",
                actual: state_name(self.state),
            });
        }

        if reply.session_id != self.session_id {
            return Err(SessionError::SessionIdMismatch {
                expected: self.session_id.clone(),
                got: reply.session_id.clone(),
            });
        }

        if self.config.use_freshness && reply.has_freshness() {
            if let Some(initiator_nonce) = &reply.initiator_nonce {
                if initiator_nonce != &self.nonce {
                    return Err(SessionError::NonceMismatch {
                        expected: self.nonce.to_hex(),
                        got: initiator_nonce.to_hex(),
                    });
                }
            }
            if let Some(deadline) = reply.deadline() {
                deadline.validate()?;
            }
            self.responder_nonce = reply.responder_nonce;
        }

        let our_count = self.masked_elements.as_ref().map(|m| m.len()).unwrap_or(0);
        if reply.initiator_doubly_masked.len() != our_count {
            return Err(SessionError::ElementCountMismatch {
                expected: our_count,
                got: reply.initiator_doubly_masked.len(),
            });
        }

        let their_doubly_masked: Vec<MaskedElement> = reply
            .responder_masked
            .iter()
            .map(|masked| {
                let point = PublicKey::from(*masked);
                self.secret.diffie_hellman(&point).to_bytes()
            })
            .collect();

        self.our_doubly_masked = Some(reply.initiator_doubly_masked.clone());
        self.responder_masked = Some(reply.responder_masked.clone());

        let result = compute_intersection(
            &reply.initiator_doubly_masked,
            &their_doubly_masked,
            &self.original_ids,
            self.mode,
        );

        self.state = InitiatorState::Complete;
        Ok(result)
    }

    /// Generate the reveal message (optional, for bilateral intersection).
    ///
    /// Must be called in Complete state.
    pub fn generate_reveal(&self) -> Result<IntersectionReveal, SessionError> {
        if self.state != InitiatorState::Complete {
            return Err(SessionError::InvalidState {
                expected: "Complete",
                actual: state_name(self.state),
            });
        }

        let responder_masked =
            self.responder_masked
                .as_ref()
                .ok_or(SessionError::InvalidState {
                    expected: "Complete with responder data",
                    actual: "missing responder masked elements",
                })?;

        let doubly_masked: Vec<MaskedElement> = responder_masked
            .iter()
            .map(|masked| {
                let point = PublicKey::from(*masked);
                self.secret.diffie_hellman(&point).to_bytes()
            })
            .collect();

        if self.config.use_freshness {
            let responder_nonce = self.responder_nonce.unwrap_or_else(SessionNonce::generate);
            Ok(IntersectionReveal::new_v2(
                &self.session_id,
                doubly_masked,
                self.nonce,
                responder_nonce,
                SessionDeadline::new(self.config.ttl_secs),
            ))
        } else {
            Ok(IntersectionReveal::new(&self.session_id, doubly_masked))
        }
    }

    /// Generate a signed reveal message using the provided identity.
    pub fn generate_reveal_signed(
        &self,
        identity: &PartyIdentity,
    ) -> Result<SignedWireMessage, SessionError> {
        let reveal = self.generate_reveal()?;
        let message = WireMessage::Reveal(reveal);
        Ok(SignedWireMessage::sign(message, identity))
    }
}

/// PSI session for the responder (party who receives the initial offer).
pub struct ResponderSession {
    session_id: String,
    secret: StaticSecret,
    fact_set: FactSet,
    original_ids: Vec<FactId>,
    mode: IntersectionMode,
    state: ResponderState,
    config: SessionConfig,
    nonce: SessionNonce,
    initiator_nonce: Option<SessionNonce>,
    masked_elements: Option<Vec<MaskedElement>>,
    initiator_doubly_masked: Option<Vec<MaskedElement>>,
    channel_binding: Option<ChannelBinding>,
    verified_peer: Option<PublicIdentity>,
}

impl ResponderSession {
    /// Create a new responder session with default configuration.
    pub fn new(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
    ) -> Result<Self, SessionError> {
        Self::with_config(session_id, fact_set, mode, SessionConfig::default())
    }

    /// Create a new responder session with custom configuration.
    pub fn with_config(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(SessionError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let original_ids = fact_set.ids();
        let nonce = SessionNonce::generate();

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: ResponderState::Created,
            config,
            nonce,
            initiator_nonce: None,
            masked_elements: None,
            initiator_doubly_masked: None,
            channel_binding: None,
            verified_peer: None,
        })
    }

    /// Create a new responder session with channel binding (identity verification).
    ///
    /// When channel binding is set:
    /// - The session binds to (local_pubkey, peer_pubkey, session_id)
    /// - Incoming messages must be signed by the expected peer
    /// - Use `process_offer_and_reply_signed()` to handle signed messages
    pub fn with_channel_binding(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
        local_identity: &PartyIdentity,
        expected_peer: PublicIdentity,
    ) -> Result<Self, SessionError> {
        let config = SessionConfig::with_identity_binding(DEFAULT_TTL_SECS);
        let mut session = Self::with_config(session_id, fact_set, mode, config)?;
        session.channel_binding = Some(ChannelBinding::new(local_identity.public(), expected_peer));
        Ok(session)
    }

    /// Create a responder session from an invite ticket.
    ///
    /// The ticket is verified before creating the session:
    /// - Signature and expiry are validated
    /// - Session ID must match the ticket
    /// - Mode must be permitted by the ticket
    /// - Local identity must match the ticket's peer_pubkey (if specified)
    ///
    /// The ticket issuer becomes the expected peer for signature verification.
    pub fn from_invite(
        ticket: &InviteTicket,
        fact_set: FactSet,
        mode: IntersectionMode,
        local_identity: &PartyIdentity,
    ) -> Result<Self, SessionError> {
        // Verify the ticket
        ticket.verify_for_session(&ticket.session_id, mode)?;

        // If ticket specifies a peer, verify local identity matches
        ticket.verify_for_peer(&local_identity.public())?;

        // Create channel-bound session with issuer as expected peer
        let session = Self::with_channel_binding(
            &ticket.session_id,
            fact_set,
            mode,
            local_identity,
            ticket.issuer_pubkey,
        )?;

        Ok(session)
    }

    /// Create session with a specific secret (for testing).
    pub fn with_secret(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
        secret: [u8; 32],
    ) -> Result<Self, SessionError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(SessionError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::from(secret);
        let original_ids = fact_set.ids();
        let nonce = SessionNonce::generate();
        let config = SessionConfig::v1_compatible();

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: ResponderState::Created,
            config,
            nonce,
            initiator_nonce: None,
            masked_elements: None,
            initiator_doubly_masked: None,
            channel_binding: None,
            verified_peer: None,
        })
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the current state.
    pub fn state(&self) -> ResponderState {
        self.state
    }

    /// Get the fact set.
    pub fn fact_set(&self) -> &FactSet {
        &self.fact_set
    }

    /// Get the intersection mode.
    pub fn mode(&self) -> IntersectionMode {
        self.mode
    }

    /// Get the responder's nonce.
    pub fn nonce(&self) -> &SessionNonce {
        &self.nonce
    }

    /// Get the initiator's nonce (available after processing offer).
    pub fn initiator_nonce(&self) -> Option<&SessionNonce> {
        self.initiator_nonce.as_ref()
    }

    /// Check if this session uses freshness (v2 protocol).
    pub fn uses_freshness(&self) -> bool {
        self.config.use_freshness
    }

    /// Check if this session has channel binding (identity verification).
    pub fn has_channel_binding(&self) -> bool {
        self.channel_binding.is_some()
    }

    /// Get the channel binding configuration, if set.
    pub fn channel_binding(&self) -> Option<&ChannelBinding> {
        self.channel_binding.as_ref()
    }

    /// Get the verified peer identity (set after successful signature verification).
    pub fn verified_peer(&self) -> Option<&PublicIdentity> {
        self.verified_peer.as_ref()
    }

    /// Process a signed offer and generate a signed reply.
    ///
    /// Verifies that the offer is signed by the expected peer before processing.
    /// Returns a signed reply message.
    pub fn process_offer_and_reply_signed(
        &mut self,
        signed_offer: &SignedWireMessage,
        identity: &PartyIdentity,
    ) -> Result<SignedWireMessage, SessionError> {
        if let Some(binding) = &self.channel_binding {
            signed_offer
                .verify_peer(&binding.peer_pubkey)
                .map_err(|e| match e {
                    crate::wire::WireError::PeerMismatch { expected, got } => {
                        SessionError::IdentityMismatch { expected, got }
                    }
                    crate::wire::WireError::Identity(_) => SessionError::BadSignature,
                    other => SessionError::Wire(other),
                })?;
            self.verified_peer = Some(signed_offer.signer_pubkey);
        } else if self.config.require_signatures {
            return Err(SessionError::MissingIdentity);
        }

        let offer = match &signed_offer.message {
            WireMessage::Offer(o) => o,
            _ => {
                return Err(SessionError::InvalidState {
                    expected: "Offer message",
                    actual: "non-offer message type",
                })
            }
        };

        let reply = self.process_offer_and_reply(offer)?;
        let message = WireMessage::Reply(reply);
        Ok(SignedWireMessage::sign(message, identity))
    }

    /// Process a signed reveal with peer verification.
    pub fn process_reveal_signed(
        &mut self,
        signed_reveal: &SignedWireMessage,
    ) -> Result<PsiResult, SessionError> {
        if let Some(binding) = &self.channel_binding {
            signed_reveal
                .verify_peer(&binding.peer_pubkey)
                .map_err(|e| match e {
                    crate::wire::WireError::PeerMismatch { expected, got } => {
                        SessionError::IdentityMismatch { expected, got }
                    }
                    crate::wire::WireError::Identity(_) => SessionError::BadSignature,
                    other => SessionError::Wire(other),
                })?;
        } else if self.config.require_signatures {
            return Err(SessionError::MissingIdentity);
        }

        let reveal = match &signed_reveal.message {
            WireMessage::Reveal(r) => r,
            _ => {
                return Err(SessionError::InvalidState {
                    expected: "Reveal message",
                    actual: "non-reveal message type",
                })
            }
        };

        self.process_reveal(reveal)
    }

    /// Process the offer message and generate the reply.
    ///
    /// Must be called in Created state.
    /// For v2 sessions, validates freshness fields and rejects expired messages.
    pub fn process_offer_and_reply(
        &mut self,
        offer: &MaskedSetOffer,
    ) -> Result<MaskedSetReply, SessionError> {
        if self.state != ResponderState::Created {
            return Err(SessionError::InvalidState {
                expected: "Created",
                actual: responder_state_name(self.state),
            });
        }

        if offer.session_id != self.session_id {
            return Err(SessionError::SessionIdMismatch {
                expected: self.session_id.clone(),
                got: offer.session_id.clone(),
            });
        }

        let use_v2 = self.config.use_freshness && offer.has_freshness();

        if use_v2 {
            if let Some(deadline) = offer.deadline() {
                deadline.validate()?;
            }
            self.initiator_nonce = offer.nonce;
        }

        let our_masked: Vec<MaskedElement> = self
            .original_ids
            .iter()
            .map(|id| {
                let point = hash_to_public_key(id);
                self.secret.diffie_hellman(&point).to_bytes()
            })
            .collect();

        let initiator_doubly_masked: Vec<MaskedElement> = offer
            .masked_elements
            .iter()
            .map(|masked| {
                let point = PublicKey::from(*masked);
                self.secret.diffie_hellman(&point).to_bytes()
            })
            .collect();

        self.masked_elements = Some(our_masked.clone());
        self.initiator_doubly_masked = Some(initiator_doubly_masked.clone());
        self.state = ResponderState::ReplySent;

        if use_v2 {
            let initiator_nonce = offer.nonce.unwrap_or_else(SessionNonce::generate);
            Ok(MaskedSetReply::new_v2(
                &self.session_id,
                our_masked,
                initiator_doubly_masked,
                initiator_nonce,
                self.nonce,
                SessionDeadline::new(self.config.ttl_secs),
            ))
        } else {
            Ok(MaskedSetReply::new(
                &self.session_id,
                our_masked,
                initiator_doubly_masked,
            ))
        }
    }

    /// Process the reveal message and compute the intersection.
    ///
    /// Must be called in ReplySent state.
    /// For v2 sessions, validates freshness fields.
    pub fn process_reveal(
        &mut self,
        reveal: &IntersectionReveal,
    ) -> Result<PsiResult, SessionError> {
        if self.state != ResponderState::ReplySent {
            return Err(SessionError::InvalidState {
                expected: "ReplySent",
                actual: responder_state_name(self.state),
            });
        }

        if reveal.session_id != self.session_id {
            return Err(SessionError::SessionIdMismatch {
                expected: self.session_id.clone(),
                got: reveal.session_id.clone(),
            });
        }

        if self.config.use_freshness && reveal.has_freshness() {
            if let Some(responder_nonce) = &reveal.responder_nonce {
                if responder_nonce != &self.nonce {
                    return Err(SessionError::NonceMismatch {
                        expected: self.nonce.to_hex(),
                        got: responder_nonce.to_hex(),
                    });
                }
            }
            if let Some(deadline) = reveal.deadline() {
                deadline.validate()?;
            }
        }

        let our_count = self.masked_elements.as_ref().map(|m| m.len()).unwrap_or(0);
        if reveal.responder_doubly_masked.len() != our_count {
            return Err(SessionError::ElementCountMismatch {
                expected: our_count,
                got: reveal.responder_doubly_masked.len(),
            });
        }

        let initiator_doubly_masked =
            self.initiator_doubly_masked
                .as_ref()
                .ok_or(SessionError::InvalidState {
                    expected: "ReplySent with initiator data",
                    actual: "missing initiator doubly masked",
                })?;

        let result = compute_intersection(
            &reveal.responder_doubly_masked,
            initiator_doubly_masked,
            &self.original_ids,
            self.mode,
        );

        self.state = ResponderState::Complete;
        Ok(result)
    }
}

fn compute_intersection(
    our_doubly_masked: &[MaskedElement],
    their_doubly_masked: &[MaskedElement],
    original_ids: &[FactId],
    mode: IntersectionMode,
) -> PsiResult {
    let their_set: BTreeSet<MaskedElement> = their_doubly_masked.iter().copied().collect();

    let count = our_doubly_masked
        .iter()
        .filter(|m| their_set.contains(*m))
        .count();

    match mode {
        IntersectionMode::Cardinality => PsiResult::Cardinality { count },
        IntersectionMode::Intersection => {
            let mut ids = Vec::new();
            for (idx, masked) in our_doubly_masked.iter().enumerate() {
                if their_set.contains(masked) {
                    if let Some(id) = original_ids.get(idx) {
                        ids.push(*id);
                    }
                }
            }
            ids.sort();
            let intersection_set = FactSet::from_ids(ids.clone());
            PsiResult::Intersection {
                ids,
                root: *intersection_set.root(),
            }
        }
    }
}

fn state_name(state: InitiatorState) -> &'static str {
    match state {
        InitiatorState::Created => "Created",
        InitiatorState::AwaitingReply => "AwaitingReply",
        InitiatorState::Complete => "Complete",
    }
}

fn responder_state_name(state: ResponderState) -> &'static str {
    match state {
        ResponderState::Created => "Created",
        ResponderState::ReplySent => "ReplySent",
        ResponderState::Complete => "Complete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_id::fact_id_from_json;
    use crate::protocol::PsiProtocol;
    use serde_json::json;

    fn make_set(values: &[serde_json::Value]) -> FactSet {
        FactSet::from_ids(values.iter().map(fact_id_from_json))
    }

    #[test]
    fn test_session_full_flow() {
        let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
        let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

        let mut initiator = InitiatorSession::new(
            "test-session",
            set_a.clone(),
            IntersectionMode::Intersection,
        )
        .unwrap();
        let mut responder = ResponderSession::new(
            "test-session",
            set_b.clone(),
            IntersectionMode::Intersection,
        )
        .unwrap();

        let offer = initiator.generate_offer().unwrap();
        assert_eq!(initiator.state(), InitiatorState::AwaitingReply);

        let reply = responder.process_offer_and_reply(&offer).unwrap();
        assert_eq!(responder.state(), ResponderState::ReplySent);

        let result = initiator.process_reply(&reply).unwrap();
        assert_eq!(initiator.state(), InitiatorState::Complete);

        match result {
            PsiResult::Intersection { ids, .. } => {
                assert_eq!(ids.len(), 2);
            }
            _ => panic!("expected intersection result"),
        }
    }

    #[test]
    fn test_session_bilateral() {
        let set_a = make_set(&[json!({"x": 1}), json!({"x": 2})]);
        let set_b = make_set(&[json!({"x": 2}), json!({"x": 3})]);

        let mut initiator =
            InitiatorSession::new("bilateral", set_a.clone(), IntersectionMode::Intersection)
                .unwrap();
        let mut responder =
            ResponderSession::new("bilateral", set_b.clone(), IntersectionMode::Intersection)
                .unwrap();

        let offer = initiator.generate_offer().unwrap();
        let reply = responder.process_offer_and_reply(&offer).unwrap();
        let initiator_result = initiator.process_reply(&reply).unwrap();

        let reveal = initiator.generate_reveal().unwrap();
        let responder_result = responder.process_reveal(&reveal).unwrap();

        let init_count = match initiator_result {
            PsiResult::Intersection { ids, .. } => ids.len(),
            _ => panic!(),
        };
        let resp_count = match responder_result {
            PsiResult::Intersection { ids, .. } => ids.len(),
            _ => panic!(),
        };

        assert_eq!(init_count, resp_count);
        assert_eq!(init_count, 1);
    }

    #[test]
    fn test_session_matches_colocated() {
        let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
        let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

        let protocol = PsiProtocol::new();
        let colocated = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        let mut initiator =
            InitiatorSession::new("compare", set_a.clone(), IntersectionMode::Intersection)
                .unwrap();
        let mut responder =
            ResponderSession::new("compare", set_b.clone(), IntersectionMode::Intersection)
                .unwrap();

        let offer = initiator.generate_offer().unwrap();
        let reply = responder.process_offer_and_reply(&offer).unwrap();
        let online = initiator.process_reply(&reply).unwrap();

        let colocated_count = match colocated {
            PsiResult::Intersection { ids, .. } => ids.len(),
            _ => panic!(),
        };
        let online_count = match online {
            PsiResult::Intersection { ids, .. } => ids.len(),
            _ => panic!(),
        };

        assert_eq!(colocated_count, online_count);
    }

    #[test]
    fn test_session_cardinality_mode() {
        let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
        let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

        let mut initiator =
            InitiatorSession::new("cardinality", set_a, IntersectionMode::Cardinality).unwrap();
        let mut responder =
            ResponderSession::new("cardinality", set_b, IntersectionMode::Cardinality).unwrap();

        let offer = initiator.generate_offer().unwrap();
        let reply = responder.process_offer_and_reply(&offer).unwrap();
        let result = initiator.process_reply(&reply).unwrap();

        match result {
            PsiResult::Cardinality { count } => assert_eq!(count, 2),
            _ => panic!("expected cardinality result"),
        }
    }

    #[test]
    fn test_session_wrong_state() {
        let set = make_set(&[json!({"x": 1})]);
        let mut initiator =
            InitiatorSession::new("state-test", set, IntersectionMode::Intersection).unwrap();

        let dummy_reply = MaskedSetReply::new("state-test", vec![], vec![]);
        let err = initiator.process_reply(&dummy_reply).unwrap_err();
        assert!(matches!(err, SessionError::InvalidState { .. }));
    }

    #[test]
    fn test_session_id_mismatch() {
        let set_a = make_set(&[json!({"x": 1})]);
        let set_b = make_set(&[json!({"x": 2})]);

        let mut initiator =
            InitiatorSession::new("session-a", set_a, IntersectionMode::Intersection).unwrap();
        let mut responder =
            ResponderSession::new("session-b", set_b, IntersectionMode::Intersection).unwrap();

        let offer = initiator.generate_offer().unwrap();
        let err = responder.process_offer_and_reply(&offer).unwrap_err();
        assert!(matches!(err, SessionError::SessionIdMismatch { .. }));
    }

    #[test]
    fn test_session_empty_sets() {
        let empty_a = FactSet::empty();
        let empty_b = FactSet::empty();

        let mut initiator =
            InitiatorSession::new("empty", empty_a, IntersectionMode::Intersection).unwrap();
        let mut responder =
            ResponderSession::new("empty", empty_b, IntersectionMode::Intersection).unwrap();

        let offer = initiator.generate_offer().unwrap();
        let reply = responder.process_offer_and_reply(&offer).unwrap();
        let result = initiator.process_reply(&reply).unwrap();

        match result {
            PsiResult::Intersection { ids, .. } => assert!(ids.is_empty()),
            _ => panic!(),
        }
    }
}
