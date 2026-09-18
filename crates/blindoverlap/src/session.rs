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
//! # Security Note
//!
//! This is semi-honest secure only. See THREAT_MODEL.md.

use crate::fact_id::{FactId, FactSet};
use crate::protocol::{IntersectionMode, MaskedElement, PsiResult, MAX_SET_SIZE};
use crate::wire::{IntersectionReveal, MaskedSetOffer, MaskedSetReply};
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

/// PSI session for the initiator (party who starts the exchange).
pub struct InitiatorSession {
    session_id: String,
    secret: StaticSecret,
    fact_set: FactSet,
    original_ids: Vec<FactId>,
    mode: IntersectionMode,
    state: InitiatorState,
    masked_elements: Option<Vec<MaskedElement>>,
    responder_masked: Option<Vec<MaskedElement>>,
    our_doubly_masked: Option<Vec<MaskedElement>>,
}

impl InitiatorSession {
    /// Create a new initiator session.
    pub fn new(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
    ) -> Result<Self, SessionError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(SessionError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let original_ids = fact_set.ids();

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: InitiatorState::Created,
            masked_elements: None,
            responder_masked: None,
            our_doubly_masked: None,
        })
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

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: InitiatorState::Created,
            masked_elements: None,
            responder_masked: None,
            our_doubly_masked: None,
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

        Ok(MaskedSetOffer::new(&self.session_id, masked))
    }

    /// Process the reply message and compute the intersection.
    ///
    /// Must be called in AwaitingReply state.
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

        Ok(IntersectionReveal::new(&self.session_id, doubly_masked))
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
    masked_elements: Option<Vec<MaskedElement>>,
    initiator_doubly_masked: Option<Vec<MaskedElement>>,
}

impl ResponderSession {
    /// Create a new responder session.
    pub fn new(
        session_id: impl Into<String>,
        fact_set: FactSet,
        mode: IntersectionMode,
    ) -> Result<Self, SessionError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(SessionError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let original_ids = fact_set.ids();

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: ResponderState::Created,
            masked_elements: None,
            initiator_doubly_masked: None,
        })
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

        Ok(Self {
            session_id: session_id.into(),
            secret,
            fact_set,
            original_ids,
            mode,
            state: ResponderState::Created,
            masked_elements: None,
            initiator_doubly_masked: None,
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

    /// Process the offer message and generate the reply.
    ///
    /// Must be called in Created state.
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

        Ok(MaskedSetReply::new(
            &self.session_id,
            our_masked,
            initiator_doubly_masked,
        ))
    }

    /// Process the reveal message and compute the intersection.
    ///
    /// Must be called in ReplySent state.
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
