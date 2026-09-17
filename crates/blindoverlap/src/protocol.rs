//! PSI protocol implementation using Diffie-Hellman based oblivious PRF.
//!
//! This implements a semi-honest DH-PSI protocol where:
//! 1. Each element is hashed to a curve point via hash-to-scalar
//! 2. Parties mask their elements with their secret scalar
//! 3. Parties exchange masked sets and apply their scalar to received elements
//! 4. Intersection is found by comparing doubly-masked values
//!
//! **Security Model:** Semi-honest only. Malicious parties can deviate.

use crate::fact_id::{FactId, FactSet};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// Maximum number of elements supported (toy scale limit).
pub const MAX_SET_SIZE: usize = 4096;

/// Errors that can occur during PSI execution.
#[derive(Debug, Error)]
pub enum PsiError {
    /// Set exceeds maximum allowed size.
    #[error("set size {0} exceeds maximum {MAX_SET_SIZE}")]
    SetTooLarge(usize),
}

/// Intersection mode: full intersection or cardinality only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntersectionMode {
    /// Return the full set of intersecting fact IDs.
    Intersection,
    /// Return only the cardinality (count) of the intersection.
    Cardinality,
}

/// Result of a PSI protocol execution.
#[derive(Debug, Clone)]
pub enum PsiResult {
    /// Full intersection result.
    Intersection {
        /// The intersecting fact IDs.
        ids: Vec<FactId>,
        /// Root commitment over the intersection.
        root: [u8; 32],
    },
    /// Cardinality-only result.
    Cardinality {
        /// Number of intersecting elements.
        count: usize,
    },
}

impl PsiResult {
    /// Get the intersection root or cardinality hash for receipt signing.
    pub fn commitment(&self) -> [u8; 32] {
        match self {
            PsiResult::Intersection { root, .. } => *root,
            PsiResult::Cardinality { count } => {
                let mut hasher = Sha256::new();
                hasher.update(b"BlindOverlap:Cardinality:v1");
                hasher.update((*count as u64).to_le_bytes());
                hasher.finalize().into()
            }
        }
    }
}

/// A masked element: the X25519 shared secret representation after masking.
pub type MaskedElement = [u8; 32];

/// Party state for the PSI protocol.
pub struct PsiParty {
    secret: StaticSecret,
    fact_set: FactSet,
    mode: IntersectionMode,
    original_ids: Vec<FactId>,
}

impl PsiParty {
    /// Create a new PSI party with a random secret.
    pub fn new(fact_set: FactSet, mode: IntersectionMode) -> Result<Self, PsiError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(PsiError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let original_ids = fact_set.ids();

        Ok(Self {
            secret,
            fact_set,
            mode,
            original_ids,
        })
    }

    /// Create a party with a specific secret (for testing).
    pub fn with_secret(
        fact_set: FactSet,
        mode: IntersectionMode,
        secret: [u8; 32],
    ) -> Result<Self, PsiError> {
        if fact_set.len() > MAX_SET_SIZE {
            return Err(PsiError::SetTooLarge(fact_set.len()));
        }

        let secret = StaticSecret::from(secret);
        let original_ids = fact_set.ids();

        Ok(Self {
            secret,
            fact_set,
            mode,
            original_ids,
        })
    }

    /// Get the fact set.
    pub fn fact_set(&self) -> &FactSet {
        &self.fact_set
    }

    /// Compute the singly-masked elements to send to the other party.
    ///
    /// For each element e, computes: secret * H(e) where H(e) is element hashed to a point.
    /// Returns elements in the same order as original_ids for positional mapping.
    pub fn compute_masked_set(&self) -> Vec<MaskedElement> {
        self.original_ids
            .iter()
            .map(|id| {
                let element_point = hash_to_public_key(id);
                let masked = self.secret.diffie_hellman(&element_point);
                masked.to_bytes()
            })
            .collect()
    }

    /// Apply our secret to the other party's masked elements.
    ///
    /// This produces doubly-masked elements that can be compared.
    /// Preserves order for positional mapping.
    pub fn apply_mask_to_received(&self, received: &[MaskedElement]) -> Vec<MaskedElement> {
        received
            .iter()
            .map(|masked| {
                let point = PublicKey::from(*masked);
                let doubly_masked = self.secret.diffie_hellman(&point);
                doubly_masked.to_bytes()
            })
            .collect()
    }

    /// Find intersection given our doubly-masked elements and their doubly-masked elements.
    ///
    /// `our_elements_doubly_masked`: Our elements after both secrets applied (in original order)
    /// `their_elements_doubly_masked`: Their elements after both secrets applied
    pub fn find_intersection(
        &self,
        our_elements_doubly_masked: &[MaskedElement],
        their_elements_doubly_masked: &[MaskedElement],
    ) -> PsiResult {
        let their_set: BTreeSet<MaskedElement> =
            their_elements_doubly_masked.iter().copied().collect();

        let count = our_elements_doubly_masked
            .iter()
            .filter(|m| their_set.contains(*m))
            .count();

        match self.mode {
            IntersectionMode::Cardinality => PsiResult::Cardinality { count },
            IntersectionMode::Intersection => {
                let mut ids = Vec::new();
                for (idx, masked) in our_elements_doubly_masked.iter().enumerate() {
                    if their_set.contains(masked) {
                        if let Some(id) = self.original_ids.get(idx) {
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
}

/// Hash a fact ID to a public key point on Curve25519.
///
/// Uses the fact ID bytes as a scalar (after clamping per X25519 spec).
fn hash_to_public_key(id: &FactId) -> PublicKey {
    let secret = StaticSecret::from(*id);
    PublicKey::from(&secret)
}

/// High-level PSI protocol for two local parties.
///
/// This is an in-process demonstration; real usage would involve
/// network message passing.
pub struct PsiProtocol;

impl PsiProtocol {
    /// Create a new protocol instance.
    pub fn new() -> Self {
        Self
    }

    /// Execute PSI between two local fact sets.
    ///
    /// Returns the intersection result.
    pub fn intersect(
        &self,
        set_a: &FactSet,
        set_b: &FactSet,
        mode: IntersectionMode,
    ) -> Result<PsiResult, PsiError> {
        let party_a = PsiParty::new(set_a.clone(), mode)?;
        let party_b = PsiParty::new(set_b.clone(), mode)?;

        let masked_a = party_a.compute_masked_set();
        let masked_b = party_b.compute_masked_set();

        let doubly_masked_a = party_b.apply_mask_to_received(&masked_a);
        let doubly_masked_b = party_a.apply_mask_to_received(&masked_b);

        let result = party_a.find_intersection(&doubly_masked_a, &doubly_masked_b);

        Ok(result)
    }
}

impl Default for PsiProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_id::fact_id_from_json;
    use serde_json::json;

    fn make_test_set(values: &[serde_json::Value]) -> FactSet {
        FactSet::from_ids(values.iter().map(fact_id_from_json))
    }

    #[test]
    fn test_empty_sets() {
        let protocol = PsiProtocol::new();
        let empty = FactSet::empty();

        let result = protocol
            .intersect(&empty, &empty, IntersectionMode::Intersection)
            .unwrap();

        match result {
            PsiResult::Intersection { ids, .. } => assert!(ids.is_empty()),
            _ => panic!("expected intersection result"),
        }
    }

    #[test]
    fn test_disjoint_sets() {
        let protocol = PsiProtocol::new();
        let set_a = make_test_set(&[json!({"a": 1}), json!({"a": 2})]);
        let set_b = make_test_set(&[json!({"b": 1}), json!({"b": 2})]);

        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        match result {
            PsiResult::Intersection { ids, .. } => assert!(ids.is_empty()),
            _ => panic!("expected intersection result"),
        }
    }

    #[test]
    fn test_equal_sets() {
        let protocol = PsiProtocol::new();
        let values = [json!({"x": 1}), json!({"x": 2}), json!({"x": 3})];
        let set_a = make_test_set(&values);
        let set_b = make_test_set(&values);

        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        match result {
            PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 3),
            _ => panic!("expected intersection result"),
        }
    }

    #[test]
    fn test_partial_overlap() {
        let protocol = PsiProtocol::new();
        let set_a = make_test_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
        let set_b = make_test_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        match result {
            PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 2),
            _ => panic!("expected intersection result"),
        }
    }

    #[test]
    fn test_cardinality_mode() {
        let protocol = PsiProtocol::new();
        let set_a = make_test_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
        let set_b = make_test_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Cardinality)
            .unwrap();

        match result {
            PsiResult::Cardinality { count } => assert_eq!(count, 2),
            _ => panic!("expected cardinality result"),
        }
    }

    #[test]
    fn test_set_too_large() {
        let ids: Vec<FactId> = (0..MAX_SET_SIZE + 1)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                id
            })
            .collect();
        let large_set = FactSet::from_ids(ids);

        let result = PsiParty::new(large_set, IntersectionMode::Intersection);
        assert!(matches!(result, Err(PsiError::SetTooLarge(_))));
    }
}
