//! Fact ID generation and FactSet management.
//!
//! Placeholder for commit 2.

/// A 32-byte content-addressed fact identifier.
pub type FactId = [u8; 32];

/// A set of fact IDs with a merkle-style root commitment.
#[derive(Debug, Clone)]
pub struct FactSet {
    ids: Vec<FactId>,
    root: [u8; 32],
}

impl FactSet {
    /// Create an empty FactSet (placeholder).
    pub fn empty() -> Self {
        Self {
            ids: Vec::new(),
            root: [0u8; 32],
        }
    }

    /// Get the set root commitment.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get the fact IDs.
    pub fn ids(&self) -> &[FactId] {
        &self.ids
    }
}
