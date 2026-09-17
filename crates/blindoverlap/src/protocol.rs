//! PSI protocol implementation.
//!
//! Placeholder for commit 3.

use crate::FactSet;

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
        ids: Vec<[u8; 32]>,
        /// Root commitment over the intersection.
        root: [u8; 32],
    },
    /// Cardinality-only result.
    Cardinality {
        /// Number of intersecting elements.
        count: usize,
    },
}

/// PSI protocol handler (placeholder).
pub struct PsiProtocol;

impl PsiProtocol {
    /// Create a new protocol instance.
    pub fn new() -> Self {
        Self
    }

    /// Execute PSI between two local fact sets (placeholder).
    pub fn intersect(&self, _a: &FactSet, _b: &FactSet, _mode: IntersectionMode) -> PsiResult {
        PsiResult::Cardinality { count: 0 }
    }
}

impl Default for PsiProtocol {
    fn default() -> Self {
        Self::new()
    }
}
