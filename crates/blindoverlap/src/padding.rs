//! Set-size padding for hiding cardinality from wire message length.
//!
//! Pads FactSets or masked element arrays to a target size using deterministic
//! dummy IDs derived from a domain-separated PRF (HMAC-SHA256).
//!
//! # Security Note
//!
//! **This is best-effort padding under the semi-honest security model.**
//!
//! - Padding hides the real set size from wire message length analysis
//! - A malicious party could still learn information through protocol deviations
//! - Does NOT provide full size-hiding against active adversaries
//! - The padding secret should be kept confidential
//!
//! For stronger guarantees, consider padding to fixed power-of-2 sizes or
//! using protocols with inherent size-hiding properties.

use crate::fact_id::FactId;
use crate::protocol::MaskedElement;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag for padding PRF.
const PADDING_DOMAIN: &[u8] = b"BlindOverlap:Padding:v1";

/// Errors that can occur during padding operations.
#[derive(Debug, Error)]
pub enum PaddingError {
    /// Target size is smaller than current size.
    #[error("target size {target} is smaller than current size {current}")]
    TargetTooSmall {
        /// Current set size.
        current: usize,
        /// Requested target size.
        target: usize,
    },
    /// Target size exceeds maximum allowed.
    #[error("target size {0} exceeds maximum {1}")]
    TargetTooLarge(usize, usize),
}

/// Configuration for padding operations.
#[derive(Debug, Clone)]
pub struct PaddingConfig {
    /// Target size to pad to.
    pub target_size: usize,
    /// Secret key for deterministic padding (32 bytes recommended).
    pub padding_secret: Vec<u8>,
}

impl PaddingConfig {
    /// Create a new padding configuration.
    pub fn new(target_size: usize, padding_secret: impl Into<Vec<u8>>) -> Self {
        Self {
            target_size,
            padding_secret: padding_secret.into(),
        }
    }

    /// Create configuration with a random padding secret.
    pub fn with_random_secret(target_size: usize) -> Self {
        use rand::RngCore;
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::new(target_size, secret)
    }
}

/// Generate deterministic dummy fact IDs for padding.
///
/// Uses HMAC-SHA256 with domain separation to generate unique dummy IDs.
/// The same inputs will always produce the same dummy IDs.
pub fn generate_dummy_fact_ids(
    padding_secret: &[u8],
    session_context: &[u8],
    count: usize,
) -> Vec<FactId> {
    let mut mac =
        HmacSha256::new_from_slice(padding_secret).expect("HMAC can take key of any size");

    mac.update(PADDING_DOMAIN);
    mac.update(b":dummy_ids:");
    mac.update(session_context);

    (0..count)
        .map(|i| {
            let mut inner_mac = mac.clone();
            inner_mac.update(&(i as u64).to_le_bytes());
            let result = inner_mac.finalize();
            let bytes: [u8; 32] = result.into_bytes().into();
            bytes
        })
        .collect()
}

/// Generate deterministic dummy masked elements for padding.
///
/// Uses HMAC-SHA256 with domain separation to generate unique dummy elements.
/// These are distinguishable from real masked elements only by the padding holder.
pub fn generate_dummy_masked_elements(
    padding_secret: &[u8],
    session_context: &[u8],
    count: usize,
) -> Vec<MaskedElement> {
    let mut mac =
        HmacSha256::new_from_slice(padding_secret).expect("HMAC can take key of any size");

    mac.update(PADDING_DOMAIN);
    mac.update(b":masked_elements:");
    mac.update(session_context);

    (0..count)
        .map(|i| {
            let mut inner_mac = mac.clone();
            inner_mac.update(&(i as u64).to_le_bytes());
            let result = inner_mac.finalize();
            let bytes: [u8; 32] = result.into_bytes().into();
            bytes
        })
        .collect()
}

/// Pad a vector of fact IDs to the target size.
///
/// Returns a new vector with dummy IDs appended.
pub fn pad_fact_ids(
    fact_ids: &[FactId],
    config: &PaddingConfig,
    session_context: &[u8],
) -> Result<Vec<FactId>, PaddingError> {
    if fact_ids.len() > config.target_size {
        return Err(PaddingError::TargetTooSmall {
            current: fact_ids.len(),
            target: config.target_size,
        });
    }

    let padding_needed = config.target_size - fact_ids.len();
    let dummies = generate_dummy_fact_ids(&config.padding_secret, session_context, padding_needed);

    let mut result = fact_ids.to_vec();
    result.extend(dummies);
    Ok(result)
}

/// Pad a vector of masked elements to the target size.
///
/// Returns a new vector with dummy elements appended.
pub fn pad_masked_elements(
    elements: &[MaskedElement],
    config: &PaddingConfig,
    session_context: &[u8],
) -> Result<Vec<MaskedElement>, PaddingError> {
    if elements.len() > config.target_size {
        return Err(PaddingError::TargetTooSmall {
            current: elements.len(),
            target: config.target_size,
        });
    }

    let padding_needed = config.target_size - elements.len();
    let dummies =
        generate_dummy_masked_elements(&config.padding_secret, session_context, padding_needed);

    let mut result = elements.to_vec();
    result.extend(dummies);
    Ok(result)
}

/// Strip dummy elements from a padded result.
///
/// Removes elements that match the padding dummies based on the original count.
/// Returns the first `original_count` elements, assuming padding was appended.
pub fn strip_padding<T: Clone>(padded: &[T], original_count: usize) -> Vec<T> {
    padded.iter().take(original_count).cloned().collect()
}

/// Compute the next power of 2 >= n, useful for standardized padding sizes.
pub fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

/// Standard padding sizes for common use cases.
pub mod standard_sizes {
    /// Small set padding target.
    pub const SMALL: usize = 64;
    /// Medium set padding target.
    pub const MEDIUM: usize = 256;
    /// Large set padding target.
    pub const LARGE: usize = 1024;
    /// Maximum set padding target.
    pub const MAX: usize = 4096;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_id::fact_id_from_json;
    use serde_json::json;

    #[test]
    fn test_generate_dummy_fact_ids_deterministic() {
        let secret = b"test-secret";
        let context = b"session-123";

        let ids1 = generate_dummy_fact_ids(secret, context, 5);
        let ids2 = generate_dummy_fact_ids(secret, context, 5);

        assert_eq!(ids1, ids2);
    }

    #[test]
    fn test_generate_dummy_fact_ids_different_context() {
        let secret = b"test-secret";

        let ids1 = generate_dummy_fact_ids(secret, b"session-a", 5);
        let ids2 = generate_dummy_fact_ids(secret, b"session-b", 5);

        assert_ne!(ids1, ids2);
    }

    #[test]
    fn test_generate_dummy_fact_ids_different_secret() {
        let context = b"session-123";

        let ids1 = generate_dummy_fact_ids(b"secret-a", context, 5);
        let ids2 = generate_dummy_fact_ids(b"secret-b", context, 5);

        assert_ne!(ids1, ids2);
    }

    #[test]
    fn test_generate_dummy_fact_ids_unique() {
        let secret = b"test-secret";
        let context = b"session-123";

        let ids = generate_dummy_fact_ids(secret, context, 100);
        let unique: std::collections::HashSet<_> = ids.iter().collect();

        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn test_pad_fact_ids() {
        let real_ids: Vec<FactId> = vec![
            fact_id_from_json(&json!({"x": 1})),
            fact_id_from_json(&json!({"x": 2})),
        ];
        let config = PaddingConfig::new(10, b"secret".to_vec());

        let padded = pad_fact_ids(&real_ids, &config, b"ctx").unwrap();

        assert_eq!(padded.len(), 10);
        assert_eq!(&padded[..2], &real_ids);
    }

    #[test]
    fn test_pad_fact_ids_exact_size() {
        let real_ids: Vec<FactId> = (0..5)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                id
            })
            .collect();
        let config = PaddingConfig::new(5, b"secret".to_vec());

        let padded = pad_fact_ids(&real_ids, &config, b"ctx").unwrap();

        assert_eq!(padded.len(), 5);
        assert_eq!(padded, real_ids);
    }

    #[test]
    fn test_pad_fact_ids_target_too_small() {
        let real_ids: Vec<FactId> = (0..10)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                id
            })
            .collect();
        let config = PaddingConfig::new(5, b"secret".to_vec());

        let err = pad_fact_ids(&real_ids, &config, b"ctx").unwrap_err();
        assert!(matches!(err, PaddingError::TargetTooSmall { .. }));
    }

    #[test]
    fn test_pad_masked_elements() {
        let real_elements: Vec<MaskedElement> = (0..3)
            .map(|i| {
                let mut elem = [0u8; 32];
                elem[0] = i;
                elem
            })
            .collect();
        let config = PaddingConfig::new(8, b"secret".to_vec());

        let padded = pad_masked_elements(&real_elements, &config, b"ctx").unwrap();

        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[..3], &real_elements);
    }

    #[test]
    fn test_strip_padding() {
        let original = vec![1, 2, 3];
        let padded = vec![1, 2, 3, 100, 101, 102];

        let stripped = strip_padding(&padded, 3);

        assert_eq!(stripped, original);
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(100), 128);
        assert_eq!(next_power_of_two(1000), 1024);
    }

    #[test]
    fn test_padding_config_random() {
        let config1 = PaddingConfig::with_random_secret(100);
        let config2 = PaddingConfig::with_random_secret(100);

        assert_ne!(config1.padding_secret, config2.padding_secret);
        assert_eq!(config1.padding_secret.len(), 32);
    }

    #[test]
    fn test_padded_length_invariance() {
        let config = PaddingConfig::new(100, b"secret".to_vec());

        for size in [0, 10, 50, 99, 100] {
            let ids: Vec<FactId> = (0..size)
                .map(|i| {
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    id
                })
                .collect();

            let padded = pad_fact_ids(&ids, &config, b"ctx").unwrap();
            assert_eq!(padded.len(), 100, "size {size} should pad to 100");
        }
    }

    #[test]
    fn test_dummy_ids_not_collide_with_real() {
        let secret = b"test-secret";
        let context = b"session";

        let real_id = fact_id_from_json(&json!({"real": "fact"}));
        let dummies = generate_dummy_fact_ids(secret, context, 1000);

        assert!(!dummies.contains(&real_id));
    }
}
