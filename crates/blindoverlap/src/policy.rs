//! Session policy profiles for gating online session bootstrap.
//!
//! Provides `PolicyProfile` — a named, serializable session policy that can be checked
//! against offered session parameters before establishing a PSI session.
//!
//! # Security Note
//!
//! Policy profiles are a **local policy gate**, not a cryptographic upgrade of the PSI.
//! They help enforce organizational policies (e.g., "always require trusted peer",
//! "minimum padding size") but do NOT change the semi-honest security model.
//!
//! A policy pass means the offered parameters meet your stated requirements.
//! It does NOT guarantee the peer will follow the protocol correctly.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Domain tag for policy-related operations.
pub const POLICY_PROFILE_DOMAIN: &str = "BlindOverlap:PolicyProfile:v1";

/// Errors that can occur during policy operations.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy name is required but missing.
    #[error("policy name is required")]
    MissingName,
    /// Trusted peer is required by policy but not provided.
    #[error("policy '{policy}' requires a trusted peer but none provided")]
    TrustedPeerRequired {
        /// Policy name.
        policy: String,
    },
    /// Padding is below minimum required by policy.
    #[error("policy '{policy}' requires minimum padding of {required}, but offered {offered}")]
    InsufficientPadding {
        /// Policy name.
        policy: String,
        /// Required minimum padding.
        required: usize,
        /// Offered padding.
        offered: usize,
    },
    /// TTL exceeds maximum allowed by policy.
    #[error("policy '{policy}' allows maximum TTL of {max_secs}s, but offered {offered_secs}s")]
    TtlTooLong {
        /// Policy name.
        policy: String,
        /// Maximum allowed TTL.
        max_secs: u64,
        /// Offered TTL.
        offered_secs: u64,
    },
    /// Lease is required by policy but not provided.
    #[error("policy '{policy}' requires a session lease")]
    LeaseRequired {
        /// Policy name.
        policy: String,
    },
    /// Invite is required by policy but not provided.
    #[error("policy '{policy}' requires an invite ticket")]
    InviteRequired {
        /// Policy name.
        policy: String,
    },
    /// Intersection mode is not allowed by policy.
    #[error("policy '{policy}' only allows cardinality mode, but intersection was requested")]
    IntersectionNotAllowed {
        /// Policy name.
        policy: String,
    },
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A named session policy profile for gating session bootstrap.
///
/// Policy profiles define constraints that must be met before establishing
/// a PSI session. They provide a declarative way to enforce organizational
/// security policies.
///
/// # Example
///
/// ```
/// use blindoverlap::PolicyProfile;
///
/// // Create a strict policy requiring trusted peers and minimum padding
/// let policy = PolicyProfile::builder("strict-production")
///     .require_trusted_peer(true)
///     .min_pad_to(256)
///     .max_ttl_secs(60)
///     .require_invite(true)
///     .build();
///
/// // Later, check session parameters against the policy
/// let params = blindoverlap::SessionParams {
///     has_trusted_peer: true,
///     pad_to: Some(256),
///     ttl_secs: 60,
///     has_lease: false,
///     has_invite: true,
///     is_intersection_mode: true,
/// };
///
/// assert!(policy.check(&params).is_ok());
/// ```
///
/// # Honest Scope
///
/// Policy profiles are a **local policy gate**, not a cryptographic upgrade.
/// They enforce your requirements before you engage, but do not change
/// the semi-honest security model of the underlying PSI protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProfile {
    /// Human-readable policy name (e.g., "production", "dev", "strict").
    pub name: String,

    /// Require a trusted peer from the peerbook before session start.
    #[serde(default)]
    pub require_trusted_peer: bool,

    /// Minimum padding size (in elements). None means no minimum.
    #[serde(default)]
    pub min_pad_to: Option<usize>,

    /// Maximum TTL in seconds. None means no maximum.
    #[serde(default)]
    pub max_ttl_secs: Option<u64>,

    /// Require a valid session lease before session start.
    #[serde(default)]
    pub require_lease: bool,

    /// Require a valid invite ticket before session start.
    #[serde(default)]
    pub require_invite: bool,

    /// Only allow cardinality mode (disallow intersection mode).
    #[serde(default)]
    pub allow_cardinality_only: bool,
}

impl PolicyProfile {
    /// Create a new policy profile with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            require_trusted_peer: false,
            min_pad_to: None,
            max_ttl_secs: None,
            require_lease: false,
            require_invite: false,
            allow_cardinality_only: false,
        }
    }

    /// Create a builder for constructing a policy profile.
    pub fn builder(name: impl Into<String>) -> PolicyProfileBuilder {
        PolicyProfileBuilder::new(name)
    }

    /// Create a permissive "default" policy that allows everything.
    pub fn permissive(name: impl Into<String>) -> Self {
        Self::new(name)
    }

    /// Create a strict policy with common production defaults.
    pub fn strict(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            require_trusted_peer: true,
            min_pad_to: Some(64),
            max_ttl_secs: Some(300),
            require_lease: false,
            require_invite: true,
            allow_cardinality_only: false,
        }
    }

    /// Check session parameters against this policy.
    ///
    /// Returns `Ok(())` if all constraints are satisfied, or a `PolicyError`
    /// describing the first violation found.
    pub fn check(&self, params: &SessionParams) -> Result<(), PolicyError> {
        if self.require_trusted_peer && !params.has_trusted_peer {
            return Err(PolicyError::TrustedPeerRequired {
                policy: self.name.clone(),
            });
        }

        if let Some(min_pad) = self.min_pad_to {
            let offered = params.pad_to.unwrap_or(0);
            if offered < min_pad {
                return Err(PolicyError::InsufficientPadding {
                    policy: self.name.clone(),
                    required: min_pad,
                    offered,
                });
            }
        }

        if let Some(max_ttl) = self.max_ttl_secs {
            if params.ttl_secs > max_ttl {
                return Err(PolicyError::TtlTooLong {
                    policy: self.name.clone(),
                    max_secs: max_ttl,
                    offered_secs: params.ttl_secs,
                });
            }
        }

        if self.require_lease && !params.has_lease {
            return Err(PolicyError::LeaseRequired {
                policy: self.name.clone(),
            });
        }

        if self.require_invite && !params.has_invite {
            return Err(PolicyError::InviteRequired {
                policy: self.name.clone(),
            });
        }

        if self.allow_cardinality_only && params.is_intersection_mode {
            return Err(PolicyError::IntersectionNotAllowed {
                policy: self.name.clone(),
            });
        }

        Ok(())
    }

    /// Enforce policy (alias for check that reads more naturally in code).
    pub fn enforce(&self, params: &SessionParams) -> Result<(), PolicyError> {
        self.check(params)
    }

    /// Load a policy profile from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, PolicyError> {
        let contents = std::fs::read_to_string(path)?;
        let profile: Self = serde_json::from_str(&contents)?;
        Ok(profile)
    }

    /// Save this policy profile to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), PolicyError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, PolicyError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Serialize to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> Result<String, PolicyError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        Ok(serde_json::from_str(json)?)
    }
}

impl Default for PolicyProfile {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Builder for constructing PolicyProfile instances.
#[derive(Debug, Clone)]
pub struct PolicyProfileBuilder {
    profile: PolicyProfile,
}

impl PolicyProfileBuilder {
    /// Create a new builder with the given policy name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            profile: PolicyProfile::new(name),
        }
    }

    /// Set whether a trusted peer is required.
    pub fn require_trusted_peer(mut self, required: bool) -> Self {
        self.profile.require_trusted_peer = required;
        self
    }

    /// Set the minimum padding size.
    pub fn min_pad_to(mut self, min: usize) -> Self {
        self.profile.min_pad_to = Some(min);
        self
    }

    /// Set the maximum TTL in seconds.
    pub fn max_ttl_secs(mut self, max: u64) -> Self {
        self.profile.max_ttl_secs = Some(max);
        self
    }

    /// Set whether a session lease is required.
    pub fn require_lease(mut self, required: bool) -> Self {
        self.profile.require_lease = required;
        self
    }

    /// Set whether an invite ticket is required.
    pub fn require_invite(mut self, required: bool) -> Self {
        self.profile.require_invite = required;
        self
    }

    /// Set whether only cardinality mode is allowed.
    pub fn allow_cardinality_only(mut self, only: bool) -> Self {
        self.profile.allow_cardinality_only = only;
        self
    }

    /// Build the policy profile.
    pub fn build(self) -> PolicyProfile {
        self.profile
    }
}

/// Session parameters to check against a policy profile.
///
/// This struct captures the relevant parameters of a prospective session
/// for policy validation.
#[derive(Debug, Clone, Default)]
pub struct SessionParams {
    /// Whether a trusted peer is available (e.g., from peerbook).
    pub has_trusted_peer: bool,

    /// Padding size (in elements), if any.
    pub pad_to: Option<usize>,

    /// Session TTL in seconds.
    pub ttl_secs: u64,

    /// Whether a session lease is available.
    pub has_lease: bool,

    /// Whether an invite ticket is available.
    pub has_invite: bool,

    /// Whether intersection mode is requested (vs cardinality).
    pub is_intersection_mode: bool,
}

impl SessionParams {
    /// Create new session parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for constructing session parameters.
    pub fn builder() -> SessionParamsBuilder {
        SessionParamsBuilder::new()
    }
}

/// Builder for constructing SessionParams instances.
#[derive(Debug, Clone, Default)]
pub struct SessionParamsBuilder {
    params: SessionParams,
}

impl SessionParamsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether a trusted peer is available.
    pub fn has_trusted_peer(mut self, has: bool) -> Self {
        self.params.has_trusted_peer = has;
        self
    }

    /// Set the padding size.
    pub fn pad_to(mut self, pad: usize) -> Self {
        self.params.pad_to = Some(pad);
        self
    }

    /// Set the session TTL.
    pub fn ttl_secs(mut self, ttl: u64) -> Self {
        self.params.ttl_secs = ttl;
        self
    }

    /// Set whether a session lease is available.
    pub fn has_lease(mut self, has: bool) -> Self {
        self.params.has_lease = has;
        self
    }

    /// Set whether an invite ticket is available.
    pub fn has_invite(mut self, has: bool) -> Self {
        self.params.has_invite = has;
        self
    }

    /// Set whether intersection mode is requested.
    pub fn is_intersection_mode(mut self, is_intersection: bool) -> Self {
        self.params.is_intersection_mode = is_intersection;
        self
    }

    /// Build the session parameters.
    pub fn build(self) -> SessionParams {
        self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_policy_profile_creation() {
        let policy = PolicyProfile::new("test");
        assert_eq!(policy.name, "test");
        assert!(!policy.require_trusted_peer);
        assert!(policy.min_pad_to.is_none());
        assert!(policy.max_ttl_secs.is_none());
        assert!(!policy.require_lease);
        assert!(!policy.require_invite);
        assert!(!policy.allow_cardinality_only);
    }

    #[test]
    fn test_policy_profile_builder() {
        let policy = PolicyProfile::builder("strict")
            .require_trusted_peer(true)
            .min_pad_to(128)
            .max_ttl_secs(60)
            .require_lease(true)
            .require_invite(true)
            .allow_cardinality_only(true)
            .build();

        assert_eq!(policy.name, "strict");
        assert!(policy.require_trusted_peer);
        assert_eq!(policy.min_pad_to, Some(128));
        assert_eq!(policy.max_ttl_secs, Some(60));
        assert!(policy.require_lease);
        assert!(policy.require_invite);
        assert!(policy.allow_cardinality_only);
    }

    #[test]
    fn test_permissive_policy_passes_all() {
        let policy = PolicyProfile::permissive("dev");

        let params = SessionParams {
            has_trusted_peer: false,
            pad_to: None,
            ttl_secs: 1000,
            has_lease: false,
            has_invite: false,
            is_intersection_mode: true,
        };

        assert!(policy.check(&params).is_ok());
    }

    #[test]
    fn test_strict_policy() {
        let policy = PolicyProfile::strict("prod");

        assert!(policy.require_trusted_peer);
        assert_eq!(policy.min_pad_to, Some(64));
        assert_eq!(policy.max_ttl_secs, Some(300));
        assert!(policy.require_invite);
    }

    #[test]
    fn test_trusted_peer_required() {
        let policy = PolicyProfile::builder("test")
            .require_trusted_peer(true)
            .build();

        let params = SessionParams {
            has_trusted_peer: false,
            ..Default::default()
        };

        let err = policy.check(&params).unwrap_err();
        assert!(matches!(err, PolicyError::TrustedPeerRequired { .. }));

        let params_ok = SessionParams {
            has_trusted_peer: true,
            ..Default::default()
        };
        assert!(policy.check(&params_ok).is_ok());
    }

    #[test]
    fn test_min_padding_required() {
        let policy = PolicyProfile::builder("test").min_pad_to(64).build();

        let params_none = SessionParams::default();
        let err = policy.check(&params_none).unwrap_err();
        assert!(matches!(err, PolicyError::InsufficientPadding { .. }));

        let params_small = SessionParams {
            pad_to: Some(32),
            ..Default::default()
        };
        let err = policy.check(&params_small).unwrap_err();
        assert!(matches!(err, PolicyError::InsufficientPadding { .. }));

        let params_ok = SessionParams {
            pad_to: Some(64),
            ..Default::default()
        };
        assert!(policy.check(&params_ok).is_ok());

        let params_large = SessionParams {
            pad_to: Some(128),
            ..Default::default()
        };
        assert!(policy.check(&params_large).is_ok());
    }

    #[test]
    fn test_max_ttl_enforced() {
        let policy = PolicyProfile::builder("test").max_ttl_secs(60).build();

        let params_over = SessionParams {
            ttl_secs: 120,
            ..Default::default()
        };
        let err = policy.check(&params_over).unwrap_err();
        assert!(matches!(err, PolicyError::TtlTooLong { .. }));

        let params_ok = SessionParams {
            ttl_secs: 60,
            ..Default::default()
        };
        assert!(policy.check(&params_ok).is_ok());

        let params_under = SessionParams {
            ttl_secs: 30,
            ..Default::default()
        };
        assert!(policy.check(&params_under).is_ok());
    }

    #[test]
    fn test_lease_required() {
        let policy = PolicyProfile::builder("test").require_lease(true).build();

        let params_no = SessionParams {
            has_lease: false,
            ..Default::default()
        };
        let err = policy.check(&params_no).unwrap_err();
        assert!(matches!(err, PolicyError::LeaseRequired { .. }));

        let params_ok = SessionParams {
            has_lease: true,
            ..Default::default()
        };
        assert!(policy.check(&params_ok).is_ok());
    }

    #[test]
    fn test_invite_required() {
        let policy = PolicyProfile::builder("test").require_invite(true).build();

        let params_no = SessionParams {
            has_invite: false,
            ..Default::default()
        };
        let err = policy.check(&params_no).unwrap_err();
        assert!(matches!(err, PolicyError::InviteRequired { .. }));

        let params_ok = SessionParams {
            has_invite: true,
            ..Default::default()
        };
        assert!(policy.check(&params_ok).is_ok());
    }

    #[test]
    fn test_cardinality_only() {
        let policy = PolicyProfile::builder("test")
            .allow_cardinality_only(true)
            .build();

        let params_intersection = SessionParams {
            is_intersection_mode: true,
            ..Default::default()
        };
        let err = policy.check(&params_intersection).unwrap_err();
        assert!(matches!(err, PolicyError::IntersectionNotAllowed { .. }));

        let params_ok = SessionParams {
            is_intersection_mode: false,
            ..Default::default()
        };
        assert!(policy.check(&params_ok).is_ok());
    }

    #[test]
    fn test_enforce_alias() {
        let policy = PolicyProfile::builder("test")
            .require_trusted_peer(true)
            .build();

        let params = SessionParams {
            has_trusted_peer: false,
            ..Default::default()
        };

        // enforce() should behave same as check()
        assert!(policy.enforce(&params).is_err());

        let params_ok = SessionParams {
            has_trusted_peer: true,
            ..Default::default()
        };
        assert!(policy.enforce(&params_ok).is_ok());
    }

    #[test]
    fn test_policy_json_roundtrip() {
        let policy = PolicyProfile::builder("test-json")
            .require_trusted_peer(true)
            .min_pad_to(256)
            .max_ttl_secs(120)
            .build();

        let json = policy.to_json_pretty().unwrap();
        let restored = PolicyProfile::from_json(&json).unwrap();

        assert_eq!(restored.name, policy.name);
        assert_eq!(restored.require_trusted_peer, policy.require_trusted_peer);
        assert_eq!(restored.min_pad_to, policy.min_pad_to);
        assert_eq!(restored.max_ttl_secs, policy.max_ttl_secs);
    }

    #[test]
    fn test_policy_file_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.json");

        let policy = PolicyProfile::builder("file-test")
            .require_invite(true)
            .allow_cardinality_only(true)
            .build();

        policy.save_to_file(&path).unwrap();
        let restored = PolicyProfile::load_from_file(&path).unwrap();

        assert_eq!(restored.name, policy.name);
        assert_eq!(restored.require_invite, policy.require_invite);
        assert_eq!(
            restored.allow_cardinality_only,
            policy.allow_cardinality_only
        );
    }

    #[test]
    fn test_session_params_builder() {
        let params = SessionParams::builder()
            .has_trusted_peer(true)
            .pad_to(128)
            .ttl_secs(60)
            .has_lease(true)
            .has_invite(true)
            .is_intersection_mode(true)
            .build();

        assert!(params.has_trusted_peer);
        assert_eq!(params.pad_to, Some(128));
        assert_eq!(params.ttl_secs, 60);
        assert!(params.has_lease);
        assert!(params.has_invite);
        assert!(params.is_intersection_mode);
    }

    #[test]
    fn test_multiple_constraints() {
        let policy = PolicyProfile::builder("multi")
            .require_trusted_peer(true)
            .min_pad_to(64)
            .max_ttl_secs(300)
            .require_invite(true)
            .build();

        // Fails first check (trusted peer)
        let params1 = SessionParams {
            has_trusted_peer: false,
            pad_to: Some(128),
            ttl_secs: 60,
            has_lease: false,
            has_invite: true,
            is_intersection_mode: true,
        };
        let err = policy.check(&params1).unwrap_err();
        assert!(matches!(err, PolicyError::TrustedPeerRequired { .. }));

        // All constraints satisfied
        let params_ok = SessionParams {
            has_trusted_peer: true,
            pad_to: Some(128),
            ttl_secs: 60,
            has_lease: false,
            has_invite: true,
            is_intersection_mode: true,
        };
        assert!(policy.check(&params_ok).is_ok());
    }

    #[test]
    fn test_default_policy() {
        let policy = PolicyProfile::default();
        assert_eq!(policy.name, "default");

        // Should pass any params
        let params = SessionParams::default();
        assert!(policy.check(&params).is_ok());
    }
}
