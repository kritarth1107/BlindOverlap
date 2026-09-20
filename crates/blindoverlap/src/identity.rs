//! Party identity management with Ed25519 keypairs.
//!
//! This module provides long-lived party identities for BlindOverlap sessions.
//! Each party has an Ed25519 keypair that can be used to sign wire messages
//! and authenticate the channel.
//!
//! ## Security Note
//!
//! Party identity provides **channel authentication only**. It does NOT upgrade
//! the PSI protocol from semi-honest to malicious security. The identity system
//! ensures you are communicating with the expected peer, but the peer may still
//! deviate from the protocol.
//!
//! ## Domain Separation
//!
//! All signatures use the domain tag `BlindOverlap:PartyIdentity:v1` to prevent
//! cross-protocol signature reuse.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Domain separation tag for party identity signatures.
pub const IDENTITY_DOMAIN: &[u8] = b"BlindOverlap:PartyIdentity:v1";

/// Errors that can occur during identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Invalid keypair format or encoding.
    #[error("invalid keypair: {0}")]
    InvalidKeypair(String),
    /// Invalid public key format or encoding.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Invalid signature format.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,
    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A party's public identity (Ed25519 public key).
///
/// This is the shareable part of a party's identity that can be used
/// to verify signatures and identify peers.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicIdentity {
    bytes: [u8; 32],
}

impl PublicIdentity {
    /// Create a public identity from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { bytes })
    }

    /// Create a public identity from hex-encoded bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, IdentityError> {
        let bytes: [u8; 32] = hex::decode(hex_str)?
            .try_into()
            .map_err(|_| IdentityError::InvalidPublicKey("expected 32 bytes".to_string()))?;
        Self::from_bytes(bytes)
    }

    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get the hex-encoded public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Verify a signature over a message with domain separation.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(&self.bytes)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
        let sig =
            Signature::from_bytes(signature);

        let mut domain_msg = Vec::with_capacity(IDENTITY_DOMAIN.len() + message.len());
        domain_msg.extend_from_slice(IDENTITY_DOMAIN);
        domain_msg.extend_from_slice(message);

        verifying_key
            .verify(&domain_msg, &sig)
            .map_err(|_| IdentityError::VerificationFailed)
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicIdentity({})", self.to_hex())
    }
}

impl fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for PublicIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A party's full identity with signing capability.
///
/// Contains both the secret signing key and the public verifying key.
/// This should be stored securely and not shared.
pub struct PartyIdentity {
    signing_key: SigningKey,
}

impl PartyIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create an identity from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Create an identity from hex-encoded seed bytes.
    pub fn from_seed_hex(hex_str: &str) -> Result<Self, IdentityError> {
        let seed: [u8; 32] = hex::decode(hex_str)?
            .try_into()
            .map_err(|_| IdentityError::InvalidKeypair("expected 32 bytes".to_string()))?;
        Ok(Self::from_seed(&seed))
    }

    /// Get the public identity (shareable).
    pub fn public(&self) -> PublicIdentity {
        let bytes = self.signing_key.verifying_key().to_bytes();
        PublicIdentity { bytes }
    }

    /// Get the seed bytes (secret).
    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the seed as hex (secret).
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed())
    }

    /// Sign a message with domain separation.
    ///
    /// The signature includes the domain tag to prevent cross-protocol reuse.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut domain_msg = Vec::with_capacity(IDENTITY_DOMAIN.len() + message.len());
        domain_msg.extend_from_slice(IDENTITY_DOMAIN);
        domain_msg.extend_from_slice(message);

        self.signing_key.sign(&domain_msg).to_bytes()
    }

    /// Load identity from a JSON file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, IdentityError> {
        let contents = std::fs::read_to_string(path)?;
        let stored: StoredIdentity = serde_json::from_str(&contents)?;
        Self::from_seed_hex(&stored.seed_hex)
    }

    /// Save identity to a JSON file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), IdentityError> {
        let stored = StoredIdentity {
            version: 1,
            public_key_hex: self.public().to_hex(),
            seed_hex: self.seed_hex(),
        };
        let json = serde_json::to_string_pretty(&stored)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load only the public key from an identity JSON file.
    pub fn load_public_from_file(path: &std::path::Path) -> Result<PublicIdentity, IdentityError> {
        let contents = std::fs::read_to_string(path)?;
        let stored: StoredIdentity = serde_json::from_str(&contents)?;
        PublicIdentity::from_hex(&stored.public_key_hex)
    }
}

impl fmt::Debug for PartyIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PartyIdentity(pubkey={})", self.public().to_hex())
    }
}

/// JSON-serializable stored identity format.
#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    public_key_hex: String,
    seed_hex: String,
}

/// Verify a signature from a public key over a message.
pub fn verify_signature(
    public_key: &PublicIdentity,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), IdentityError> {
    public_key.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = PartyIdentity::generate();
        let public = identity.public();

        assert_eq!(public.as_bytes().len(), 32);
        assert!(!public.to_hex().is_empty());
    }

    #[test]
    fn test_identity_from_seed() {
        let seed = [42u8; 32];
        let id1 = PartyIdentity::from_seed(&seed);
        let id2 = PartyIdentity::from_seed(&seed);

        assert_eq!(id1.public(), id2.public());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let identity = PartyIdentity::generate();
        let message = b"test message";

        let signature = identity.sign(message);
        let public = identity.public();

        assert!(public.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let identity = PartyIdentity::generate();
        let signature = identity.sign(b"original message");
        let public = identity.public();

        assert!(public.verify(b"different message", &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let identity1 = PartyIdentity::generate();
        let identity2 = PartyIdentity::generate();
        let message = b"test message";

        let signature = identity1.sign(message);

        assert!(identity2.public().verify(message, &signature).is_err());
    }

    #[test]
    fn test_public_identity_hex_roundtrip() {
        let identity = PartyIdentity::generate();
        let public = identity.public();
        let hex_str = public.to_hex();

        let restored = PublicIdentity::from_hex(&hex_str).unwrap();
        assert_eq!(public, restored);
    }

    #[test]
    fn test_public_identity_serialization() {
        let identity = PartyIdentity::generate();
        let public = identity.public();

        let json = serde_json::to_string(&public).unwrap();
        let restored: PublicIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(public, restored);
    }

    #[test]
    fn test_identity_seed_hex() {
        let seed_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let identity = PartyIdentity::from_seed_hex(seed_hex).unwrap();

        assert_eq!(identity.seed_hex(), seed_hex);
    }

    #[test]
    fn test_invalid_public_key() {
        let result = PublicIdentity::from_hex("invalid");
        assert!(result.is_err());

        let result = PublicIdentity::from_hex(&hex::encode([0u8; 31]));
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_uniqueness() {
        let id1 = PartyIdentity::generate();
        let id2 = PartyIdentity::generate();

        assert_ne!(id1.public(), id2.public());
    }
}
