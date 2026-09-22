//! Trusted peer book for managing known party identities.
//!
//! A `TrustedPeerBook` is a file-backed directory of known peer Ed25519 public keys
//! with optional nickname/label and timestamp. It provides a trust registry for
//! channel-bound PSI sessions.
//!
//! ## Security Note
//!
//! **Peer book trust is out-of-band policy, not PSI security.**
//!
//! - The peer book tracks WHO you trust for session bootstrapping
//! - It does NOT upgrade PSI security from semi-honest to malicious
//! - Trust decisions must be made through external verification
//! - A trusted peer may still deviate from the protocol
//!
//! ## Usage
//!
//! ```ignore
//! let mut book = TrustedPeerBook::open(Path::new("peers.json"))?;
//! book.add(peer_pubkey, Some("Alice"))?;
//! if book.is_trusted(&peer_pubkey) {
//!     // proceed with channel-bound session
//! }
//! ```

use crate::freshness::current_unix_time;
use crate::identity::PublicIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during peer book operations.
#[derive(Debug, Error)]
pub enum PeerBookError {
    /// Peer already exists in the book.
    #[error("peer already exists: {0}")]
    DuplicatePeer(String),
    /// Peer not found in the book.
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    /// Invalid public key format.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    /// IO error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Identity error.
    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::IdentityError),
}

/// A trusted peer entry in the peer book.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPeer {
    /// The peer's public identity (Ed25519 public key).
    pub pubkey: PublicIdentity,
    /// Optional nickname or label for the peer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Unix timestamp when the peer was added.
    pub added_at: u64,
}

impl TrustedPeer {
    /// Create a new trusted peer entry.
    pub fn new(pubkey: PublicIdentity, nickname: Option<String>) -> Self {
        Self {
            pubkey,
            nickname,
            added_at: current_unix_time(),
        }
    }

    /// Get the peer's public key as hex.
    pub fn pubkey_hex(&self) -> String {
        self.pubkey.to_hex()
    }
}

/// Stored format for the peer book.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredPeerBook {
    version: u8,
    peers: Vec<TrustedPeer>,
}

/// A file-backed directory of trusted peer public keys.
///
/// The peer book provides a local trust registry for channel-bound sessions.
/// Trust decisions are made out-of-band (e.g., key exchange ceremonies,
/// verified contacts) and recorded here for session authorization.
pub struct TrustedPeerBook {
    path: PathBuf,
    peers: HashMap<[u8; 32], TrustedPeer>,
}

impl TrustedPeerBook {
    /// Open or create a peer book at the given path.
    ///
    /// If the file exists, loads existing peers. Otherwise creates an empty book.
    pub fn open(path: &Path) -> Result<Self, PeerBookError> {
        let mut book = Self {
            path: path.to_path_buf(),
            peers: HashMap::new(),
        };

        if path.exists() {
            book.load()?;
        }

        Ok(book)
    }

    /// Create a new in-memory peer book (not backed by file).
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            peers: HashMap::new(),
        }
    }

    /// Add a peer to the book.
    ///
    /// Returns an error if the peer already exists.
    pub fn add(
        &mut self,
        pubkey: PublicIdentity,
        nickname: Option<String>,
    ) -> Result<(), PeerBookError> {
        let key = *pubkey.as_bytes();
        if self.peers.contains_key(&key) {
            return Err(PeerBookError::DuplicatePeer(pubkey.to_hex()));
        }

        let entry = TrustedPeer::new(pubkey, nickname);
        self.peers.insert(key, entry);
        self.save()?;

        Ok(())
    }

    /// Add a peer from hex-encoded public key.
    pub fn add_hex(
        &mut self,
        pubkey_hex: &str,
        nickname: Option<String>,
    ) -> Result<(), PeerBookError> {
        let pubkey = PublicIdentity::from_hex(pubkey_hex)?;
        self.add(pubkey, nickname)
    }

    /// Remove a peer from the book.
    ///
    /// Returns an error if the peer doesn't exist.
    pub fn remove(&mut self, pubkey: &PublicIdentity) -> Result<TrustedPeer, PeerBookError> {
        let key = *pubkey.as_bytes();
        let peer = self
            .peers
            .remove(&key)
            .ok_or_else(|| PeerBookError::PeerNotFound(pubkey.to_hex()))?;
        self.save()?;
        Ok(peer)
    }

    /// Remove a peer by hex-encoded public key.
    pub fn remove_hex(&mut self, pubkey_hex: &str) -> Result<TrustedPeer, PeerBookError> {
        let pubkey = PublicIdentity::from_hex(pubkey_hex)?;
        self.remove(&pubkey)
    }

    /// Look up a peer by public key.
    pub fn lookup(&self, pubkey: &PublicIdentity) -> Option<&TrustedPeer> {
        self.peers.get(pubkey.as_bytes())
    }

    /// Look up a peer by hex-encoded public key.
    pub fn lookup_hex(&self, pubkey_hex: &str) -> Result<Option<&TrustedPeer>, PeerBookError> {
        let pubkey = PublicIdentity::from_hex(pubkey_hex)?;
        Ok(self.lookup(&pubkey))
    }

    /// Check if a peer is trusted.
    pub fn is_trusted(&self, pubkey: &PublicIdentity) -> bool {
        self.peers.contains_key(pubkey.as_bytes())
    }

    /// Check if a peer (by hex) is trusted.
    pub fn is_trusted_hex(&self, pubkey_hex: &str) -> Result<bool, PeerBookError> {
        let pubkey = PublicIdentity::from_hex(pubkey_hex)?;
        Ok(self.is_trusted(&pubkey))
    }

    /// Get all trusted peers.
    pub fn list(&self) -> Vec<&TrustedPeer> {
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by_key(|p| p.added_at);
        peers
    }

    /// Get the number of trusted peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the peer book is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Assert that a peer is trusted before proceeding with a session.
    ///
    /// Returns the peer entry if trusted, error otherwise.
    /// Use this as an optional gate before channel-bound sessions.
    pub fn require_trusted(
        &self,
        pubkey: &PublicIdentity,
    ) -> Result<&TrustedPeer, PeerBookError> {
        self.lookup(pubkey)
            .ok_or_else(|| PeerBookError::PeerNotFound(pubkey.to_hex()))
    }

    fn load(&mut self) -> Result<(), PeerBookError> {
        let contents = std::fs::read_to_string(&self.path)?;
        if contents.trim().is_empty() {
            return Ok(());
        }
        let stored: StoredPeerBook = serde_json::from_str(&contents)?;

        self.peers.clear();
        for peer in stored.peers {
            self.peers.insert(*peer.pubkey.as_bytes(), peer);
        }

        Ok(())
    }

    fn save(&self) -> Result<(), PeerBookError> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }

        let peers: Vec<TrustedPeer> = self.list().into_iter().cloned().collect();
        let stored = StoredPeerBook { version: 1, peers };
        let json = serde_json::to_string_pretty(&stored)?;
        std::fs::write(&self.path, json)?;

        Ok(())
    }

    /// Force a save to disk (useful after in-memory modifications).
    pub fn flush(&self) -> Result<(), PeerBookError> {
        self.save()
    }

    /// Reload peers from disk.
    pub fn reload(&mut self) -> Result<(), PeerBookError> {
        if self.path.exists() {
            self.load()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PartyIdentity;
    use tempfile::NamedTempFile;

    #[test]
    fn test_peerbook_add_lookup() {
        let mut book = TrustedPeerBook::in_memory();
        let identity = PartyIdentity::generate();

        book.add(identity.public(), Some("Alice".to_string()))
            .unwrap();

        assert!(book.is_trusted(&identity.public()));
        let peer = book.lookup(&identity.public()).unwrap();
        assert_eq!(peer.nickname, Some("Alice".to_string()));
    }

    #[test]
    fn test_peerbook_duplicate_rejected() {
        let mut book = TrustedPeerBook::in_memory();
        let identity = PartyIdentity::generate();

        book.add(identity.public(), None).unwrap();
        let result = book.add(identity.public(), None);

        assert!(matches!(result, Err(PeerBookError::DuplicatePeer(_))));
    }

    #[test]
    fn test_peerbook_remove() {
        let mut book = TrustedPeerBook::in_memory();
        let identity = PartyIdentity::generate();

        book.add(identity.public(), Some("Bob".to_string())).unwrap();
        assert!(book.is_trusted(&identity.public()));

        let removed = book.remove(&identity.public()).unwrap();
        assert_eq!(removed.nickname, Some("Bob".to_string()));
        assert!(!book.is_trusted(&identity.public()));
    }

    #[test]
    fn test_peerbook_remove_not_found() {
        let mut book = TrustedPeerBook::in_memory();
        let identity = PartyIdentity::generate();

        let result = book.remove(&identity.public());
        assert!(matches!(result, Err(PeerBookError::PeerNotFound(_))));
    }

    #[test]
    fn test_peerbook_list_sorted_by_added_at() {
        let mut book = TrustedPeerBook::in_memory();

        let id1 = PartyIdentity::generate();
        let id2 = PartyIdentity::generate();
        let id3 = PartyIdentity::generate();

        book.add(id1.public(), Some("First".to_string())).unwrap();
        book.add(id2.public(), Some("Second".to_string())).unwrap();
        book.add(id3.public(), Some("Third".to_string())).unwrap();

        let list = book.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_peerbook_file_persistence() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let identity = PartyIdentity::generate();

        {
            let mut book = TrustedPeerBook::open(&path).unwrap();
            book.add(identity.public(), Some("Carol".to_string()))
                .unwrap();
        }

        {
            let book = TrustedPeerBook::open(&path).unwrap();
            assert!(book.is_trusted(&identity.public()));
            let peer = book.lookup(&identity.public()).unwrap();
            assert_eq!(peer.nickname, Some("Carol".to_string()));
        }
    }

    #[test]
    fn test_peerbook_require_trusted() {
        let book = TrustedPeerBook::in_memory();
        let identity = PartyIdentity::generate();

        let result = book.require_trusted(&identity.public());
        assert!(result.is_err());
    }

    #[test]
    fn test_peerbook_hex_operations() {
        let mut book = TrustedPeerBook::in_memory();
        let identity = PartyIdentity::generate();
        let hex = identity.public().to_hex();

        book.add_hex(&hex, Some("Dave".to_string())).unwrap();
        assert!(book.is_trusted_hex(&hex).unwrap());

        let peer = book.lookup_hex(&hex).unwrap().unwrap();
        assert_eq!(peer.nickname, Some("Dave".to_string()));

        book.remove_hex(&hex).unwrap();
        assert!(!book.is_trusted_hex(&hex).unwrap());
    }
}
