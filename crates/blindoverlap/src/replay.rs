//! Replay store for detecting duplicate messages.
//!
//! Provides tracking of:
//! - Session nonces (to detect replayed sessions)
//! - Transcript digests (to detect replayed wire exchanges)
//!
//! Two implementations:
//! - `ReplayStore`: In-memory only (does not persist)
//! - `PersistentReplayStore`: File-backed persistence (survives restart)
//!
//! # Security Note
//!
//! This is **best-effort replay protection under the semi-honest model**.
//!
//! - Entries have TTL-based expiry for memory management
//! - Does NOT provide protection against determined adversaries
//! - File-backed persistence helps survive process restart
//! - Applications may need more robust replay tracking for production use
//!
//! # Persistence Limitations
//!
//! The persistent store uses simple JSON files:
//! - Loaded on construction, flushed after each record operation
//! - Not designed for high-concurrency or crash safety
//! - Best-effort: if file write fails, operation still succeeds in memory

use crate::freshness::{current_unix_time, FreshnessError, SessionNonce, TranscriptDigest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Entry in the replay store with expiration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreEntry {
    /// Unix timestamp when this entry was recorded.
    recorded_at: u64,
    /// Unix timestamp when this entry expires (can be cleaned up).
    expires_at: u64,
    /// Optional session ID for context (stored for debugging/auditing).
    #[allow(dead_code)]
    session_id: Option<String>,
}

/// In-memory replay store for nonces and transcript digests.
///
/// Tracks recently used nonces and digests to detect potential replays.
/// Entries expire after a configurable TTL for memory management.
#[derive(Debug)]
pub struct ReplayStore {
    /// Used session nonces (nonce -> entry).
    nonces: HashMap<SessionNonce, StoreEntry>,
    /// Used transcript digests (digest -> entry).
    digests: HashMap<TranscriptDigest, StoreEntry>,
    /// Default TTL for new entries (seconds).
    default_ttl: u64,
    /// Maximum number of entries before forced cleanup.
    max_entries: usize,
}

impl ReplayStore {
    /// Create a new replay store with default settings.
    ///
    /// Default TTL: 3600 seconds (1 hour)
    /// Max entries: 100,000
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
            digests: HashMap::new(),
            default_ttl: 3600,
            max_entries: 100_000,
        }
    }

    /// Create a replay store with custom TTL.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            nonces: HashMap::new(),
            digests: HashMap::new(),
            default_ttl: ttl_secs,
            max_entries: 100_000,
        }
    }

    /// Create a replay store with custom limits.
    pub fn with_limits(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            nonces: HashMap::new(),
            digests: HashMap::new(),
            default_ttl: ttl_secs,
            max_entries,
        }
    }

    /// Check if a nonce has been seen before.
    ///
    /// Returns `Ok(())` if the nonce is fresh, or `Err(ReplayDetected)` if seen.
    pub fn check_nonce(&self, nonce: &SessionNonce) -> Result<(), FreshnessError> {
        let now = current_unix_time();
        if let Some(entry) = self.nonces.get(nonce) {
            if now < entry.expires_at {
                return Err(FreshnessError::ReplayDetected(format!(
                    "nonce {} seen at {}",
                    nonce, entry.recorded_at
                )));
            }
        }
        Ok(())
    }

    /// Record a nonce as used.
    ///
    /// First checks if the nonce was already used (returns error if so),
    /// then records it if fresh.
    pub fn record_nonce(
        &mut self,
        nonce: SessionNonce,
        session_id: Option<&str>,
    ) -> Result<(), FreshnessError> {
        self.check_nonce(&nonce)?;
        self.maybe_cleanup();

        let now = current_unix_time();
        self.nonces.insert(
            nonce,
            StoreEntry {
                recorded_at: now,
                expires_at: now + self.default_ttl,
                session_id: session_id.map(String::from),
            },
        );
        Ok(())
    }

    /// Check if a transcript digest has been seen before.
    ///
    /// Returns `Ok(())` if the digest is fresh, or `Err(ReplayDetected)` if seen.
    pub fn check_digest(&self, digest: &TranscriptDigest) -> Result<(), FreshnessError> {
        let now = current_unix_time();
        if let Some(entry) = self.digests.get(digest) {
            if now < entry.expires_at {
                return Err(FreshnessError::ReplayDetected(format!(
                    "transcript {} seen at {}",
                    digest, entry.recorded_at
                )));
            }
        }
        Ok(())
    }

    /// Record a transcript digest as used.
    ///
    /// First checks if the digest was already used (returns error if so),
    /// then records it if fresh.
    pub fn record_digest(
        &mut self,
        digest: TranscriptDigest,
        session_id: Option<&str>,
    ) -> Result<(), FreshnessError> {
        self.check_digest(&digest)?;
        self.maybe_cleanup();

        let now = current_unix_time();
        self.digests.insert(
            digest,
            StoreEntry {
                recorded_at: now,
                expires_at: now + self.default_ttl,
                session_id: session_id.map(String::from),
            },
        );
        Ok(())
    }

    /// Remove expired entries if we're over capacity.
    fn maybe_cleanup(&mut self) {
        let total = self.nonces.len() + self.digests.len();
        if total > self.max_entries {
            self.cleanup_expired();
        }
    }

    /// Remove all expired entries.
    pub fn cleanup_expired(&mut self) {
        let now = current_unix_time();
        self.nonces.retain(|_, entry| entry.expires_at > now);
        self.digests.retain(|_, entry| entry.expires_at > now);
    }

    /// Get the number of tracked nonces.
    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }

    /// Get the number of tracked digests.
    pub fn digest_count(&self) -> usize {
        self.digests.len()
    }

    /// Get the total number of tracked entries.
    pub fn total_count(&self) -> usize {
        self.nonces.len() + self.digests.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.nonces.clear();
        self.digests.clear();
    }
}

impl Default for ReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable format for the persistent store.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStoreData {
    version: u8,
    default_ttl: u64,
    nonces: Vec<(String, StoreEntry)>,  // hex-encoded nonces
    digests: Vec<(String, StoreEntry)>, // hex-encoded digests
}

/// File-backed persistent replay store.
///
/// Extends the in-memory `ReplayStore` with file-based persistence.
/// Data is loaded on construction and flushed after each record operation.
///
/// # Limitations
///
/// - Uses simple JSON format (not optimized for large stores)
/// - Flush is best-effort (memory state updated even if file write fails)
/// - Not designed for concurrent access from multiple processes
/// - TTL cleanup happens on load and record operations
#[derive(Debug)]
pub struct PersistentReplayStore {
    /// Inner in-memory store.
    inner: ReplayStore,
    /// File path for persistence.
    path: PathBuf,
}

impl PersistentReplayStore {
    /// Create or load a persistent replay store from the given path.
    ///
    /// If the file exists, entries are loaded and expired ones are cleaned.
    /// If the file doesn't exist, an empty store is created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        Self::open_with_ttl(path, 3600)
    }

    /// Create or load a persistent replay store with custom TTL.
    pub fn open_with_ttl(path: impl AsRef<Path>, ttl_secs: u64) -> Result<Self, ReplayStoreError> {
        let path = path.as_ref().to_path_buf();
        let mut inner = ReplayStore::with_ttl(ttl_secs);

        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            // Handle empty files (treat as empty store)
            if !contents.trim().is_empty() {
                let data: PersistentStoreData = serde_json::from_str(&contents)?;

                for (hex, entry) in data.nonces {
                    if let Ok(nonce) = SessionNonce::from_hex(&hex) {
                        inner.nonces.insert(nonce, entry);
                    }
                }
                for (hex, entry) in data.digests {
                    if let Ok(digest) = TranscriptDigest::from_hex(&hex) {
                        inner.digests.insert(digest, entry);
                    }
                }

                // Clean up expired entries on load
                inner.cleanup_expired();
            }
        }

        Ok(Self { inner, path })
    }

    /// Check if a nonce has been seen before.
    pub fn check_nonce(&self, nonce: &SessionNonce) -> Result<(), FreshnessError> {
        self.inner.check_nonce(nonce)
    }

    /// Record a nonce as used (and flush to disk).
    pub fn record_nonce(
        &mut self,
        nonce: SessionNonce,
        session_id: Option<&str>,
    ) -> Result<(), FreshnessError> {
        self.inner.record_nonce(nonce, session_id)?;
        let _ = self.flush(); // Best-effort flush
        Ok(())
    }

    /// Check if a transcript digest has been seen before.
    pub fn check_digest(&self, digest: &TranscriptDigest) -> Result<(), FreshnessError> {
        self.inner.check_digest(digest)
    }

    /// Record a transcript digest as used (and flush to disk).
    pub fn record_digest(
        &mut self,
        digest: TranscriptDigest,
        session_id: Option<&str>,
    ) -> Result<(), FreshnessError> {
        self.inner.record_digest(digest, session_id)?;
        let _ = self.flush(); // Best-effort flush
        Ok(())
    }

    /// Remove all expired entries.
    pub fn cleanup_expired(&mut self) {
        self.inner.cleanup_expired();
        let _ = self.flush();
    }

    /// Get the number of tracked nonces.
    pub fn nonce_count(&self) -> usize {
        self.inner.nonce_count()
    }

    /// Get the number of tracked digests.
    pub fn digest_count(&self) -> usize {
        self.inner.digest_count()
    }

    /// Get the total number of tracked entries.
    pub fn total_count(&self) -> usize {
        self.inner.total_count()
    }

    /// Clear all entries (in memory and on disk).
    pub fn clear(&mut self) {
        self.inner.clear();
        let _ = self.flush();
    }

    /// Get the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush the store to disk.
    pub fn flush(&self) -> Result<(), ReplayStoreError> {
        let data = PersistentStoreData {
            version: 1,
            default_ttl: self.inner.default_ttl,
            nonces: self
                .inner
                .nonces
                .iter()
                .map(|(k, v)| (k.to_hex(), v.clone()))
                .collect(),
            digests: self
                .inner
                .digests
                .iter()
                .map(|(k, v)| (k.to_hex(), v.clone()))
                .collect(),
        };

        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    /// Force reload from disk.
    pub fn reload(&mut self) -> Result<(), ReplayStoreError> {
        if self.path.exists() {
            let contents = std::fs::read_to_string(&self.path)?;

            self.inner.nonces.clear();
            self.inner.digests.clear();

            // Handle empty files
            if !contents.trim().is_empty() {
                let data: PersistentStoreData = serde_json::from_str(&contents)?;

                for (hex, entry) in data.nonces {
                    if let Ok(nonce) = SessionNonce::from_hex(&hex) {
                        self.inner.nonces.insert(nonce, entry);
                    }
                }
                for (hex, entry) in data.digests {
                    if let Ok(digest) = TranscriptDigest::from_hex(&hex) {
                        self.inner.digests.insert(digest, entry);
                    }
                }

                self.inner.cleanup_expired();
            }
        }
        Ok(())
    }
}

/// Errors that can occur with the persistent replay store.
#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    /// IO error reading/writing file.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_nonce_accepted() {
        let store = ReplayStore::new();
        let nonce = SessionNonce::generate();

        assert!(store.check_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_replay_nonce_rejected() {
        let mut store = ReplayStore::new();
        let nonce = SessionNonce::generate();

        store.record_nonce(nonce, Some("session-1")).unwrap();

        let result = store.check_nonce(&nonce);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FreshnessError::ReplayDetected(_)
        ));
    }

    #[test]
    fn test_record_nonce_rejects_duplicate() {
        let mut store = ReplayStore::new();
        let nonce = SessionNonce::generate();

        assert!(store.record_nonce(nonce, None).is_ok());
        assert!(store.record_nonce(nonce, None).is_err());
    }

    #[test]
    fn test_different_nonces_both_accepted() {
        let mut store = ReplayStore::new();
        let nonce1 = SessionNonce::generate();
        let nonce2 = SessionNonce::generate();

        store.record_nonce(nonce1, None).unwrap();
        assert!(store.record_nonce(nonce2, None).is_ok());
    }

    #[test]
    fn test_fresh_digest_accepted() {
        let store = ReplayStore::new();
        let nonce = SessionNonce::generate();
        let digest = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

        assert!(store.check_digest(&digest).is_ok());
    }

    #[test]
    fn test_replay_digest_rejected() {
        let mut store = ReplayStore::new();
        let nonce = SessionNonce::generate();
        let digest = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

        store.record_digest(digest, Some("session")).unwrap();

        let result = store.check_digest(&digest);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FreshnessError::ReplayDetected(_)
        ));
    }

    #[test]
    fn test_counts() {
        let mut store = ReplayStore::new();

        for _ in 0..5 {
            store.record_nonce(SessionNonce::generate(), None).unwrap();
        }
        for i in 0..3 {
            let nonce = SessionNonce::from_bytes([i; 32]);
            let digest = TranscriptDigest::compute(&format!("s{i}"), &nonce, None, &[], None, None);
            store.record_digest(digest, None).unwrap();
        }

        assert_eq!(store.nonce_count(), 5);
        assert_eq!(store.digest_count(), 3);
        assert_eq!(store.total_count(), 8);
    }

    #[test]
    fn test_clear() {
        let mut store = ReplayStore::new();

        store.record_nonce(SessionNonce::generate(), None).unwrap();
        store.record_nonce(SessionNonce::generate(), None).unwrap();

        assert_eq!(store.total_count(), 2);

        store.clear();
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn test_custom_ttl() {
        let store = ReplayStore::with_ttl(60);

        assert_eq!(store.default_ttl, 60);
    }

    #[test]
    fn test_custom_limits() {
        let store = ReplayStore::with_limits(120, 1000);

        assert_eq!(store.default_ttl, 120);
        assert_eq!(store.max_entries, 1000);
    }

    // === PersistentReplayStore tests ===

    use tempfile::NamedTempFile;

    #[test]
    fn test_persistent_store_create_new() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // Open from empty temp file
        let mut store = PersistentReplayStore::open(&path).unwrap();
        assert_eq!(store.total_count(), 0);

        // Record something to trigger flush
        store.record_nonce(SessionNonce::generate(), None).unwrap();
        assert!(path.exists());
        assert!(std::fs::read_to_string(&path).unwrap().contains("version"));
    }

    #[test]
    fn test_persistent_store_record_and_reload() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let nonce = SessionNonce::generate();
        let digest = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

        // Record entries
        {
            let mut store = PersistentReplayStore::open(&path).unwrap();
            store.record_nonce(nonce, Some("test-session")).unwrap();
            store.record_digest(digest, Some("test-session")).unwrap();
            assert_eq!(store.total_count(), 2);
        }

        // Reload and verify
        {
            let store = PersistentReplayStore::open(&path).unwrap();
            assert_eq!(store.total_count(), 2);
            assert!(store.check_nonce(&nonce).is_err());
            assert!(store.check_digest(&digest).is_err());
        }
    }

    #[test]
    fn test_persistent_store_survives_restart() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let nonce1 = SessionNonce::generate();
        let nonce2 = SessionNonce::generate();

        // First session
        {
            let mut store = PersistentReplayStore::open(&path).unwrap();
            store.record_nonce(nonce1, None).unwrap();
        }

        // Second session (simulating restart)
        {
            let mut store = PersistentReplayStore::open(&path).unwrap();
            // nonce1 should be rejected (seen before)
            assert!(store.record_nonce(nonce1, None).is_err());
            // nonce2 should be accepted (fresh)
            assert!(store.record_nonce(nonce2, None).is_ok());
        }

        // Third session (verify both recorded)
        {
            let store = PersistentReplayStore::open(&path).unwrap();
            assert_eq!(store.nonce_count(), 2);
        }
    }

    #[test]
    fn test_persistent_store_clear() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut store = PersistentReplayStore::open(&path).unwrap();
        store.record_nonce(SessionNonce::generate(), None).unwrap();
        store.record_nonce(SessionNonce::generate(), None).unwrap();
        assert_eq!(store.total_count(), 2);

        store.clear();
        assert_eq!(store.total_count(), 0);

        // Reload and verify cleared
        drop(store);
        let store = PersistentReplayStore::open(&path).unwrap();
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn test_persistent_store_custom_ttl() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let store = PersistentReplayStore::open_with_ttl(&path, 60).unwrap();
        assert_eq!(store.inner.default_ttl, 60);
    }
}
