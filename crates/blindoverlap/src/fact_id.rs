//! Fact ID generation and FactSet management.
//!
//! Implements RFC 8785 (JSON Canonicalization Scheme) for deterministic fact hashing.
//! A FactId is a 32-byte SHA-256 hash of the canonical JSON representation of a fact.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use thiserror::Error;

/// A 32-byte content-addressed fact identifier (SHA-256 of canonical JSON).
pub type FactId = [u8; 32];

/// Errors that can occur during fact encoding.
#[derive(Debug, Error)]
pub enum FactIdError {
    /// Invalid JSON input.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    /// Value type not supported for canonicalization.
    #[error("unsupported JSON value type")]
    UnsupportedType,
}

/// Encode a JSON value to RFC 8785 canonical form.
///
/// RFC 8785 (JCS) specifies:
/// - Object keys sorted lexicographically by Unicode code points
/// - No whitespace between tokens
/// - Numbers serialized without unnecessary precision
/// - Strings use minimal escaping
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        serde_json::Value::Number(n) => canonical_number(n),
        serde_json::Value::String(s) => canonical_string(s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", canonical_string(k), canonical_json(&obj[*k])))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn canonical_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(f) = n.as_f64() {
        if f.is_nan() || f.is_infinite() {
            return "null".to_string();
        }
        if f == 0.0 {
            return "0".to_string();
        }
        let formatted = format!("{}", f);
        if formatted.contains('e') || formatted.contains('E') {
            return formatted.to_lowercase();
        }
        formatted
    } else {
        "null".to_string()
    }
}

fn canonical_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\x08' => result.push_str("\\b"),
            '\x0c' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c < '\x20' => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

/// Compute the FactId (SHA-256 hash) of a JSON value using RFC 8785 canonicalization.
pub fn fact_id_from_json(value: &serde_json::Value) -> FactId {
    let canonical = canonical_json(value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

/// Compute the FactId from a JSON string.
pub fn fact_id_from_str(json_str: &str) -> Result<FactId, FactIdError> {
    let value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| FactIdError::InvalidJson(e.to_string()))?;
    Ok(fact_id_from_json(&value))
}

/// A set of fact IDs with a merkle-style root commitment.
///
/// The set root is computed as SHA-256 over the sorted, concatenated fact IDs.
/// This provides a deterministic commitment to the exact set contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactSet {
    ids: BTreeSet<FactId>,
    root: [u8; 32],
}

impl FactSet {
    /// Create an empty FactSet.
    pub fn empty() -> Self {
        Self {
            ids: BTreeSet::new(),
            root: compute_set_root(&BTreeSet::new()),
        }
    }

    /// Create a FactSet from an iterator of fact IDs.
    pub fn from_ids(ids: impl IntoIterator<Item = FactId>) -> Self {
        let ids: BTreeSet<FactId> = ids.into_iter().collect();
        let root = compute_set_root(&ids);
        Self { ids, root }
    }

    /// Create a FactSet from JSON values.
    pub fn from_json_values(values: impl IntoIterator<Item = serde_json::Value>) -> Self {
        let ids: BTreeSet<FactId> = values.into_iter().map(|v| fact_id_from_json(&v)).collect();
        let root = compute_set_root(&ids);
        Self { ids, root }
    }

    /// Get the set root commitment.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get the fact IDs as a sorted slice.
    pub fn ids(&self) -> Vec<FactId> {
        self.ids.iter().copied().collect()
    }

    /// Get the number of facts in the set.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Check if a fact ID is in the set.
    pub fn contains(&self, id: &FactId) -> bool {
        self.ids.contains(id)
    }

    /// Insert a fact ID into the set and recompute the root.
    pub fn insert(&mut self, id: FactId) {
        self.ids.insert(id);
        self.root = compute_set_root(&self.ids);
    }

    /// Get the underlying BTreeSet for iteration.
    pub fn iter(&self) -> impl Iterator<Item = &FactId> {
        self.ids.iter()
    }
}

fn compute_set_root(ids: &BTreeSet<FactId>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BlindOverlap:SetRoot:v1");
    hasher.update((ids.len() as u64).to_le_bytes());
    for id in ids {
        hasher.update(id);
    }
    hasher.finalize().into()
}

impl Default for FactSet {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_primitives() {
        assert_eq!(canonical_json(&json!(null)), "null");
        assert_eq!(canonical_json(&json!(true)), "true");
        assert_eq!(canonical_json(&json!(false)), "false");
        assert_eq!(canonical_json(&json!(42)), "42");
        assert_eq!(canonical_json(&json!(-17)), "-17");
        assert_eq!(canonical_json(&json!("hello")), "\"hello\"");
    }

    #[test]
    fn test_canonical_json_string_escaping() {
        assert_eq!(canonical_json(&json!("a\"b")), "\"a\\\"b\"");
        assert_eq!(canonical_json(&json!("a\\b")), "\"a\\\\b\"");
        assert_eq!(canonical_json(&json!("a\nb")), "\"a\\nb\"");
        assert_eq!(canonical_json(&json!("a\tb")), "\"a\\tb\"");
    }

    #[test]
    fn test_canonical_json_object_key_ordering() {
        let obj = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonical_json(&obj), "{\"a\":2,\"m\":3,\"z\":1}");
    }

    #[test]
    fn test_canonical_json_nested() {
        let obj = json!({"b": [3, 1, 2], "a": {"y": 1, "x": 2}});
        assert_eq!(
            canonical_json(&obj),
            "{\"a\":{\"x\":2,\"y\":1},\"b\":[3,1,2]}"
        );
    }

    #[test]
    fn test_fact_id_determinism() {
        let v1 = json!({"name": "Alice", "age": 30});
        let v2 = json!({"age": 30, "name": "Alice"});
        assert_eq!(fact_id_from_json(&v1), fact_id_from_json(&v2));
    }

    #[test]
    fn test_fact_set_root_determinism() {
        let id1 = fact_id_from_json(&json!({"a": 1}));
        let id2 = fact_id_from_json(&json!({"b": 2}));

        let set1 = FactSet::from_ids([id1, id2]);
        let set2 = FactSet::from_ids([id2, id1]);

        assert_eq!(set1.root(), set2.root());
    }

    #[test]
    fn test_fact_set_different_contents_different_root() {
        let id1 = fact_id_from_json(&json!({"a": 1}));
        let id2 = fact_id_from_json(&json!({"b": 2}));
        let id3 = fact_id_from_json(&json!({"c": 3}));

        let set1 = FactSet::from_ids([id1, id2]);
        let set2 = FactSet::from_ids([id1, id3]);

        assert_ne!(set1.root(), set2.root());
    }
}
