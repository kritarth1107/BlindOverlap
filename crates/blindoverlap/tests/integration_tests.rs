//! Comprehensive integration tests for BlindOverlap.

use blindoverlap::{
    canonical_json, fact_id_from_json, fact_id_from_str, FactSet, IntersectionMode,
    IntersectionReceipt, PsiProtocol, PsiResult, ReceiptSigner, ReceiptVerifier,
};
use serde_json::json;

fn make_set(values: &[serde_json::Value]) -> FactSet {
    FactSet::from_ids(values.iter().map(fact_id_from_json))
}

// === Fact ID Tests ===

#[test]
fn test_fact_id_from_string() {
    let json_str = r#"{"hello": "world"}"#;
    let id = fact_id_from_str(json_str).unwrap();
    assert_eq!(id.len(), 32);
}

#[test]
fn test_fact_id_invalid_json() {
    let result = fact_id_from_str("not valid json {");
    assert!(result.is_err());
}

#[test]
fn test_canonical_json_unicode() {
    let value = json!({"emoji": "🎉", "text": "hello"});
    let canonical = canonical_json(&value);
    assert!(canonical.contains("🎉"));
    assert_eq!(canonical, r#"{"emoji":"🎉","text":"hello"}"#);
}

#[test]
fn test_canonical_json_deeply_nested() {
    let value = json!({
        "level1": {
            "level2": {
                "level3": {
                    "value": 42
                }
            }
        }
    });
    let canonical = canonical_json(&value);
    assert!(canonical.contains("42"));
}

// === FactSet Tests ===

#[test]
fn test_fact_set_empty_vs_nonempty() {
    let empty = FactSet::empty();
    let nonempty = make_set(&[json!({"x": 1})]);

    assert_ne!(empty.root(), nonempty.root());
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert!(!nonempty.is_empty());
}

#[test]
fn test_fact_set_single_element() {
    let id = fact_id_from_json(&json!({"single": true}));
    let set = FactSet::from_ids([id]);

    assert_eq!(set.len(), 1);
    assert!(set.contains(&id));

    let wrong_id = fact_id_from_json(&json!({"single": false}));
    assert!(!set.contains(&wrong_id));
}

#[test]
fn test_fact_set_duplicate_ids() {
    let id = fact_id_from_json(&json!({"dup": 1}));
    let set = FactSet::from_ids([id, id, id]);

    assert_eq!(set.len(), 1);
}

// === PSI Protocol Tests ===

#[test]
fn test_psi_single_element_match() {
    let protocol = PsiProtocol::new();
    let common = json!({"shared": true});

    let set_a = make_set(&[common.clone()]);
    let set_b = make_set(&[common]);

    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 1),
        _ => panic!("expected intersection result"),
    }
}

#[test]
fn test_psi_single_element_disjoint() {
    let protocol = PsiProtocol::new();
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);

    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert!(ids.is_empty()),
        _ => panic!("expected intersection result"),
    }
}

#[test]
fn test_psi_one_empty_set() {
    let protocol = PsiProtocol::new();
    let empty = FactSet::empty();
    let nonempty = make_set(&[json!({"x": 1}), json!({"x": 2})]);

    let result = protocol
        .intersect(&empty, &nonempty, IntersectionMode::Intersection)
        .unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert!(ids.is_empty()),
        _ => panic!("expected intersection result"),
    }
}

#[test]
fn test_psi_subset_relationship() {
    let protocol = PsiProtocol::new();

    let subset = make_set(&[json!({"x": 1}), json!({"x": 2})]);
    let superset = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);

    let result = protocol
        .intersect(&subset, &superset, IntersectionMode::Intersection)
        .unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 2),
        _ => panic!("expected intersection result"),
    }
}

#[test]
fn test_psi_cardinality_vs_intersection_consistency() {
    let protocol = PsiProtocol::new();
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    let int_result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();
    let card_result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Cardinality)
        .unwrap();

    let int_count = match int_result {
        PsiResult::Intersection { ids, .. } => ids.len(),
        _ => panic!("expected intersection"),
    };
    let card_count = match card_result {
        PsiResult::Cardinality { count } => count,
        _ => panic!("expected cardinality"),
    };

    assert_eq!(int_count, card_count);
}

// === Receipt Tests ===

#[test]
fn test_receipt_serialization_roundtrip() {
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let signer = ReceiptSigner::new();
    let receipt = signer.sign(set_a.root(), set_b.root(), &result, IntersectionMode::Intersection);

    let json_str = serde_json::to_string(&receipt).unwrap();
    let deserialized: IntersectionReceipt = serde_json::from_str(&json_str).unwrap();

    assert_eq!(receipt.version, deserialized.version);
    assert_eq!(receipt.set_root_a, deserialized.set_root_a);
    assert_eq!(receipt.set_root_b, deserialized.set_root_b);
    assert_eq!(receipt.signature, deserialized.signature);
}

#[test]
fn test_receipt_wrong_public_key() {
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let signer = ReceiptSigner::new();
    let mut receipt = signer.sign(set_a.root(), set_b.root(), &result, IntersectionMode::Intersection);

    receipt.signer_public_key[0] ^= 0xFF;

    let verifier = ReceiptVerifier::new();
    assert!(verifier.verify(&receipt).is_err());
}

#[test]
fn test_receipt_cardinality_mode() {
    let set_a = make_set(&[json!({"a": 1}), json!({"a": 2})]);
    let set_b = make_set(&[json!({"a": 2}), json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Cardinality)
        .unwrap();

    let signer = ReceiptSigner::new();
    let receipt = signer.sign(set_a.root(), set_b.root(), &result, IntersectionMode::Cardinality);

    let verifier = ReceiptVerifier::new();
    assert!(verifier.verify(&receipt).is_ok());
    assert_eq!(receipt.mode, blindoverlap::ReceiptMode::Cardinality);
}

#[test]
fn test_receipt_id_uniqueness() {
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let signer1 = ReceiptSigner::new();
    let signer2 = ReceiptSigner::new();

    let receipt1 = signer1.sign(set_a.root(), set_b.root(), &result, IntersectionMode::Intersection);
    let receipt2 = signer2.sign(set_a.root(), set_b.root(), &result, IntersectionMode::Intersection);

    assert_ne!(receipt1.receipt_id(), receipt2.receipt_id());
}

// === Property-ish Fuzz Tests ===

#[test]
fn test_psi_symmetry() {
    let protocol = PsiProtocol::new();
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    let result_ab = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Cardinality)
        .unwrap();
    let result_ba = protocol
        .intersect(&set_b, &set_a, IntersectionMode::Cardinality)
        .unwrap();

    let count_ab = match result_ab {
        PsiResult::Cardinality { count } => count,
        _ => panic!(),
    };
    let count_ba = match result_ba {
        PsiResult::Cardinality { count } => count,
        _ => panic!(),
    };

    assert_eq!(count_ab, count_ba);
}

#[test]
fn test_psi_random_sets() {
    use rand::Rng;

    let protocol = PsiProtocol::new();
    let mut rng = rand::thread_rng();

    for _ in 0..10 {
        let size_a = rng.gen_range(1..50);
        let size_b = rng.gen_range(1..50);

        let values_a: Vec<serde_json::Value> = (0..size_a)
            .map(|i| json!({"set": "a", "idx": i, "rand": rng.gen::<u32>()}))
            .collect();
        let values_b: Vec<serde_json::Value> = (0..size_b)
            .map(|i| json!({"set": "b", "idx": i, "rand": rng.gen::<u32>()}))
            .collect();

        let set_a = make_set(&values_a);
        let set_b = make_set(&values_b);

        let result = protocol
            .intersect(&set_a, &set_b, IntersectionMode::Intersection)
            .unwrap();

        match result {
            PsiResult::Intersection { ids, .. } => {
                assert!(ids.len() <= set_a.len().min(set_b.len()));
            }
            _ => panic!("expected intersection"),
        }
    }
}

#[test]
fn test_psi_known_overlap_random() {
    use rand::Rng;

    let protocol = PsiProtocol::new();
    let mut rng = rand::thread_rng();

    let common: Vec<serde_json::Value> = (0..5)
        .map(|i| json!({"common": true, "idx": i}))
        .collect();

    let unique_a: Vec<serde_json::Value> = (0..rng.gen_range(5..20))
        .map(|i| json!({"set": "a", "unique": i}))
        .collect();

    let unique_b: Vec<serde_json::Value> = (0..rng.gen_range(5..20))
        .map(|i| json!({"set": "b", "unique": i}))
        .collect();

    let mut all_a = common.clone();
    all_a.extend(unique_a);

    let mut all_b = common.clone();
    all_b.extend(unique_b);

    let set_a = make_set(&all_a);
    let set_b = make_set(&all_b);

    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => {
            assert_eq!(ids.len(), 5, "expected exactly 5 common elements");
        }
        _ => panic!("expected intersection"),
    }
}

// === Security Boundary Tests ===

#[test]
fn test_set_root_mismatch_detection() {
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);
    let set_c = make_set(&[json!({"c": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let signer = ReceiptSigner::new();
    let receipt = signer.sign(set_a.root(), set_b.root(), &result, IntersectionMode::Intersection);

    let verifier = ReceiptVerifier::new();

    assert!(verifier.verify(&receipt).is_ok());

    assert!(verifier
        .verify_with_roots(&receipt, set_c.root(), set_b.root())
        .is_err());
    assert!(verifier
        .verify_with_roots(&receipt, set_a.root(), set_c.root())
        .is_err());
}

#[test]
fn test_result_commitment_integrity() {
    let set_a = make_set(&[json!({"a": 1}), json!({"a": 2})]);
    let set_b = make_set(&[json!({"a": 2})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let commitment = result.commitment();
    assert_eq!(commitment.len(), 32);

    let result2 = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();
    let commitment2 = result2.commitment();

    assert_eq!(commitment, commitment2);
}
