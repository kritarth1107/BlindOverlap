//! Comprehensive integration tests for BlindOverlap.

use blindoverlap::{
    canonical_json, fact_id_from_json, fact_id_from_str, pad_masked_elements, wire_decode,
    wire_encode, FactSet, InitiatorSession, IntersectionMode, IntersectionReceipt, MaskedSetOffer,
    MaskedSetReply, PaddingConfig, PsiProtocol, PsiResult, ReceiptSigner, ReceiptVerifier,
    ResponderSession, WireMessage,
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

    let set_a = make_set(std::slice::from_ref(&common));
    let set_b = make_set(std::slice::from_ref(&common));

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
    let receipt = signer.sign(
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

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
    let mut receipt = signer.sign(
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

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
    let receipt = signer.sign(
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Cardinality,
    );

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

    let receipt1 = signer1.sign(
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );
    let receipt2 = signer2.sign(
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

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

    let common: Vec<serde_json::Value> =
        (0..5).map(|i| json!({"common": true, "idx": i})).collect();

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
    let receipt = signer.sign(
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

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

// === Wire Protocol Tests ===

#[test]
fn test_wire_roundtrip_with_session_data() {
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);

    let mut session =
        InitiatorSession::new("wire-test", set_a, IntersectionMode::Intersection).unwrap();
    let offer = session.generate_offer().unwrap();

    let message = WireMessage::Offer(offer.clone());
    let json = wire_encode(&message).unwrap();

    let decoded = wire_decode(&json).unwrap();
    match decoded {
        WireMessage::Offer(decoded_offer) => {
            assert_eq!(decoded_offer.session_id, offer.session_id);
            assert_eq!(
                decoded_offer.masked_elements.len(),
                offer.masked_elements.len()
            );
            assert_eq!(decoded_offer.masked_elements, offer.masked_elements);
        }
        _ => panic!("expected offer message"),
    }
}

#[test]
fn test_wire_reply_roundtrip() {
    let reply = MaskedSetReply::new(
        "test-session",
        vec![[1u8; 32], [2u8; 32]],
        vec![[3u8; 32], [4u8; 32], [5u8; 32]],
    );

    let message = WireMessage::Reply(reply.clone());
    let json = wire_encode(&message).unwrap();
    let decoded = wire_decode(&json).unwrap();

    match decoded {
        WireMessage::Reply(decoded_reply) => {
            assert_eq!(decoded_reply.session_id, reply.session_id);
            assert_eq!(decoded_reply.responder_masked.len(), 2);
            assert_eq!(decoded_reply.initiator_doubly_masked.len(), 3);
        }
        _ => panic!("expected reply message"),
    }
}

// === Online Session Tests ===

#[test]
fn test_online_session_correctness_vs_colocated() {
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    let protocol = PsiProtocol::new();
    let colocated = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let mut initiator = InitiatorSession::new(
        "correctness-test",
        set_a.clone(),
        IntersectionMode::Intersection,
    )
    .unwrap();
    let mut responder = ResponderSession::new(
        "correctness-test",
        set_b.clone(),
        IntersectionMode::Intersection,
    )
    .unwrap();

    let offer = initiator.generate_offer().unwrap();
    let reply = responder.process_offer_and_reply(&offer).unwrap();
    let online = initiator.process_reply(&reply).unwrap();

    let colocated_count = match &colocated {
        PsiResult::Intersection { ids, .. } => ids.len(),
        _ => panic!(),
    };
    let online_count = match &online {
        PsiResult::Intersection { ids, .. } => ids.len(),
        _ => panic!(),
    };

    assert_eq!(colocated_count, online_count);
    assert_eq!(colocated_count, 2);
}

#[test]
fn test_online_bilateral_intersection() {
    let set_a = make_set(&[json!({"shared": 1}), json!({"only_a": 1})]);
    let set_b = make_set(&[json!({"shared": 1}), json!({"only_b": 1})]);

    let mut initiator =
        InitiatorSession::new("bilateral-test", set_a, IntersectionMode::Intersection).unwrap();
    let mut responder =
        ResponderSession::new("bilateral-test", set_b, IntersectionMode::Intersection).unwrap();

    let offer = initiator.generate_offer().unwrap();
    let reply = responder.process_offer_and_reply(&offer).unwrap();
    let initiator_result = initiator.process_reply(&reply).unwrap();

    let reveal = initiator.generate_reveal().unwrap();
    let responder_result = responder.process_reveal(&reveal).unwrap();

    let init_ids = match initiator_result {
        PsiResult::Intersection { ids, .. } => ids,
        _ => panic!(),
    };
    let resp_ids = match responder_result {
        PsiResult::Intersection { ids, .. } => ids,
        _ => panic!(),
    };

    assert_eq!(init_ids.len(), 1);
    assert_eq!(resp_ids.len(), 1);
    assert_eq!(init_ids, resp_ids);
}

// === Padding Tests ===

#[test]
fn test_padding_length_invariance() {
    let config = PaddingConfig::new(100, b"test-secret".to_vec());

    for real_size in [1, 10, 50, 99, 100] {
        let elements: Vec<[u8; 32]> = (0..real_size)
            .map(|i| {
                let mut elem = [0u8; 32];
                elem[0] = i as u8;
                elem
            })
            .collect();

        let padded = pad_masked_elements(&elements, &config, b"ctx").unwrap();
        assert_eq!(padded.len(), 100, "size {real_size} should pad to 100");
    }
}

#[test]
fn test_padding_preserves_original_elements() {
    let config = PaddingConfig::new(50, b"secret".to_vec());

    let original: Vec<[u8; 32]> = (0..10)
        .map(|i| {
            let mut elem = [0u8; 32];
            elem[0] = i;
            elem[1] = 0xFF;
            elem
        })
        .collect();

    let padded = pad_masked_elements(&original, &config, b"ctx").unwrap();

    assert_eq!(padded.len(), 50);
    assert_eq!(&padded[..10], &original);
}

#[test]
fn test_padded_online_intersect_end_to_end() {
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    let mut initiator =
        InitiatorSession::new("padded-test", set_a, IntersectionMode::Intersection).unwrap();
    let mut responder =
        ResponderSession::new("padded-test", set_b, IntersectionMode::Intersection).unwrap();

    let offer = initiator.generate_offer().unwrap();

    let config = PaddingConfig::new(64, b"padding-secret".to_vec());
    let padded_offer_elements =
        pad_masked_elements(&offer.masked_elements, &config, b"padded-test").unwrap();

    assert_eq!(padded_offer_elements.len(), 64);

    let padded_offer = MaskedSetOffer::new("padded-test", padded_offer_elements);
    let reply = responder.process_offer_and_reply(&padded_offer).unwrap();

    let original_reply = MaskedSetReply::new(
        "padded-test",
        reply.responder_masked.clone(),
        reply.initiator_doubly_masked[..2].to_vec(),
    );

    let result = initiator.process_reply(&original_reply).unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => {
            assert_eq!(ids.len(), 1, "should find 1 common element");
        }
        _ => panic!("expected intersection result"),
    }
}

#[test]
fn test_wire_with_padding_roundtrip() {
    let elements: Vec<[u8; 32]> = (0..5)
        .map(|i| {
            let mut elem = [0u8; 32];
            elem[0] = i;
            elem
        })
        .collect();

    let config = PaddingConfig::new(32, b"secret".to_vec());
    let padded = pad_masked_elements(&elements, &config, b"session").unwrap();

    let offer = MaskedSetOffer::new("padded-session", padded.clone());
    let message = WireMessage::Offer(offer);

    let json = wire_encode(&message).unwrap();
    let decoded = wire_decode(&json).unwrap();

    match decoded {
        WireMessage::Offer(decoded_offer) => {
            assert_eq!(decoded_offer.masked_elements.len(), 32);
            assert_eq!(&decoded_offer.masked_elements[..5], &elements);
        }
        _ => panic!("expected offer"),
    }
}

// === Freshness Tests (v0.3.0) ===

use blindoverlap::{
    FreshnessError, ReplayStore, SessionConfig, SessionDeadline, SessionNonce, TranscriptDigest,
    WireBoundReceipt,
};

#[test]
fn test_session_nonce_uniqueness() {
    let nonce1 = SessionNonce::generate();
    let nonce2 = SessionNonce::generate();

    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce1.to_hex(), nonce2.to_hex());
}

#[test]
fn test_session_nonce_roundtrip() {
    let nonce = SessionNonce::generate();
    let hex = nonce.to_hex();
    let parsed = SessionNonce::from_hex(&hex).unwrap();

    assert_eq!(nonce, parsed);
}

#[test]
fn test_session_deadline_valid() {
    let deadline = SessionDeadline::new(300);

    assert!(!deadline.is_expired());
    assert!(deadline.validate().is_ok());
    assert!(deadline.remaining().is_some());
}

#[test]
fn test_session_deadline_expired() {
    let deadline = SessionDeadline::from_timestamps(1000, 1001);

    assert!(deadline.is_expired());
    assert!(deadline.validate().is_err());
    assert!(deadline.remaining().is_none());
}

#[test]
fn test_transcript_digest_deterministic() {
    let nonce = SessionNonce::from_bytes([1u8; 32]);
    let elements = vec![[2u8; 32], [3u8; 32]];

    let digest1 = TranscriptDigest::compute("session-1", &nonce, None, &elements, None, None);
    let digest2 = TranscriptDigest::compute("session-1", &nonce, None, &elements, None, None);

    assert_eq!(digest1, digest2);
}

#[test]
fn test_transcript_digest_different_nonces() {
    let nonce1 = SessionNonce::from_bytes([1u8; 32]);
    let nonce2 = SessionNonce::from_bytes([2u8; 32]);
    let elements = vec![[3u8; 32]];

    let digest1 = TranscriptDigest::compute("session", &nonce1, None, &elements, None, None);
    let digest2 = TranscriptDigest::compute("session", &nonce2, None, &elements, None, None);

    assert_ne!(digest1, digest2);
}

// === Replay Store Tests ===

#[test]
fn test_replay_store_fresh_nonce_accepted() {
    let store = ReplayStore::new();
    let nonce = SessionNonce::generate();

    assert!(store.check_nonce(&nonce).is_ok());
}

#[test]
fn test_replay_store_duplicate_nonce_rejected() {
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
fn test_replay_store_transcript_tracking() {
    let mut store = ReplayStore::new();
    let nonce = SessionNonce::generate();
    let digest = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

    assert!(store.record_digest(digest, Some("session")).is_ok());
    assert!(store.record_digest(digest, Some("session")).is_err());
}

// === V2 Session with Freshness ===

#[test]
fn test_v2_session_generates_freshness_fields() {
    let set_a = make_set(&[json!({"x": 1})]);
    let config = SessionConfig::with_ttl(300);

    let mut session = InitiatorSession::with_config(
        "fresh-session",
        set_a,
        IntersectionMode::Intersection,
        config,
    )
    .unwrap();

    let offer = session.generate_offer().unwrap();

    assert!(offer.has_freshness());
    assert!(offer.nonce.is_some());
    assert!(offer.issued_at.is_some());
    assert!(offer.expires_at.is_some());
}

#[test]
fn test_v2_session_full_flow_with_freshness() {
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    let config = SessionConfig::with_ttl(300);

    let mut initiator = InitiatorSession::with_config(
        "v2-test",
        set_a.clone(),
        IntersectionMode::Intersection,
        config.clone(),
    )
    .unwrap();

    let mut responder = ResponderSession::with_config(
        "v2-test",
        set_b.clone(),
        IntersectionMode::Intersection,
        config,
    )
    .unwrap();

    let offer = initiator.generate_offer().unwrap();
    assert!(offer.has_freshness());

    let reply = responder.process_offer_and_reply(&offer).unwrap();
    assert!(reply.has_freshness());

    let result = initiator.process_reply(&reply).unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 2),
        _ => panic!("expected intersection result"),
    }

    assert!(initiator.responder_nonce().is_some());
    assert!(responder.initiator_nonce().is_some());
}

// === Wire-Bound Receipt Tests ===

#[test]
fn test_wire_bound_receipt_creation_and_verification() {
    let set_a = make_set(&[json!({"a": 1}), json!({"a": 2})]);
    let set_b = make_set(&[json!({"a": 2}), json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let init_nonce = SessionNonce::generate();
    let resp_nonce = SessionNonce::generate();
    let transcript = TranscriptDigest::compute(
        "bound-session",
        &init_nonce,
        Some(&resp_nonce),
        &[[1u8; 32]],
        Some(&[[2u8; 32]]),
        Some(&[[3u8; 32]]),
    );

    let signer = ReceiptSigner::new();
    let receipt = signer.sign_wire_bound(
        "bound-session",
        transcript,
        init_nonce,
        resp_nonce,
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

    let verifier = ReceiptVerifier::new();
    assert!(verifier.verify_wire_bound(&receipt).is_ok());

    assert!(verifier
        .verify_wire_bound_with_bindings(
            &receipt,
            "bound-session",
            &transcript,
            set_a.root(),
            set_b.root()
        )
        .is_ok());
}

#[test]
fn test_wire_bound_receipt_wrong_session_rejected() {
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let init_nonce = SessionNonce::generate();
    let resp_nonce = SessionNonce::generate();
    let transcript = TranscriptDigest::compute("session-1", &init_nonce, None, &[], None, None);

    let signer = ReceiptSigner::new();
    let receipt = signer.sign_wire_bound(
        "session-1",
        transcript,
        init_nonce,
        resp_nonce,
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

    let verifier = ReceiptVerifier::new();
    let result = verifier.verify_wire_bound_with_bindings(
        &receipt,
        "session-WRONG",
        &transcript,
        set_a.root(),
        set_b.root(),
    );
    assert!(result.is_err());
}

#[test]
fn test_wire_bound_receipt_json_serialization() {
    let set_a = make_set(&[json!({"a": 1})]);
    let set_b = make_set(&[json!({"b": 1})]);

    let protocol = PsiProtocol::new();
    let result = protocol
        .intersect(&set_a, &set_b, IntersectionMode::Intersection)
        .unwrap();

    let init_nonce = SessionNonce::generate();
    let resp_nonce = SessionNonce::generate();
    let transcript = TranscriptDigest::compute("session", &init_nonce, None, &[], None, None);

    let signer = ReceiptSigner::new();
    let receipt = signer.sign_wire_bound(
        "session",
        transcript,
        init_nonce,
        resp_nonce,
        set_a.root(),
        set_b.root(),
        &result,
        IntersectionMode::Intersection,
    );

    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let parsed: WireBoundReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(receipt.session_id, parsed.session_id);
    assert_eq!(receipt.transcript_digest, parsed.transcript_digest);
    assert_eq!(receipt.initiator_nonce, parsed.initiator_nonce);
    assert_eq!(receipt.responder_nonce, parsed.responder_nonce);
    assert_eq!(receipt.signature, parsed.signature);

    let verifier = ReceiptVerifier::new();
    assert!(verifier.verify_wire_bound(&parsed).is_ok());
}

// === V2 Wire Message Tests ===

#[test]
fn test_v2_offer_wire_roundtrip() {
    let nonce = SessionNonce::generate();
    let deadline = SessionDeadline::new(300);
    let elements = vec![[1u8; 32], [2u8; 32]];

    let offer = MaskedSetOffer::new_v2("v2-session", elements.clone(), nonce, deadline);

    assert!(offer.has_freshness());
    assert_eq!(offer.version, 2);

    let message = WireMessage::Offer(offer.clone());
    let json = wire_encode(&message).unwrap();
    let decoded = wire_decode(&json).unwrap();

    match decoded {
        WireMessage::Offer(decoded_offer) => {
            assert_eq!(decoded_offer.version, 2);
            assert_eq!(decoded_offer.nonce, offer.nonce);
            assert_eq!(decoded_offer.masked_elements, elements);
        }
        _ => panic!("expected offer"),
    }
}

#[test]
fn test_v2_reply_wire_roundtrip() {
    let init_nonce = SessionNonce::generate();
    let resp_nonce = SessionNonce::generate();
    let deadline = SessionDeadline::new(300);

    let reply = MaskedSetReply::new_v2(
        "v2-session",
        vec![[1u8; 32]],
        vec![[2u8; 32]],
        init_nonce,
        resp_nonce,
        deadline,
    );

    assert!(reply.has_freshness());
    assert_eq!(reply.version, 2);

    let message = WireMessage::Reply(reply.clone());
    let json = wire_encode(&message).unwrap();
    let decoded = wire_decode(&json).unwrap();

    match decoded {
        WireMessage::Reply(decoded_reply) => {
            assert_eq!(decoded_reply.version, 2);
            assert_eq!(decoded_reply.initiator_nonce, reply.initiator_nonce);
            assert_eq!(decoded_reply.responder_nonce, reply.responder_nonce);
        }
        _ => panic!("expected reply"),
    }
}

// === Mixed v1/v2 Compatibility ===

#[test]
fn test_v2_session_with_v1_messages_still_works() {
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3})]);

    let mut initiator = InitiatorSession::with_secret(
        "compat-test",
        set_a,
        IntersectionMode::Intersection,
        [1u8; 32],
    )
    .unwrap();

    let mut responder = ResponderSession::with_secret(
        "compat-test",
        set_b,
        IntersectionMode::Intersection,
        [2u8; 32],
    )
    .unwrap();

    let offer = initiator.generate_offer().unwrap();
    assert!(!offer.has_freshness());

    let reply = responder.process_offer_and_reply(&offer).unwrap();
    let result = initiator.process_reply(&reply).unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 1),
        _ => panic!("expected intersection"),
    }
}

// === Identity Tests (v0.4.0) ===

use blindoverlap::{
    wire_decode_signed, wire_decode_signed_from_peer, wire_encode_signed, PartyIdentity,
    PublicIdentity, SignedWireMessage,
};

#[test]
fn test_signed_message_roundtrip() {
    let identity = PartyIdentity::generate();
    let offer = MaskedSetOffer::new("signed-test", vec![[1u8; 32], [2u8; 32]]);
    let message = WireMessage::Offer(offer);

    let signed = SignedWireMessage::sign(message.clone(), &identity);
    let json = wire_encode_signed(&signed).unwrap();
    let decoded = wire_decode_signed(&json).unwrap();

    assert_eq!(decoded.signer_pubkey, identity.public());
    assert_eq!(decoded.message, message);
}

#[test]
fn test_signed_message_bad_signature_rejected() {
    let identity = PartyIdentity::generate();
    let offer = MaskedSetOffer::new("test", vec![[1u8; 32]]);
    let message = WireMessage::Offer(offer);

    let mut signed = SignedWireMessage::sign(message, &identity);
    signed.signature[0] ^= 0xFF; // Corrupt signature

    let json = wire_encode_signed(&signed).unwrap();
    let result = wire_decode_signed(&json);
    assert!(result.is_err());
}

#[test]
fn test_signed_message_wrong_peer_rejected() {
    let alice = PartyIdentity::generate();
    let bob = PartyIdentity::generate();

    let offer = MaskedSetOffer::new("test", vec![[1u8; 32]]);
    let message = WireMessage::Offer(offer);

    let signed = SignedWireMessage::sign(message, &alice);
    let json = wire_encode_signed(&signed).unwrap();

    // Alice signed it, but we expect Bob
    let result = wire_decode_signed_from_peer(&json, &bob.public());
    assert!(result.is_err());

    // Should work when we expect Alice
    let result = wire_decode_signed_from_peer(&json, &alice.public());
    assert!(result.is_ok());
}

#[test]
fn test_identity_end_to_end_signed_psi() {
    let alice_id = PartyIdentity::generate();
    let bob_id = PartyIdentity::generate();

    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    // Alice initiates with her identity
    let mut initiator = InitiatorSession::with_channel_binding(
        "identity-test",
        set_a.clone(),
        IntersectionMode::Intersection,
        &alice_id,
        bob_id.public(),
    )
    .unwrap();

    // Bob responds with his identity
    let mut responder = ResponderSession::with_channel_binding(
        "identity-test",
        set_b.clone(),
        IntersectionMode::Intersection,
        &bob_id,
        alice_id.public(),
    )
    .unwrap();

    // Alice creates signed offer
    let signed_offer = initiator.generate_offer_signed(&alice_id).unwrap();
    assert_eq!(signed_offer.signer_pubkey, alice_id.public());

    // Bob processes signed offer, creates signed reply
    let signed_reply = responder
        .process_offer_and_reply_signed(&signed_offer, &bob_id)
        .unwrap();
    assert_eq!(signed_reply.signer_pubkey, bob_id.public());
    assert!(responder.verified_peer().is_some());
    assert_eq!(responder.verified_peer().unwrap(), &alice_id.public());

    // Alice processes signed reply
    let result = initiator.process_reply_signed(&signed_reply).unwrap();
    assert!(initiator.verified_peer().is_some());
    assert_eq!(initiator.verified_peer().unwrap(), &bob_id.public());

    match result {
        PsiResult::Intersection { ids, .. } => {
            assert_eq!(ids.len(), 2, "should find 2 common elements");
        }
        _ => panic!("expected intersection result"),
    }
}

#[test]
fn test_identity_mismatch_rejected() {
    let alice_id = PartyIdentity::generate();
    let bob_id = PartyIdentity::generate();
    let eve_id = PartyIdentity::generate(); // Malicious party

    let set_a = make_set(&[json!({"x": 1})]);

    // Alice initiates expecting Bob
    let mut initiator = InitiatorSession::with_channel_binding(
        "mismatch-test",
        set_a,
        IntersectionMode::Intersection,
        &alice_id,
        bob_id.public(),
    )
    .unwrap();

    // Eve impersonates by signing with her own key
    let eve_signed_reply = SignedWireMessage::sign(
        WireMessage::Reply(MaskedSetReply::new(
            "mismatch-test",
            vec![[2u8; 32]],
            vec![[1u8; 32]],
        )),
        &eve_id,
    );

    let _ = initiator.generate_offer().unwrap();

    // Alice rejects Eve's reply because it's not signed by Bob
    let result = initiator.process_reply_signed(&eve_signed_reply);
    assert!(result.is_err());
}

#[test]
fn test_public_identity_hex_serialization() {
    let identity = PartyIdentity::generate();
    let pubkey = identity.public();

    let hex = pubkey.to_hex();
    let restored = PublicIdentity::from_hex(&hex).unwrap();

    assert_eq!(pubkey, restored);
}

#[test]
fn test_unsigned_v2_still_works_without_identity() {
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3})]);

    // Sessions without identity binding should still work with v2 protocol
    let config = SessionConfig::with_ttl(300);

    let mut initiator = InitiatorSession::with_config(
        "no-identity",
        set_a,
        IntersectionMode::Intersection,
        config.clone(),
    )
    .unwrap();

    let mut responder =
        ResponderSession::with_config("no-identity", set_b, IntersectionMode::Intersection, config)
            .unwrap();

    // Use regular (unsigned) message flow
    let offer = initiator.generate_offer().unwrap();
    assert!(offer.has_freshness());

    let reply = responder.process_offer_and_reply(&offer).unwrap();
    let result = initiator.process_reply(&reply).unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => assert_eq!(ids.len(), 1),
        _ => panic!("expected intersection"),
    }
}

// === v0.5.0 Integration Tests ===

use blindoverlap::{
    AllowedMode, InviteError, InviteTicket, PersistentReplayStore, SealedSessionRecord,
    SessionStatus,
};
use tempfile::NamedTempFile;

// === Invite Ticket Tests ===

#[test]
fn test_invite_issue_verify_roundtrip() {
    let issuer = PartyIdentity::generate();

    let ticket = InviteTicket::issue_default(&issuer, "test-session", None, AllowedMode::Any);

    assert!(ticket.verify().is_ok());
    assert!(ticket.verify_issuer(&issuer.public()).is_ok());
    assert!(!ticket.is_expired());
}

#[test]
fn test_invite_peer_binding() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();
    let other = PartyIdentity::generate();

    let ticket = InviteTicket::issue_default(
        &issuer,
        "peer-bound-session",
        Some(peer.public()),
        AllowedMode::Intersection,
    );

    // Correct peer can use it
    assert!(ticket.verify_for_peer(&peer.public()).is_ok());

    // Wrong peer cannot
    assert!(ticket.verify_for_peer(&other.public()).is_err());
}

#[test]
fn test_invite_mode_restriction() {
    let issuer = PartyIdentity::generate();

    let intersection_only =
        InviteTicket::issue_default(&issuer, "mode-test", None, AllowedMode::Intersection);

    assert!(intersection_only
        .verify_for_session("mode-test", IntersectionMode::Intersection)
        .is_ok());
    assert!(intersection_only
        .verify_for_session("mode-test", IntersectionMode::Cardinality)
        .is_err());
}

#[test]
fn test_invite_expired_ticket() {
    let issuer = PartyIdentity::generate();

    // Create manually with past timestamps to test expiry detection
    let ticket = InviteTicket {
        version: 1,
        session_id: "expired-session".to_string(),
        issuer_pubkey: issuer.public(),
        peer_pubkey: None,
        allowed_mode: AllowedMode::Any,
        issued_at: 1000,
        expires_at: 1001,
        signature: [0u8; 64], // Invalid sig but we test expiry first
    };

    assert!(ticket.is_expired());
    assert!(ticket.remaining_secs().is_none());
}

#[test]
fn test_invite_json_roundtrip() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let ticket = InviteTicket::issue_default(
        &issuer,
        "json-test",
        Some(peer.public()),
        AllowedMode::Cardinality,
    );

    let json = ticket.to_json_pretty().unwrap();
    let parsed = InviteTicket::from_json(&json).unwrap();

    assert_eq!(ticket.session_id, parsed.session_id);
    assert_eq!(ticket.issuer_pubkey, parsed.issuer_pubkey);
    assert_eq!(ticket.peer_pubkey, parsed.peer_pubkey);
    assert!(parsed.verify().is_ok());
}

#[test]
fn test_invite_tampered_signature_rejected() {
    let issuer = PartyIdentity::generate();

    let mut ticket = InviteTicket::issue_default(&issuer, "tamper-test", None, AllowedMode::Any);
    ticket.signature[0] ^= 0xFF;

    assert!(matches!(
        ticket.verify(),
        Err(InviteError::InvalidSignature)
    ));
}

// === Sealed Session Record Tests ===

#[test]
fn test_sealed_record_build_unsigned() {
    let record = SealedSessionRecord::builder()
        .session_id("record-test")
        .protocol_version(2)
        .status(SessionStatus::Completed)
        .add_sent_message("offer", r#"{"test":"offer"}"#)
        .add_received_message("reply", r#"{"test":"reply"}"#)
        .build()
        .unwrap();

    assert_eq!(record.session_id, "record-test");
    assert_eq!(record.messages.len(), 2);
    assert!(!record.is_sealed());
    assert!(record.verify_integrity().is_ok());
}

#[test]
fn test_sealed_record_with_seal() {
    let identity = PartyIdentity::generate();

    let record = SealedSessionRecord::builder()
        .session_id("sealed-test")
        .local_pubkey(identity.public())
        .build_sealed(&identity)
        .unwrap();

    assert!(record.is_sealed());
    assert!(record.verify_seal().is_ok());
    assert!(record.verify_seal_from(&identity.public()).is_ok());
}

#[test]
fn test_sealed_record_wrong_sealer_rejected() {
    let alice = PartyIdentity::generate();
    let bob = PartyIdentity::generate();

    let record = SealedSessionRecord::builder()
        .session_id("sealer-test")
        .build_sealed(&alice)
        .unwrap();

    assert!(record.verify_seal_from(&alice.public()).is_ok());
    assert!(record.verify_seal_from(&bob.public()).is_err());
}

#[test]
fn test_sealed_record_json_roundtrip() {
    let identity = PartyIdentity::generate();

    let record = SealedSessionRecord::builder()
        .session_id("json-record")
        .add_sent_message("offer", r#"{"data":"test"}"#)
        .build_sealed(&identity)
        .unwrap();

    let json = record.to_json_pretty().unwrap();
    let parsed = SealedSessionRecord::from_json(&json).unwrap();

    assert_eq!(record.session_id, parsed.session_id);
    assert_eq!(record.body_digest, parsed.body_digest);
    assert!(parsed.verify_seal().is_ok());
}

#[test]
fn test_sealed_record_tampered_fails_integrity() {
    let mut record = SealedSessionRecord::builder()
        .session_id("tamper-test")
        .build()
        .unwrap();

    record.session_id = "modified".to_string();

    assert!(record.verify_integrity().is_err());
}

// === Persistent Replay Store Tests ===

#[test]
fn test_persistent_replay_survives_reload() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let nonce1 = SessionNonce::generate();
    let nonce2 = SessionNonce::generate();

    // First session
    {
        let mut store = PersistentReplayStore::open(&path).unwrap();
        store.record_nonce(nonce1, Some("session-1")).unwrap();
    }

    // Second session (simulates restart)
    {
        let mut store = PersistentReplayStore::open(&path).unwrap();
        // nonce1 should be rejected
        assert!(store.check_nonce(&nonce1).is_err());
        // nonce2 should be fresh
        store.record_nonce(nonce2, Some("session-2")).unwrap();
    }

    // Third session
    {
        let store = PersistentReplayStore::open(&path).unwrap();
        assert_eq!(store.nonce_count(), 2);
        assert!(store.check_nonce(&nonce1).is_err());
        assert!(store.check_nonce(&nonce2).is_err());
    }
}

#[test]
fn test_persistent_replay_with_digests() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let nonce = SessionNonce::generate();
    let digest = TranscriptDigest::compute("session", &nonce, None, &[], None, None);

    {
        let mut store = PersistentReplayStore::open(&path).unwrap();
        store.record_digest(digest, Some("session")).unwrap();
    }

    {
        let store = PersistentReplayStore::open(&path).unwrap();
        assert_eq!(store.digest_count(), 1);
        assert!(store.check_digest(&digest).is_err());
    }
}

// === Invite-Based Session Bootstrap Tests ===

#[test]
fn test_session_from_invite_initiator() {
    let issuer = PartyIdentity::generate();
    let responder_id = PartyIdentity::generate();

    let ticket = InviteTicket::issue_default(
        &issuer,
        "invite-session",
        Some(responder_id.public()),
        AllowedMode::Intersection,
    );

    let set = make_set(&[json!({"x": 1}), json!({"x": 2})]);

    // Responder uses the ticket to create session
    let session =
        ResponderSession::from_invite(&ticket, set, IntersectionMode::Intersection, &responder_id)
            .unwrap();

    assert_eq!(session.session_id(), "invite-session");
    assert!(session.has_channel_binding());
}

#[test]
fn test_session_from_invite_wrong_peer_rejected() {
    let issuer = PartyIdentity::generate();
    let intended_peer = PartyIdentity::generate();
    let wrong_peer = PartyIdentity::generate();

    let ticket = InviteTicket::issue_default(
        &issuer,
        "wrong-peer-session",
        Some(intended_peer.public()),
        AllowedMode::Any,
    );

    let set = make_set(&[json!({"x": 1})]);

    // Wrong peer tries to use the ticket
    let result =
        ResponderSession::from_invite(&ticket, set, IntersectionMode::Intersection, &wrong_peer);

    assert!(result.is_err());
}

#[test]
fn test_session_from_invite_wrong_mode_rejected() {
    let issuer = PartyIdentity::generate();
    let responder_id = PartyIdentity::generate();

    let ticket = InviteTicket::issue_default(
        &issuer,
        "mode-restrict-session",
        None,
        AllowedMode::Cardinality, // Only cardinality allowed
    );

    let set = make_set(&[json!({"x": 1})]);

    // Try to use intersection mode
    let result = ResponderSession::from_invite(
        &ticket,
        set,
        IntersectionMode::Intersection, // Wrong mode
        &responder_id,
    );

    assert!(result.is_err());
}

// === End-to-End Invite → Signed PSI → Export Test ===

#[test]
fn test_end_to_end_invite_signed_psi_export() {
    let alice = PartyIdentity::generate();
    let bob = PartyIdentity::generate();

    // Alice issues invite to Bob
    let ticket = InviteTicket::issue_default(
        &alice,
        "e2e-session",
        Some(bob.public()),
        AllowedMode::Intersection,
    );

    assert!(ticket.verify().is_ok());

    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    // Alice (the issuer) creates initiator session directly with channel binding
    // She expects Bob as the peer
    let mut initiator = InitiatorSession::with_channel_binding(
        "e2e-session",
        set_a,
        IntersectionMode::Intersection,
        &alice,
        bob.public(),
    )
    .unwrap();

    // Bob (the invitee) creates responder session from the invite
    // from_invite verifies the ticket and sets issuer (Alice) as expected peer
    let mut responder =
        ResponderSession::from_invite(&ticket, set_b, IntersectionMode::Intersection, &bob)
            .unwrap();

    // Run signed PSI protocol
    let signed_offer = initiator.generate_offer_signed(&alice).unwrap();
    let signed_reply = responder
        .process_offer_and_reply_signed(&signed_offer, &bob)
        .unwrap();
    let result = initiator.process_reply_signed(&signed_reply).unwrap();

    // Verify result
    match result {
        PsiResult::Intersection { ids, .. } => {
            assert_eq!(ids.len(), 2); // {x:2} and {x:3}
        }
        _ => panic!("expected intersection"),
    }

    // Export sealed session record
    let record = SealedSessionRecord::builder()
        .session_id("e2e-session")
        .status(SessionStatus::Completed)
        .local_pubkey(alice.public())
        .peer_pubkey(bob.public())
        .initiator_nonce(*initiator.nonce())
        .add_sent_message("offer", &serde_json::to_string(&signed_offer).unwrap())
        .add_received_message("reply", &serde_json::to_string(&signed_reply).unwrap())
        .build_sealed(&alice)
        .unwrap();

    // Verify the record
    assert!(record.verify_seal().is_ok());
    assert!(record.verify_seal_from(&alice.public()).is_ok());
    assert_eq!(record.messages.len(), 2);
    assert_eq!(record.status, SessionStatus::Completed);
}

// === v0.6.0 Integration Tests ===

use blindoverlap::{AbortReason, AbortReceipt, SessionLease, TrustedPeerBook};

// === TrustedPeerBook Tests ===

#[test]
fn test_peerbook_add_lookup_remove() {
    let mut book = TrustedPeerBook::in_memory();
    let alice = PartyIdentity::generate();
    let bob = PartyIdentity::generate();

    // Add peers
    book.add(alice.public(), Some("Alice".to_string())).unwrap();
    book.add(bob.public(), Some("Bob".to_string())).unwrap();

    // Lookup
    assert!(book.is_trusted(&alice.public()));
    assert!(book.is_trusted(&bob.public()));
    assert_eq!(book.len(), 2);

    let alice_entry = book.lookup(&alice.public()).unwrap();
    assert_eq!(alice_entry.nickname, Some("Alice".to_string()));

    // Remove
    let removed = book.remove(&alice.public()).unwrap();
    assert_eq!(removed.nickname, Some("Alice".to_string()));
    assert!(!book.is_trusted(&alice.public()));
    assert_eq!(book.len(), 1);
}

#[test]
fn test_peerbook_duplicate_rejected() {
    let mut book = TrustedPeerBook::in_memory();
    let identity = PartyIdentity::generate();

    book.add(identity.public(), None).unwrap();
    let result = book.add(identity.public(), Some("Duplicate".to_string()));

    assert!(result.is_err());
}

#[test]
fn test_peerbook_file_persistence() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let identity = PartyIdentity::generate();

    {
        let mut book = TrustedPeerBook::open(&path).unwrap();
        book.add(identity.public(), Some("Persistent".to_string()))
            .unwrap();
    }

    {
        let book = TrustedPeerBook::open(&path).unwrap();
        assert!(book.is_trusted(&identity.public()));
        let peer = book.lookup(&identity.public()).unwrap();
        assert_eq!(peer.nickname, Some("Persistent".to_string()));
    }
}

#[test]
fn test_peerbook_require_trusted() {
    let book = TrustedPeerBook::in_memory();
    let identity = PartyIdentity::generate();

    let result = book.require_trusted(&identity.public());
    assert!(result.is_err());
}

// === SessionLease Tests ===

#[test]
fn test_lease_issue_verify() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let lease = SessionLease::issue_default(&issuer, "test-session", peer.public());

    assert!(lease.verify().is_ok());
    assert!(!lease.is_expired());
    assert!(!lease.is_renewal());
    assert_eq!(lease.renew_count, 0);
}

#[test]
fn test_lease_verify_full() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let lease = SessionLease::issue_default(&issuer, "full-test", peer.public());

    // Full verification passes
    assert!(lease
        .verify_full(&issuer.public(), &peer.public(), "full-test")
        .is_ok());

    // Wrong issuer
    let other = PartyIdentity::generate();
    assert!(lease
        .verify_full(&other.public(), &peer.public(), "full-test")
        .is_err());

    // Wrong peer
    assert!(lease
        .verify_full(&issuer.public(), &other.public(), "full-test")
        .is_err());

    // Wrong session
    assert!(lease
        .verify_full(&issuer.public(), &peer.public(), "wrong-session")
        .is_err());
}

#[test]
fn test_lease_renew_chain() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let lease1 = SessionLease::issue_default(&issuer, "chain-session", peer.public());
    let lease2 = lease1.renew_default(&issuer).unwrap();
    let lease3 = lease2.renew_default(&issuer).unwrap();

    assert_eq!(lease3.renew_count, 2);
    assert!(lease3.is_renewal());
    assert_eq!(lease3.parent_lease_id, Some(lease2.lease_id()));
    assert!(lease3.verify().is_ok());
}

#[test]
fn test_lease_renew_wrong_issuer() {
    let issuer = PartyIdentity::generate();
    let other = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let lease = SessionLease::issue_default(&issuer, "test", peer.public());
    let result = lease.renew_default(&other);

    assert!(result.is_err());
}

#[test]
fn test_lease_json_roundtrip() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let lease = SessionLease::issue_default(&issuer, "json-test", peer.public());
    let json = lease.to_json_pretty().unwrap();
    let parsed = SessionLease::from_json(&json).unwrap();

    assert_eq!(lease.session_id, parsed.session_id);
    assert_eq!(lease.issuer_pubkey, parsed.issuer_pubkey);
    assert_eq!(lease.peer_pubkey, parsed.peer_pubkey);
    assert!(parsed.verify().is_ok());
}

// === AbortReceipt Tests ===

#[test]
fn test_abort_receipt_simple() {
    let issuer = PartyIdentity::generate();

    let receipt = AbortReceipt::simple(&issuer, "abort-session", AbortReason::UserCancelled);

    assert!(receipt.verify().is_ok());
    assert_eq!(receipt.reason, AbortReason::UserCancelled);
    assert!(receipt.reason_text.is_none());
}

#[test]
fn test_abort_receipt_with_reason_text() {
    let issuer = PartyIdentity::generate();

    let receipt = AbortReceipt::with_reason(&issuer, "abort-session", "Connection lost");

    assert!(receipt.verify().is_ok());
    assert_eq!(receipt.reason, AbortReason::Custom);
    assert_eq!(receipt.reason_text, Some("Connection lost".to_string()));
}

#[test]
fn test_abort_receipt_with_transcript() {
    let issuer = PartyIdentity::generate();
    let nonce = SessionNonce::generate();
    let digest = TranscriptDigest::compute("abort-session", &nonce, None, &[], None, None);

    let receipt =
        AbortReceipt::with_transcript(&issuer, "abort-session", AbortReason::Timeout, digest);

    assert!(receipt.verify().is_ok());
    assert_eq!(receipt.transcript_digest, Some(digest));
}

#[test]
fn test_abort_receipt_json_roundtrip() {
    let issuer = PartyIdentity::generate();

    let receipt = AbortReceipt::with_reason(&issuer, "json-test", "Testing");
    let json = receipt.to_json_pretty().unwrap();
    let parsed = AbortReceipt::from_json(&json).unwrap();

    assert_eq!(receipt.session_id, parsed.session_id);
    assert_eq!(receipt.reason, parsed.reason);
    assert_eq!(receipt.reason_text, parsed.reason_text);
    assert!(parsed.verify().is_ok());
}

#[test]
fn test_abort_receipt_tampered_rejected() {
    let issuer = PartyIdentity::generate();

    let mut receipt = AbortReceipt::simple(&issuer, "tamper-test", AbortReason::Unknown);
    receipt.signature[0] ^= 0xFF;

    assert!(receipt.verify().is_err());
}

// === Session from Lease Tests ===

#[test]
fn test_session_from_lease() {
    let issuer = PartyIdentity::generate();
    let peer = PartyIdentity::generate();

    let lease = SessionLease::issue_default(&issuer, "lease-session", peer.public());

    let set = make_set(&[json!({"x": 1}), json!({"x": 2})]);

    // Peer uses the lease to create responder session
    let session =
        ResponderSession::from_lease(&lease, set, IntersectionMode::Intersection, &peer).unwrap();

    assert_eq!(session.session_id(), "lease-session");
    assert!(session.has_channel_binding());
}

#[test]
fn test_session_from_lease_wrong_peer() {
    let issuer = PartyIdentity::generate();
    let intended_peer = PartyIdentity::generate();
    let wrong_peer = PartyIdentity::generate();

    let lease = SessionLease::issue_default(&issuer, "lease-session", intended_peer.public());

    let set = make_set(&[json!({"x": 1})]);

    // Wrong peer tries to use the lease
    let result =
        ResponderSession::from_lease(&lease, set, IntersectionMode::Intersection, &wrong_peer);

    assert!(result.is_err());
}

// === Sealed Record with Aborted Status ===

#[test]
fn test_sealed_record_aborted_status() {
    let identity = PartyIdentity::generate();

    let record = SealedSessionRecord::builder()
        .session_id("aborted-session")
        .status(SessionStatus::Aborted)
        .build_sealed(&identity)
        .unwrap();

    assert_eq!(record.status, SessionStatus::Aborted);
    assert!(record.verify_seal().is_ok());
}

// === End-to-End: Peerbook Trust Gate → Lease → PSI → Abort ===

#[test]
fn test_end_to_end_peerbook_lease_psi_abort() {
    let alice = PartyIdentity::generate();
    let bob = PartyIdentity::generate();

    // Alice adds Bob to her peerbook
    let mut alice_peerbook = TrustedPeerBook::in_memory();
    alice_peerbook
        .add(bob.public(), Some("Bob".to_string()))
        .unwrap();

    // Alice issues a lease to Bob
    let lease = SessionLease::issue_default(&alice, "e2e-v6-session", bob.public());
    assert!(lease.verify().is_ok());

    // Bob creates responder from lease (Alice is expected peer)
    let set_a = make_set(&[json!({"x": 1}), json!({"x": 2}), json!({"x": 3})]);
    let set_b = make_set(&[json!({"x": 2}), json!({"x": 3}), json!({"x": 4})]);

    // Verify Bob is trusted before starting session
    assert!(alice_peerbook.require_trusted(&bob.public()).is_ok());

    let mut initiator = InitiatorSession::with_channel_binding(
        "e2e-v6-session",
        set_a,
        IntersectionMode::Intersection,
        &alice,
        bob.public(),
    )
    .unwrap();

    let mut responder =
        ResponderSession::from_lease(&lease, set_b, IntersectionMode::Intersection, &bob).unwrap();

    // Run signed PSI protocol
    let signed_offer = initiator.generate_offer_signed(&alice).unwrap();
    let signed_reply = responder
        .process_offer_and_reply_signed(&signed_offer, &bob)
        .unwrap();
    let result = initiator.process_reply_signed(&signed_reply).unwrap();

    match result {
        PsiResult::Intersection { ids, .. } => {
            assert_eq!(ids.len(), 2); // {x:2} and {x:3}
        }
        _ => panic!("expected intersection"),
    }

    // Create abort receipt to cancel before bilateral reveal
    let abort = AbortReceipt::simple(&alice, "e2e-v6-session", AbortReason::UserCancelled);
    assert!(abort.verify().is_ok());

    // Export sealed session record with Aborted status
    let record = SealedSessionRecord::builder()
        .session_id("e2e-v6-session")
        .status(SessionStatus::Aborted)
        .local_pubkey(alice.public())
        .peer_pubkey(bob.public())
        .initiator_nonce(*initiator.nonce())
        .build_sealed(&alice)
        .unwrap();

    assert!(record.verify_seal().is_ok());
    assert_eq!(record.status, SessionStatus::Aborted);
}

// === Wire AbortMessage Tests ===

use blindoverlap::AbortMessage;

#[test]
fn test_abort_message_roundtrip() {
    let abort = AbortMessage::new("abort-wire-test", "user_cancelled");
    let message = WireMessage::Abort(abort.clone());

    let json = wire_encode(&message).unwrap();
    let decoded = wire_decode(&json).unwrap();

    match decoded {
        WireMessage::Abort(decoded_abort) => {
            assert_eq!(decoded_abort.session_id, abort.session_id);
            assert_eq!(decoded_abort.reason_code, abort.reason_code);
        }
        _ => panic!("expected abort message"),
    }
}

#[test]
fn test_abort_message_with_reason_text() {
    let abort = AbortMessage::with_reason("abort-wire-test", "custom", "Something went wrong");
    let message = WireMessage::Abort(abort);

    let json = wire_encode(&message).unwrap();
    let decoded = wire_decode(&json).unwrap();

    assert!(decoded.is_abort());
    match decoded {
        WireMessage::Abort(a) => {
            assert_eq!(a.reason_text, Some("Something went wrong".to_string()));
        }
        _ => panic!(),
    }
}
