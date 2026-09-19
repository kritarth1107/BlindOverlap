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
    assert!(matches!(result.unwrap_err(), FreshnessError::ReplayDetected(_)));
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
        .verify_wire_bound_with_bindings(&receipt, "bound-session", &transcript, set_a.root(), set_b.root())
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
