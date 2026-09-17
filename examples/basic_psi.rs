//! Basic PSI example demonstrating BlindOverlap usage.
//!
//! Run with: cargo run --example basic_psi

use blindoverlap::{
    fact_id_from_json, FactSet, IntersectionMode, PsiProtocol, PsiResult, ReceiptSigner,
    ReceiptVerifier,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BlindOverlap Basic PSI Example ===\n");

    // Agent A's facts (memories)
    let agent_a_facts = [
        json!({"event": "meeting", "date": "2026-01-15", "topic": "project kickoff"}),
        json!({"event": "meeting", "date": "2026-02-20", "topic": "design review"}),
        json!({"event": "meeting", "date": "2026-03-10", "topic": "launch planning"}),
        json!({"observation": "sky", "color": "blue"}),
    ];

    // Agent B's facts (memories)
    let agent_b_facts = [
        json!({"event": "meeting", "date": "2026-02-20", "topic": "design review"}),
        json!({"event": "meeting", "date": "2026-03-10", "topic": "launch planning"}),
        json!({"event": "meeting", "date": "2026-04-01", "topic": "retrospective"}),
        json!({"observation": "grass", "color": "green"}),
    ];

    // Convert to fact IDs and create FactSets
    let set_a = FactSet::from_ids(agent_a_facts.iter().map(fact_id_from_json));
    let set_b = FactSet::from_ids(agent_b_facts.iter().map(fact_id_from_json));

    println!("Agent A has {} facts", set_a.len());
    println!("Agent A set root: {}", hex::encode(set_a.root()));
    println!();

    println!("Agent B has {} facts", set_b.len());
    println!("Agent B set root: {}", hex::encode(set_b.root()));
    println!();

    // Run PSI protocol
    let protocol = PsiProtocol::new();

    // First, try cardinality mode
    println!("=== Cardinality Mode ===");
    let cardinality_result = protocol.intersect(&set_a, &set_b, IntersectionMode::Cardinality)?;

    match &cardinality_result {
        PsiResult::Cardinality { count } => {
            println!("Agents share {} common fact(s)", count);
        }
        _ => unreachable!(),
    }
    println!();

    // Now, full intersection mode
    println!("=== Intersection Mode ===");
    let intersection_result = protocol.intersect(&set_a, &set_b, IntersectionMode::Intersection)?;

    match &intersection_result {
        PsiResult::Intersection { ids, root } => {
            println!("Found {} matching fact(s)", ids.len());
            println!("Intersection root: {}", hex::encode(root));
            println!("\nMatching fact IDs:");
            for (i, id) in ids.iter().enumerate() {
                println!("  {}: {}", i + 1, hex::encode(id));
            }
        }
        _ => unreachable!(),
    }
    println!();

    // Create and verify a receipt
    println!("=== Receipt Signing ===");
    let signer = ReceiptSigner::new();
    let receipt = signer.sign(
        set_a.root(),
        set_b.root(),
        &intersection_result,
        IntersectionMode::Intersection,
    );

    println!("Receipt created:");
    println!("  Version: {}", receipt.version);
    println!("  Mode: {:?}", receipt.mode);
    println!("  Receipt ID: {}", hex::encode(receipt.receipt_id()));
    println!("  Signer: {}", hex::encode(receipt.signer_public_key));
    println!();

    // Verify the receipt
    println!("=== Receipt Verification ===");
    let verifier = ReceiptVerifier::new();

    match verifier.verify_with_roots(&receipt, set_a.root(), set_b.root()) {
        Ok(()) => {
            println!("✓ Receipt verified successfully!");
            println!("✓ Set roots match expected values");
        }
        Err(e) => {
            println!("✗ Receipt verification failed: {}", e);
        }
    }
    println!();

    // Demonstrate tampering detection
    println!("=== Tampering Detection Demo ===");
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.signature[0] ^= 0xFF;

    match verifier.verify(&tampered_receipt) {
        Ok(()) => println!("✗ Tampered receipt incorrectly verified!"),
        Err(_) => println!("✓ Tampered receipt correctly rejected!"),
    }

    println!("\n=== Done ===");
    Ok(())
}
