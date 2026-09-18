//! HTTP Demo: Two-party PSI over TCP using wire protocol.
//!
//! **THIS IS A DEMO, NOT PRODUCTION CODE.**
//!
//! This example demonstrates:
//! - Server (Party B) exposes PSI responder endpoint
//! - Client (Party A) initiates PSI by sending offer, receiving reply
//!
//! To run:
//! ```bash
//! # Terminal 1: Start server
//! cargo run --example http_psi_demo -- server
//!
//! # Terminal 2: Run client
//! cargo run --example http_psi_demo -- client
//! ```
//!
//! Security notes:
//! - No TLS (use in local/trusted networks only)
//! - No authentication (any client can query)
//! - Semi-honest security model only
//! - Uses simple length-prefixed TCP framing

use blindoverlap::{
    fact_id_from_json, wire_decode, wire_encode, FactSet, InitiatorSession, IntersectionMode,
    PsiResult, ResponderSession, WireMessage,
};
use serde_json::json;
use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SERVER_ADDR: &str = "127.0.0.1:3000";

fn make_server_facts() -> FactSet {
    FactSet::from_ids([
        fact_id_from_json(&json!({"fact": "shared-1"})),
        fact_id_from_json(&json!({"fact": "shared-2"})),
        fact_id_from_json(&json!({"fact": "server-only-1"})),
        fact_id_from_json(&json!({"fact": "server-only-2"})),
    ])
}

fn make_client_facts() -> FactSet {
    FactSet::from_ids([
        fact_id_from_json(&json!({"fact": "shared-1"})),
        fact_id_from_json(&json!({"fact": "shared-2"})),
        fact_id_from_json(&json!({"fact": "client-only-1"})),
    ])
}

async fn send_message(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn recv_message(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: http_psi_demo <server|client>");
        println!();
        println!("Demo: Two-party PSI over TCP with wire protocol");
        println!();
        println!("  server  - Start PSI responder server on {}", SERVER_ADDR);
        println!("  client  - Connect to server and run PSI");
        println!();
        println!("This demo uses length-prefixed TCP framing for simplicity.");
        println!("In production, use TLS and proper HTTP with axum/hyper.");
        return Ok(());
    }

    match args[1].as_str() {
        "server" => run_server().await,
        "client" => run_client().await,
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI Demo Server (Party B) ===");
    println!();
    println!("Server facts (4 elements):");
    println!("  - shared-1, shared-2 (will match with client)");
    println!("  - server-only-1, server-only-2 (private)");
    println!();

    let listener = TcpListener::bind(SERVER_ADDR).await?;
    println!("Listening on tcp://{SERVER_ADDR}");
    println!("Waiting for client connections...");
    println!();

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("Client connected from {addr}");

        let server_facts = make_server_facts();

        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut socket, server_facts).await {
                eprintln!("Client error: {e}");
            }
        });
    }
}

async fn handle_client(
    socket: &mut TcpStream,
    server_facts: FactSet,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let offer_data = recv_message(socket).await?;
    let offer_json = String::from_utf8(offer_data)?;
    let offer_msg = wire_decode(&offer_json)?;

    let offer = match offer_msg {
        WireMessage::Offer(o) => o,
        _ => return Err("Expected offer message".into()),
    };

    println!("Received offer (session: {})", offer.session_id);
    println!("  Initiator elements: {}", offer.masked_elements.len());

    let mut session =
        ResponderSession::new(&offer.session_id, server_facts, IntersectionMode::Intersection)?;

    let reply = session.process_offer_and_reply(&offer)?;
    println!(
        "Sending reply with {} responder elements",
        reply.responder_masked.len()
    );

    let reply_msg = WireMessage::Reply(reply);
    let reply_json = wire_encode(&reply_msg)?;
    send_message(socket, reply_json.as_bytes()).await?;

    let reveal_data = recv_message(socket).await?;
    let reveal_json = String::from_utf8(reveal_data)?;
    let reveal_msg = wire_decode(&reveal_json)?;

    let reveal = match reveal_msg {
        WireMessage::Reveal(r) => r,
        _ => return Err("Expected reveal message".into()),
    };

    println!("Received reveal (session: {})", reveal.session_id);

    let result = session.process_reveal(&reveal)?;

    match result {
        PsiResult::Intersection { ids, root } => {
            println!();
            println!("=== Server Intersection Result ===");
            println!("Matching elements: {}", ids.len());
            println!("Intersection root: {}", hex::encode(root));
        }
        PsiResult::Cardinality { count } => {
            println!("Intersection cardinality: {count}");
        }
    }

    send_message(socket, b"ok").await?;

    println!("Session complete");
    println!();

    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI Demo Client (Party A) ===");
    println!();
    println!("Client facts (3 elements):");
    println!("  - shared-1, shared-2 (will match with server)");
    println!("  - client-only-1 (private)");
    println!();

    let client_facts = make_client_facts();
    let session_id = format!("demo-{}", rand::random::<u32>());

    println!("Starting PSI session: {session_id}");
    println!();

    let mut socket = TcpStream::connect(SERVER_ADDR).await?;
    println!("Connected to server at {SERVER_ADDR}");

    let mut session =
        InitiatorSession::new(&session_id, client_facts, IntersectionMode::Intersection)?;

    let offer = session.generate_offer()?;
    println!(
        "Generated offer with {} masked elements",
        offer.masked_elements.len()
    );

    let offer_msg = WireMessage::Offer(offer);
    let offer_json = wire_encode(&offer_msg)?;

    println!("Sending offer to server...");
    send_message(&mut socket, offer_json.as_bytes()).await?;

    let reply_data = recv_message(&mut socket).await?;
    let reply_json = String::from_utf8(reply_data)?;
    let reply_msg = wire_decode(&reply_json)?;

    let reply = match reply_msg {
        WireMessage::Reply(r) => r,
        _ => return Err("Expected reply message".into()),
    };

    println!(
        "Received reply with {} responder elements",
        reply.responder_masked.len()
    );

    let result = session.process_reply(&reply)?;

    match &result {
        PsiResult::Intersection { ids, root } => {
            println!();
            println!("=== Client Intersection Result ===");
            println!("Matching elements: {}", ids.len());
            println!("Intersection root: {}", hex::encode(root));
            println!();
            println!("Expected: 2 matching elements (shared-1, shared-2)");
            assert_eq!(ids.len(), 2, "Expected 2 matching elements");
        }
        PsiResult::Cardinality { count } => {
            println!("Intersection cardinality: {count}");
        }
    }

    let reveal = session.generate_reveal()?;
    println!();
    println!("Sending reveal for bilateral intersection...");

    let reveal_msg = WireMessage::Reveal(reveal);
    let reveal_json = wire_encode(&reveal_msg)?;
    send_message(&mut socket, reveal_json.as_bytes()).await?;

    let ack = recv_message(&mut socket).await?;
    if ack == b"ok" {
        println!("Reveal acknowledged by server");
    }

    println!();
    println!("=== Demo Complete ===");
    println!("Both parties now know the intersection of 2 elements,");
    println!("without revealing their other private facts.");

    Ok(())
}
