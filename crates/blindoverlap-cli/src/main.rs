//! BlindOverlap CLI - Private set intersection over content-addressed fact IDs.

use blindoverlap::{
    canonical_json, fact_id_from_str, pad_masked_elements, wire_decode, wire_decode_signed,
    wire_decode_signed_from_peer, wire_encode, wire_encode_pretty, wire_encode_signed_pretty,
    AbortReason, AbortReceipt, AllowedMode, FactSet, InitiatorSession, IntersectionMode,
    IntersectionReceipt, InviteTicket, MaskedSetOffer, MaskedSetReply, MessageDirection,
    PaddingConfig, PartyIdentity, PsiProtocol, PsiResult, PublicIdentity, ReceiptSigner,
    ReceiptVerifier, ResponderSession, SealedSessionRecord, SessionConfig, SessionLease,
    SessionNonce, SessionStatus, SignedWireMessage, TranscriptDigest, TrustedPeerBook,
    WireBoundReceipt, WireMessage, DEFAULT_TTL_SECS,
};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "blindoverlap")]
#[command(author = "Kritarth Agrawal <singhalkritarth@gmail.com>")]
#[command(about = "Private set intersection over content-addressed fact IDs")]
#[command(version)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode JSON facts to fact IDs using RFC 8785 canonical hashing
    Encode {
        /// Input file (one JSON value per line). Use - for stdin.
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Output format: hex or base64
        #[arg(short, long, default_value = "hex")]
        format: String,

        /// Also output the set root
        #[arg(long)]
        with_root: bool,
    },

    /// Compute the canonical JSON representation (for debugging)
    Canonicalize {
        /// JSON string to canonicalize
        json: String,
    },

    /// Generate a new party identity (Ed25519 keypair)
    IdentityGen {
        /// Output file for identity keypair (JSON format)
        #[arg(short, long)]
        output: PathBuf,

        /// Also output just the public key to a separate file
        #[arg(long)]
        pubkey_out: Option<PathBuf>,
    },

    /// Show public key from an identity file
    IdentityShow {
        /// Identity file (JSON format)
        #[arg(short, long)]
        identity: PathBuf,
    },

    /// Run PSI intersection between two fact ID files
    Intersect {
        /// File containing party A's fact IDs (hex, one per line)
        #[arg(short = 'a', long)]
        set_a: PathBuf,

        /// File containing party B's fact IDs (hex, one per line)
        #[arg(short = 'b', long)]
        set_b: PathBuf,

        /// Output only cardinality (count)
        #[arg(long)]
        cardinality: bool,

        /// Output file for intersection result (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Sign an intersection receipt
    ReceiptSign {
        /// Set root A (hex)
        #[arg(long)]
        root_a: String,

        /// Set root B (hex)
        #[arg(long)]
        root_b: String,

        /// Intersection result file (hex IDs, one per line) or cardinality count
        #[arg(long)]
        result: String,

        /// Mode: intersection or cardinality
        #[arg(long, default_value = "intersection")]
        mode: String,

        /// Signing key seed (hex, 32 bytes). If not provided, generates random key.
        #[arg(long)]
        key_seed: Option<String>,

        /// Output file for receipt (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify an intersection receipt
    ReceiptVerify {
        /// Receipt file (JSON)
        #[arg(short, long)]
        receipt: PathBuf,

        /// Expected set root A (hex, optional)
        #[arg(long)]
        expect_root_a: Option<String>,

        /// Expected set root B (hex, optional)
        #[arg(long)]
        expect_root_b: Option<String>,
    },

    /// Output the cardinality of a fact ID set
    Card {
        /// File containing fact IDs (hex, one per line). Use - for stdin.
        #[arg(short, long, default_value = "-")]
        input: String,
    },

    /// Encode a wire protocol message (initiator offer)
    WireEncode {
        /// File containing fact IDs (hex, one per line)
        #[arg(short, long)]
        input: PathBuf,

        /// Session ID for the exchange
        #[arg(long)]
        session: String,

        /// Role: initiator or responder
        #[arg(long, default_value = "initiator")]
        role: String,

        /// Pad to target size (hides real set size)
        #[arg(long)]
        pad_to: Option<usize>,

        /// Padding secret (hex, for deterministic padding). Random if not provided.
        #[arg(long)]
        pad_secret: Option<String>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Pretty-print JSON output
        #[arg(long)]
        pretty: bool,
    },

    /// Decode and display a wire protocol message
    WireDecode {
        /// Wire message file (JSON)
        #[arg(short, long)]
        input: PathBuf,

        /// Show only summary (default: show full message)
        #[arg(long)]
        summary: bool,
    },

    /// Generate initiator offer message
    OnlineOffer {
        /// File containing fact IDs (hex, one per line)
        #[arg(short, long)]
        input: PathBuf,

        /// Session ID for the exchange
        #[arg(long)]
        session: String,

        /// Mode: intersection or cardinality
        #[arg(long, default_value = "intersection")]
        mode: String,

        /// Session TTL in seconds (default: 300)
        #[arg(long)]
        ttl_secs: Option<u64>,

        /// Pad to target size
        #[arg(long)]
        pad_to: Option<usize>,

        /// Padding secret (hex)
        #[arg(long)]
        pad_secret: Option<String>,

        /// Output file for offer message (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output file for session state (required for later steps)
        #[arg(long)]
        state_out: PathBuf,

        /// Identity file for signing messages (enables channel binding)
        #[arg(long)]
        identity: Option<PathBuf>,

        /// Expected peer public key (hex, enables channel binding)
        #[arg(long)]
        expect_peer: Option<String>,
    },

    /// Process offer and generate reply (responder)
    OnlineReply {
        /// File containing fact IDs (hex, one per line)
        #[arg(short, long)]
        input: PathBuf,

        /// Offer message file (JSON)
        #[arg(long)]
        offer: PathBuf,

        /// Mode: intersection or cardinality
        #[arg(long, default_value = "intersection")]
        mode: String,

        /// Session TTL in seconds (default: 300)
        #[arg(long)]
        ttl_secs: Option<u64>,

        /// Pad to target size
        #[arg(long)]
        pad_to: Option<usize>,

        /// Padding secret (hex)
        #[arg(long)]
        pad_secret: Option<String>,

        /// Output file for reply message (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output file for session state
        #[arg(long)]
        state_out: PathBuf,

        /// Identity file for signing messages (enables channel binding)
        #[arg(long)]
        identity: Option<PathBuf>,

        /// Expected peer public key (hex, enables channel binding)
        #[arg(long)]
        expect_peer: Option<String>,
    },

    /// Process reply and compute intersection (initiator)
    OnlineComplete {
        /// Reply message file (JSON)
        #[arg(long)]
        reply: PathBuf,

        /// Session state file (from online-offer)
        #[arg(long)]
        state: PathBuf,

        /// Output file for result (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Also generate reveal message for responder
        #[arg(long)]
        with_reveal: bool,

        /// Output file for reveal message
        #[arg(long)]
        reveal_out: Option<PathBuf>,

        /// Identity file for signing messages
        #[arg(long)]
        identity: Option<PathBuf>,

        /// Expected peer public key (hex, for verifying signed replies)
        #[arg(long)]
        expect_peer: Option<String>,
    },

    /// Process reveal and compute intersection (responder)
    OnlineReveal {
        /// Reveal message file (JSON)
        #[arg(long)]
        reveal: PathBuf,

        /// Session state file (from online-reply)
        #[arg(long)]
        state: PathBuf,

        /// Output file for result (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Expected peer public key (hex, for verifying signed reveals)
        #[arg(long)]
        expect_peer: Option<String>,
    },

    /// Sign a wire-bound receipt (binds to session and transcript)
    WireBoundSign {
        /// Session ID
        #[arg(long)]
        session: String,

        /// Offer message file (JSON)
        #[arg(long)]
        offer: PathBuf,

        /// Reply message file (JSON)
        #[arg(long)]
        reply: PathBuf,

        /// Set root A (hex)
        #[arg(long)]
        root_a: String,

        /// Set root B (hex)
        #[arg(long)]
        root_b: String,

        /// Intersection result file (hex IDs, one per line) or cardinality count
        #[arg(long)]
        result: String,

        /// Mode: intersection or cardinality
        #[arg(long, default_value = "intersection")]
        mode: String,

        /// Signing key seed (hex, 32 bytes). If not provided, generates random key.
        #[arg(long)]
        key_seed: Option<String>,

        /// Output file for receipt (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a wire-bound receipt
    WireBoundVerify {
        /// Receipt file (JSON)
        #[arg(short, long)]
        receipt: PathBuf,

        /// Expected session ID (optional)
        #[arg(long)]
        expect_session: Option<String>,

        /// Offer message file for transcript verification (optional)
        #[arg(long)]
        offer: Option<PathBuf>,

        /// Reply message file for transcript verification (optional)
        #[arg(long)]
        reply: Option<PathBuf>,

        /// Expected set root A (hex, optional)
        #[arg(long)]
        expect_root_a: Option<String>,

        /// Expected set root B (hex, optional)
        #[arg(long)]
        expect_root_b: Option<String>,
    },

    /// Create an invite ticket for a PSI session
    InviteCreate {
        /// Session ID to authorize
        #[arg(long)]
        session: String,

        /// Identity file of the issuer (JSON format)
        #[arg(short, long)]
        identity: PathBuf,

        /// Expected peer public key (hex, optional - if set, only this peer can use ticket)
        #[arg(long)]
        peer: Option<String>,

        /// Allowed mode: intersection, cardinality, or any (default: any)
        #[arg(long, default_value = "any")]
        mode: String,

        /// TTL in seconds (default: 300)
        #[arg(long, default_value = "300")]
        ttl_secs: u64,

        /// Output file for ticket (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify an invite ticket
    InviteVerify {
        /// Ticket file (JSON)
        #[arg(short, long)]
        ticket: PathBuf,

        /// Expected issuer public key (hex, optional)
        #[arg(long)]
        expect_issuer: Option<String>,

        /// Verify for this peer public key (hex, optional)
        #[arg(long)]
        for_peer: Option<String>,

        /// Verify for this session ID (optional)
        #[arg(long)]
        for_session: Option<String>,

        /// Verify for this mode: intersection or cardinality (optional)
        #[arg(long)]
        for_mode: Option<String>,
    },

    /// Export a sealed session record from state and wire files
    SessionExport {
        /// Session ID
        #[arg(long)]
        session: String,

        /// Session state file (JSON)
        #[arg(long)]
        state: PathBuf,

        /// Offer message file (JSON, optional)
        #[arg(long)]
        offer: Option<PathBuf>,

        /// Reply message file (JSON, optional)
        #[arg(long)]
        reply: Option<PathBuf>,

        /// Reveal message file (JSON, optional)
        #[arg(long)]
        reveal: Option<PathBuf>,

        /// Mark session as completed
        #[arg(long)]
        completed: bool,

        /// Identity file for sealing (JSON, optional)
        #[arg(long)]
        identity: Option<PathBuf>,

        /// Output file for sealed record (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a sealed session record
    SessionVerify {
        /// Sealed record file (JSON)
        #[arg(short, long)]
        record: PathBuf,

        /// Expected sealer public key (hex, optional)
        #[arg(long)]
        expect_sealer: Option<String>,
    },

    /// Add a peer to the trusted peer book
    PeerbookAdd {
        /// Peer book file (JSON). Created if doesn't exist.
        #[arg(short, long)]
        book: PathBuf,

        /// Peer public key (hex)
        #[arg(long)]
        pubkey: String,

        /// Optional nickname for the peer
        #[arg(long)]
        nickname: Option<String>,
    },

    /// List trusted peers in the peer book
    PeerbookList {
        /// Peer book file (JSON)
        #[arg(short, long)]
        book: PathBuf,
    },

    /// Remove a peer from the trusted peer book
    PeerbookRemove {
        /// Peer book file (JSON)
        #[arg(short, long)]
        book: PathBuf,

        /// Peer public key to remove (hex)
        #[arg(long)]
        pubkey: String,
    },

    /// Issue a session lease
    LeaseIssue {
        /// Session ID
        #[arg(long)]
        session: String,

        /// Identity file of the issuer (JSON format)
        #[arg(short, long)]
        identity: PathBuf,

        /// Peer public key (hex)
        #[arg(long)]
        peer: String,

        /// TTL in seconds (default: 1800 = 30 minutes)
        #[arg(long, default_value = "1800")]
        ttl_secs: u64,

        /// Output file for lease (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a session lease
    LeaseVerify {
        /// Lease file (JSON)
        #[arg(short, long)]
        lease: PathBuf,

        /// Expected issuer public key (hex, optional)
        #[arg(long)]
        expect_issuer: Option<String>,

        /// Verify for this peer public key (hex, optional)
        #[arg(long)]
        for_peer: Option<String>,

        /// Verify for this session ID (optional)
        #[arg(long)]
        for_session: Option<String>,
    },

    /// Renew a session lease
    LeaseRenew {
        /// Existing lease file (JSON)
        #[arg(short, long)]
        lease: PathBuf,

        /// Identity file of the issuer (must match original issuer)
        #[arg(short, long)]
        identity: PathBuf,

        /// TTL in seconds (default: 1800 = 30 minutes)
        #[arg(long, default_value = "1800")]
        ttl_secs: u64,

        /// Output file for renewed lease (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Create a signed abort receipt
    SessionAbort {
        /// Session ID
        #[arg(long)]
        session: String,

        /// Identity file for signing the abort (JSON format)
        #[arg(short, long)]
        identity: PathBuf,

        /// Reason code: user_cancelled, timeout, protocol_error, network_error, etc.
        #[arg(long, default_value = "user_cancelled")]
        reason: String,

        /// Optional reason text
        #[arg(long)]
        reason_text: Option<String>,

        /// Optional transcript digest (hex, 32 bytes)
        #[arg(long)]
        transcript: Option<String>,

        /// Output file for abort receipt (JSON). Default: stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify an abort receipt
    AbortVerify {
        /// Abort receipt file (JSON)
        #[arg(short, long)]
        receipt: PathBuf,

        /// Expected issuer public key (hex, optional)
        #[arg(long)]
        expect_issuer: Option<String>,

        /// Verify for this session ID (optional)
        #[arg(long)]
        for_session: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode {
            input,
            format,
            with_root,
        } => cmd_encode(&input, &format, with_root)?,

        Commands::Canonicalize { json } => cmd_canonicalize(&json)?,

        Commands::IdentityGen { output, pubkey_out } => {
            cmd_identity_gen(&output, pubkey_out.as_deref())?
        }

        Commands::IdentityShow { identity } => cmd_identity_show(&identity)?,

        Commands::Intersect {
            set_a,
            set_b,
            cardinality,
            output,
        } => cmd_intersect(&set_a, &set_b, cardinality, output.as_deref())?,

        Commands::ReceiptSign {
            root_a,
            root_b,
            result,
            mode,
            key_seed,
            output,
        } => cmd_receipt_sign(
            &root_a,
            &root_b,
            &result,
            &mode,
            key_seed.as_deref(),
            output.as_deref(),
        )?,

        Commands::ReceiptVerify {
            receipt,
            expect_root_a,
            expect_root_b,
        } => cmd_receipt_verify(&receipt, expect_root_a.as_deref(), expect_root_b.as_deref())?,

        Commands::Card { input } => cmd_card(&input)?,

        Commands::WireEncode {
            input,
            session,
            role,
            pad_to,
            pad_secret,
            output,
            pretty,
        } => cmd_wire_encode(
            &input,
            &session,
            &role,
            pad_to,
            pad_secret.as_deref(),
            output.as_deref(),
            pretty,
        )?,

        Commands::WireDecode { input, summary } => cmd_wire_decode(&input, summary)?,

        Commands::OnlineOffer {
            input,
            session,
            mode,
            ttl_secs,
            pad_to,
            pad_secret,
            output,
            state_out,
            identity,
            expect_peer,
        } => cmd_online_offer(
            &input,
            &session,
            &mode,
            ttl_secs,
            pad_to,
            pad_secret.as_deref(),
            output.as_deref(),
            &state_out,
            identity.as_deref(),
            expect_peer.as_deref(),
        )?,

        Commands::OnlineReply {
            input,
            offer,
            mode,
            ttl_secs,
            pad_to,
            pad_secret,
            output,
            state_out,
            identity,
            expect_peer,
        } => cmd_online_reply(
            &input,
            &offer,
            &mode,
            ttl_secs,
            pad_to,
            pad_secret.as_deref(),
            output.as_deref(),
            &state_out,
            identity.as_deref(),
            expect_peer.as_deref(),
        )?,

        Commands::OnlineComplete {
            reply,
            state,
            output,
            with_reveal,
            reveal_out,
            identity,
            expect_peer,
        } => cmd_online_complete(
            &reply,
            &state,
            output.as_deref(),
            with_reveal,
            reveal_out.as_deref(),
            identity.as_deref(),
            expect_peer.as_deref(),
        )?,

        Commands::OnlineReveal {
            reveal,
            state,
            output,
            expect_peer,
        } => cmd_online_reveal(&reveal, &state, output.as_deref(), expect_peer.as_deref())?,

        Commands::WireBoundSign {
            session,
            offer,
            reply,
            root_a,
            root_b,
            result,
            mode,
            key_seed,
            output,
        } => cmd_wire_bound_sign(
            &session,
            &offer,
            &reply,
            &root_a,
            &root_b,
            &result,
            &mode,
            key_seed.as_deref(),
            output.as_deref(),
        )?,

        Commands::WireBoundVerify {
            receipt,
            expect_session,
            offer,
            reply,
            expect_root_a,
            expect_root_b,
        } => cmd_wire_bound_verify(
            &receipt,
            expect_session.as_deref(),
            offer.as_deref(),
            reply.as_deref(),
            expect_root_a.as_deref(),
            expect_root_b.as_deref(),
        )?,

        Commands::InviteCreate {
            session,
            identity,
            peer,
            mode,
            ttl_secs,
            output,
        } => cmd_invite_create(
            &session,
            &identity,
            peer.as_deref(),
            &mode,
            ttl_secs,
            output.as_deref(),
        )?,

        Commands::InviteVerify {
            ticket,
            expect_issuer,
            for_peer,
            for_session,
            for_mode,
        } => cmd_invite_verify(
            &ticket,
            expect_issuer.as_deref(),
            for_peer.as_deref(),
            for_session.as_deref(),
            for_mode.as_deref(),
        )?,

        Commands::SessionExport {
            session,
            state,
            offer,
            reply,
            reveal,
            completed,
            identity,
            output,
        } => cmd_session_export(
            &session,
            &state,
            offer.as_deref(),
            reply.as_deref(),
            reveal.as_deref(),
            completed,
            identity.as_deref(),
            output.as_deref(),
        )?,

        Commands::SessionVerify {
            record,
            expect_sealer,
        } => cmd_session_verify(&record, expect_sealer.as_deref())?,

        Commands::PeerbookAdd {
            book,
            pubkey,
            nickname,
        } => cmd_peerbook_add(&book, &pubkey, nickname.as_deref())?,

        Commands::PeerbookList { book } => cmd_peerbook_list(&book)?,

        Commands::PeerbookRemove { book, pubkey } => cmd_peerbook_remove(&book, &pubkey)?,

        Commands::LeaseIssue {
            session,
            identity,
            peer,
            ttl_secs,
            output,
        } => cmd_lease_issue(&session, &identity, &peer, ttl_secs, output.as_deref())?,

        Commands::LeaseVerify {
            lease,
            expect_issuer,
            for_peer,
            for_session,
        } => cmd_lease_verify(
            &lease,
            expect_issuer.as_deref(),
            for_peer.as_deref(),
            for_session.as_deref(),
        )?,

        Commands::LeaseRenew {
            lease,
            identity,
            ttl_secs,
            output,
        } => cmd_lease_renew(&lease, &identity, ttl_secs, output.as_deref())?,

        Commands::SessionAbort {
            session,
            identity,
            reason,
            reason_text,
            transcript,
            output,
        } => cmd_session_abort(
            &session,
            &identity,
            &reason,
            reason_text.as_deref(),
            transcript.as_deref(),
            output.as_deref(),
        )?,

        Commands::AbortVerify {
            receipt,
            expect_issuer,
            for_session,
        } => cmd_abort_verify(&receipt, expect_issuer.as_deref(), for_session.as_deref())?,
    }

    Ok(())
}

fn cmd_encode(
    input: &str,
    format: &str,
    with_root: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader: Box<dyn BufRead> = if input == "-" {
        Box::new(io::stdin().lock())
    } else {
        Box::new(io::BufReader::new(fs::File::open(input)?))
    };

    let mut fact_ids = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let fact_id = fact_id_from_str(trimmed)?;
        fact_ids.push(fact_id);

        let encoded = match format {
            "hex" => hex::encode(fact_id),
            "base64" => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, fact_id),
            _ => return Err(format!("unknown format: {format}").into()),
        };
        println!("{encoded}");
    }

    if with_root {
        let set = FactSet::from_ids(fact_ids);
        eprintln!("set_root: {}", hex::encode(set.root()));
    }

    Ok(())
}

fn cmd_canonicalize(json: &str) -> Result<(), Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let canonical = canonical_json(&value);
    println!("{canonical}");
    Ok(())
}

fn cmd_identity_gen(
    output: &std::path::Path,
    pubkey_out: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = PartyIdentity::generate();
    identity.save_to_file(output)?;

    let pubkey = identity.public();
    eprintln!("identity saved to: {}", output.display());
    eprintln!("public_key: {}", pubkey.to_hex());

    if let Some(pubkey_path) = pubkey_out {
        fs::write(pubkey_path, pubkey.to_hex())?;
        eprintln!("public key saved to: {}", pubkey_path.display());
    }

    Ok(())
}

fn cmd_identity_show(identity_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let identity = PartyIdentity::load_from_file(identity_path)?;
    println!("{}", identity.public().to_hex());
    Ok(())
}

fn cmd_intersect(
    set_a_path: &std::path::Path,
    set_b_path: &std::path::Path,
    cardinality_only: bool,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let set_a = load_fact_set(set_a_path)?;
    let set_b = load_fact_set(set_b_path)?;

    let mode = if cardinality_only {
        IntersectionMode::Cardinality
    } else {
        IntersectionMode::Intersection
    };

    let protocol = PsiProtocol::new();
    let result = protocol.intersect(&set_a, &set_b, mode)?;

    let mut out: Box<dyn Write> = match output {
        Some(path) => Box::new(fs::File::create(path)?),
        None => Box::new(io::stdout()),
    };

    match result {
        PsiResult::Cardinality { count } => {
            writeln!(out, "cardinality: {count}")?;
        }
        PsiResult::Intersection { ids, root } => {
            writeln!(out, "# intersection_root: {}", hex::encode(root))?;
            writeln!(out, "# set_root_a: {}", hex::encode(set_a.root()))?;
            writeln!(out, "# set_root_b: {}", hex::encode(set_b.root()))?;
            writeln!(out, "# count: {}", ids.len())?;
            for id in ids {
                writeln!(out, "{}", hex::encode(id))?;
            }
        }
    }

    Ok(())
}

fn cmd_receipt_sign(
    root_a: &str,
    root_b: &str,
    result: &str,
    mode: &str,
    key_seed: Option<&str>,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root_a: [u8; 32] = hex::decode(root_a)?
        .try_into()
        .map_err(|_| "root_a must be 32 bytes")?;
    let root_b: [u8; 32] = hex::decode(root_b)?
        .try_into()
        .map_err(|_| "root_b must be 32 bytes")?;

    let intersection_mode = match mode {
        "intersection" => IntersectionMode::Intersection,
        "cardinality" => IntersectionMode::Cardinality,
        _ => return Err(format!("unknown mode: {mode}").into()),
    };

    let psi_result = if intersection_mode == IntersectionMode::Cardinality {
        let count: usize = result.parse()?;
        PsiResult::Cardinality { count }
    } else {
        let ids = if std::path::Path::new(result).exists() {
            load_fact_ids(std::path::Path::new(result))?
        } else {
            vec![]
        };
        let set = FactSet::from_ids(ids.clone());
        PsiResult::Intersection {
            ids,
            root: *set.root(),
        }
    };

    let signer = if let Some(seed_hex) = key_seed {
        let seed: [u8; 32] = hex::decode(seed_hex)?
            .try_into()
            .map_err(|_| "key_seed must be 32 bytes")?;
        ReceiptSigner::from_seed(&seed)
    } else {
        ReceiptSigner::new()
    };

    let receipt = signer.sign(&root_a, &root_b, &psi_result, intersection_mode);

    let json = serde_json::to_string_pretty(&receipt)?;

    match output {
        Some(path) => fs::write(path, json)?,
        None => println!("{json}"),
    }

    eprintln!("receipt_id: {}", hex::encode(receipt.receipt_id()));
    eprintln!(
        "signer_public_key: {}",
        hex::encode(receipt.signer_public_key)
    );

    Ok(())
}

fn cmd_receipt_verify(
    receipt_path: &PathBuf,
    expect_root_a: Option<&str>,
    expect_root_b: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt_json = fs::read_to_string(receipt_path)?;
    let receipt: IntersectionReceipt = serde_json::from_str(&receipt_json)?;

    let verifier = ReceiptVerifier::new();

    match (expect_root_a, expect_root_b) {
        (Some(a), Some(b)) => {
            let root_a: [u8; 32] = hex::decode(a)?
                .try_into()
                .map_err(|_| "expect_root_a must be 32 bytes")?;
            let root_b: [u8; 32] = hex::decode(b)?
                .try_into()
                .map_err(|_| "expect_root_b must be 32 bytes")?;
            verifier.verify_with_roots(&receipt, &root_a, &root_b)?;
        }
        _ => {
            verifier.verify(&receipt)?;
        }
    }

    println!("Receipt verification: OK");
    println!("  version: {}", receipt.version);
    println!("  mode: {:?}", receipt.mode);
    println!("  set_root_a: {}", hex::encode(receipt.set_root_a));
    println!("  set_root_b: {}", hex::encode(receipt.set_root_b));
    println!(
        "  result_commitment: {}",
        hex::encode(receipt.result_commitment)
    );
    println!("  signer: {}", hex::encode(receipt.signer_public_key));
    println!("  receipt_id: {}", hex::encode(receipt.receipt_id()));

    Ok(())
}

fn cmd_card(input: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ids = if input == "-" {
        load_fact_ids_from_reader(io::stdin().lock())?
    } else {
        load_fact_ids(std::path::Path::new(input))?
    };

    let set = FactSet::from_ids(ids);
    println!("count: {}", set.len());
    println!("set_root: {}", hex::encode(set.root()));

    Ok(())
}

fn cmd_wire_encode(
    input: &std::path::Path,
    session: &str,
    role: &str,
    pad_to: Option<usize>,
    pad_secret: Option<&str>,
    output: Option<&std::path::Path>,
    pretty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let fact_set = load_fact_set(input)?;

    let mode = IntersectionMode::Intersection;
    let mut session_obj = InitiatorSession::new(session, fact_set, mode)?;
    let offer = session_obj.generate_offer()?;

    let masked = if role == "initiator" {
        offer.masked_elements.clone()
    } else {
        return Err(
            "wire-encode only supports initiator role (use online-reply for responder)".into(),
        );
    };

    let final_masked = if let Some(target) = pad_to {
        let secret = if let Some(s) = pad_secret {
            hex::decode(s)?
        } else {
            let config = PaddingConfig::with_random_secret(target);
            config.padding_secret
        };
        let config = PaddingConfig::new(target, secret);
        pad_masked_elements(&masked, &config, session.as_bytes())?
    } else {
        masked
    };

    let message = WireMessage::Offer(MaskedSetOffer::new(session, final_masked));

    let json = if pretty {
        wire_encode_pretty(&message)?
    } else {
        wire_encode(&message)?
    };

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!("session_id: {session}");
    eprintln!("message_type: offer");
    eprintln!("element_count: {}", offer.masked_elements.len());
    if let Some(target) = pad_to {
        eprintln!("padded_to: {target}");
    }

    Ok(())
}

fn cmd_wire_decode(
    input: &std::path::Path,
    summary: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = fs::read_to_string(input)?;
    let message = wire_decode(&json)?;

    if summary {
        match &message {
            WireMessage::Offer(m) => {
                println!("type: MaskedSetOffer");
                println!("session_id: {}", m.session_id);
                println!("version: {}", m.version);
                println!("element_count: {}", m.masked_elements.len());
            }
            WireMessage::Reply(m) => {
                println!("type: MaskedSetReply");
                println!("session_id: {}", m.session_id);
                println!("version: {}", m.version);
                println!("responder_element_count: {}", m.responder_masked.len());
                println!(
                    "initiator_doubly_masked_count: {}",
                    m.initiator_doubly_masked.len()
                );
            }
            WireMessage::Reveal(m) => {
                println!("type: IntersectionReveal");
                println!("session_id: {}", m.session_id);
                println!("version: {}", m.version);
                println!(
                    "responder_doubly_masked_count: {}",
                    m.responder_doubly_masked.len()
                );
            }
            WireMessage::Abort(m) => {
                println!("type: AbortMessage");
                println!("session_id: {}", m.session_id);
                println!("version: {}", m.version);
                println!("reason_code: {}", m.reason_code);
                if let Some(text) = &m.reason_text {
                    println!("reason_text: {}", text);
                }
            }
        }
    } else {
        let pretty = serde_json::to_string_pretty(&message)?;
        println!("{pretty}");
    }

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InitiatorState {
    session_id: String,
    mode: String,
    original_count: usize,
    fact_ids_hex: Vec<String>,
    secret_hex: String,
    masked_elements_hex: Vec<String>,
    #[serde(default)]
    nonce_hex: Option<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ResponderState {
    session_id: String,
    mode: String,
    original_count: usize,
    fact_ids_hex: Vec<String>,
    secret_hex: String,
    masked_elements_hex: Vec<String>,
    initiator_doubly_masked_hex: Vec<String>,
    #[serde(default)]
    nonce_hex: Option<String>,
    #[serde(default)]
    initiator_nonce_hex: Option<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
fn cmd_online_offer(
    input: &std::path::Path,
    session: &str,
    mode: &str,
    ttl_secs: Option<u64>,
    pad_to: Option<usize>,
    pad_secret: Option<&str>,
    output: Option<&std::path::Path>,
    state_out: &std::path::Path,
    identity_path: Option<&std::path::Path>,
    expect_peer_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fact_set = load_fact_set(input)?;
    let fact_ids = fact_set.ids();
    let original_count = fact_ids.len();

    let int_mode = match mode {
        "intersection" => IntersectionMode::Intersection,
        "cardinality" => IntersectionMode::Cardinality,
        _ => return Err(format!("unknown mode: {mode}").into()),
    };

    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    let config = SessionConfig::with_ttl(ttl);
    let mut session_obj = InitiatorSession::with_config(session, fact_set, int_mode, config)?;

    let identity = if let Some(path) = identity_path {
        Some(PartyIdentity::load_from_file(path)?)
    } else {
        None
    };

    let expect_peer = if let Some(hex) = expect_peer_hex {
        Some(PublicIdentity::from_hex(hex)?)
    } else {
        None
    };

    let offer = session_obj.generate_offer()?;

    let final_masked = if let Some(target) = pad_to {
        let secret_bytes = if let Some(s) = pad_secret {
            hex::decode(s)?
        } else {
            let config = PaddingConfig::with_random_secret(target);
            config.padding_secret
        };
        let config = PaddingConfig::new(target, secret_bytes);
        pad_masked_elements(&offer.masked_elements, &config, session.as_bytes())?
    } else {
        offer.masked_elements.clone()
    };

    let message = if offer.has_freshness() {
        WireMessage::Offer(MaskedSetOffer::new_v2(
            session,
            final_masked,
            offer.nonce.unwrap(),
            offer.deadline().unwrap(),
        ))
    } else {
        WireMessage::Offer(MaskedSetOffer::new(session, final_masked))
    };

    let json = if let Some(ref id) = identity {
        let signed = SignedWireMessage::sign(message, id);
        wire_encode_signed_pretty(&signed)?
    } else {
        wire_encode_pretty(&message)?
    };

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    let state = InitiatorState {
        session_id: session.to_string(),
        mode: mode.to_string(),
        original_count,
        fact_ids_hex: fact_ids.iter().map(hex::encode).collect(),
        secret_hex: hex::encode([0u8; 32]),
        masked_elements_hex: offer.masked_elements.iter().map(hex::encode).collect(),
        nonce_hex: Some(session_obj.nonce().to_hex()),
        ttl_secs: Some(ttl),
    };
    fs::write(state_out, serde_json::to_string_pretty(&state)?)?;

    eprintln!("session_id: {session}");
    eprintln!("original_count: {original_count}");
    if offer.has_freshness() {
        eprintln!("nonce: {}", session_obj.nonce());
        eprintln!("ttl_secs: {ttl}");
    }
    if let Some(ref id) = identity {
        eprintln!("signed by: {}", id.public().to_hex());
    }
    if let Some(ref peer) = expect_peer {
        eprintln!("expect_peer: {}", peer.to_hex());
    }
    eprintln!("state saved to: {}", state_out.display());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_online_reply(
    input: &std::path::Path,
    offer_path: &std::path::Path,
    mode: &str,
    ttl_secs: Option<u64>,
    pad_to: Option<usize>,
    pad_secret: Option<&str>,
    output: Option<&std::path::Path>,
    state_out: &std::path::Path,
    identity_path: Option<&std::path::Path>,
    expect_peer_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fact_set = load_fact_set(input)?;
    let fact_ids = fact_set.ids();
    let original_count = fact_ids.len();

    let identity = if let Some(path) = identity_path {
        Some(PartyIdentity::load_from_file(path)?)
    } else {
        None
    };

    let expect_peer = if let Some(hex) = expect_peer_hex {
        Some(PublicIdentity::from_hex(hex)?)
    } else {
        None
    };

    let offer_json = fs::read_to_string(offer_path)?;

    let (offer, verified_signer) = if let Some(peer) = &expect_peer {
        let signed = wire_decode_signed_from_peer(&offer_json, peer)?;
        let o = match &signed.message {
            WireMessage::Offer(o) => o.clone(),
            _ => return Err("expected offer message".into()),
        };
        (o, Some(signed.signer_pubkey))
    } else if let Ok(signed) = wire_decode_signed(&offer_json) {
        let o = match &signed.message {
            WireMessage::Offer(o) => o.clone(),
            _ => return Err("expected offer message".into()),
        };
        (o, Some(signed.signer_pubkey))
    } else {
        let offer_msg = wire_decode(&offer_json)?;
        let o = match offer_msg {
            WireMessage::Offer(o) => o,
            _ => return Err("expected offer message".into()),
        };
        (o, None)
    };

    let int_mode = match mode {
        "intersection" => IntersectionMode::Intersection,
        "cardinality" => IntersectionMode::Cardinality,
        _ => return Err(format!("unknown mode: {mode}").into()),
    };

    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    let config = SessionConfig::with_ttl(ttl);
    let mut session_obj =
        ResponderSession::with_config(&offer.session_id, fact_set, int_mode, config)?;
    let reply = session_obj.process_offer_and_reply(&offer)?;

    let final_responder_masked = if let Some(target) = pad_to {
        let secret_bytes = if let Some(s) = pad_secret {
            hex::decode(s)?
        } else {
            let config = PaddingConfig::with_random_secret(target);
            config.padding_secret
        };
        let config = PaddingConfig::new(target, secret_bytes);
        pad_masked_elements(
            &reply.responder_masked,
            &config,
            offer.session_id.as_bytes(),
        )?
    } else {
        reply.responder_masked.clone()
    };

    let message = if reply.has_freshness() {
        WireMessage::Reply(MaskedSetReply::new_v2(
            &offer.session_id,
            final_responder_masked,
            reply.initiator_doubly_masked.clone(),
            reply.initiator_nonce.unwrap(),
            reply.responder_nonce.unwrap(),
            reply.deadline().unwrap(),
        ))
    } else {
        WireMessage::Reply(MaskedSetReply::new(
            &offer.session_id,
            final_responder_masked,
            reply.initiator_doubly_masked.clone(),
        ))
    };

    let json = if let Some(ref id) = identity {
        let signed = SignedWireMessage::sign(message, id);
        wire_encode_signed_pretty(&signed)?
    } else {
        wire_encode_pretty(&message)?
    };

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    if let Some(signer) = verified_signer {
        eprintln!("verified signer: {}", signer.to_hex());
    }
    if let Some(ref id) = identity {
        eprintln!("signed by: {}", id.public().to_hex());
    }

    let state = ResponderState {
        session_id: offer.session_id.clone(),
        mode: mode.to_string(),
        original_count,
        fact_ids_hex: fact_ids.iter().map(hex::encode).collect(),
        secret_hex: hex::encode([0u8; 32]),
        masked_elements_hex: reply.responder_masked.iter().map(hex::encode).collect(),
        initiator_doubly_masked_hex: reply
            .initiator_doubly_masked
            .iter()
            .map(hex::encode)
            .collect(),
        nonce_hex: Some(session_obj.nonce().to_hex()),
        initiator_nonce_hex: session_obj.initiator_nonce().map(|n| n.to_hex()),
        ttl_secs: Some(ttl),
    };
    fs::write(state_out, serde_json::to_string_pretty(&state)?)?;

    eprintln!("session_id: {}", offer.session_id);
    eprintln!("original_count: {original_count}");
    if reply.has_freshness() {
        eprintln!("responder_nonce: {}", session_obj.nonce());
        if let Some(init_nonce) = session_obj.initiator_nonce() {
            eprintln!("initiator_nonce: {}", init_nonce);
        }
        eprintln!("ttl_secs: {ttl}");
    }
    eprintln!("state saved to: {}", state_out.display());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_online_complete(
    reply_path: &std::path::Path,
    state_path: &std::path::Path,
    output: Option<&std::path::Path>,
    with_reveal: bool,
    reveal_out: Option<&std::path::Path>,
    identity_path: Option<&std::path::Path>,
    expect_peer_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state_json = fs::read_to_string(state_path)?;
    let state: InitiatorState = serde_json::from_str(&state_json)?;

    let identity = if let Some(path) = identity_path {
        Some(PartyIdentity::load_from_file(path)?)
    } else {
        None
    };

    let expect_peer = if let Some(hex) = expect_peer_hex {
        Some(PublicIdentity::from_hex(hex)?)
    } else {
        None
    };

    let reply_json = fs::read_to_string(reply_path)?;

    let (reply, verified_signer) = if let Some(peer) = &expect_peer {
        let signed = wire_decode_signed_from_peer(&reply_json, peer)?;
        let r = match &signed.message {
            WireMessage::Reply(r) => r.clone(),
            _ => return Err("expected reply message".into()),
        };
        (r, Some(signed.signer_pubkey))
    } else if let Ok(signed) = wire_decode_signed(&reply_json) {
        let r = match &signed.message {
            WireMessage::Reply(r) => r.clone(),
            _ => return Err("expected reply message".into()),
        };
        (r, Some(signed.signer_pubkey))
    } else {
        let reply_msg = wire_decode(&reply_json)?;
        let r = match reply_msg {
            WireMessage::Reply(r) => r,
            _ => return Err("expected reply message".into()),
        };
        (r, None)
    };

    let int_mode = match state.mode.as_str() {
        "intersection" => IntersectionMode::Intersection,
        "cardinality" => IntersectionMode::Cardinality,
        _ => return Err(format!("unknown mode: {}", state.mode).into()),
    };

    let fact_ids: Vec<[u8; 32]> = state
        .fact_ids_hex
        .iter()
        .map(|s| {
            hex::decode(s)
                .map_err(|e| format!("hex decode error: {e}"))
                .and_then(|b| b.try_into().map_err(|_| "expected 32 bytes".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fact_set = FactSet::from_ids(fact_ids);

    let secret: [u8; 32] = hex::decode(&state.secret_hex)?
        .try_into()
        .map_err(|_| "secret must be 32 bytes")?;

    let mut session_obj =
        InitiatorSession::with_secret(&state.session_id, fact_set, int_mode, secret)?;
    let _ = session_obj.generate_offer()?;
    let result = session_obj.process_reply(&reply)?;

    if let Some(signer) = verified_signer {
        eprintln!("verified signer: {}", signer.to_hex());
    }

    let mut out: Box<dyn Write> = match output {
        Some(path) => Box::new(fs::File::create(path)?),
        None => Box::new(io::stdout()),
    };

    match &result {
        PsiResult::Cardinality { count } => {
            writeln!(out, "cardinality: {count}")?;
        }
        PsiResult::Intersection { ids, root } => {
            writeln!(out, "# intersection_root: {}", hex::encode(root))?;
            writeln!(out, "# count: {}", ids.len())?;
            for id in ids {
                writeln!(out, "{}", hex::encode(id))?;
            }
        }
    }

    if with_reveal {
        let reveal = session_obj.generate_reveal()?;
        let reveal_msg = WireMessage::Reveal(reveal);

        let reveal_json = if let Some(ref id) = identity {
            let signed = SignedWireMessage::sign(reveal_msg, id);
            wire_encode_signed_pretty(&signed)?
        } else {
            wire_encode_pretty(&reveal_msg)?
        };

        match reveal_out {
            Some(path) => fs::write(path, &reveal_json)?,
            None => eprintln!("\n--- Reveal Message ---\n{reveal_json}"),
        }

        if let Some(ref id) = identity {
            eprintln!("reveal signed by: {}", id.public().to_hex());
        }
    }

    Ok(())
}

fn cmd_online_reveal(
    reveal_path: &std::path::Path,
    state_path: &std::path::Path,
    output: Option<&std::path::Path>,
    expect_peer_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state_json = fs::read_to_string(state_path)?;
    let state: ResponderState = serde_json::from_str(&state_json)?;

    let expect_peer = if let Some(hex) = expect_peer_hex {
        Some(PublicIdentity::from_hex(hex)?)
    } else {
        None
    };

    let reveal_json = fs::read_to_string(reveal_path)?;

    let (reveal, verified_signer) = if let Some(peer) = &expect_peer {
        let signed = wire_decode_signed_from_peer(&reveal_json, peer)?;
        let r = match &signed.message {
            WireMessage::Reveal(r) => r.clone(),
            _ => return Err("expected reveal message".into()),
        };
        (r, Some(signed.signer_pubkey))
    } else if let Ok(signed) = wire_decode_signed(&reveal_json) {
        let r = match &signed.message {
            WireMessage::Reveal(r) => r.clone(),
            _ => return Err("expected reveal message".into()),
        };
        (r, Some(signed.signer_pubkey))
    } else {
        let reveal_msg = wire_decode(&reveal_json)?;
        let r = match reveal_msg {
            WireMessage::Reveal(r) => r,
            _ => return Err("expected reveal message".into()),
        };
        (r, None)
    };

    let int_mode = match state.mode.as_str() {
        "intersection" => IntersectionMode::Intersection,
        "cardinality" => IntersectionMode::Cardinality,
        _ => return Err(format!("unknown mode: {}", state.mode).into()),
    };

    let fact_ids: Vec<[u8; 32]> = state
        .fact_ids_hex
        .iter()
        .map(|s| {
            hex::decode(s)
                .map_err(|e| format!("hex decode error: {e}"))
                .and_then(|b| b.try_into().map_err(|_| "expected 32 bytes".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fact_set = FactSet::from_ids(fact_ids);

    let secret: [u8; 32] = hex::decode(&state.secret_hex)?
        .try_into()
        .map_err(|_| "secret must be 32 bytes")?;

    let offer = MaskedSetOffer::new(
        &state.session_id,
        vec![[0u8; 32]; state.initiator_doubly_masked_hex.len()],
    );
    let mut session_obj =
        ResponderSession::with_secret(&state.session_id, fact_set, int_mode, secret)?;

    let _ = session_obj.process_offer_and_reply(&offer);
    let result = session_obj.process_reveal(&reveal)?;

    if let Some(signer) = verified_signer {
        eprintln!("verified signer: {}", signer.to_hex());
    }

    let mut out: Box<dyn Write> = match output {
        Some(path) => Box::new(fs::File::create(path)?),
        None => Box::new(io::stdout()),
    };

    match &result {
        PsiResult::Cardinality { count } => {
            writeln!(out, "cardinality: {count}")?;
        }
        PsiResult::Intersection { ids, root } => {
            writeln!(out, "# intersection_root: {}", hex::encode(root))?;
            writeln!(out, "# count: {}", ids.len())?;
            for id in ids {
                writeln!(out, "{}", hex::encode(id))?;
            }
        }
    }

    Ok(())
}

fn load_fact_set(path: &std::path::Path) -> Result<FactSet, Box<dyn std::error::Error>> {
    let ids = load_fact_ids(path)?;
    Ok(FactSet::from_ids(ids))
}

fn load_fact_ids(path: &std::path::Path) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let reader = io::BufReader::new(fs::File::open(path)?);
    load_fact_ids_from_reader(reader)
}

fn load_fact_ids_from_reader<R: BufRead>(
    reader: R,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let mut ids = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let bytes = hex::decode(trimmed)?;
        let id: [u8; 32] = bytes.try_into().map_err(|_| "fact ID must be 32 bytes")?;
        ids.push(id);
    }
    Ok(ids)
}

#[allow(clippy::too_many_arguments)]
fn cmd_wire_bound_sign(
    session: &str,
    offer_path: &std::path::Path,
    reply_path: &std::path::Path,
    root_a: &str,
    root_b: &str,
    result: &str,
    mode: &str,
    key_seed: Option<&str>,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let offer_json = fs::read_to_string(offer_path)?;
    let offer_msg = wire_decode(&offer_json)?;
    let offer = match offer_msg {
        WireMessage::Offer(o) => o,
        _ => return Err("expected offer message".into()),
    };

    let reply_json = fs::read_to_string(reply_path)?;
    let reply_msg = wire_decode(&reply_json)?;
    let reply = match reply_msg {
        WireMessage::Reply(r) => r,
        _ => return Err("expected reply message".into()),
    };

    let initiator_nonce = offer.nonce.unwrap_or_else(SessionNonce::generate);
    let responder_nonce = reply.responder_nonce.unwrap_or_else(SessionNonce::generate);

    let transcript = TranscriptDigest::compute(
        session,
        &initiator_nonce,
        Some(&responder_nonce),
        &offer.masked_elements,
        Some(&reply.responder_masked),
        Some(&reply.initiator_doubly_masked),
    );

    let root_a: [u8; 32] = hex::decode(root_a)?
        .try_into()
        .map_err(|_| "root_a must be 32 bytes")?;
    let root_b: [u8; 32] = hex::decode(root_b)?
        .try_into()
        .map_err(|_| "root_b must be 32 bytes")?;

    let intersection_mode = match mode {
        "intersection" => IntersectionMode::Intersection,
        "cardinality" => IntersectionMode::Cardinality,
        _ => return Err(format!("unknown mode: {mode}").into()),
    };

    let psi_result = if intersection_mode == IntersectionMode::Cardinality {
        let count: usize = result.parse()?;
        PsiResult::Cardinality { count }
    } else {
        let ids = if std::path::Path::new(result).exists() {
            load_fact_ids(std::path::Path::new(result))?
        } else {
            vec![]
        };
        let set = FactSet::from_ids(ids.clone());
        PsiResult::Intersection {
            ids,
            root: *set.root(),
        }
    };

    let signer = if let Some(seed_hex) = key_seed {
        let seed: [u8; 32] = hex::decode(seed_hex)?
            .try_into()
            .map_err(|_| "key_seed must be 32 bytes")?;
        ReceiptSigner::from_seed(&seed)
    } else {
        ReceiptSigner::new()
    };

    let receipt = signer.sign_wire_bound(
        session,
        transcript,
        initiator_nonce,
        responder_nonce,
        &root_a,
        &root_b,
        &psi_result,
        intersection_mode,
    );

    let json = serde_json::to_string_pretty(&receipt)?;

    match output {
        Some(path) => fs::write(path, json)?,
        None => println!("{json}"),
    }

    eprintln!("receipt_id: {}", hex::encode(receipt.receipt_id()));
    eprintln!("transcript_digest: {}", receipt.transcript_digest);
    eprintln!(
        "signer_public_key: {}",
        hex::encode(receipt.signer_public_key)
    );

    Ok(())
}

fn cmd_wire_bound_verify(
    receipt_path: &PathBuf,
    expect_session: Option<&str>,
    offer_path: Option<&std::path::Path>,
    reply_path: Option<&std::path::Path>,
    expect_root_a: Option<&str>,
    expect_root_b: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt_json = fs::read_to_string(receipt_path)?;
    let receipt: WireBoundReceipt = serde_json::from_str(&receipt_json)?;

    let verifier = ReceiptVerifier::new();

    verifier.verify_wire_bound(&receipt)?;

    if let Some(expected_session) = expect_session {
        if receipt.session_id != expected_session {
            return Err(format!(
                "session ID mismatch: expected {}, got {}",
                expected_session, receipt.session_id
            )
            .into());
        }
    }

    if let (Some(offer_p), Some(reply_p)) = (offer_path, reply_path) {
        let offer_json = fs::read_to_string(offer_p)?;
        let offer_msg = wire_decode(&offer_json)?;
        let offer = match offer_msg {
            WireMessage::Offer(o) => o,
            _ => return Err("expected offer message".into()),
        };

        let reply_json = fs::read_to_string(reply_p)?;
        let reply_msg = wire_decode(&reply_json)?;
        let reply = match reply_msg {
            WireMessage::Reply(r) => r,
            _ => return Err("expected reply message".into()),
        };

        let expected_transcript = TranscriptDigest::compute(
            &receipt.session_id,
            &receipt.initiator_nonce,
            Some(&receipt.responder_nonce),
            &offer.masked_elements,
            Some(&reply.responder_masked),
            Some(&reply.initiator_doubly_masked),
        );

        if receipt.transcript_digest != expected_transcript {
            return Err("transcript digest mismatch".into());
        }
    }

    if let (Some(a), Some(b)) = (expect_root_a, expect_root_b) {
        let root_a: [u8; 32] = hex::decode(a)?
            .try_into()
            .map_err(|_| "expect_root_a must be 32 bytes")?;
        let root_b: [u8; 32] = hex::decode(b)?
            .try_into()
            .map_err(|_| "expect_root_b must be 32 bytes")?;

        if receipt.set_root_a != root_a {
            return Err(format!(
                "root_a mismatch: expected {}, got {}",
                hex::encode(root_a),
                hex::encode(receipt.set_root_a)
            )
            .into());
        }
        if receipt.set_root_b != root_b {
            return Err(format!(
                "root_b mismatch: expected {}, got {}",
                hex::encode(root_b),
                hex::encode(receipt.set_root_b)
            )
            .into());
        }
    }

    println!("Wire-bound receipt verification: OK");
    println!("  version: {}", receipt.version);
    println!("  session_id: {}", receipt.session_id);
    println!("  mode: {:?}", receipt.mode);
    println!("  transcript_digest: {}", receipt.transcript_digest);
    println!("  initiator_nonce: {}", receipt.initiator_nonce);
    println!("  responder_nonce: {}", receipt.responder_nonce);
    println!("  set_root_a: {}", hex::encode(receipt.set_root_a));
    println!("  set_root_b: {}", hex::encode(receipt.set_root_b));
    println!(
        "  result_commitment: {}",
        hex::encode(receipt.result_commitment)
    );
    println!("  signer: {}", hex::encode(receipt.signer_public_key));
    println!("  receipt_id: {}", hex::encode(receipt.receipt_id()));

    Ok(())
}

fn cmd_invite_create(
    session: &str,
    identity_path: &std::path::Path,
    peer_hex: Option<&str>,
    mode: &str,
    ttl_secs: u64,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = PartyIdentity::load_from_file(identity_path)?;

    let peer_pubkey = if let Some(hex) = peer_hex {
        Some(PublicIdentity::from_hex(hex)?)
    } else {
        None
    };

    let allowed_mode = match mode {
        "intersection" => AllowedMode::Intersection,
        "cardinality" => AllowedMode::Cardinality,
        "any" => AllowedMode::Any,
        _ => return Err(format!("unknown mode: {mode}").into()),
    };

    let ticket = InviteTicket::issue(&identity, session, peer_pubkey, allowed_mode, ttl_secs);

    let json = ticket.to_json_pretty()?;

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!("ticket_id: {}", hex::encode(ticket.ticket_id()));
    eprintln!("session_id: {}", ticket.session_id);
    eprintln!("issuer: {}", ticket.issuer_pubkey.to_hex());
    if let Some(peer) = &ticket.peer_pubkey {
        eprintln!("peer: {}", peer.to_hex());
    }
    eprintln!("allowed_mode: {:?}", ticket.allowed_mode);
    eprintln!("ttl_secs: {}", ttl_secs);
    if let Some(remaining) = ticket.remaining_secs() {
        eprintln!("expires_in: {}s", remaining);
    }

    Ok(())
}

fn cmd_invite_verify(
    ticket_path: &std::path::Path,
    expect_issuer_hex: Option<&str>,
    for_peer_hex: Option<&str>,
    for_session: Option<&str>,
    for_mode: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ticket = InviteTicket::load_from_file(ticket_path)?;

    // Basic verification (signature + expiry)
    ticket.verify()?;

    // Check issuer if specified
    if let Some(hex) = expect_issuer_hex {
        let expected = PublicIdentity::from_hex(hex)?;
        ticket.verify_issuer(&expected)?;
    }

    // Check peer if specified
    if let Some(hex) = for_peer_hex {
        let peer = PublicIdentity::from_hex(hex)?;
        ticket.verify_for_peer(&peer)?;
    }

    // Check session and mode if specified
    if let Some(session) = for_session {
        let mode = if let Some(m) = for_mode {
            match m {
                "intersection" => IntersectionMode::Intersection,
                "cardinality" => IntersectionMode::Cardinality,
                _ => return Err(format!("unknown mode: {m}").into()),
            }
        } else {
            IntersectionMode::Intersection // Default for verification
        };
        ticket.verify_for_session(session, mode)?;
    }

    println!("Invite ticket verification: OK");
    println!("  version: {}", ticket.version);
    println!("  session_id: {}", ticket.session_id);
    println!("  issuer: {}", ticket.issuer_pubkey.to_hex());
    if let Some(peer) = &ticket.peer_pubkey {
        println!("  peer: {}", peer.to_hex());
    } else {
        println!("  peer: (any)");
    }
    println!("  allowed_mode: {:?}", ticket.allowed_mode);
    println!("  issued_at: {}", ticket.issued_at);
    println!("  expires_at: {}", ticket.expires_at);
    if let Some(remaining) = ticket.remaining_secs() {
        println!("  remaining: {}s", remaining);
    } else {
        println!("  remaining: (expired)");
    }
    println!("  ticket_id: {}", hex::encode(ticket.ticket_id()));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_session_export(
    session_id: &str,
    state_path: &std::path::Path,
    offer_path: Option<&std::path::Path>,
    reply_path: Option<&std::path::Path>,
    reveal_path: Option<&std::path::Path>,
    completed: bool,
    identity_path: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state_json = fs::read_to_string(state_path)?;
    let state_value: serde_json::Value = serde_json::from_str(&state_json)?;

    let status = if completed {
        SessionStatus::Completed
    } else {
        SessionStatus::InProgress
    };

    let mut builder = SealedSessionRecord::builder()
        .session_id(session_id)
        .protocol_version(2)
        .status(status);

    // Extract nonces from state if available
    if let Some(nonce_hex) = state_value.get("nonce_hex").and_then(|v| v.as_str()) {
        if let Ok(nonce) = SessionNonce::from_hex(nonce_hex) {
            builder = builder.initiator_nonce(nonce);
        }
    }
    if let Some(nonce_hex) = state_value
        .get("initiator_nonce_hex")
        .and_then(|v| v.as_str())
    {
        if let Ok(nonce) = SessionNonce::from_hex(nonce_hex) {
            builder = builder.responder_nonce(nonce);
        }
    }

    // Add wire messages
    if let Some(path) = offer_path {
        let json = fs::read_to_string(path)?;
        builder = builder.add_message_hash(MessageDirection::Sent, "offer", &json);
    }
    if let Some(path) = reply_path {
        let json = fs::read_to_string(path)?;
        builder = builder.add_message_hash(MessageDirection::Received, "reply", &json);
    }
    if let Some(path) = reveal_path {
        let json = fs::read_to_string(path)?;
        builder = builder.add_message_hash(MessageDirection::Sent, "reveal", &json);
    }

    // Build and optionally seal
    let record = if let Some(id_path) = identity_path {
        let identity = PartyIdentity::load_from_file(id_path)?;
        builder = builder.local_pubkey(identity.public());
        builder.build_sealed(&identity)?
    } else {
        builder.build()?
    };

    let json = record.to_json_pretty()?;

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!("record_id: {}", hex::encode(record.record_id()));
    eprintln!("session_id: {}", record.session_id);
    eprintln!("status: {:?}", record.status);
    eprintln!("message_count: {}", record.messages.len());
    if record.is_sealed() {
        eprintln!("sealed_by: {}", record.sealer().unwrap().to_hex());
    } else {
        eprintln!("sealed: no");
    }

    Ok(())
}

fn cmd_session_verify(
    record_path: &std::path::Path,
    expect_sealer_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = SealedSessionRecord::load_from_file(record_path)?;

    // Verify integrity
    record.verify_integrity()?;

    // Verify seal if present
    if record.is_sealed() {
        if let Some(hex) = expect_sealer_hex {
            let expected = PublicIdentity::from_hex(hex)?;
            record.verify_seal_from(&expected)?;
        } else {
            record.verify_seal()?;
        }
    } else if expect_sealer_hex.is_some() {
        return Err("record is not sealed but expected sealer was specified".into());
    }

    println!("Sealed session record verification: OK");
    println!("  version: {}", record.version);
    println!("  session_id: {}", record.session_id);
    println!("  protocol_version: {}", record.protocol_version);
    println!("  status: {:?}", record.status);
    println!("  started_at: {}", record.started_at);
    println!("  exported_at: {}", record.exported_at);
    if let Some(local) = &record.local_pubkey {
        println!("  local_pubkey: {}", local.to_hex());
    }
    if let Some(peer) = &record.peer_pubkey {
        println!("  peer_pubkey: {}", peer.to_hex());
    }
    println!("  message_count: {}", record.messages.len());
    for msg in &record.messages {
        println!(
            "    [{}] {:?} {} ({}B)",
            msg.sequence, msg.direction, msg.message_type, msg.size_bytes
        );
    }
    if let Some(digest) = &record.transcript_digest {
        println!("  transcript_digest: {}", digest);
    }
    println!("  body_digest: {}", hex::encode(record.body_digest));
    if record.is_sealed() {
        let seal = record.seal.as_ref().unwrap();
        println!("  sealed: yes");
        println!("  sealer: {}", seal.sealer_pubkey.to_hex());
        println!("  sealed_at: {}", seal.sealed_at);
    } else {
        println!("  sealed: no");
    }
    println!("  record_id: {}", hex::encode(record.record_id()));

    Ok(())
}

fn cmd_peerbook_add(
    book_path: &std::path::Path,
    pubkey_hex: &str,
    nickname: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut book = TrustedPeerBook::open(book_path)?;

    book.add_hex(pubkey_hex, nickname.map(|s| s.to_string()))?;

    eprintln!("peer added successfully");
    eprintln!("pubkey: {}", pubkey_hex);
    if let Some(nick) = nickname {
        eprintln!("nickname: {}", nick);
    }
    eprintln!("total peers: {}", book.len());

    Ok(())
}

fn cmd_peerbook_list(book_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let book = TrustedPeerBook::open(book_path)?;

    println!("Trusted peers: {}", book.len());
    for peer in book.list() {
        println!("---");
        println!("  pubkey: {}", peer.pubkey_hex());
        if let Some(nick) = &peer.nickname {
            println!("  nickname: {}", nick);
        }
        println!("  added_at: {}", peer.added_at);
    }

    Ok(())
}

fn cmd_peerbook_remove(
    book_path: &std::path::Path,
    pubkey_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut book = TrustedPeerBook::open(book_path)?;

    let removed = book.remove_hex(pubkey_hex)?;

    eprintln!("peer removed successfully");
    eprintln!("pubkey: {}", removed.pubkey_hex());
    if let Some(nick) = &removed.nickname {
        eprintln!("nickname: {}", nick);
    }
    eprintln!("remaining peers: {}", book.len());

    Ok(())
}

fn cmd_lease_issue(
    session: &str,
    identity_path: &std::path::Path,
    peer_hex: &str,
    ttl_secs: u64,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = PartyIdentity::load_from_file(identity_path)?;
    let peer = PublicIdentity::from_hex(peer_hex)?;

    let lease = SessionLease::issue(&identity, session, peer, ttl_secs);

    let json = lease.to_json_pretty()?;

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!("lease_id: {}", hex::encode(lease.lease_id()));
    eprintln!("session_id: {}", lease.session_id);
    eprintln!("issuer: {}", lease.issuer_pubkey.to_hex());
    eprintln!("peer: {}", lease.peer_pubkey.to_hex());
    eprintln!("ttl_secs: {}", ttl_secs);
    if let Some(remaining) = lease.remaining_secs() {
        eprintln!("expires_in: {}s", remaining);
    }

    Ok(())
}

fn cmd_lease_verify(
    lease_path: &std::path::Path,
    expect_issuer_hex: Option<&str>,
    for_peer_hex: Option<&str>,
    for_session: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let lease = SessionLease::load_from_file(lease_path)?;

    // Basic verification
    lease.verify()?;

    // Check issuer if specified
    if let Some(hex) = expect_issuer_hex {
        let expected = PublicIdentity::from_hex(hex)?;
        lease.verify_issuer(&expected)?;
    }

    // Check peer if specified
    if let Some(hex) = for_peer_hex {
        let peer = PublicIdentity::from_hex(hex)?;
        lease.verify_for_peer(&peer)?;
    }

    // Check session if specified
    if let Some(session) = for_session {
        lease.verify_for_session(session)?;
    }

    println!("Session lease verification: OK");
    println!("  version: {}", lease.version);
    println!("  session_id: {}", lease.session_id);
    println!("  issuer: {}", lease.issuer_pubkey.to_hex());
    println!("  peer: {}", lease.peer_pubkey.to_hex());
    println!("  issued_at: {}", lease.issued_at);
    println!("  expires_at: {}", lease.expires_at);
    println!("  renew_count: {}", lease.renew_count);
    if lease.is_renewal() {
        println!(
            "  parent_lease_id: {}",
            hex::encode(lease.parent_lease_id.unwrap())
        );
    }
    if let Some(remaining) = lease.remaining_secs() {
        println!("  remaining: {}s", remaining);
    } else {
        println!("  remaining: (expired)");
    }
    println!("  lease_id: {}", hex::encode(lease.lease_id()));

    Ok(())
}

fn cmd_lease_renew(
    lease_path: &std::path::Path,
    identity_path: &std::path::Path,
    ttl_secs: u64,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let lease = SessionLease::load_from_file(lease_path)?;
    let identity = PartyIdentity::load_from_file(identity_path)?;

    let renewed = lease.renew(&identity, ttl_secs)?;

    let json = renewed.to_json_pretty()?;

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!("lease_id: {}", hex::encode(renewed.lease_id()));
    eprintln!(
        "parent_lease_id: {}",
        hex::encode(renewed.parent_lease_id.unwrap())
    );
    eprintln!("session_id: {}", renewed.session_id);
    eprintln!("renew_count: {}", renewed.renew_count);
    eprintln!("ttl_secs: {}", ttl_secs);
    if let Some(remaining) = renewed.remaining_secs() {
        eprintln!("expires_in: {}s", remaining);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_session_abort(
    session: &str,
    identity_path: &std::path::Path,
    reason_code: &str,
    reason_text: Option<&str>,
    transcript_hex: Option<&str>,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = PartyIdentity::load_from_file(identity_path)?;

    let reason = match reason_code {
        "user_cancelled" => AbortReason::UserCancelled,
        "timeout" => AbortReason::Timeout,
        "protocol_error" => AbortReason::ProtocolError,
        "network_error" => AbortReason::NetworkError,
        "resource_exhaustion" => AbortReason::ResourceExhaustion,
        "policy_violation" => AbortReason::PolicyViolation,
        "unknown" => AbortReason::Unknown,
        "custom" => AbortReason::Custom,
        _ => return Err(format!("unknown reason code: {}", reason_code).into()),
    };

    let transcript = if let Some(hex) = transcript_hex {
        let bytes: [u8; 32] = hex::decode(hex)?
            .try_into()
            .map_err(|_| "transcript must be 32 bytes")?;
        Some(TranscriptDigest::from_bytes(bytes))
    } else {
        None
    };

    let receipt = AbortReceipt::new(
        &identity,
        session,
        reason,
        reason_text.map(|s| s.to_string()),
        transcript,
    );

    let json = receipt.to_json_pretty()?;

    match output {
        Some(path) => fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!("receipt_id: {}", hex::encode(receipt.receipt_id()));
    eprintln!("session_id: {}", receipt.session_id);
    eprintln!("issuer: {}", receipt.issuer_pubkey.to_hex());
    eprintln!("reason: {}", receipt.reason);
    if let Some(text) = &receipt.reason_text {
        eprintln!("reason_text: {}", text);
    }
    if receipt.transcript_digest.is_some() {
        eprintln!("transcript_digest: present");
    }

    Ok(())
}

fn cmd_abort_verify(
    receipt_path: &std::path::Path,
    expect_issuer_hex: Option<&str>,
    for_session: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = AbortReceipt::load_from_file(receipt_path)?;

    // Basic verification
    receipt.verify()?;

    // Check issuer if specified
    if let Some(hex) = expect_issuer_hex {
        let expected = PublicIdentity::from_hex(hex)?;
        receipt.verify_issuer(&expected)?;
    }

    // Check session if specified
    if let Some(session) = for_session {
        receipt.verify_for_session(session)?;
    }

    println!("Abort receipt verification: OK");
    println!("  version: {}", receipt.version);
    println!("  session_id: {}", receipt.session_id);
    println!("  issuer: {}", receipt.issuer_pubkey.to_hex());
    println!("  reason: {}", receipt.reason);
    if let Some(text) = &receipt.reason_text {
        println!("  reason_text: {}", text);
    }
    println!("  issued_at: {}", receipt.issued_at);
    if let Some(digest) = &receipt.transcript_digest {
        println!("  transcript_digest: {}", digest);
    }
    println!("  receipt_id: {}", hex::encode(receipt.receipt_id()));

    Ok(())
}
