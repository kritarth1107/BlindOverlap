//! BlindOverlap CLI - Private set intersection over content-addressed fact IDs.

use blindoverlap::{
    canonical_json, fact_id_from_str, FactSet, IntersectionMode, IntersectionReceipt, PsiProtocol,
    ReceiptSigner, ReceiptVerifier,
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
        } => cmd_receipt_sign(&root_a, &root_b, &result, &mode, key_seed.as_deref(), output.as_deref())?,

        Commands::ReceiptVerify {
            receipt,
            expect_root_a,
            expect_root_b,
        } => cmd_receipt_verify(&receipt, expect_root_a.as_deref(), expect_root_b.as_deref())?,

        Commands::Card { input } => cmd_card(&input)?,
    }

    Ok(())
}

fn cmd_encode(input: &str, format: &str, with_root: bool) -> Result<(), Box<dyn std::error::Error>> {
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
        blindoverlap::PsiResult::Cardinality { count } => {
            writeln!(out, "cardinality: {count}")?;
        }
        blindoverlap::PsiResult::Intersection { ids, root } => {
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
        blindoverlap::PsiResult::Cardinality { count }
    } else {
        let ids = if std::path::Path::new(result).exists() {
            load_fact_ids(std::path::Path::new(result))?
        } else {
            vec![]
        };
        let set = FactSet::from_ids(ids.clone());
        blindoverlap::PsiResult::Intersection {
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
    eprintln!("signer_public_key: {}", hex::encode(receipt.signer_public_key));

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
    println!("  result_commitment: {}", hex::encode(receipt.result_commitment));
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

fn load_fact_set(path: &std::path::Path) -> Result<FactSet, Box<dyn std::error::Error>> {
    let ids = load_fact_ids(path)?;
    Ok(FactSet::from_ids(ids))
}

fn load_fact_ids(path: &std::path::Path) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let reader = io::BufReader::new(fs::File::open(path)?);
    load_fact_ids_from_reader(reader)
}

fn load_fact_ids_from_reader<R: BufRead>(reader: R) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
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
