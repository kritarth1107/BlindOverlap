# BlindOverlap

**Two agents compare memories. Only the overlap comes out.**

BlindOverlap is an agent-native private set intersection (PSI) library for content-addressed fact IDs. It allows two parties to discover which facts they have in common without revealing any other facts from their sets.

## Features

- **Content-addressed facts**: Facts are 32-byte SHA-256 hashes of RFC 8785 (JCS) canonical JSON
- **Private set intersection**: DH-based PSI protocol using X25519 elliptic curve cryptography
- **Intersection modes**: Full intersection (reveal matching IDs) or cardinality-only (reveal only count)
- **Signed receipts**: Ed25519 signatures over intersection results for auditability
- **CLI tool**: Encode facts, run intersections, sign and verify receipts

## Honest Scope & Limitations

| Feature | Status |
|---------|--------|
| Security model | **Semi-honest only** — assumes parties follow protocol |
| Malicious security | ❌ NOT supported (no VOLE-PSI) |
| Fuzzy/embedding PSI | ❌ NOT supported (exact match only) |
| Cardinality mode | ⚠️ Leaks intersection size |\\|
| Scale | **Toy scale**: ≤4,096 IDs per set, 32 bytes each |
| Production readiness | ❌ **NOT production ready** — for experimentation only |

> **Warning**: This is a v0.1.0 release intended for experimentation and learning. Do not use in production systems where security is critical. See [THREAT_MODEL.md](THREAT_MODEL.md) for details.

## Quick Start

### Installation

```bash
# From source
cargo install --path crates/blindoverlap-cli

# Or build locally
cargo build --release
```

### Encode JSON Facts

```bash
# Encode JSON facts to fact IDs (one JSON per line)
echo '{"name": "Alice", "age": 30}' | blindoverlap encode
# Output: 1b3d1428a344b4a5f9e479024cd76449100aec4c3ace922a317dd45696412f77

# With set root
echo -e '{"fact": 1}\n{"fact": 2}' | blindoverlap encode --with-root
```

### Run PSI Intersection

```bash
# Create two fact files
echo -e '{"x": 1}\n{"x": 2}\n{"x": 3}' | blindoverlap encode > set_a.ids
echo -e '{"x": 2}\n{"x": 3}\n{"x": 4}' | blindoverlap encode > set_b.ids

# Run intersection
blindoverlap intersect --set-a set_a.ids --set-b set_b.ids
# Output: IDs that appear in both sets

# Cardinality only (just the count)
blindoverlap intersect --set-a set_a.ids --set-b set_b.ids --cardinality
```

### Sign & Verify Receipts

```bash
# Get set roots
ROOT_A=$(blindoverlap card -i set_a.ids | grep set_root | cut -d' ' -f2)
ROOT_B=$(blindoverlap card -i set_b.ids | grep set_root | cut -d' ' -f2)

# Sign a receipt
blindoverlap receipt-sign \
  --root-a $ROOT_A \
  --root-b $ROOT_B \
  --result intersection.ids \
  --mode intersection \
  --output receipt.json

# Verify receipt
blindoverlap receipt-verify --receipt receipt.json
```

## Library Usage

```rust
use blindoverlap::{FactSet, PsiProtocol, IntersectionMode, fact_id_from_json};
use serde_json::json;

// Create fact sets
let set_a = FactSet::from_ids([
    fact_id_from_json(&json!({"shared": true})),
    fact_id_from_json(&json!({"only_a": true})),
]);

let set_b = FactSet::from_ids([
    fact_id_from_json(&json!({"shared": true})),
    fact_id_from_json(&json!({"only_b": true})),
]);

// Run PSI
let protocol = PsiProtocol::new();
let result = protocol.intersect(&set_a, &set_b, IntersectionMode::Intersection)?;

match result {
    blindoverlap::PsiResult::Intersection { ids, root } => {
        println!("Found {} matching facts", ids.len());
        println!("Intersection root: {}", hex::encode(root));
    }
    _ => {}
}
```

## Modules

| Module | Description |
|--------|-------------|
| `fact_id` | RFC 8785 canonical JSON hashing, FactSet with merkle root |
| `protocol` | DH-PSI implementation using X25519 |
| `receipt` | Ed25519 signed intersection receipts |

## CLI Commands

| Command | Description |
|---------|-------------|
| `encode` | Convert JSON facts to fact IDs |
| `canonicalize` | Show RFC 8785 canonical JSON form |
| `intersect` | Run PSI between two fact sets |
| `receipt-sign` | Create signed intersection receipt |
| `receipt-verify` | Verify receipt signature and roots |
| `card` | Output set cardinality and root |

## Protocol Overview

BlindOverlap uses a Diffie-Hellman based PSI protocol:

1. **Fact Encoding**: Each JSON fact is canonicalized per RFC 8785 and hashed with SHA-256 to produce a 32-byte fact ID
2. **Set Commitment**: Each set is committed via a merkle-style root over sorted fact IDs
3. **Masking**: Each party masks their fact IDs with their secret scalar
4. **Exchange**: Parties exchange masked sets
5. **Double-Masking**: Each party applies their secret to the other's masked set
6. **Comparison**: Matching doubly-masked values indicate common facts

## License

MIT License — see [LICENSE](LICENSE)

## Contributing

This is an experimental project. Issues and PRs welcome for:
- Bug fixes
- Documentation improvements
- Test coverage
- Performance improvements

Not accepting changes that claim stronger security guarantees than the semi-honest model provides.
