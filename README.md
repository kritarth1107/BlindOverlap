# BlindOverlap

**Two agents compare memories. Only the overlap comes out.**

BlindOverlap is an agent-native private set intersection (PSI) library for content-addressed fact IDs. It allows two parties to discover which facts they have in common without revealing any other facts from their sets.

## Features

- **Content-addressed facts**: Facts are 32-byte SHA-256 hashes of RFC 8785 (JCS) canonical JSON
- **Private set intersection**: DH-based PSI protocol using X25519 elliptic curve cryptography
- **Intersection modes**: Full intersection (reveal matching IDs) or cardinality-only (reveal only count)
- **Signed receipts**: Ed25519 signatures over intersection results for auditability
- **Wire protocol**: JSON-serializable messages for network-based PSI exchanges (v0.2.0)
- **Online sessions**: State machine API for two-party PSI over wire messages (v0.2.0)
- **Set-size padding**: Hide real set cardinality from wire message length analysis (v0.2.0)
- **Session freshness**: Nonces, TTL, and replay protection primitives (v0.3.0)
- **Wire-bound receipts**: Receipts bound to specific sessions and transcripts (v0.3.0)
- **Party identity**: Long-lived Ed25519 keypairs for channel authentication (v0.4.0)
- **Signed wire messages**: Every message signed by sender, verified by recipient (v0.4.0)
- **Session channel-binding**: Sessions bind to (local_pubkey, peer_pubkey, session_id) (v0.4.0)
- **CLI tool**: Encode facts, run intersections, wire encode/decode, online sessions, receipts, identity

## Honest Scope & Limitations

| Feature | Status |
|---------|--------|
| Security model | **Semi-honest only** — assumes parties follow protocol |
| Malicious security | ❌ NOT supported (no VOLE-PSI) |
| Fuzzy/embedding PSI | ❌ NOT supported (exact match only) |
| Cardinality mode | ⚠️ Leaks intersection size |
| Padding | ⚠️ Best-effort size hiding (semi-honest only) |
| Freshness | ⚠️ Best-effort TTL/replay (semi-honest only) |
| Scale | **Toy scale**: ≤4,096 IDs per set, 32 bytes each |
| Production readiness | ❌ **NOT production ready** — for experimentation only |

> **Warning**: This is a v0.3.0 release intended for experimentation and learning. Do not use in production systems where security is critical. See [THREAT_MODEL.md](THREAT_MODEL.md) for details.

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

### Run PSI Intersection (Colocated)

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

### Online PSI (Network-capable)

```bash
# Party A (initiator): Generate offer
blindoverlap online-offer \
  --input set_a.ids \
  --session "my-session" \
  --state-out a_state.json \
  --output offer.json

# Party B (responder): Process offer, generate reply
blindoverlap online-reply \
  --input set_b.ids \
  --offer offer.json \
  --state-out b_state.json \
  --output reply.json

# Party A: Process reply, compute intersection
blindoverlap online-complete \
  --reply reply.json \
  --state a_state.json \
  --with-reveal \
  --reveal-out reveal.json

# Party B: Process reveal for bilateral intersection
blindoverlap online-reveal \
  --reveal reveal.json \
  --state b_state.json
```

### Padding (Hide Set Size)

```bash
# Pad to 64 elements to hide real set size
blindoverlap online-offer \
  --input set_a.ids \
  --session "padded-session" \
  --pad-to 64 \
  --state-out a_state.json
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

### Session Freshness (v0.3.0)

```bash
# Online session with custom TTL (60 seconds)
blindoverlap online-offer \
  --input set_a.ids \
  --session "fresh-session" \
  --ttl-secs 60 \
  --state-out a_state.json \
  --output offer.json

# Responder with matching TTL
blindoverlap online-reply \
  --input set_b.ids \
  --offer offer.json \
  --ttl-secs 60 \
  --state-out b_state.json \
  --output reply.json
```

### Wire-Bound Receipts (v0.3.0)

```bash
# Sign a wire-bound receipt (binds to session and transcript)
blindoverlap wire-bound-sign \
  --session "my-session" \
  --offer offer.json \
  --reply reply.json \
  --root-a $ROOT_A \
  --root-b $ROOT_B \
  --result intersection.ids \
  --mode intersection \
  --output wire_receipt.json

# Verify with transcript checking
blindoverlap wire-bound-verify \
  --receipt wire_receipt.json \
  --expect-session "my-session" \
  --offer offer.json \
  --reply reply.json
```

### Party Identity (v0.4.0)

```bash
# Generate identity keypairs for both parties
blindoverlap identity-gen --output alice_id.json --pubkey-out alice.pub
blindoverlap identity-gen --output bob_id.json --pubkey-out bob.pub

# Show public key from identity file
blindoverlap identity-show --identity alice_id.json

# Exchange public keys out-of-band, then run authenticated PSI:

# Party A (initiator): Generate signed offer
ALICE_PUBKEY=$(cat alice.pub)
BOB_PUBKEY=$(cat bob.pub)

blindoverlap online-offer \
  --input set_a.ids \
  --session "auth-session" \
  --identity alice_id.json \
  --expect-peer $BOB_PUBKEY \
  --state-out a_state.json \
  --output offer.json

# Party B (responder): Verify offer signature, generate signed reply
blindoverlap online-reply \
  --input set_b.ids \
  --offer offer.json \
  --identity bob_id.json \
  --expect-peer $ALICE_PUBKEY \
  --state-out b_state.json \
  --output reply.json

# Party A: Verify reply signature, compute intersection
blindoverlap online-complete \
  --reply reply.json \
  --state a_state.json \
  --expect-peer $BOB_PUBKEY \
  --with-reveal \
  --identity alice_id.json \
  --reveal-out reveal.json

# Party B: Verify reveal signature for bilateral intersection
blindoverlap online-reveal \
  --reveal reveal.json \
  --state b_state.json \
  --expect-peer $ALICE_PUBKEY
```

## Library Usage

```rust
use blindoverlap::{
    FactSet, PsiProtocol, IntersectionMode, fact_id_from_json,
    InitiatorSession, ResponderSession, WireMessage, wire_encode, wire_decode,
};
use serde_json::json;

// Colocated intersection (both sets on same machine)
let set_a = FactSet::from_ids([
    fact_id_from_json(&json!({"shared": true})),
    fact_id_from_json(&json!({"only_a": true})),
]);
let set_b = FactSet::from_ids([
    fact_id_from_json(&json!({"shared": true})),
    fact_id_from_json(&json!({"only_b": true})),
]);

let protocol = PsiProtocol::new();
let result = protocol.intersect(&set_a, &set_b, IntersectionMode::Intersection)?;

// Online intersection (network-capable)
let mut initiator = InitiatorSession::new("session-1", set_a, IntersectionMode::Intersection)?;
let mut responder = ResponderSession::new("session-1", set_b, IntersectionMode::Intersection)?;

// Generate and exchange wire messages
let offer = initiator.generate_offer()?;
let reply = responder.process_offer_and_reply(&offer)?;
let result = initiator.process_reply(&reply)?;

// Optional: bilateral intersection
let reveal = initiator.generate_reveal()?;
let responder_result = responder.process_reveal(&reveal)?;
```

## Modules

| Module | Description |
|--------|-------------|
| `fact_id` | RFC 8785 canonical JSON hashing, FactSet with merkle root |
| `protocol` | DH-PSI implementation using X25519 |
| `receipt` | Ed25519 signed receipts (basic and wire-bound) |
| `wire` | JSON wire protocol for network exchanges (v0.2.0+) |
| `session` | Online two-party PSI state machine (v0.2.0+) |
| `padding` | Set-size padding with domain-separated PRF (v0.2.0+) |
| `freshness` | Session nonces, deadlines, transcript digests (v0.3.0) |
| `replay` | In-memory replay protection store (v0.3.0) |
| `identity` | Party identity with Ed25519 keypairs (v0.4.0) |

## CLI Commands

| Command | Description |
|---------|-------------|
| `encode` | Convert JSON facts to fact IDs |
| `canonicalize` | Show RFC 8785 canonical JSON form |
| `identity-gen` | Generate Ed25519 identity keypair (v0.4.0) |
| `identity-show` | Display public key from identity file (v0.4.0) |
| `intersect` | Run PSI between two fact sets (colocated) |
| `receipt-sign` | Create signed intersection receipt |
| `receipt-verify` | Verify receipt signature and roots |
| `card` | Output set cardinality and root |
| `wire-encode` | Encode wire protocol message |
| `wire-decode` | Decode and display wire message |
| `online-offer` | Generate initiator offer with `--ttl-secs`, `--identity`, `--expect-peer` |
| `online-reply` | Process offer, generate reply with identity options |
| `online-complete` | Process reply, compute intersection with identity options |
| `online-reveal` | Process reveal for bilateral mode with `--expect-peer` |
| `wire-bound-sign` | Create session-bound receipt (v0.3.0) |
| `wire-bound-verify` | Verify wire-bound receipt with transcript (v0.3.0) |

## Protocol Overview

BlindOverlap uses a Diffie-Hellman based PSI protocol:

1. **Fact Encoding**: Each JSON fact is canonicalized per RFC 8785 and hashed with SHA-256 to produce a 32-byte fact ID
2. **Set Commitment**: Each set is committed via a merkle-style root over sorted fact IDs
3. **Masking**: Each party masks their fact IDs with their secret scalar
4. **Exchange**: Parties exchange masked sets (via wire protocol for network use)
5. **Double-Masking**: Each party applies their secret to the other's masked set
6. **Comparison**: Matching doubly-masked values indicate common facts

### Wire Protocol (v0.2.0)

For network-based PSI, the protocol uses three message types:
- `MaskedSetOffer`: Initiator sends masked elements
- `MaskedSetReply`: Responder sends their masked elements + doubly-masked initiator elements
- `IntersectionReveal`: Optional message for bilateral intersection

## Examples

See the `examples/` directory:
- `basic_psi.rs` — Colocated PSI demonstration
- `http_psi_demo.rs` — TCP-based two-party PSI demo (server/client)

Run the HTTP demo:
```bash
# Terminal 1: Start server
cargo run --example http_psi_demo -- server

# Terminal 2: Run client
cargo run --example http_psi_demo -- client
```

## License

MIT License — see [LICENSE](LICENSE)

## Contributing

This is an experimental project. Issues and PRs welcome for:
- Bug fixes
- Documentation improvements
- Test coverage
- Performance improvements

Not accepting changes that claim stronger security guarantees than the semi-honest model provides.
