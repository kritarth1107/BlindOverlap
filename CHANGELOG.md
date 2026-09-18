# Changelog

All notable changes to BlindOverlap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-18

### Added

- **Wire Protocol (`wire` module)**
  - JSON-serializable message types for network PSI exchanges
  - `MaskedSetOffer`: Initiator sends masked elements
  - `MaskedSetReply`: Responder sends masked + doubly-masked elements
  - `IntersectionReveal`: Optional bilateral intersection support
  - Domain-separated message tags (`BlindOverlap:*:v1`)
  - Session ID tracking for multi-round correlation
  - `wire_encode()` and `wire_decode()` functions

- **Online Session API (`session` module)**
  - `InitiatorSession`: State machine for initiating party
  - `ResponderSession`: State machine for responding party
  - Clear state transitions (Created → AwaitingReply → Complete)
  - Session ID validation and element count checks
  - Both intersection and cardinality modes supported

- **Set-Size Padding (`padding` module)**
  - `PaddingConfig` for target size and padding secret
  - `generate_dummy_fact_ids()` using HMAC-SHA256 PRF
  - `generate_dummy_masked_elements()` for wire-level padding
  - `pad_fact_ids()` and `pad_masked_elements()` functions
  - `next_power_of_two()` helper for standardized sizes
  - Standard size constants (64, 256, 1024, 4096)
  - Best-effort size hiding under semi-honest model

- **CLI Commands**
  - `wire-encode`: Encode wire protocol messages
  - `wire-decode`: Decode and display wire messages
  - `online-offer`: Generate initiator offer with state persistence
  - `online-reply`: Process offer and generate reply
  - `online-complete`: Process reply and compute intersection
  - `online-reveal`: Process reveal for bilateral mode
  - `--pad-to` flag for set-size padding
  - `--pad-secret` for deterministic padding

- **HTTP/TCP Demo**
  - `examples/http_psi_demo.rs`: Two-party PSI over TCP
  - Server/client mode for network demonstration
  - Length-prefixed TCP framing
  - Shows bilateral intersection computation

- **Tests**
  - Wire roundtrip tests with session data
  - Online session correctness vs colocated protocol
  - Bilateral intersection verification
  - Padding length invariance tests
  - End-to-end padded online intersect

### Changed

- Updated README with v0.2.0 features and examples
- Updated THREAT_MODEL with padding and wire protocol security notes
- Added `hmac` and `tokio` dependencies

### Security Notes

- Wire protocol requires TLS for transport security
- Padding is best-effort under semi-honest model only
- Does NOT provide malicious security
- Keep padding secrets confidential

## [0.1.0] - 2026-09-17

### Added

- **Core Library (`blindoverlap`)**
  - RFC 8785 (JCS) canonical JSON encoding
  - SHA-256 fact ID generation from canonical JSON
  - `FactSet` with merkle-style root commitment
  - DH-PSI protocol using X25519 elliptic curve
  - Intersection mode (reveal matching IDs)
  - Cardinality mode (reveal only count)
  - Ed25519 signed intersection receipts
  - Receipt verification with root checking

- **CLI Tool (`blindoverlap-cli`)**
  - `encode` - Convert JSON facts to fact IDs
  - `canonicalize` - Show RFC 8785 canonical form
  - `intersect` - Run PSI between two fact sets
  - `receipt-sign` - Create signed receipts
  - `receipt-verify` - Verify receipt signatures
  - `card` - Output set cardinality and root

- **Documentation**
  - README with quick start guide
  - THREAT_MODEL.md with honest scope
  - SECURITY.md with disclosure policy
  - Example code

- **Infrastructure**
  - GitHub Actions CI (test + clippy)
  - MIT License
  - 38 unit and integration tests

### Security Notes

- Semi-honest security model only
- NOT malicious-secure
- NOT production-ready
- Maximum 4,096 elements per set

[0.2.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kritarth1107/BlindOverlap/releases/tag/v0.1.0
