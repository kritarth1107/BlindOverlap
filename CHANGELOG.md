# Changelog

All notable changes to BlindOverlap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/kritarth1107/BlindOverlap/releases/tag/v0.1.0
