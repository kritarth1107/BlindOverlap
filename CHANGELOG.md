# Changelog

All notable changes to BlindOverlap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-09-23

### Added

- **Policy Profiles (`policy` module)**
  - `PolicyProfile`: Named, serializable session policy for gating session bootstrap
  - Fields: name, require_trusted_peer, min_pad_to, max_ttl_secs, require_lease, require_invite, allow_cardinality_only
  - `check()` / `enforce()` for validating session parameters against policy constraints
  - `PolicyProfile::builder()` for fluent policy construction
  - `PolicyProfile::strict()` and `PolicyProfile::permissive()` presets
  - `SessionParams` struct for representing session parameters to check
  - JSON serialization and file I/O helpers
  - Honest limitation: local policy gate, not cryptographic upgrade

- **Overlap Attestations (`attest` module)**
  - `OverlapAttestation`: Ed25519-signed attestation of intersection outcome
  - Third-party verification WITHOUT re-running PSI
  - Domain-separated signing using `blindoverlap-attest-v1` tag
  - Binds: session_id (optional), mode (intersection | cardinality), set_root_a, set_root_b, intersection_root OR cardinality, transcript_digest (optional), issued_at, expires_at, issuer_pubkey
  - `sign_intersection()` and `sign_cardinality()` constructors
  - `verify()`, `verify_issuer()`, `verify_session()`, `verify_full()` for validation
  - TTL-based expiry with `is_expired()` and `remaining_secs()`
  - `co_sign()` for dual-signature (co-attestation) support
  - `verify_co_signature()` for mutual agreement verification
  - `attestation_id()` for unique attestation identifier
  - JSON serialization and file I/O helpers
  - Honest limitation: attestation proves issuer claimed outcome, not that outcome is truthful

- **CLI Commands**
  - `policy-check`: Check session parameters against a policy profile
  - `policy-show`: Display a policy profile (from file or built-in example)
  - `attest-sign`: Sign an overlap attestation (intersection or cardinality mode)
  - `attest-verify`: Verify an overlap attestation (signature, expiry, issuer, session)

- **Tests**
  - 12 new integration tests for v0.7.0 features
  - PolicyProfile constraint checking tests
  - Attestation sign/verify/dual-sign tests
  - Policy + attestation integration test

### Security Notes

- **Policy profiles are local policy gates, not cryptographic security upgrades**
- **Attestations prove an issuer CLAIMED an outcome, not that it is truthful**
- Dual-signature (co-attestation) helps establish mutual agreement but still relies on semi-honest parties
- None of these features upgrade PSI from semi-honest to malicious security
- This is the FINAL release of the BlindOverlap campaign week (Sep 17–23)
- See THREAT_MODEL.md for detailed security analysis

## [0.6.0] - 2026-09-22

### Added

- **Trusted Peer Book (`peerbook` module)**
  - `TrustedPeerBook`: File-backed directory of known peer Ed25519 public keys
  - `TrustedPeer` struct with pubkey, optional nickname, added_at timestamp
  - Add/remove/lookup by pubkey hex with duplicate rejection
  - `require_trusted()` for optional trust gate before channel-bound sessions
  - JSON file persistence with load/save
  - Honest limitation: trust is out-of-band policy, not PSI security

- **Session Lease (`lease` module)**
  - `SessionLease`: Signed time-bounded lease extending session authority
  - Fields: issuer_pubkey, peer_pubkey, session_id, issued_at, expires_at, renew_count
  - Domain-separated signing using `BlindOverlap:SessionLease:v1` tag
  - `issue()` and `issue_default()` for creating leases (default TTL: 30 minutes)
  - `verify()`, `verify_issuer()`, `verify_for_peer()`, `verify_for_session()`, `verify_full()`
  - `renew()` for issuer to extend lease with parent chain tracking
  - Optional `parent_lease_id` for renewal chain integrity
  - JSON serialization and file I/O helpers

- **Abort Receipt (`abort` module)**
  - `AbortReceipt`: Signed abort receipt for mid-protocol cancellation
  - `AbortReason` enum: UserCancelled, Timeout, ProtocolError, NetworkError, etc.
  - Domain-separated signing using `BlindOverlap:AbortReceipt:v1` tag
  - `simple()`, `with_reason()`, `with_transcript()` constructors
  - Optional transcript digest binding for audit trails
  - `AbortError` with typed error variants

- **Wire Protocol: AbortMessage**
  - `AbortMessage` struct for mid-protocol cancellation over wire
  - `WireMessage::Abort` variant with backward compatibility note
  - Domain tag `BlindOverlap:AbortMessage:v1`
  - Older peers (pre-v0.6.0) may reject unknown message types

- **Session Status: Aborted**
  - `SessionStatus::Aborted` for explicit session abort in sealed records
  - Distinct from `Failed` (protocol error) for clearer audit trails

- **Lease-Aware Session Bootstrap**
  - `InitiatorSession::from_lease()`: Create session from verified lease
  - `ResponderSession::from_lease()`: Create responder from verified lease
  - Lease issuer becomes expected peer for channel binding
  - Keep InviteTicket paths working alongside lease paths

- **Optional Peerbook Trust Gate**
  - `require_peer_trusted()` helper function
  - Check peerbook before creating channel-bound sessions
  - Policy enforcement, not security upgrade

- **CLI Commands**
  - `peerbook-add`: Add peer with pubkey and optional nickname
  - `peerbook-list`: List all trusted peers
  - `peerbook-remove`: Remove peer by pubkey
  - `lease-issue`: Issue session lease with TTL
  - `lease-verify`: Verify lease signature and bindings
  - `lease-renew`: Renew existing lease with new TTL
  - `session-abort`: Create signed abort receipt
  - `abort-verify`: Verify abort receipt signature

- **Tests**
  - 25+ new integration tests for v0.6.0 features
  - Peerbook CRUD, file persistence, trust gate tests
  - Lease issue/verify/renew chain tests
  - Abort sign/verify with transcript tests
  - Session from_lease tests
  - End-to-end: peerbook trust gate → lease → PSI → abort → sealed export

### Security Notes

- **Peerbook trust is out-of-band policy, not PSI security**
- **Leases authenticate WHO may continue a session, not WHAT they compute**
- **Abort receipts are audit aids only, not security guarantees**
- None of these features upgrade PSI from semi-honest to malicious
- See THREAT_MODEL.md for detailed security analysis

## [0.5.0] - 2026-09-21

### Added

- **Invite Tickets (`invite` module)**
  - `InviteTicket`: Short-lived signed capability for bootstrapping channel-bound PSI sessions
  - Fields: issuer_pubkey, optional peer_pubkey, session_id, allowed_mode, issued_at, expires_at, signature
  - Domain-separated signing using `BlindOverlap:InviteTicket:v1` tag
  - `issue()` and `issue_default()` for creating tickets
  - `verify()`, `verify_issuer()`, `verify_for_peer()`, `verify_for_session()`, `verify_full()` for validation
  - `AllowedMode` enum (Intersection, Cardinality, Any) for mode restriction
  - `InviteError` with typed error variants
  - JSON serialization and file I/O helpers

- **Sealed Session Export (`seal` module)**
  - `SealedSessionRecord`: JSON export of completed/in-progress online sessions for audit
  - Captures session metadata, ordered wire messages (or hashes), transcript digest
  - Body digest for integrity verification (domain-separated hash)
  - Optional Ed25519 seal using `BlindOverlap:SealedRecord:v1` tag
  - `SealedSessionBuilder` for fluent record construction
  - `WireMessageEntry` with hash, size, optional content
  - `MessageDirection` (Sent/Received) and `SessionStatus` (InProgress, Completed, Failed)
  - `verify_integrity()` and `verify_seal()` for validation
  - `SealError` with typed error variants

- **Persistent Replay Store**
  - `PersistentReplayStore`: File-backed persistence for replay protection
  - JSON-based storage format (simple append/load pattern)
  - Data loaded on `open()`, flushed after each record operation
  - Survives process restart; TTL cleanup still applies on load
  - `open()` and `open_with_ttl()` constructors
  - `flush()` for explicit persistence, `reload()` to refresh from disk
  - `ReplayStoreError` for typed IO/JSON errors

- **Session Invite Integration**
  - `InitiatorSession::from_invite()`: Create initiator from verified invite ticket
  - `ResponderSession::from_invite()`: Create responder from verified invite ticket
  - Automatic channel binding with issuer as expected peer
  - `SessionError::Invite` variant for ticket verification failures

- **CLI Commands**
  - `invite-create`: Issue invite ticket with --session, --identity, --peer, --mode, --ttl-secs
  - `invite-verify`: Verify ticket with --expect-issuer, --for-peer, --for-session, --for-mode
  - `session-export`: Export SealedSessionRecord from state and wire files
  - `session-verify`: Verify sealed record integrity and optional seal

- **Tests**
  - 17 new integration tests for v0.5.0 features
  - Invite issue/verify/expiry/bad-sig tests
  - Sealed record roundtrip and integrity tests
  - Persistent replay survives reload tests
  - End-to-end invite → signed PSI → export test

### Security Notes

- **Invite tickets authenticate WHO may start a session, not WHAT they compute**
- Tickets do NOT upgrade PSI security from semi-honest to malicious
- **Sealed records are audit aids only**, not security guarantees
- Persistent replay store is best-effort, not crash-safe
- See THREAT_MODEL.md for detailed security analysis

## [0.4.0] - 2026-09-20

### Added

- **Party Identity (`identity` module)**
  - `PartyIdentity`: Long-lived Ed25519 keypair for signing
  - `PublicIdentity`: Shareable public key for peer identification
  - Domain-separated signatures using `BlindOverlap:PartyIdentity:v1` tag
  - Keypair generation, seed-based creation, hex encoding
  - File-based keypair persistence (load/save as JSON)
  - `IdentityError` for typed error handling

- **Signed Wire Messages**
  - `SignedWireMessage`: Envelope wrapping any wire message with signature
  - `signer_pubkey` and `signature` fields for channel authentication
  - `wire_encode_signed()` / `wire_decode_signed()` functions
  - `wire_decode_signed_from_peer()` for peer verification
  - v3 protocol tags for signed messages
  - Backward compatible: unsigned v1/v2 messages still decode

- **Session Channel Binding**
  - `ChannelBinding`: Binds session to (local_pubkey, peer_pubkey)
  - `InitiatorSession::with_channel_binding()` constructor
  - `ResponderSession::with_channel_binding()` constructor
  - `generate_offer_signed()` / `generate_reveal_signed()` for initiator
  - `process_offer_and_reply_signed()` / `process_reveal_signed()` for responder
  - `SessionError::IdentityMismatch`, `BadSignature`, `MissingIdentity`
  - `verified_peer()` getter to check who signed incoming messages

- **CLI Commands**
  - `identity-gen`: Generate Ed25519 keypair to JSON file
  - `identity-show`: Display public key from identity file
  - `--identity` flag on `online-offer`, `online-reply`, `online-complete`
  - `--expect-peer` flag for verifying signed messages
  - Auto-detection of signed vs unsigned messages when decoding

- **Tests**
  - 7 new integration tests for identity features
  - Sign/verify roundtrip, bad signature rejection, wrong peer rejection
  - End-to-end PSI with identities, impersonation rejection
  - Backward compatibility with unsigned v2 messages

### Security Notes

- **Party identity provides channel authentication only**
- Does NOT upgrade PSI security from semi-honest to malicious
- Signatures prevent message swapping/MITM but not protocol deviation
- Both parties must verify expected peer keys out-of-band
- See THREAT_MODEL.md for detailed security analysis

## [0.3.0] - 2026-09-19

### Added

- **Session Freshness (`freshness` module)**
  - `SessionNonce`: 32-byte cryptographic nonce for session binding
  - `SessionDeadline`: TTL enforcement with `issued_at` / `expires_at` timestamps
  - `TranscriptDigest`: Domain-separated hash over wire messages for binding
  - `FreshnessError`: Typed errors for expiry, nonce mismatch, replay detection
  - `current_unix_time()` helper and `DEFAULT_TTL_SECS` (300 seconds)

- **Wire Protocol v2**
  - Protocol version bump with new domain tags (`BlindOverlap:*:v2`)
  - `MaskedSetOffer`: adds `nonce`, `issued_at`, `expires_at` fields
  - `MaskedSetReply`: adds `initiator_nonce`, `responder_nonce`, timestamps
  - `IntersectionReveal`: adds freshness fields for bilateral sessions
  - `WireError::MissingFreshness` for v2 validation failures
  - `new_v2()` constructors and `has_freshness()` methods
  - Backward compatible: v1 messages still work

- **Session API Updates**
  - `SessionConfig`: Configure TTL and protocol version
  - `with_config()` constructor for custom session settings
  - Sessions default to v2 with freshness (300s TTL)
  - `process_reply()` validates nonce echo and deadline expiry
  - `process_offer_and_reply()` validates offer deadline
  - `nonce()`, `responder_nonce()`, `initiator_nonce()` getters
  - `SessionError::Freshness`, `NonceMismatch`, `VersionMismatch`

- **Replay Protection (`replay` module)**
  - `ReplayStore`: In-memory tracking of used nonces and transcript digests
  - `check_nonce()` / `record_nonce()` for nonce tracking
  - `check_digest()` / `record_digest()` for transcript tracking
  - TTL-based expiry for memory management
  - Configurable limits: default 1 hour TTL, 100k max entries

- **Wire-Bound Receipts**
  - `WireBoundReceipt`: Binds to session_id + transcript digest + nonces
  - Stronger binding than basic `IntersectionReceipt`
  - `ReceiptSigner::sign_wire_bound()` for creating bound receipts
  - `ReceiptVerifier::verify_wire_bound_with_bindings()` for full validation
  - `ReceiptError::SessionMismatch`, `TranscriptMismatch` variants

- **CLI Commands**
  - `--ttl-secs` flag on `online-offer` and `online-reply`
  - `wire-bound-sign`: Create session-bound receipts
  - `wire-bound-verify`: Verify with transcript validation
  - State files now include `nonce_hex` and `ttl_secs`

- **Tests**
  - 46 integration tests covering freshness, replay, TTL, wire-bound receipts
  - V1/V2 compatibility tests
  - Nonce/digest roundtrip tests

### Changed

- Sessions now default to v2 protocol with freshness
- Wire messages include optional freshness fields
- Session state structs include nonce tracking
- Documentation updated for v0.3.0 features

### Security Notes

- **Freshness is best-effort under semi-honest model**
- TTL and nonce validation help prevent accidental replay
- Does NOT provide protection against active adversaries
- ReplayStore is in-memory only (does not persist)
- Applications may need more robust replay tracking for production

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

[0.7.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kritarth1107/BlindOverlap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kritarth1107/BlindOverlap/releases/tag/v0.1.0
