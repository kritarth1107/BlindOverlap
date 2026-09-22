# BlindOverlap Threat Model

This document describes the security model, assumptions, and known limitations of BlindOverlap v0.5.0.

## Security Model: Semi-Honest

BlindOverlap operates under a **semi-honest (honest-but-curious) security model**.

### What This Means

- **Parties follow the protocol correctly** but may try to learn additional information from the messages they receive
- **No malicious behavior** is protected against — parties are assumed to:
  - Send correctly formatted messages
  - Use the agreed-upon parameters
  - Not deviate from the protocol steps
  - Not send malformed or adversarial inputs

### What Semi-Honest Security Provides

✅ A semi-honest party learns only:
- The intersection of the two sets (in Intersection mode)
- The cardinality of the intersection (in Cardinality mode)
- The size of their own set
- The size of the other party's set (from message count, unless padding is used)

### What Semi-Honest Security Does NOT Provide

❌ No protection against:
- Malicious parties who deviate from the protocol
- Parties who send fake or crafted elements
- Parties who manipulate their set after seeing protocol messages
- Timing attacks or side channels
- Network-level adversaries who can modify messages

## What BlindOverlap Is NOT

### Not Malicious-Secure PSI

BlindOverlap does **NOT** implement malicious-secure PSI protocols such as:
- VOLE-PSI (Vector Oblivious Linear Evaluation)
- Circuit-based PSI
- Zero-knowledge proof-based PSI

A malicious party could:
- Learn elements not in the intersection by crafting inputs
- Cause incorrect intersection results
- Perform set membership queries

### Not Fuzzy or Embedding PSI

BlindOverlap performs **exact match** PSI only:
- Fact IDs must match exactly (32-byte equality)
- No similarity matching or approximate PSI
- No support for embedding-based comparison

### Not Production-Ready

This is a **toy implementation** intended for:
- Learning about PSI protocols
- Prototyping and experimentation
- Educational purposes

Do NOT use for:
- Financial or healthcare data
- Sensitive personal information
- Critical security decisions
- Production systems

## Cardinality Mode Leakage

When using Cardinality mode, the protocol reveals |A ∩ B| — the exact count of matching elements.

### Information Leaked

- If cardinality = 0: parties share nothing
- If cardinality = |A|: A is a subset of B
- If cardinality = |B|: B is a subset of A
- If cardinality = |A| = |B|: sets are equal

### Mitigation Considerations

For sensitive applications, consider:
- Adding noise (differential privacy)
- Bucketing cardinality into ranges
- Using full intersection mode when count alone is sensitive

## Set-Size Padding (v0.2.0)

BlindOverlap v0.2.0 introduces **set-size padding** to hide the real set cardinality from wire message length analysis.

### How Padding Works

- Dummy elements are generated using HMAC-SHA256 with a domain-separated PRF
- Elements are padded to a target size before transmission
- The padding secret must be kept confidential

### Padding Limitations

⚠️ **Padding is best-effort under the semi-honest model only.**

- A semi-honest party cannot distinguish real elements from padding in the wire message
- A malicious party could still learn information through:
  - Protocol deviations (sending subset queries)
  - Timing analysis of processing time
  - Observing which elements match in the result
  
- Padding does NOT:
  - Provide full size-hiding against active adversaries
  - Prevent intersection result from revealing overlap
  - Hide the number of *matching* elements

### Recommended Padding Practices

- Pad to fixed power-of-2 sizes (64, 256, 1024, 4096)
- Use the same padding size across all sessions
- Keep padding secrets confidential and session-specific
- Do not rely on padding for security-critical size hiding

## Wire Protocol Surface (v0.2.0)

The wire protocol introduces additional attack surface:

### Message Integrity

- Messages are JSON-serialized with hex-encoded elements
- No built-in message authentication or encryption
- **Use TLS** for transport security in production

### Session Management (Updated in v0.3.0)

- Session IDs correlate multi-round exchanges
- **v0.3.0 adds session freshness primitives:**
  - `SessionNonce`: 32-byte cryptographic nonces for session binding
  - `SessionDeadline`: TTL enforcement with `issued_at` / `expires_at`
  - `ReplayStore`: In-memory tracking of used nonces and transcripts
- These are **best-effort aids under the semi-honest model**
- Freshness does NOT provide protection against active adversaries
- Applications may need more robust replay tracking for production
- See "Session Freshness Limitations" below for details

### Denial of Service

- No rate limiting built-in
- Large messages could cause memory exhaustion
- The 4096 element limit provides some protection

## Party Identity and Channel Binding (v0.4.0)

BlindOverlap v0.4.0 introduces party identity and signed wire messages for **channel authentication**.

### What Party Identity Provides

✅ Channel authentication:
- Each party has an Ed25519 keypair (long-lived identity)
- Wire messages are signed with the sender's private key
- Recipients verify signatures against expected peer public key
- Sessions bind to (local_pubkey, peer_pubkey, session_id)
- MITM swapping messages between sessions is detected

### What Party Identity Does NOT Provide

❌ **Party identity does NOT upgrade PSI security from semi-honest to malicious.**

- A signed message proves the message came from the expected peer
- It does NOT prove the peer followed the protocol correctly
- A semi-honest peer can still:
  - Send fake or crafted elements
  - Learn elements not in the intersection by protocol deviation
  - Cause incorrect intersection results
  
⚠️ **Channel authentication ≠ Protocol security**

| Threat | Protected? | Notes |
|--------|-----------|-------|
| Message swapping between sessions | ✅ Yes | Session binding prevents |
| MITM inserting messages | ✅ Yes | Signature verification catches |
| Replay of signed messages | ⚠️ Partial | Nonces help; dedicated replay store needed |
| Malicious peer deviating from protocol | ❌ No | Still semi-honest model |
| Peer sending fake/crafted elements | ❌ No | Still semi-honest model |

### Recommended Practices for Identity

- Generate identity keypairs securely and protect private keys
- Exchange public keys out-of-band before PSI sessions
- Verify peer identities match expected parties
- Use channel binding for all production sessions
- Remember: identity authenticates WHO, not WHAT they compute

## Invite Tickets (v0.5.0)

BlindOverlap v0.5.0 introduces invite tickets for **session bootstrapping authentication**.

### What Invite Tickets Provide

✅ Session authorization:
- Short-lived signed capability for starting a session
- Issuer controls WHO may join a specific session
- Optional peer binding (ticket only valid for one peer)
- Mode restriction (intersection-only, cardinality-only, or any)
- TTL-based expiry with signature verification

### What Invite Tickets Do NOT Provide

❌ **Invite tickets do NOT upgrade PSI security from semi-honest to malicious.**

- A valid ticket proves the issuer authorized the session
- It does NOT prove the peer will follow the protocol correctly
- A semi-honest peer can still:
  - Send fake or crafted elements
  - Deviate from the protocol
  - Learn elements not in the intersection

⚠️ **Ticket authorization ≠ Protocol security**

| Threat | Protected? | Notes |
|--------|-----------|-------|
| Unauthorized session start | ✅ Yes | Ticket required to join |
| Expired ticket reuse | ✅ Yes | TTL + signature verification |
| Peer impersonation | ⚠️ Partial | Only if peer_pubkey is set |
| Malicious protocol deviation | ❌ No | Still semi-honest model |
| Ticket theft/replay | ⚠️ TTL helps | Short-lived by design |

### Recommended Practices for Invite Tickets

- Use short TTLs (5 minutes or less)
- Always bind tickets to specific peers when possible
- Restrict mode to minimum required (not "any")
- Verify tickets before creating sessions
- Protect ticket distribution channel

## Sealed Session Records (v0.5.0)

BlindOverlap v0.5.0 introduces sealed session records for **audit purposes**.

### What Sealed Records Provide

✅ Audit trail:
- JSON export of session metadata and wire messages
- Body digest for integrity verification
- Optional Ed25519 seal by local identity
- Message hashes for compact storage

### What Sealed Records Do NOT Provide

❌ **Sealed records are audit aids only, not security guarantees.**

- A sealed record proves a session occurred as recorded
- It does NOT prove parties followed the protocol correctly
- It does NOT provide non-repudiation against malicious parties
- Records can be created for sessions that deviated from protocol

⚠️ **Audit trail ≠ Protocol compliance proof**

| Property | Provided? | Notes |
|----------|-----------|-------|
| Session occurred as recorded | ✅ Yes | If integrity/seal verify |
| Protocol was followed correctly | ❌ No | Cannot detect deviations |
| Non-repudiation | ⚠️ Partial | Seal proves who exported |
| Tamper detection | ✅ Yes | Body digest + seal |

### Recommended Practices for Sealed Records

- Always seal records with local identity
- Verify seal signature before trusting records
- Store records securely for audit purposes
- Remember: records prove recording, not compliance

## Persistent Replay Store (v0.5.0)

BlindOverlap v0.5.0 extends the replay store with **file-backed persistence**.

### What Persistence Provides

✅ Replay protection across restarts:
- Nonces and digests survive process restart
- TTL-based cleanup still applies
- JSON file storage format

### Persistence Limitations

⚠️ **Best-effort, not crash-safe:**

- Flush is best-effort (memory updated even if write fails)
- Not designed for concurrent access from multiple processes
- Simple JSON format, not optimized for large stores
- Still semi-honest security model

### Recommended Practices for Persistent Replay

- Use dedicated file per application instance
- Monitor file for corruption
- Backup periodically for critical applications
- Don't rely on persistence for security-critical decisions

## Session Freshness Limitations (v0.3.0)

BlindOverlap v0.3.0 introduces session freshness primitives for **best-effort** replay protection.

### What Freshness Provides

✅ Under the semi-honest model:
- Session binding via cryptographic nonces
- Message expiry via TTL (default 300 seconds)
- Duplicate detection via `ReplayStore`
- Transcript binding in wire-bound receipts

### What Freshness Does NOT Provide

❌ No protection against:
- Active adversaries who manipulate clocks
- Malicious parties who ignore TTL/nonce checks
- Replay attacks across application restarts (ReplayStore is in-memory)
- Persistent replay protection without external storage

### Freshness Implementation Notes

⚠️ **Best-effort, not security guarantees:**
- `SessionDeadline`: Validates timestamps but relies on honest clocks
- `SessionNonce`: Provides binding but no mutual authentication
- `ReplayStore`: In-memory only, TTL-based cleanup for memory management
- `WireBoundReceipt`: Binds to transcript but relies on honest signing

### Recommended Practices for Freshness

- Use wire-bound receipts to audit protocol executions
- Configure appropriate TTL for your use case
- Consider persisting nonces if replay across restarts is a concern
- Use TLS to protect message integrity in transit
- Don't rely on freshness alone for security-critical decisions

## Scale Limitations

BlindOverlap enforces a **4,096 element maximum** per set.

### Rationale

- Protocol is O(n·m) where n, m are set sizes
- Memory usage scales with set size
- Not designed for large-scale deployments

### At Scale Considerations

For larger sets, consider:
- Bloom filter pre-filtering
- Cuckoo hashing-based PSI
- Parallelized or distributed PSI protocols

## Cryptographic Assumptions

BlindOverlap's security relies on:

### X25519 (Curve25519)

- Computational Diffie-Hellman (CDH) assumption
- 128-bit security level

### SHA-256

- Collision resistance
- Pre-image resistance
- Second pre-image resistance

### HMAC-SHA256 (for padding)

- PRF security under the CDH assumption
- Key must be kept secret

### Ed25519

- Existential unforgeability under chosen message attack (EUF-CMA)
- Standard model security

## Known Attack Vectors

### Protocol-Level

| Attack | Possible? | Notes |
|--------|-----------|-------|
| Set enumeration by malicious party | ⚠️ Yes | Attacker can probe for specific elements |
| Fake element injection | ⚠️ Yes | No verification of element validity |
| Replay attacks | ⚠️ Possible | No built-in freshness guarantees |
| Set size inference | ✅ Always | Unless padding is used |
| Padded set size inference | ⚠️ Semi-honest | Malicious party may still learn |

### Implementation-Level

| Attack | Status | Notes |
|--------|--------|-------|
| Timing side channels | ⚠️ Not hardened | Standard Rust, not constant-time |
| Memory side channels | ⚠️ Not hardened | No memory clearing |
| Key reuse | ⚠️ Risk | Fresh keys recommended per session |

### Wire Protocol (v0.3.0)

| Attack | Status | Notes |
|--------|--------|-------|
| Message tampering | ⚠️ Possible | Use TLS for transport security |
| Session hijacking | ⚠️ Possible | Nonces provide binding, not auth |
| Message replay | ⚠️ Mitigated | TTL + ReplayStore (semi-honest only) |
| Clock manipulation | ⚠️ Possible | TTL relies on honest clocks |
| Nonce reuse | ⚠️ Detectable | Via ReplayStore (in-memory only) |

## Recommendations for Users

1. **Understand the threat model** before using in any application
2. **Generate fresh keys** for each PSI session
3. **Verify receipts** against expected set roots
4. **Don't trust cardinality alone** for sensitive decisions
5. **Limit set sizes** to reasonable amounts
6. **Audit the code** if using for anything beyond experimentation
7. **Use TLS** for network transport (v0.2.0+)
8. **Use padding** if set size is sensitive (v0.2.0+)
9. **Keep padding secrets confidential** (v0.2.0+)
10. **Use wire-bound receipts** for auditable session binding (v0.3.0)
11. **Configure appropriate TTL** for your session lifetime needs (v0.3.0)
12. **Track nonces** if replay across restarts is a concern (v0.3.0)

## Trusted Peer Book (v0.6.0)

BlindOverlap v0.6.0 introduces a trusted peer book for **managing known party identities**.

### What Peer Book Provides

✅ Trust registry:
- File-backed directory of known peer Ed25519 public keys
- Nickname/label and added_at timestamp for each peer
- Optional trust gate before channel-bound sessions

### What Peer Book Does NOT Provide

❌ **Peer book trust is out-of-band policy, not PSI security.**

- Adding a peer to the book does NOT make PSI malicious-secure
- Trust decisions must be made through external verification
- A trusted peer can still deviate from the protocol

⚠️ **Trust registry ≠ Protocol security**

| Property | Provided? | Notes |
|----------|-----------|-------|
| Track known peers | ✅ Yes | With metadata |
| Policy enforcement | ✅ Yes | Optional trust gate |
| Protocol compliance | ❌ No | Still semi-honest model |
| Out-of-band verification | ❌ No | User responsibility |

### Recommended Practices for Peer Book

- Verify peer identities out-of-band before adding
- Use require_trusted() as policy enforcement
- Remember: trust registry is convenience, not security

## Session Leases (v0.6.0)

BlindOverlap v0.6.0 introduces session leases for **extending session authority**.

### What Session Leases Provide

✅ Session continuation authentication:
- Signed time-bounded lease extending beyond invite TTL
- Renewal chain for long-running sessions
- Issuer/peer binding for channel authentication

### What Session Leases Do NOT Provide

❌ **Session leases do NOT upgrade PSI security from semi-honest to malicious.**

- A valid lease proves the issuer authorized continued participation
- It does NOT prove the peer will follow the protocol correctly
- A semi-honest peer can still deviate

⚠️ **Lease authorization ≠ Protocol security**

| Property | Provided? | Notes |
|----------|-----------|-------|
| Session continuation auth | ✅ Yes | Signed by issuer |
| Renewal chain integrity | ✅ Yes | Parent lease tracking |
| TTL enforcement | ✅ Yes | Expiry validation |
| Protocol compliance | ❌ No | Still semi-honest model |

### Recommended Practices for Session Leases

- Use short TTLs appropriate for your use case
- Verify lease chains if using renewals
- Remember: leases authenticate WHO, not WHAT they compute

## Abort Receipts (v0.6.0)

BlindOverlap v0.6.0 introduces abort receipts for **mid-protocol cancellation**.

### What Abort Receipts Provide

✅ Abort audit trail:
- Signed record of WHO aborted and WHY
- Optional transcript binding for context
- Reason codes for categorization

### What Abort Receipts Do NOT Provide

❌ **Abort receipts are audit aids, not security guarantees.**

- They do NOT force the other party to accept the abort
- They do NOT prevent continued protocol execution
- A malicious party could claim abort without actually aborting

⚠️ **Abort receipt ≠ Enforced cancellation**

| Property | Provided? | Notes |
|----------|-----------|-------|
| Audit trail | ✅ Yes | Signed by issuer |
| Reason documentation | ✅ Yes | Code + optional text |
| Transcript binding | ⚠️ Optional | If available at abort |
| Enforced cancellation | ❌ No | Cooperative only |

### Recommended Practices for Abort Receipts

- Include transcript digest when available
- Use standard reason codes for interoperability
- Store abort receipts for audit purposes
- Remember: abort is cooperative, not enforced

## Future Considerations

Potential improvements (not in scope for v0.6.0):

- Malicious security via VOLE-PSI or zkSNARKs
- Constant-time implementations
- Differential privacy for cardinality
- Streaming/batched protocols for larger sets
- Built-in TLS transport
- Formal security proofs
- Persistent replay protection storage
- Mutual authentication for sessions

## References

- [PSI from PaXoS](https://eprint.iacr.org/2020/193) - Modern PSI constructions
- [Practical Private Set Intersection](https://eprint.iacr.org/2016/799) - Survey of PSI protocols
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) - JSON Canonicalization Scheme

---

**Last Updated**: v0.6.0
