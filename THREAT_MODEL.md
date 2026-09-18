# BlindOverlap Threat Model

This document describes the security model, assumptions, and known limitations of BlindOverlap v0.2.0.

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

### Session Management

- Session IDs correlate multi-round exchanges
- No built-in session expiry or replay protection
- Applications should implement their own session management

### Denial of Service

- No rate limiting built-in
- Large messages could cause memory exhaustion
- The 4096 element limit provides some protection

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

### Wire Protocol (v0.2.0)

| Attack | Status | Notes |
|--------|--------|-------|
| Message tampering | ⚠️ Possible | Use TLS for transport security |
| Session hijacking | ⚠️ Possible | No built-in authentication |
| Message replay | ⚠️ Possible | Application must handle |

## Recommendations for Users

1. **Understand the threat model** before using in any application
2. **Generate fresh keys** for each PSI session
3. **Verify receipts** against expected set roots
4. **Don't trust cardinality alone** for sensitive decisions
5. **Limit set sizes** to reasonable amounts
6. **Audit the code** if using for anything beyond experimentation
7. **Use TLS** for network transport (v0.2.0)
8. **Use padding** if set size is sensitive (v0.2.0)
9. **Keep padding secrets confidential** (v0.2.0)

## Future Considerations

Potential improvements (not in scope for v0.2.0):

- Malicious security via VOLE-PSI or zkSNARKs
- Constant-time implementations
- Differential privacy for cardinality
- Streaming/batched protocols for larger sets
- Built-in TLS transport
- Formal security proofs

## References

- [PSI from PaXoS](https://eprint.iacr.org/2020/193) - Modern PSI constructions
- [Practical Private Set Intersection](https://eprint.iacr.org/2016/799) - Survey of PSI protocols
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) - JSON Canonicalization Scheme

---

**Last Updated**: v0.2.0
