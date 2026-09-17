# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ⚠️ Experimental only |

## Important Notice

BlindOverlap is an **experimental, semi-honest PSI implementation** intended for learning and prototyping. It is **NOT suitable for production use** where security is critical.

Please read [THREAT_MODEL.md](THREAT_MODEL.md) before using this library.

## Reporting a Vulnerability

If you discover a security issue:

1. **Do NOT open a public issue** for security vulnerabilities
2. Email the maintainer directly (see repository owner)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

## Expected Response

- Acknowledgment within 48 hours
- Assessment within 1 week
- Fix or documentation update as appropriate

## Scope

Given the experimental nature of this project, we accept reports for:

- Cryptographic implementation bugs
- Protocol deviations from documented behavior
- Memory safety issues
- Information leakage beyond documented model

We may **not** treat as vulnerabilities:

- Issues inherent to the semi-honest security model (documented)
- Performance-related concerns
- Theoretical attacks requiring malicious parties (documented limitation)

## Responsible Disclosure

We appreciate responsible disclosure and will:
- Credit reporters (if desired) in release notes
- Work collaboratively on fixes
- Not pursue legal action for good-faith research

## Security Best Practices for Users

1. Do not use for sensitive production data
2. Generate fresh keys per session
3. Verify receipt signatures
4. Limit trust in cardinality-only results
5. Keep dependencies updated
6. Review code before any non-experimental use

---

Thank you for helping keep BlindOverlap (relatively) safe.
