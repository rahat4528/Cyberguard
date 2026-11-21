# Internal Security Self-Review: 02-password-manager

> [!IMPORTANT]
> This review is an internal engineering self-review against the OWASP Application Security Verification Standard (ASVS Level 2 target), OWASP Password Storage, and Cryptographic Storage cheat sheets. It is not an independent third-party audit or formal security certification.

## Checklist & Verified Controls

| Domain | Control Description | Status | Evidence / Verification Method |
|---|---|---|---|
| **Zero-Knowledge Architecture** | Plaintext never leaves client | PASS | Client derives KEK and AuthKey via HKDF; server only stores ciphertext and hashed AuthKey. Verified in canary test. |
| **V2: Authentication** | Domain-separated Authentication Key | PASS | HKDF-SHA256 with distinct labels derives KEK and AuthKey; verified in `kdf-crypto.test.ts`. |
| **V2: Authentication** | User enumeration resistance | PASS | Pre-login returns deterministic decoy salt for unregistered accounts. |
| **V5: Cryptography** | Authenticated Encryption (AEAD) | PASS | AES-256-GCM with 96-bit random IV; tag verified; wrong key aborts cleanly. |
| **V5: Cryptography** | Associated Data (AAD) Binding | PASS | AAD binds `${userId}:${itemId}:${schemaVersion}`; prevents ciphertext swapping across accounts or items. |
| **V5: Cryptography** | Rejection sampling CSPRNG | PASS | Eliminates modulo bias in random password generation; verified in `generator.test.ts`. |
| **V5: Cryptography** | Master password change without re-encryption | PASS | Vault key re-wrapped under new KEK; items remain untouched; verified in `kdf-crypto.test.ts`. |
| **V10: Malicious Code** | Plaintext secret avoidance | PASS | Plaintext canary test verifies 0 instances of test master password or item notes in raw database dumps. |
| **V14: Browser Extension Security** | Exact approved-origin matching | PASS | Strict scheme, host, and port matching; prevents lookalike domains and iframe attacks; verified in `autofill-origin.test.ts`. |
| **Concurrency & Synchronization** | Optimistic concurrency conflict detection | PASS | 409 conflict returned when writing against stale base revision; non-destructive resolution. |

## Residual Risks & Recommendations
1. Web-delivered cryptography: Malicious server code could compromise client-side execution; users requiring maximum security should use packaged native apps or pinned browser extensions.
2. Endpoint compromise: A compromised workstation with keyloggers or memory dumpers invalidates client-side security guarantees.
