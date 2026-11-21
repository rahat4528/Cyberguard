# Cryptography Design: 03-two-factor-authentication-system

## Standards Conformance
- **RFC 4226 (HOTP)**:
  - HMAC computation: `HMAC-SHA-1(K, C)`
  - Counter `C`: 64-bit unsigned big-endian integer (using JavaScript `BigInt`).
  - Dynamic Truncation: extracts 31-bit integer, computes modulo `10^digits`.
  - Counter persistence: Updated on disk before display.
- **RFC 6238 (TOTP)**:
  - Time step derivation: `T = floor((CurrentTime - T0) / X)` where default `X = 30` seconds and `T0 = 0`.
  - Supports SHA-1, SHA-256, and SHA-512 algorithms.
  - Safe beyond Unix 2038 epoch via 64-bit integer timestamp math.
- **RFC 4648 Base32 Secret Encoding**:
  - Handles uppercase/lowercase, spaces, hyphens, and padding cleanly.
  - Warns on secrets shorter than recommended lengths (128 bits for SHA-1, 256 bits for SHA-256/512).

## Vault Encryption & Key Derivation
- **Vault AEAD**: AES-256-GCM with 96-bit random IV.
- **Key Derivation**: scrypt / Argon2id derived from user PIN/passphrase with unique random salt.
- **Atomic Persistence**:
  1. Write serialized ciphertext to temporary file `vault.json.tmp`.
  2. Flush and sync file descriptors to physical disk.
  3. Atomic rename to `vault.json`.
  4. Retain backup `vault.json.bak` for corruption recovery.
