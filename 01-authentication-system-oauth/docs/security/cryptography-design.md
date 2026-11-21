# Cryptography Design: 01-authentication-system-oauth

## Cryptographic Primitives & Parameters
- **Password Hashing**: Argon2id (memory: 64MB, iterations: 3, parallelism: 4, salt: 16 cryptographically secure random bytes).
- **Token Signing**: Asymmetric RSASSA-PKCS1-v1_5 with SHA-256 (RS256) or ECDSA P-256 (ES256). Key length: 2048-bit RSA minimum.
- **Key-Encryption Key (KEK)**: AES-256-GCM envelope encryption protecting private signing keys at rest.
- **Randomness**: System cryptographically secure pseudorandom number generator (`crypto.randomBytes`). Non-cryptographic RNGs are strictly banned.
- **Constant-Time Comparison**: `crypto.timingSafeEqual` used for all token, verifier, and hash comparisons.

## Key Management & Rotation
- Private signing keys are stored encrypted outside the database.
- Database contains only `SigningKeyMetadata` and public keys.
- Scheduled and emergency key rotation supported.
- Old public keys remain active in the JWKS endpoint until all issued tokens signed under them expire.
