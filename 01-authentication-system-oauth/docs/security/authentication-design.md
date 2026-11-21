# Authentication Design

## User Authentication
- Primary factor: Identifier (email/username) and password verified via Argon2id.
- Password policy: Minimum 12 characters, complexity requirements, checked against common passwords.
- Protection against enumeration: Constant-time authentication responses, generic error messages on login and password reset.
- Single-use, cryptographically random, expiring tokens for email verification and password reset.

## Client Authentication
- Public clients: Required PKCE with S256 challenge.
- Confidential clients: Secret authentication hashed with Argon2id or private_key_jwt with JWKS verification.
