# Cyberguard

Cyberguard is a defensive cybersecurity and identity management suite composed of three independent, standalone software systems. Each application operates autonomously with its own security boundaries, runtime environments, storage engines, and testing infrastructure.

## Independent Applications

1. **Authentication System (OAuth)** (`01-authentication-system-oauth`)
   - An authoritative identity provider and access management platform.
   - Built on OAuth 2.0 and OpenID Connect standards.
   - Features Authorization Code flow with PKCE (S256 enforcement), refresh token rotation, role-based access control (RBAC), session lifecycle monitoring, and cryptographic key rotation.

2. **Password Manager** (`02-password-manager`)
   - A zero-knowledge credential vault featuring client-side encryption.
   - Utilizes Argon2id key derivation, HKDF key splitting, and authenticated envelope encryption (AEAD).
   - Includes local password health evaluation, cryptographically secure password generation, and an isolated browser extension client.

3. **Two-Factor Authentication System** (`03-two-factor-authentication-system`)
   - A standalone, local-first one-time password authenticator.
   - Full implementation of RFC 6238 (TOTP) and RFC 4226 (HOTP) algorithms.
   - Secure local encrypted storage with tamper detection, encrypted backups, and optional end-to-end encrypted synchronization.

## Architecture & Isolation Principles

- **No Shared Backends**: Each application maintains an isolated backend, database schema, and configuration parameters.
- **Strict Cryptographic Boundaries**: Master keys, signing keys, and secrets are strictly separated. The password manager does not rely on the authentication service, and the authenticator operates fully offline without external dependencies.
- **Defensive Engineering**: Built following defense-in-depth principles, strict input validation, constant-time comparisons, and comprehensive audit trails.
- **Independent Assessment Disclaimer**: These applications are engineered for defensive security demonstration and self-reviewed against OWASP ASVS objectives. They have not undergone an external third-party cryptographic audit and must not be used to protect production or high-value environments without formal evaluation.

## Directory Structure

```
Cyberguard/
├── 01-authentication-system-oauth/
├── 02-password-manager/
├── 03-two-factor-authentication-system/
├── docs/
├── .gitignore
├── LICENSE
├── PROGRESS.md
└── README.md
```
