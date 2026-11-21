# Cyberguard Architecture Overview

## Isolation & Separation
- **No Shared Backends**: Neither the password manager nor the authenticator rely on the OAuth identity provider.
- **Independent Cryptographic Boundaries**: Signing keys, master vault keys, and OTP seeds are strictly contained within their respective application boundaries.
- **Local-First Design**: The Password Manager and Two-Factor Authenticator operate locally without mandatory remote infrastructure.

## Application Summaries
- **01-authentication-system-oauth**: Built with Node.js/TypeScript, featuring PKCE (S256), token family rotation, JWKS key management, and RBAC.
- **02-password-manager**: Client-side cryptography using Argon2id, HKDF key splitting, and AEAD encryption.
- **03-two-factor-authentication-system**: Pure algorithmic implementation of RFC 6238 and RFC 4226 with secure local storage and optional E2EE sync.
