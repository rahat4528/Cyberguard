# Authentication System (OAuth)

An independent, authoritative OpenID Connect and OAuth 2.0 identity provider and access management server built following defensive cybersecurity principles and RFC 9700 (OAuth 2.0 Security BCP).

## Security Disclaimer
> [!WARNING]
> This application has been internally self-reviewed against OWASP ASVS Level 2 criteria. It has not undergone an independent third-party cryptographic assessment. Do not use this system to protect high-value production systems without formal external evaluation.

## Key Features
- **RFC 9700 BCP Compliance**: Enforced Authorization Code flow with mandatory PKCE (S256). Plain code challenge method is rejected.
- **Exact Redirect URI Matching**: Full string matching; path traversals and wildcards are strictly prohibited.
- **Token Family Rotation**: Refresh tokens rotate on every exchange. Reuse of expired or previously exchanged tokens triggers immediate revocation of the entire token family.
- **Envelope-Encrypted Key Management**: RSA 2048 private keys are encrypted at rest with AES-256-GCM using a Key-Encryption Key (KEK).
- **Tamper-Evident Audit Chain**: Append-only log where each entry cryptographically hashes the previous entry.
- **Brute-Force & Enumeration Protection**: Sliding-window rate limiting and constant-time authentication routines.

## Installation & Setup

```bash
cd 01-authentication-system-oauth
npm install
npm test
npm run dev
```

Server starts on `http://localhost:4000` (or configured `PORT`).

## Demo Accounts
- **Admin**: `admin@cyberguard.local` / `AdminPass!2026#Secure`
- **User**: `alice@cyberguard.local` / `AlicePass!2026#Secure`
