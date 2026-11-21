# Threat Model: 01-authentication-system-oauth

## Methodology
This threat model follows the STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) aligned with RFC 9700 (OAuth 2.0 Security Best Current Practice).

## Assets
1. User Credentials (passwords, salts, MFA secrets).
2. Asymmetric Signing Keys (private signing keys for RS256/ES256).
3. Authorization Codes (short-lived authorization tokens).
4. Refresh Tokens (long-lived session credentials).
5. Access Tokens (stateless bearer tokens).
6. Client Secrets (confidential client credentials).
7. Audit Log Records (tamper-evident security history).

## STRIDE Analysis & Mitigations

| Threat Category | Specific Attack Vector | Mitigation in Cyberguard |
|---|---|---|
| **Spoofing** | Authorization Code Injection / Interception | Mandatory PKCE with S256 code challenge method. Plain method is strictly rejected. Single-use codes. |
| **Spoofing** | Open Redirect / Client Impersonation | Exact string matching on registered redirect URIs; wildcards strictly forbidden. Client ID and secret checks. |
| **Tampering** | Token Alteration / Algorithm Confusion | Strict JWT header validation: algorithm allowlist enforced, "none" algorithm unconditionally rejected, signature verified via JWKS. |
| **Repudiation** | Administrative Actions & Authentication Events | Append-only audit log with SHA-256 cryptographic hash-chaining preventing retroactive modification. |
| **Information Disclosure** | Secret Leaks in Logs or DB | Plaintext passwords, private keys, and raw tokens never stored. Signing keys stored under envelope encryption (KEK). Redacted logging. |
| **Denial of Service** | Password Guessing / Endpoint Flooding | Progressive brute-force throttling per IP and account; strict rate limiting on `/token`, `/authorize`, and `/login`. |
| **Elevation of Privilege** | Scope Escalation / Token Substitution | Strict scope consent binding; audience (`aud`) and issuer (`iss`) claim enforcement; RBAC permission matrix. |
