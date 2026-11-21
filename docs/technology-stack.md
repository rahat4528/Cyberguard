# Technology Stack

## 01-authentication-system-oauth
- Runtime: Node.js / TypeScript
- Protocol Framework: Standards-compliant OAuth 2.0 / OpenID Connect engine
- Database: PostgreSQL with Prisma ORM (cyberguard_auth_db)
- Cache & Rate Limiting: Redis / In-Memory Token Store
- Web Console: Next.js / React / Tailwind CSS

## 02-password-manager
- Core Cryptography: Web Crypto API & Libsodium (Argon2id, XChaCha20-Poly1305 / AES-256-GCM)
- Web Vault & Extension: React, Manifest V3 Browser Extension
- Storage & Sync Backend: NestJS / Node.js, PostgreSQL (cyberguard_vault_db)

## 03-two-factor-authentication-system
- Engine: Pure TypeScript implementation of RFC 4226 (HOTP) and RFC 6238 (TOTP)
- Client: React Native / Local-first Web App
- Sync Backend: Optional NestJS sync service (cyberguard_2fa_sync_db)
