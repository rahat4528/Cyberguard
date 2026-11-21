# Two-Factor Authentication System

An independent, local-first authenticator application providing standards-compliant TOTP (RFC 6238) and HOTP (RFC 4226) one-time password generation, secure encrypted storage, and optional end-to-end encrypted synchronization.

## Security Disclaimer
> [!WARNING]
> This application has been internally self-reviewed against OWASP ASVS Level 2 criteria and RFC test vectors. It has not undergone an independent third-party cryptographic assessment. Do not use this system to protect high-consequence infrastructure without formal external evaluation.

## Key Features
- **Strict RFC 4226 & RFC 6238 Conformance**: Passes exact test vectors for SHA-1, SHA-256, and SHA-512 beyond the Unix 2038 epoch.
- **Pure Algorithmic OTP Engine**: Zero-dependency mathematical implementation of dynamic truncation and BigInt 64-bit counter operations.
- **Durable Pre-Display HOTP Persistence**: Increments and flushes counter state to disk before rendering the code, preventing counter reuse attacks upon application crashes.
- **Replay Protection**: Verifier rejects time-step reuse within the allowable drift window.
- **AES-256-GCM Vault Storage**: Encrypted with scrypt-derived key from user PIN with escalating failure delays.
- **Atomic File Operations**: Prevents corruption via temporary write, sync, atomic rename, and backup snapshots.

## Installation & Setup

```bash
cd 03-two-factor-authentication-system
npm install
npm test
npm run dev
```

Server starts on `http://localhost:4002` (or configured `PORT`).
