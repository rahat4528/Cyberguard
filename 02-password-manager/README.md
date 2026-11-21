# Password Manager

An independent, zero-knowledge credential vault featuring client-side authenticated encryption (AEAD), local-first storage, password health evaluation, and an isolated Manifest V3 browser extension.

## Security Disclaimer
> [!WARNING]
> This application has been internally self-reviewed against OWASP ASVS Level 2 criteria. It has not undergone an independent third-party cryptographic assessment. Do not use this system to store real-world high-value production secrets without formal external evaluation.

## Key Features
- **Zero-Knowledge Design**: The server never receives master passwords or unencrypted credentials.
- **HKDF Domain Separation**: Derives independent Key-Encryption Key (KEK) and Authentication Key from the master key.
- **AES-256-GCM AEAD with AAD Binding**: Associated Data binds user ID and item ID, preventing ciphertext swapping attacks.
- **Master Password Change Efficiency**: Re-wraps the 256-bit vault key under a new KEK without requiring re-encryption of stored items.
- **Rejection-Sampling Password Generator**: Eliminates modulo bias across arbitrary character sets.
- **Client-Side Health Analyzer**: Audits credential strength and detects reused passwords entirely in memory.
- **Manifest V3 Extension**: Autofill engine enforces exact scheme, host, and port matching.

## Installation & Setup

```bash
cd 02-password-manager
npm install
npm test
npm run dev
```

Server runs on `http://localhost:4001` (or configured `PORT`).
