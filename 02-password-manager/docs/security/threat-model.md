# Threat Model: 02-password-manager

## Methodology: STRIDE Analysis

| Threat Category | Specific Attack Vector | Mitigation in Cyberguard |
|---|---|---|
| **Spoofing** | Server impersonation / Credential Phishing | Pre-login returns salt and KDF parameters. Client proves knowledge of authentication key (derived via HKDF) without exposing master password or KEK. |
| **Tampering** | Ciphertext or Metadata Alteration | Authenticated Encryption with Associated Data (AEAD: AES-256-GCM / XChaCha20-Poly1305). Associated Data (AAD) binds user ID, item ID, schema version, and key version. Any tampering causes immediate decryption failure. |
| **Repudiation** | Unauthorized Vault Modifications | Monotonic vault versioning, per-item revision tracking, and tamper-evident audit logging of device synchronization events. |
| **Information Disclosure** | Database Breach / Server Compromise | Zero-knowledge: the server stores only ciphertext blobs and slow hashes (scrypt/Argon2id) of the client-derived authentication key. Stolen server database reveals zero plaintext credentials. |
| **Information Disclosure** | Memory Scraping / Lingering Secrets | Explicit vault locking wipes key buffers from memory as far as managed runtime allows; automatic idle lock timeouts. |
| **Denial of Service** | Pre-login Parameter Flooding | Rate limiting and stable dummy parameters returned for unknown email addresses to prevent enumeration and denial of service. |
| **Elevation of Privilege** | Malicious Autofill / Cross-Origin Injection | Browser extension strictly enforces exact scheme, host, and port matching. Autofill requires deliberate user action. Suggestion UI rendered in isolated extension context. |
