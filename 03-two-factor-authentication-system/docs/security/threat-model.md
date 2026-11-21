# Threat Model: 03-two-factor-authentication-system

## Methodology: STRIDE Analysis

| Threat Category | Specific Attack Vector | Mitigation in Cyberguard |
|---|---|---|
| **Spoofing** | Code Replay / Re-submission | Verification logic implements replay protection by caching and rejecting already-used time steps within the drift window. |
| **Spoofing** | Malicious / Hostile QR Payloads | Strict `otpauth://` URI validation: strict percent-decoding, length limits, type validation; rejects execution or URL redirection. |
| **Tampering** | Vault File Modification / Corruption | AES-256-GCM AEAD encryption with AAD binding; atomic-write file updates (`.tmp` write -> fsync -> atomic rename). |
| **Tampering** | HOTP Counter Reuse upon Crash | HOTP counters are incremented and durably flushed to disk BEFORE the code is rendered to the user. |
| **Repudiation** | Local Vault Access | Pin/Password authentication with escalating delays; auto-lock on inactivity; audit logging of security events. |
| **Information Disclosure** | Memory / Log Secret Leaks | OTP secret seeds are never written to logs, error messages, or crash dumps; secrets stored in Base32/byte buffers. |
| **Information Disclosure** | Shoulder Surfing / App Switcher | Codes rendered with optional tap-to-reveal; clipboard cleared after configurable timeout. |
| **Denial of Service** | Clock Desynchronization | Time-step drift tolerance (configurable window); clock skew detection and per-device offset correction. |
