# Data Protection & Privacy

- **Data Minimization**: Only strictly necessary profile information is stored.
- **Secrets at Rest**: Client secrets and passwords stored as slow cryptographic hashes; signing keys envelope-encrypted with AES-256-GCM.
- **Secrets in Transit**: HTTPS enforced; HSTS headers and secure cookies (`HttpOnly`, `Secure`, `SameSite=Lax`).
- **Log Hygiene**: Automated sanitization ensuring tokens, authorization codes, passwords, and secrets are never logged.
