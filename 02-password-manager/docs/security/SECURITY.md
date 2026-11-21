# Security Policy: 02-password-manager

## Zero-Knowledge Principle & Security Disclaimer
The Cyberguard Password Manager is built upon a zero-knowledge architecture: the master password and unencrypted vault secrets never leave client memory and are never transmitted to or stored on the server.

> [!WARNING]
> This application has been designed following OWASP Cryptographic Storage and Password Storage cheat sheets and internally self-reviewed against OWASP ASVS Level 2 requirements. It has not undergone an independent third-party cryptographic evaluation or application penetration test. It should not be used to protect high-value production secrets without formal audit.

## Honest Claims & Boundary Limits
- Client-side encryption cannot defend against a device that is already fully compromised by malware, rootkits, or memory dumpers.
- Web-delivered cryptography carries the inherent limitation that a malicious server could theoretically serve modified JavaScript; users requiring highest assurance should use audited standalone binaries or browser extensions with locked permissions.
