# Security Policy: 03-two-factor-authentication-system

## Standalone Authenticator Principle & Disclaimer
The Cyberguard Two-Factor Authentication System is an independent, local-first authenticator designed to store OTP secret seeds securely and generate RFC-compliant one-time passwords entirely offline.

> [!WARNING]
> This application has been built to conform strictly with RFC 4226 (HOTP) and RFC 6238 (TOTP) and internally self-reviewed against OWASP ASVS Level 2 standards. It has not undergone an independent third-party cryptographic evaluation. Do not deploy in high-consequence environments without formal security audit.

## Honest Device-Threat Disclosure
- Co-location risk: If the authenticator application resides on the exact same physical device as the accounts it authenticates, full compromise of the device (e.g. rootkits, spyware) allows an adversary access to both factors.
- Defense objective: Protects against remote credential theft, network sniffing, and unauthorized casual device access.
