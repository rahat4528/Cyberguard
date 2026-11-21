# Incident Response Guide

## Incident Scenarios
1. **Signing Key Compromise**: Execute emergency key rotation via `/admin/keys/rotate?emergency=true`. Immediately invalidate all active sessions and access tokens.
2. **Brute Force Detection**: IP-based rate limiting automatically triggers temporary blocks. High-volume alerts notify administrators.
3. **Audit Log Tampering**: The hash-chain verification tool (`npm run verify-audit`) detects breaks in the cryptographic chain.
