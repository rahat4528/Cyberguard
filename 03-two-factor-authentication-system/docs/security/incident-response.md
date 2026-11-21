# Incident Response Guide

## Scenarios
1. **Lost Device**: Revoke device from optional sync server; re-provision 2FA on external services using recovery codes.
2. **Corrupted Vault File**: Application automatically restores from atomic backup `vault.json.bak` and alerts user.
