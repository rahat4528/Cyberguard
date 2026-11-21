# Incident Response Guide

## Scenarios
1. **Compromised Master Password**: User must immediately change master password on trusted device (which re-wraps the vault key under a new KEK) and rotate all stored credentials.
2. **Lost Master Password**: If user possesses their client-generated Recovery Key (128-bit entropy), the recovery flow unwraps the vault key and establishes a new master password. Without master password or recovery key, encrypted data is mathematically unrecoverable.
