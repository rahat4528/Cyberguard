# Authentication & Account Lifecycle Design

## Pre-Login Exchange (Enumeration Resistance)
1. Client sends email address to `/api/auth/prelogin`.
2. Server returns account salt and KDF parameters. If email is unregistered, server returns stable, deterministic dummy parameters to prevent username enumeration and timing leaks.
3. Client derives Master Key, then derives Authentication Key via HKDF.
4. Client sends Authentication Key to `/api/auth/login`.
5. Server hashes the received Authentication Key and compares in constant time against stored hash.
