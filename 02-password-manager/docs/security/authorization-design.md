# Authorization & Device Synchronization Design

## Device Registration & Token Security
- Devices authenticate using short-lived access tokens and revocable refresh tokens.
- Revoking a device immediately invalidates all active sessions for that device.

## Optimistic Concurrency & Conflict Handling
- Each vault write carries a `baseRevision`.
- If server revision is higher than `baseRevision`, server returns `409 Conflict`.
- The client fetches both versions, decrypts them in memory, and presents a non-destructive conflict resolver allowing the user to preserve both items.
- Item deletions create tombstones with revision tracking to propagate deletions securely.
