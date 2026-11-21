# Authorization & E2EE Sync Protocol

- Optional end-to-end encrypted synchronization.
- Server acts solely as a zero-knowledge ciphertext store.
- Merge conflict rules:
  - Accounts merged by unique ID.
  - Newest update timestamp wins for account metadata.
  - Highest counter value wins for HOTP accounts (`max(localCounter, remoteCounter)`).
  - Tombstones ensure deletions propagate cleanly across devices.
