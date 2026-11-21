# Authentication Design: Local PIN & Escalating Delays

- User configures an application PIN/passphrase.
- Incorrect attempt triggers exponential backoff:
  - Attempts 1-3: Immediate retry.
  - Attempt 4: 5-second delay.
  - Attempt 5: 30-second delay.
  - Attempt 6+: 60-second delay.
- In-memory key material wiped on lock.
