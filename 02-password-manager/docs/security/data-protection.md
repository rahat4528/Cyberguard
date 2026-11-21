# Data Protection & Privacy

- **Zero Plaintext at Rest**: Websites, usernames, passwords, notes, tags, and custom fields are stored solely as ciphertext.
- **Client-Side Search**: Searching and password health checks occur exclusively in client memory on decrypted structures.
- **Canary Tests**: Automated tests verify that no canary password or secret string exists anywhere in database dumps, logs, or network payloads.
