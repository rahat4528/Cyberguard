# Authorization Design (RFC 9700 & OIDC)

## Authorization Code Flow with PKCE
1. Client initiates authorization request with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, and `code_challenge_method=S256`.
2. Server validates redirect URI by exact matching.
3. User authenticates and grants consent.
4. Server generates cryptographically random single-use authorization code (60-second TTL).
5. Client exchanges code with `code_verifier`. Server computes `BASE64URL(SHA256(code_verifier))` and compares in constant time.
6. Tokens issued: Access Token (short-lived, 15 min), Refresh Token (rotating).
7. If an authorization code is reused, all tokens issued from that code are immediately revoked.
