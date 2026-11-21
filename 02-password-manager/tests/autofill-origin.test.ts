import test from 'node:test';
import assert from 'node:assert';
import { isExactOriginMatch } from '../browser-extension/autofill.js';

test('Autofill Security: Strict exact origin matching prevents phishing & iframe attacks', () => {
  const savedUrl = 'https://login.example.com/signin';

  // 1. Exact match (same scheme, host, and port)
  assert.strictEqual(isExactOriginMatch(savedUrl, 'https://login.example.com/dashboard'), true);
  assert.strictEqual(isExactOriginMatch(savedUrl, 'https://login.example.com:443/'), true);

  // 2. Scheme mismatch (HTTP vs HTTPS)
  assert.strictEqual(isExactOriginMatch(savedUrl, 'http://login.example.com/signin'), false);

  // 3. Subdomain mismatch (Attacker phishing on different subdomain)
  assert.strictEqual(isExactOriginMatch(savedUrl, 'https://evil.example.com/signin'), false);
  assert.strictEqual(isExactOriginMatch(savedUrl, 'https://example.com/signin'), false);

  // 4. Port mismatch
  assert.strictEqual(isExactOriginMatch(savedUrl, 'https://login.example.com:8443/'), false);

  // 5. Lookalike / Punycode domain attack
  assert.strictEqual(isExactOriginMatch('https://apple.com', 'https://xn--pple-43d.com'), false);

  // 6. Malformed URL fails closed
  assert.strictEqual(isExactOriginMatch(savedUrl, 'javascript:alert(1)'), false);
  assert.strictEqual(isExactOriginMatch('invalid_url', savedUrl), false);
});
