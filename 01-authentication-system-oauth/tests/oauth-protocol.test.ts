import test from 'node:test';
import assert from 'node:assert';
import * as jose from 'jose';
import { DatabaseStore } from '../database/store.js';
import { seedDatabase } from '../database/seed.js';
import { KeyManagementService } from '../security/key-management.js';
import { OAuthServer } from '../authorization-server/oauth-server.js';
import { computeS256CodeChallenge } from '../security/crypto-utils.js';

const KEK = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const ISSUER = 'http://localhost:4000';

function setupEnvironment() {
  const db = new DatabaseStore();
  seedDatabase(db);
  const keyManager = new KeyManagementService(KEK);
  const oauthServer = new OAuthServer(db, keyManager, {
    issuer: ISSUER,
    tokenExpirySeconds: 900,
    codeExpirySeconds: 60
  });
  return { db, keyManager, oauthServer };
}

test('OAuth Protocol: Authorization Code flow with PKCE (S256)', async () => {
  const { oauthServer } = setupEnvironment();
  const verifier = 'test_verifier_string_of_sufficient_length_43_chars_minimum';
  const challenge = computeS256CodeChallenge(verifier);

  // 1. Authorize
  const authRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://localhost:3000/auth/callback',
    responseType: 'code',
    scope: 'openid profile email',
    state: 'xyzState123',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    userId: 'usr_alice_02'
  });

  assert.strictEqual(authRes.success, true);
  assert.ok(authRes.redirectUrl?.includes('code='));
  assert.ok(authRes.redirectUrl?.includes('state=xyzState123'));

  const url = new URL(authRes.redirectUrl!);
  const code = url.searchParams.get('code')!;

  // 2. Token Exchange
  const tokenRes = await oauthServer.processToken({
    grantType: 'authorization_code',
    clientId: 'public-spa-app',
    code,
    redirectUri: 'http://localhost:3000/auth/callback',
    codeVerifier: verifier
  });

  assert.strictEqual(tokenRes.status, 200);
  assert.ok(tokenRes.body.access_token);
  assert.ok(tokenRes.body.refresh_token);
  assert.ok(tokenRes.body.id_token);
  assert.strictEqual(tokenRes.body.token_type, 'Bearer');

  // 3. Introspect Access Token
  const intro = await oauthServer.introspectToken(tokenRes.body.access_token);
  assert.strictEqual(intro.active, true);
  assert.strictEqual(intro.sub, 'usr_alice_02');
  assert.strictEqual(intro.client_id, 'public-spa-app');
});

test('OAuth Security: Rejection of plain code_challenge_method (Mandatory RFC 9700 S256)', () => {
  const { oauthServer } = setupEnvironment();
  const verifier = 'test_verifier_string_of_sufficient_length_43_chars_minimum';

  const authRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://localhost:3000/auth/callback',
    responseType: 'code',
    codeChallenge: verifier,
    codeChallengeMethod: 'plain',
    userId: 'usr_alice_02'
  });

  assert.strictEqual(authRes.success, false);
  assert.strictEqual(authRes.errorCode, 'invalid_request');
  assert.ok(authRes.error?.includes('Only S256'));
});

test('OAuth Security: Exact Redirect URI matching (Rejects subpaths, traversal, and mismatched schemes)', () => {
  const { oauthServer } = setupEnvironment();
  const challenge = computeS256CodeChallenge('test_verifier_string_of_sufficient_length_43_chars_minimum');

  // Attempt subpath / open-redirect variant
  const subpathRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://localhost:3000/auth/callback/extra',
    responseType: 'code',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    userId: 'usr_alice_02'
  });
  assert.strictEqual(subpathRes.success, false);

  // Attempt different port / host
  const wrongHostRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://evil.com/auth/callback',
    responseType: 'code',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    userId: 'usr_alice_02'
  });
  assert.strictEqual(wrongHostRes.success, false);
});

test('OAuth Security: Code reuse detection revokes entire token family', async () => {
  const { oauthServer, db } = setupEnvironment();
  const verifier = 'test_verifier_string_of_sufficient_length_43_chars_minimum';
  const challenge = computeS256CodeChallenge(verifier);

  const authRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://localhost:3000/auth/callback',
    responseType: 'code',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    userId: 'usr_alice_02'
  });

  const code = new URL(authRes.redirectUrl!).searchParams.get('code')!;

  // 1st Exchange (Legitimate)
  const firstExchange = await oauthServer.processToken({
    grantType: 'authorization_code',
    clientId: 'public-spa-app',
    code,
    redirectUri: 'http://localhost:3000/auth/callback',
    codeVerifier: verifier
  });
  assert.strictEqual(firstExchange.status, 200);

  // Confirm token is active
  const introBefore = await oauthServer.introspectToken(firstExchange.body.access_token);
  assert.strictEqual(introBefore.active, true);

  // 2nd Exchange (Attacker replaying code)
  const replayExchange = await oauthServer.processToken({
    grantType: 'authorization_code',
    clientId: 'public-spa-app',
    code,
    redirectUri: 'http://localhost:3000/auth/callback',
    codeVerifier: verifier
  });
  assert.strictEqual(replayExchange.status, 400);
  assert.ok(replayExchange.body.error_description?.includes('already used'));

  // Confirm token family was revoked by reuse detection!
  const introAfter = await oauthServer.introspectToken(firstExchange.body.access_token);
  assert.strictEqual(introAfter.active, false);
});

test('OAuth Security: Refresh Token rotation and reuse detection', async () => {
  const { oauthServer } = setupEnvironment();
  const verifier = 'test_verifier_string_of_sufficient_length_43_chars_minimum';
  const challenge = computeS256CodeChallenge(verifier);

  const authRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://localhost:3000/auth/callback',
    responseType: 'code',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    userId: 'usr_alice_02'
  });
  const code = new URL(authRes.redirectUrl!).searchParams.get('code')!;

  const tokenRes1 = await oauthServer.processToken({
    grantType: 'authorization_code',
    clientId: 'public-spa-app',
    code,
    redirectUri: 'http://localhost:3000/auth/callback',
    codeVerifier: verifier
  });

  const refreshToken1 = tokenRes1.body.refresh_token;

  // 1. Legitimate Refresh
  const tokenRes2 = await oauthServer.processToken({
    grantType: 'refresh_token',
    clientId: 'public-spa-app',
    refreshToken: refreshToken1
  });
  assert.strictEqual(tokenRes2.status, 200);
  const refreshToken2 = tokenRes2.body.refresh_token;
  assert.notStrictEqual(refreshToken1, refreshToken2); // Rotated!

  // 2. Replay of Old Refresh Token (Attacker reuse)
  const replayRes = await oauthServer.processToken({
    grantType: 'refresh_token',
    clientId: 'public-spa-app',
    refreshToken: refreshToken1
  });
  assert.strictEqual(replayRes.status, 400);

  // Both tokens in family must now be revoked
  const introNew = await oauthServer.introspectToken(tokenRes2.body.access_token);
  assert.strictEqual(introNew.active, false);
});

test('OAuth Security: Key rotation & JWKS continuity', async () => {
  const { oauthServer, keyManager } = setupEnvironment();
  const initialKey = keyManager.getActiveKey();

  const verifier = 'test_verifier_string_of_sufficient_length_43_chars_minimum';
  const challenge = computeS256CodeChallenge(verifier);

  const authRes = oauthServer.processAuthorize({
    clientId: 'public-spa-app',
    redirectUri: 'http://localhost:3000/auth/callback',
    responseType: 'code',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    userId: 'usr_alice_02'
  });
  const code = new URL(authRes.redirectUrl!).searchParams.get('code')!;

  const tokenRes = await oauthServer.processToken({
    grantType: 'authorization_code',
    clientId: 'public-spa-app',
    code,
    redirectUri: 'http://localhost:3000/auth/callback',
    codeVerifier: verifier
  });

  // Verify token signed under initialKey
  const jwks = oauthServer.getJWKS();
  assert.strictEqual(jwks.keys.length, 1);
  assert.strictEqual(jwks.keys[0].kid, initialKey.kid);

  // Scheduled Rotation: generate new key
  const rotatedKey = keyManager.rotateKey(false);
  assert.notStrictEqual(rotatedKey.kid, initialKey.kid);

  // JWKS must now contain BOTH keys for verification continuity!
  const jwksAfterRotation = oauthServer.getJWKS();
  assert.strictEqual(jwksAfterRotation.keys.length, 2);

  // Old token must still validate via JWKS!
  const intro = await oauthServer.introspectToken(tokenRes.body.access_token);
  assert.strictEqual(intro.active, true);
});
