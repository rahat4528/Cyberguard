import test from 'node:test';
import assert from 'node:assert';
import { DatabaseStore } from '../database/store.js';
import { seedDatabase } from '../database/seed.js';
import { KeyManagementService } from '../security/key-management.js';
import { OAuthServer } from '../authorization-server/oauth-server.js';
import { DemoPublicClient } from '../demo/client.js';
import { DemoResourceServer } from '../demo/resource-server.js';

const KEK = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const ISSUER = 'http://localhost:4000';

test('Integration: Public Client + OAuth Server + Resource Server JWKS validation', async () => {
  const db = new DatabaseStore();
  seedDatabase(db);
  const keyManager = new KeyManagementService(KEK);
  const oauthServer = new OAuthServer(db, keyManager, { issuer: ISSUER });

  // 1. Client initiates PKCE authorization
  const client = new DemoPublicClient('public-spa-app', 'http://localhost:3000/auth/callback');
  const authUrl = client.buildAuthorizationUrl(ISSUER, 'openid profile roles');

  const parsedUrl = new URL(authUrl);
  const authRes = oauthServer.processAuthorize({
    clientId: parsedUrl.searchParams.get('client_id')!,
    redirectUri: parsedUrl.searchParams.get('redirect_uri')!,
    responseType: parsedUrl.searchParams.get('response_type')!,
    scope: parsedUrl.searchParams.get('scope')!,
    codeChallenge: parsedUrl.searchParams.get('code_challenge')!,
    codeChallengeMethod: parsedUrl.searchParams.get('code_challenge_method')!,
    userId: 'usr_alice_02'
  });

  assert.strictEqual(authRes.success, true);
  const code = new URL(authRes.redirectUrl!).searchParams.get('code')!;

  // 2. Client exchanges code with verifier
  const tokenRes = await oauthServer.processToken({
    grantType: 'authorization_code',
    clientId: client.clientId,
    code,
    redirectUri: client.redirectUri,
    codeVerifier: client.codeVerifier
  });

  assert.strictEqual(tokenRes.status, 200);
  const accessToken = tokenRes.body.access_token;

  // 3. Resource server validates token using public JWKS
  const jwks = oauthServer.getJWKS();
  const resourceServer = new DemoResourceServer(ISSUER, jwks);

  // Authorize with valid scope
  const authorized = await resourceServer.validateTokenAndAuthorize(accessToken, 'profile');
  assert.strictEqual(authorized.authorized, true);
  assert.strictEqual(authorized.claims.sub, 'usr_alice_02');

  // Attempt unauthorized scope
  const unauthorized = await resourceServer.validateTokenAndAuthorize(accessToken, 'admin:superpower');
  assert.strictEqual(unauthorized.authorized, false);
  assert.strictEqual(unauthorized.error, 'insufficient_scope');
});
