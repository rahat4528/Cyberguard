import crypto from 'node:crypto';
import * as jose from 'jose';
import { DatabaseStore, OAuthClient, AuthorizationCode, TokenRecord } from '../database/store.js';
import { KeyManagementService } from '../security/key-management.js';
import { generateRandomBase64Url, generateRandomString, verifyPKCE, timingSafeStringCompare, verifyPassword } from '../security/crypto-utils.js';

export interface OAuthServerOptions {
  issuer: string;
  tokenExpirySeconds?: number;
  refreshTokenExpirySeconds?: number;
  codeExpirySeconds?: number;
}

export class OAuthServer {
  private issuer: string;
  private tokenExpiry: number;
  private refreshTokenExpiry: number;
  private codeExpiry: number;

  constructor(
    private db: DatabaseStore,
    private keyManager: KeyManagementService,
    options: OAuthServerOptions
  ) {
    this.issuer = options.issuer;
    this.tokenExpiry = options.tokenExpirySeconds || 900; // 15 mins
    this.refreshTokenExpiry = options.refreshTokenExpirySeconds || 604800; // 7 days
    this.codeExpiry = options.codeExpirySeconds || 60; // 60 seconds (BCP)
  }

  // --- Discovery Metadata ---
  public getOpenIdConfiguration() {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      userinfo_endpoint: `${this.issuer}/userinfo`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      revocation_endpoint: `${this.issuer}/oauth/revoke`,
      introspection_endpoint: `${this.issuer}/oauth/introspect`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email', 'roles', 'admin:all'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'] // Only S256 allowed per RFC 9700
    };
  }

  // --- JWKS ---
  public getJWKS() {
    return this.keyManager.getJWKS();
  }

  // --- Process Authorization Request ---
  public processAuthorize(params: {
    clientId: string;
    redirectUri: string;
    responseType: string;
    scope?: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    nonce?: string;
    userId: string;
  }): { success: boolean; redirectUrl?: string; error?: string; errorCode?: string } {
    const client = this.db.clients.get(params.clientId);
    if (!client || client.status !== 'active') {
      return { success: false, error: 'Unauthorized client', errorCode: 'unauthorized_client' };
    }

    // Exact redirect URI matching (RFC 9700 strict enforcement)
    const exactMatch = client.redirectUris.includes(params.redirectUri);
    if (!exactMatch) {
      return { success: false, error: 'Invalid redirect URI: mismatch with registered client URIs', errorCode: 'invalid_request' };
    }

    if (params.responseType !== 'code') {
      return { success: false, error: 'Unsupported response type (only code allowed)', errorCode: 'unsupported_response_type' };
    }

    // PKCE S256 Enforcement (Mandatory for public clients, strict S256 for all)
    if (client.clientType === 'public') {
      if (!params.codeChallenge || !params.codeChallengeMethod) {
        return { success: false, error: 'PKCE code challenge required for public clients', errorCode: 'invalid_request' };
      }
    }

    if (params.codeChallengeMethod && params.codeChallengeMethod !== 'S256') {
      return { success: false, error: 'Only S256 code challenge method is permitted', errorCode: 'invalid_request' };
    }

    // Generate single-use authorization code
    const code = 'authcode_' + generateRandomBase64Url(32);
    const codeRecord: AuthorizationCode = {
      code,
      clientId: params.clientId,
      redirectUri: params.redirectUri,
      userId: params.userId,
      scope: params.scope || 'openid',
      codeChallenge: params.codeChallenge || '',
      codeChallengeMethod: params.codeChallengeMethod || 'S256',
      nonce: params.nonce,
      expiresAt: Date.now() + (this.codeExpiry * 1000),
      used: false,
      issuedTokens: []
    };

    this.db.authCodes.set(code, codeRecord);
    this.db.logAudit('AUTH_CODE_ISSUED', params.userId, `Issued auth code for client ${params.clientId}`);

    const redirectUrl = new URL(params.redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (params.state) {
      redirectUrl.searchParams.set('state', params.state);
    }

    return { success: true, redirectUrl: redirectUrl.toString() };
  }

  // --- Exchange Token ---
  public async processToken(params: {
    grantType: string;
    clientId: string;
    clientSecret?: string;
    code?: string;
    redirectUri?: string;
    codeVerifier?: string;
    refreshToken?: string;
  }): Promise<{ status: number; body: any }> {
    const client = this.db.clients.get(params.clientId);
    if (!client || client.status !== 'active') {
      return { status: 401, body: { error: 'invalid_client', error_description: 'Client authentication failed.' } };
    }

    // Validate confidential client credentials
    if (client.clientType === 'confidential') {
      if (!params.clientSecret || !client.clientSecretHash || !client.clientSecretSalt) {
        return { status: 401, body: { error: 'invalid_client', error_description: 'Client secret required.' } };
      }
      const valid = verifyPassword(params.clientSecret, client.clientSecretSalt, client.clientSecretHash);
      if (!valid) {
        return { status: 401, body: { error: 'invalid_client', error_description: 'Bad client secret.' } };
      }
    }

    if (params.grantType === 'authorization_code') {
      if (!params.code) {
        return { status: 400, body: { error: 'invalid_request', error_description: 'Missing code parameter.' } };
      }

      const codeRecord = this.db.authCodes.get(params.code);
      if (!codeRecord) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Invalid authorization code.' } };
      }

      // Check client and redirectUri match
      if (codeRecord.clientId !== params.clientId || (params.redirectUri && codeRecord.redirectUri !== params.redirectUri)) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Code was not issued to this client/redirect URI.' } };
      }

      // CODE REUSE ATTACK DETECTION
      if (codeRecord.used) {
        // Revoke all tokens issued from this code family
        for (const family of codeRecord.issuedTokens) {
          this.db.revokeTokenFamily(family);
        }
        this.db.logAudit('SECURITY_ALERT', params.clientId, `Authorization code reuse detected! Revoked associated token families.`);
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Authorization code already used. Associated tokens revoked.' } };
      }

      // Check expiration
      if (Date.now() > codeRecord.expiresAt) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Authorization code has expired.' } };
      }

      // Validate PKCE verifier
      if (codeRecord.codeChallenge) {
        if (!params.codeVerifier) {
          return { status: 400, body: { error: 'invalid_request', error_description: 'Missing code_verifier.' } };
        }
        const pkceValid = verifyPKCE(params.codeVerifier, codeRecord.codeChallenge, codeRecord.codeChallengeMethod);
        if (!pkceValid) {
          return { status: 400, body: { error: 'invalid_grant', error_description: 'PKCE verification failed.' } };
        }
      }

      // Mark code as used immediately
      codeRecord.used = true;

      const user = this.db.users.get(codeRecord.userId);
      if (!user) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'User not found.' } };
      }

      // Mint Tokens
      const tokenFamily = 'fam_' + generateRandomString(16);
      codeRecord.issuedTokens.push(tokenFamily);

      const tokens = await this.mintTokens(client, user, codeRecord.scope, tokenFamily, codeRecord.nonce);
      return { status: 200, body: tokens };
    }

    if (params.grantType === 'refresh_token') {
      if (!params.refreshToken) {
        return { status: 400, body: { error: 'invalid_request', error_description: 'Missing refresh_token.' } };
      }

      let targetToken: TokenRecord | undefined;
      for (const token of this.db.tokens.values()) {
        if (token.type === 'refresh' && token.tokenHash === params.refreshToken) {
          targetToken = token;
          break;
        }
      }

      if (!targetToken) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Invalid refresh token.' } };
      }

      // REUSE DETECTION: If token is already revoked, revoke whole family
      if (targetToken.isRevoked) {
        this.db.revokeTokenFamily(targetToken.tokenFamily);
        this.db.logAudit('SECURITY_ALERT', params.clientId, `Revoked refresh token reuse detected for family ${targetToken.tokenFamily}.`);
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Refresh token revoked. Entire family invalidated.' } };
      }

      if (Date.now() > targetToken.expiresAt) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'Refresh token expired.' } };
      }

      // Rotate: revoke current refresh token
      targetToken.isRevoked = true;

      const user = this.db.users.get(targetToken.userId);
      if (!user) {
        return { status: 400, body: { error: 'invalid_grant', error_description: 'User not found.' } };
      }

      // Mint new tokens in the same family
      const tokens = await this.mintTokens(client, user, targetToken.scope, targetToken.tokenFamily);
      return { status: 200, body: tokens };
    }

    return { status: 400, body: { error: 'unsupported_grant_type', error_description: 'Unsupported grant_type.' } };
  }

  // --- Token Minting ---
  private async mintTokens(client: OAuthClient, user: any, scope: string, tokenFamily: string, nonce?: string) {
    const activeKey = this.keyManager.getActiveKey();
    const privateKey = await jose.importPKCS8(this.keyManager.getDecryptedPrivateKey(activeKey.kid), activeKey.alg);

    const jti = 'jti_' + generateRandomString(16);
    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.tokenExpiry;

    const accessPayload: any = {
      iss: this.issuer,
      sub: user.id,
      aud: client.clientId,
      jti,
      scope,
      roles: [user.role]
    };

    const accessToken = await new jose.SignJWT(accessPayload)
      .setProtectedHeader({ alg: activeKey.alg, kid: activeKey.kid, typ: 'at+jwt' })
      .setIssuedAt(now)
      .setExpirationTime(exp)
      .sign(privateKey);

    // Save Access Token Record
    this.db.tokens.set(jti, {
      jti,
      tokenHash: jti,
      clientId: client.clientId,
      userId: user.id,
      scope,
      type: 'access',
      tokenFamily,
      isRevoked: false,
      expiresAt: exp * 1000,
      createdAt: Date.now()
    });

    // Mint Refresh Token
    const refreshTokenValue = 'rft_' + generateRandomBase64Url(32);
    const refreshJti = 'rjti_' + generateRandomString(16);
    const refreshExp = Date.now() + (this.refreshTokenExpiry * 1000);

    this.db.tokens.set(refreshJti, {
      jti: refreshJti,
      tokenHash: refreshTokenValue,
      clientId: client.clientId,
      userId: user.id,
      scope,
      type: 'refresh',
      tokenFamily,
      isRevoked: false,
      expiresAt: refreshExp,
      createdAt: Date.now()
    });

    // Mint ID Token if openid scope requested
    let idToken: string | undefined;
    if (scope.includes('openid')) {
      const idPayload: any = {
        iss: this.issuer,
        sub: user.id,
        aud: client.clientId,
        email: user.email,
        name: user.name,
        role: user.role
      };
      if (nonce) {
        idPayload.nonce = nonce;
      }
      idToken = await new jose.SignJWT(idPayload)
        .setProtectedHeader({ alg: activeKey.alg, kid: activeKey.kid })
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(privateKey);
    }

    this.db.logAudit('TOKEN_ISSUED', user.id, `Issued tokens for client ${client.clientId} under family ${tokenFamily}`);

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.tokenExpiry,
      refresh_token: refreshTokenValue,
      id_token: idToken,
      scope
    };
  }

  // --- Revocation ---
  public revokeToken(tokenString: string): boolean {
    for (const [_, token] of this.db.tokens.entries()) {
      if (token.tokenHash === tokenString || token.jti === tokenString) {
        token.isRevoked = true;
        this.db.logAudit('TOKEN_REVOKED', token.userId, `Revoked token ${token.jti}`);
        return true;
      }
    }
    return true; // RFC 7009: return success even if token did not exist
  }

  // --- Introspection ---
  public async introspectToken(tokenString: string): Promise<any> {
    try {
      const JWKS = jose.createLocalJWKSet(this.keyManager.getJWKS());
      const { payload, protectedHeader } = await jose.jwtVerify(tokenString, JWKS, {
        issuer: this.issuer
      });

      const tokenRecord = this.db.tokens.get(payload.jti as string);
      if (tokenRecord && tokenRecord.isRevoked) {
        return { active: false };
      }

      return {
        active: true,
        scope: payload.scope,
        client_id: payload.aud,
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
        token_type: 'Bearer'
      };
    } catch {
      return { active: false };
    }
  }

  // --- UserInfo ---
  public async getUserInfo(authHeader?: string): Promise<{ status: number; body: any }> {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { status: 401, body: { error: 'invalid_token', error_description: 'Bearer token required' } };
    }
    const token = authHeader.substring(7);
    const introspection = await this.introspectToken(token);
    if (!introspection.active) {
      return { status: 401, body: { error: 'invalid_token', error_description: 'Token expired or revoked' } };
    }

    const user = this.db.users.get(introspection.sub);
    if (!user) {
      return { status: 404, body: { error: 'user_not_found' } };
    }

    return {
      status: 200,
      body: {
        sub: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    };
  }
}
