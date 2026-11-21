import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { DatabaseStore } from './database/store.js';
import { seedDatabase } from './database/seed.js';
import { KeyManagementService } from './security/key-management.js';
import { OAuthServer } from './authorization-server/oauth-server.js';
import { AuthService } from './backend/auth-service.js';
import { SessionService } from './backend/session-service.js';
import { RateLimiter } from './backend/rate-limiter.js';
import { validateStartupConfig } from './security/startup-checks.js';

export function createApp(customConfig?: Partial<any>) {
  const config = {
    nodeEnv: process.env.NODE_ENV || 'development',
    port: Number(process.env.PORT) || 4000,
    issuerUrl: process.env.ISSUER_URL || 'http://localhost:4000',
    keyEncryptionKey: process.env.KEY_ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    sessionSecret: process.env.SESSION_SECRET || 'dev-session-secret-32-chars-long-minimum',
    databasePath: process.env.DATABASE_PATH || './database/cyberguard_auth_db.json',
    auditLogPath: process.env.AUDIT_LOG_PATH || './database/audit_chain.json',
    tokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 604800,
    codeExpirySeconds: 60,
    ...customConfig
  };

  const startupValidation = validateStartupConfig(config);
  if (!startupValidation.valid) {
    throw new Error('Startup Configuration Refusal: ' + startupValidation.errors.join('; '));
  }

  const db = new DatabaseStore();
  seedDatabase(db);

  const keyManager = new KeyManagementService(config.keyEncryptionKey);
  const oauthServer = new OAuthServer(db, keyManager, {
    issuer: config.issuerUrl,
    tokenExpirySeconds: config.tokenExpirySeconds,
    refreshTokenExpirySeconds: config.refreshTokenExpirySeconds,
    codeExpirySeconds: config.codeExpirySeconds
  });

  const authService = new AuthService(db);
  const sessionService = new SessionService(db);
  const authRateLimiter = new RateLimiter(5, 60000); // 5 attempts per min

  const app = express();
  app.use(cors());
  app.use(cookieParser(config.sessionSecret));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Security Headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    next();
  });

  // Discovery & JWKS
  app.get('/.well-known/openid-configuration', (req, res) => {
    res.json(oauthServer.getOpenIdConfiguration());
  });

  app.get('/.well-known/jwks.json', (req, res) => {
    res.json(oauthServer.getJWKS());
  });

  // OAuth Authorization Endpoint
  app.get('/oauth/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, nonce } = req.query as any;

    // Check session
    const sessionId = req.cookies['cg_session'];
    const sessionValidation = sessionId ? sessionService.validateSession(sessionId) : { valid: false };

    if (!sessionValidation.valid) {
      // Store pending auth request and redirect to login
      const returnUrl = req.originalUrl;
      return res.redirect(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
    }

    const userId = sessionValidation.session!.userId;

    const result = oauthServer.processAuthorize({
      clientId: client_id,
      redirectUri: redirect_uri,
      responseType: response_type,
      scope,
      state,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      nonce,
      userId
    });

    if (!result.success) {
      return res.status(400).send(`<h3>Authorization Error</h3><p>${result.error}</p>`);
    }

    return res.redirect(result.redirectUrl!);
  });

  // OAuth Token Endpoint
  app.post('/oauth/token', async (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const rateCheck = authRateLimiter.checkLimit(`token_${ip}`);
    if (!rateCheck.allowed) {
      return res.status(429).json({ error: 'slow_down', error_description: 'Rate limit exceeded.' });
    }

    const { grant_type, client_id, client_secret, code, redirect_uri, code_verifier, refresh_token } = req.body;

    const result = await oauthServer.processToken({
      grantType: grant_type,
      clientId: client_id,
      clientSecret: client_secret,
      code,
      redirectUri: redirect_uri,
      codeVerifier: code_verifier,
      refreshToken: refresh_token
    });

    return res.status(result.status).json(result.body);
  });

  // OAuth Revoke & Introspect
  app.post('/oauth/revoke', (req, res) => {
    const { token } = req.body;
    oauthServer.revokeToken(token);
    return res.status(200).json({ status: 'revoked' });
  });

  app.post('/oauth/introspect', async (req, res) => {
    const { token } = req.body;
    const result = await oauthServer.introspectToken(token);
    return res.json(result);
  });

  // Userinfo Endpoint
  app.get('/userinfo', async (req, res) => {
    const authHeader = req.headers.authorization;
    const result = await oauthServer.getUserInfo(authHeader);
    return res.status(result.status).json(result.body);
  });

  // User Authentication Endpoints (Web UI & API)
  app.post('/api/login', (req, res) => {
    const ip = req.ip || '127.0.0.1';
    const rateCheck = authRateLimiter.checkLimit(`login_${ip}`);
    if (!rateCheck.allowed) {
      return res.status(429).json({ error: 'Too many login attempts. Please wait.' });
    }

    const { email, password, returnUrl } = req.body;
    const authResult = authService.authenticate(email, password);
    if (!authResult.success) {
      return res.status(401).json({ error: authResult.error });
    }

    const session = sessionService.createSession(authResult.user!.id, req.headers['user-agent'] || 'unknown', ip);
    res.cookie('cg_session', session.sessionId, {
      httpOnly: true,
      secure: config.nodeEnv === 'production',
      sameSite: 'lax',
      maxAge: 86400 * 1000
    });

    return res.json({ success: true, redirect: returnUrl || '/account' });
  });

  app.post('/api/logout', (req, res) => {
    const sessionId = req.cookies['cg_session'];
    if (sessionId) {
      sessionService.revokeSession(sessionId);
    }
    res.clearCookie('cg_session');
    return res.json({ success: true, redirect: '/login' });
  });

  // HTML Web Identity Console
  app.get('/login', (req, res) => {
    const returnUrl = req.query.returnUrl || '/account';
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Cyberguard Identity Console - Login</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2.5rem; border-radius: 12px; border: 1px solid #334155; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h2 { margin-top: 0; color: #38bdf8; font-size: 1.5rem; text-align: center; }
    p.sub { font-size: 0.875rem; color: #94a3b8; text-align: center; margin-bottom: 2rem; }
    .form-group { margin-bottom: 1.25rem; }
    label { display: block; margin-bottom: 0.5rem; font-size: 0.875rem; font-weight: 500; }
    input { width: 100%; padding: 0.75rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; box-sizing: border-box; }
    button { width: 100%; padding: 0.75rem; border-radius: 6px; border: none; background: #0284c7; color: #fff; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-top: 1rem; }
    button:hover { background: #0369a1; }
    .demo-creds { margin-top: 1.5rem; padding: 1rem; background: #0f172a; border-radius: 6px; font-size: 0.8rem; border-left: 3px solid #38bdf8; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Cyberguard Identity</h2>
    <p class="sub">Defensive OpenID Connect & OAuth 2.0</p>
    <form action="/api/login" method="POST">
      <input type="hidden" name="returnUrl" value="${returnUrl}" />
      <div class="form-group">
        <label>Email Address</label>
        <input type="email" name="email" value="admin@cyberguard.local" required />
      </div>
      <div class="form-group">
        <label>Master Password</label>
        <input type="password" name="password" value="AdminPass!2026#Secure" required />
      </div>
      <button type="submit">Authenticate & Proceed</button>
    </form>
    <div class="demo-creds">
      <strong>Demo Accounts:</strong><br/>
      Admin: <code>admin@cyberguard.local</code> / <code>AdminPass!2026#Secure</code><br/>
      User: <code>alice@cyberguard.local</code> / <code>AlicePass!2026#Secure</code>
    </div>
  </div>
</body>
</html>
    `);
  });

  // Admin Dashboard
  app.get('/admin', (req, res) => {
    const keys = keyManager.getAllKeysMetadata();
    const auditStatus = db.verifyAuditChain();
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Cyberguard Admin Identity Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; margin: 0; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }
    h1 { color: #38bdf8; margin: 0; font-size: 1.75rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
    .panel { background: #1e293b; padding: 1.5rem; border-radius: 8px; border: 1px solid #334155; }
    h3 { margin-top: 0; color: #94a3b8; font-size: 1.1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    ul { list-style: none; padding: 0; margin: 0; font-size: 0.9rem; }
    li { padding: 0.5rem 0; border-bottom: 1px solid #334155; }
    .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .badge-active { background: #065f46; color: #34d399; }
    .badge-retired { background: #78350f; color: #f59e0b; }
    .badge-audit { background: #1e3a8a; color: #60a5fa; }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>Cyberguard Identity Administration</h1>
      <span style="color:#94a3b8; font-size:0.9rem;">Authoritative Identity & OAuth 2.0 Server</span>
    </div>
    <form action="/api/logout" method="POST">
      <button style="padding:0.5rem 1rem; background:#dc2626; border:none; color:#fff; border-radius:4px; cursor:pointer;">Log Out</button>
    </form>
  </div>
  <div class="grid">
    <div class="panel">
      <h3>Registered OAuth Clients</h3>
      <ul>
        ${Array.from(db.clients.values()).map(c => `
          <li>
            <strong>${c.clientName}</strong> (${c.clientId})<br/>
            Type: <span class="badge ${c.clientType === 'public' ? 'badge-audit' : 'badge-active'}">${c.clientType}</span> | Status: ${c.status}
          </li>
        `).join('')}
      </ul>
    </div>
    <div class="panel">
      <h3>Asymmetric Signing Keys</h3>
      <ul>
        ${keys.map(k => `
          <li>
            <strong>KID: ${k.kid}</strong> (${k.alg})<br/>
            Status: <span class="badge ${k.status === 'active' ? 'badge-active' : 'badge-retired'}">${k.status}</span><br/>
            Created: ${new Date(k.createdAt).toLocaleTimeString()}
          </li>
        `).join('')}
      </ul>
    </div>
    <div class="panel">
      <h3>Audit Log Cryptographic Chain</h3>
      <p>Tamper-evident verification: <strong style="color: #34d399;">${auditStatus.valid ? 'VALID (Integrity Verified)' : 'COMPROMISED'}</strong></p>
      <p>Total events logged: ${db.auditLogs.length}</p>
      <small style="color:#94a3b8;">Head Hash: ${db.auditLogs.length > 0 ? db.auditLogs[db.auditLogs.length - 1].entryHash.substring(0, 24) + '...' : 'Genesis'}</small>
    </div>
  </div>
</body>
</html>
    `);
  });

  return { app, db, keyManager, oauthServer, authService, sessionService, config };
}

if (process.argv[1] && process.argv[1].endsWith('app.ts')) {
  const { app, config } = createApp();
  app.listen(config.port, () => {
    console.log(`[Cyberguard Auth Server] Running on ${config.issuerUrl} (Port ${config.port})`);
  });
}
