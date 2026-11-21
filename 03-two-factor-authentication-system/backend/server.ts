import express from 'express';
import cors from 'cors';
import { AuthenticatorVault } from '../secure-storage/vault.js';

export function createTwoFactorApp(customPort?: number) {
  const app = express();
  const port = customPort || Number(process.env.PORT) || 4002;
  const vault = new AuthenticatorVault('./data/authenticator_vault.json');

  app.use(cors());
  app.use(express.json());

  // Security Headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    next();
  });

  // Authenticator UI
  app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Cyberguard Authenticator</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #000000; color: #ffffff; margin: 0; padding: 2rem; display: flex; flex-direction: column; align-items: center; }
    .container { width: 100%; max-width: 440px; }
    h1 { color: #38bdf8; font-size: 1.5rem; text-align: center; margin-bottom: 2rem; }
    .card { background: #121212; border: 1px solid #27272a; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; }
    .code-display { font-size: 2.25rem; font-weight: bold; letter-spacing: 4px; color: #4ade80; text-align: center; margin: 1rem 0; font-family: monospace; }
    .countdown-ring { width: 40px; height: 40px; border-radius: 50%; border: 3px solid #38bdf8; display: flex; justify-content: center; align-items: center; font-size: 0.8rem; margin: 0 auto; }
    button { width: 100%; padding: 0.75rem; border-radius: 6px; border: none; background: #0284c7; color: #fff; font-weight: 600; cursor: pointer; }
    .status-badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; background: #22c55e; color: #000; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Cyberguard Authenticator</h1>
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <strong>Cloud Console Admin</strong>
        <span class="status-badge">TOTP</span>
      </div>
      <div class="code-display">849 201</div>
      <div class="countdown-ring">24s</div>
    </div>
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <strong>GitHub Engineering</strong>
        <span class="status-badge">TOTP</span>
      </div>
      <div class="code-display">193 847</div>
      <div class="countdown-ring">18s</div>
    </div>
  </div>
</body>
</html>
    `);
  });

  return { app, vault, port };
}

if (process.argv[1] && process.argv[1].endsWith('server.ts')) {
  const { app, port } = createTwoFactorApp();
  app.listen(port, () => {
    console.log(`[Cyberguard 2FA Authenticator] Running on port ${port}`);
  });
}
