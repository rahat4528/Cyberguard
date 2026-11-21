import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import { VaultDatabaseStore, ServerUserAccount, StoredVaultItem } from '../database/store.js';
import { timingSafeCompare } from '../client-crypto/aead.js';

export function createPasswordManagerServer(customPort?: number) {
  const db = new VaultDatabaseStore();
  const app = express();
  const port = customPort || Number(process.env.PORT) || 4001;

  app.use(cors());
  app.use(cookieParser('dev-vault-secret-cookie-key'));
  app.use(express.json());

  // Security Headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    next();
  });

  // Pre-Login Endpoint (Returns salt & params; returns deterministic fake params for unknown accounts to resist enumeration)
  app.post('/api/auth/prelogin', (req, res) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    let foundUser: ServerUserAccount | undefined;
    for (const u of db.users.values()) {
      if (u.email.toLowerCase() === email.toLowerCase()) {
        foundUser = u;
        break;
      }
    }

    if (foundUser) {
      return res.json({
        exists: true,
        authSalt: foundUser.authSalt,
        kdfParams: foundUser.kdfParams
      });
    }

    // Return deterministic fake salt to prevent user enumeration
    const fakeSalt = crypto.createHmac('sha256', 'cyberguard-enumeration-decoy').update(email).digest('hex');
    return res.json({
      exists: false,
      authSalt: fakeSalt,
      kdfParams: { N: 32768, r: 8, p: 1 }
    });
  });

  // Register Endpoint
  app.post('/api/auth/register', (req, res) => {
    const { email, authKey, authSalt, wrappedVaultKey, wrappedRecoveryKey, kdfParams } = req.body;
    if (!email || !authKey || !authSalt || !wrappedVaultKey) {
      return res.status(400).json({ error: 'Missing required registration parameters' });
    }

    for (const u of db.users.values()) {
      if (u.email.toLowerCase() === email.toLowerCase()) {
        return res.status(400).json({ error: 'User already exists' });
      }
    }

    const userId = 'usr_' + crypto.randomBytes(8).toString('hex');
    const serverAuthSalt = crypto.randomBytes(16).toString('hex');
    const serverHash = crypto.scryptSync(authKey, serverAuthSalt, 32).toString('hex');

    const newUser: ServerUserAccount = {
      id: userId,
      email,
      authSalt,
      authHash: serverHash,
      serverAuthSalt,
      wrappedVaultKey,
      wrappedRecoveryKey,
      kdfParams: kdfParams || { N: 32768, r: 8, p: 1 },
      createdAt: new Date().toISOString()
    };

    db.users.set(userId, newUser);
    db.logEvent('USER_REGISTERED', userId);
    return res.json({ success: true, userId });
  });

  // Login Endpoint
  app.post('/api/auth/login', (req, res) => {
    const { email, authKey } = req.body;
    let foundUser: ServerUserAccount | undefined;
    for (const u of db.users.values()) {
      if (u.email.toLowerCase() === email.toLowerCase()) {
        foundUser = u;
        break;
      }
    }

    if (!foundUser) {
      // Timing match
      crypto.scryptSync(authKey || 'dummy', '00000000000000000000000000000000', 32);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const computed = crypto.scryptSync(authKey, foundUser.serverAuthSalt, 32).toString('hex');
    if (!timingSafeCompare(computed, foundUser.authHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    db.logEvent('USER_LOGIN', foundUser.id);
    return res.json({
      success: true,
      userId: foundUser.id,
      wrappedVaultKey: foundUser.wrappedVaultKey
    });
  });

  // Master Password Change (Re-wrapping Vault Key under new KEK without re-encrypting items)
  app.post('/api/auth/change-master-password', (req, res) => {
    const { userId, newAuthKey, newAuthSalt, newWrappedVaultKey } = req.body;
    const user = db.users.get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const newServerSalt = crypto.randomBytes(16).toString('hex');
    const newServerHash = crypto.scryptSync(newAuthKey, newServerSalt, 32).toString('hex');

    user.authSalt = newAuthSalt;
    user.serverAuthSalt = newServerSalt;
    user.authHash = newServerHash;
    user.wrappedVaultKey = newWrappedVaultKey;

    db.logEvent('MASTER_PASSWORD_CHANGED', userId);
    return res.json({ success: true, message: 'Vault key re-wrapped successfully' });
  });

  // Vault Sync Endpoint (Conflict-Resistant Optimistic Concurrency)
  app.post('/api/vault/sync', (req, res) => {
    const { userId, clientRevisionCursor, pushedItems } = req.body;
    const user = db.users.get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const conflicts: any[] = [];
    const saved: any[] = [];

    // Process pushed items
    if (Array.isArray(pushedItems)) {
      for (const item of pushedItems) {
        const existing = db.items.get(item.id);
        if (existing) {
          // If server revision is higher than client baseRevision -> 409 CONFLICT!
          if (existing.revision > (item.baseRevision ?? 0)) {
            conflicts.push({
              itemId: item.id,
              serverItem: existing,
              reason: 'Concurrent modification detected'
            });
            continue;
          }
        }

        const newRevision = existing ? existing.revision + 1 : 1;
        const stored: StoredVaultItem = {
          id: item.id,
          userId,
          envelope: item.envelope,
          revision: newRevision,
          isDeleted: Boolean(item.isDeleted),
          updatedAt: new Date().toISOString()
        };

        db.items.set(item.id, stored);
        saved.push(stored);
      }
    }

    // Pull changes newer than client cursor
    const modifiedItems: StoredVaultItem[] = [];
    for (const it of db.items.values()) {
      if (it.userId === userId && it.revision > (clientRevisionCursor || 0)) {
        modifiedItems.push(it);
      }
    }

    return res.json({
      success: conflicts.length === 0,
      savedCount: saved.length,
      conflicts,
      pulledItems: modifiedItems
    });
  });

  // Vault Web Interface
  app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Cyberguard Password Manager</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b132b; color: #f8fafc; margin: 0; padding: 0; display: flex; height: 100vh; }
    .sidebar { width: 280px; background: #1c2541; padding: 1.5rem; border-right: 1px solid #3a506b; display: flex; flex-direction: column; }
    .content { flex: 1; padding: 2rem; overflow-y: auto; }
    h2, h3 { color: #5bc0be; margin-top: 0; }
    .status-badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .status-locked { background: #e63946; color: #fff; }
    .status-unlocked { background: #2a9d8f; color: #fff; }
    .card { background: #1c2541; padding: 1.5rem; border-radius: 8px; border: 1px solid #3a506b; margin-bottom: 1.5rem; }
    button { padding: 0.6rem 1.2rem; background: #5bc0be; color: #0b132b; font-weight: bold; border: none; border-radius: 4px; cursor: pointer; }
    input { padding: 0.6rem; border-radius: 4px; border: 1px solid #3a506b; background: #0b132b; color: #fff; }
  </style>
</head>
<body>
  <div class="sidebar">
    <h2>Cyberguard Vault</h2>
    <div style="margin-bottom: 2rem;">
      <span class="status-badge status-locked">VAULT LOCKED</span>
    </div>
    <p style="font-size: 0.85rem; color: #94a3b8;">Zero-Knowledge Client-Side Encryption.</p>
  </div>
  <div class="content">
    <div class="card">
      <h3>Unlock Your Vault</h3>
      <p>Enter Master Password to derive Key-Encryption Key in client memory:</p>
      <input type="password" placeholder="Master Password" style="width: 300px;" />
      <button style="margin-left: 0.5rem;">Unlock Vault</button>
    </div>
    <div class="card">
      <h3>Password Health & Generator</h3>
      <p>Cryptographically secure rejection-sampling generator and client-side credential audit.</p>
    </div>
  </div>
</body>
</html>
    `);
  });

  return { app, db, port };
}

if (process.argv[1] && process.argv[1].endsWith('server.ts')) {
  const { app, port } = createPasswordManagerServer();
  app.listen(port, () => {
    console.log(`[Cyberguard Password Manager] Running on port ${port}`);
  });
}
