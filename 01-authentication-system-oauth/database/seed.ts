import { DatabaseStore } from './store.js';
import { hashPassword } from '../security/crypto-utils.js';

export function seedDatabase(db: DatabaseStore): void {
  // 1. Seed Users
  const adminPass = hashPassword('AdminPass!2026#Secure');
  db.users.set('usr_admin_01', {
    id: 'usr_admin_01',
    email: 'admin@cyberguard.local',
    passwordHash: adminPass.hash,
    salt: adminPass.salt,
    name: 'Security Administrator',
    role: 'admin',
    status: 'active',
    createdAt: new Date().toISOString()
  });

  const alicePass = hashPassword('AlicePass!2026#Secure');
  db.users.set('usr_alice_02', {
    id: 'usr_alice_02',
    email: 'alice@cyberguard.local',
    passwordHash: alicePass.hash,
    salt: alicePass.salt,
    name: 'Alice Cooper',
    role: 'user',
    status: 'active',
    createdAt: new Date().toISOString()
  });

  const bobPass = hashPassword('BobPass!2026#Secure');
  db.users.set('usr_bob_03', {
    id: 'usr_bob_03',
    email: 'bob@cyberguard.local',
    passwordHash: bobPass.hash,
    salt: bobPass.salt,
    name: 'Bob Martin',
    role: 'user',
    status: 'active',
    createdAt: new Date().toISOString()
  });

  // 2. Seed OAuth Clients
  // Public client (SPA / Mobile) requiring PKCE (S256)
  db.clients.set('public-spa-app', {
    clientId: 'public-spa-app',
    clientName: 'Cyberguard Public Single Page App',
    clientType: 'public',
    redirectUris: [
      'http://localhost:3000/auth/callback',
      'http://localhost:4000/demo/callback'
    ],
    allowedScopes: ['openid', 'profile', 'email'],
    status: 'active',
    createdAt: new Date().toISOString()
  });

  // Confidential client (Backend service / Web portal) with client secret
  const portalSecret = hashPassword('portal-secret-2026');
  db.clients.set('client-portal', {
    clientId: 'client-portal',
    clientSecretHash: portalSecret.hash,
    clientSecretSalt: portalSecret.salt,
    clientName: 'Cyberguard Customer Portal',
    clientType: 'confidential',
    redirectUris: [
      'http://localhost:3000/callback',
      'https://oauth.pstmn.io/v1/callback'
    ],
    allowedScopes: ['openid', 'profile', 'email', 'roles'],
    status: 'active',
    createdAt: new Date().toISOString()
  });

  // First-party administrative console client
  db.clients.set('cyberguard-admin-console', {
    clientId: 'cyberguard-admin-console',
    clientName: 'Cyberguard Admin Identity Console',
    clientType: 'public',
    redirectUris: [
      'http://localhost:4000/admin/callback'
    ],
    allowedScopes: ['openid', 'profile', 'email', 'admin:all'],
    status: 'active',
    createdAt: new Date().toISOString()
  });

  db.logAudit('SYSTEM_SEED', 'system', 'Database successfully initialized with initial security fixtures.');
}
