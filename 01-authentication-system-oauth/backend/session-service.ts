import { DatabaseStore, UserSession } from '../database/store.js';
import { generateRandomString } from '../security/crypto-utils.js';

export class SessionService {
  constructor(private db: DatabaseStore) {}

  public createSession(userId: string, userAgent: string, ipAddress: string, ttlSeconds: number = 86400): UserSession {
    const sessionId = 'sess_' + generateRandomString(24);
    const expiresAt = Date.now() + (ttlSeconds * 1000);

    const session: UserSession = {
      sessionId,
      userId,
      userAgent,
      ipAddress,
      createdAt: new Date().toISOString(),
      expiresAt,
      isRevoked: false
    };

    this.db.sessions.set(sessionId, session);
    this.db.logAudit('SESSION_CREATED', userId, `Session ${sessionId} created from ${ipAddress}`);
    return session;
  }

  public validateSession(sessionId: string): { valid: boolean; session?: UserSession } {
    const session = this.db.sessions.get(sessionId);
    if (!session) {
      return { valid: false };
    }
    if (session.isRevoked) {
      return { valid: false };
    }
    if (Date.now() > session.expiresAt) {
      return { valid: false };
    }
    return { valid: true, session };
  }

  public revokeSession(sessionId: string): boolean {
    const session = this.db.sessions.get(sessionId);
    if (session) {
      session.isRevoked = true;
      this.db.logAudit('SESSION_REVOKED', session.userId, `Session ${sessionId} revoked.`);
      return true;
    }
    return false;
  }
}
