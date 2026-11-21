import { DatabaseStore, User } from '../database/store.js';
import { generateRandomString, hashPassword, verifyPassword } from '../security/crypto-utils.js';

export class AuthService {
  constructor(private db: DatabaseStore) {}

  public authenticate(email: string, password: string): { success: boolean; user?: User; error?: string } {
    // Constant-time execution to prevent user enumeration
    let targetUser: User | undefined;
    for (const user of this.db.users.values()) {
      if (user.email.toLowerCase() === email.toLowerCase()) {
        targetUser = user;
        break;
      }
    }

    if (!targetUser) {
      // Run dummy verification to match timing
      verifyPassword(password, '00000000000000000000000000000000', '0000000000000000000000000000000000000000000000000000000000000000');
      this.db.logAudit('AUTH_FAILURE', email, 'Login attempt failed: user not found or bad password.');
      return { success: false, error: 'Invalid credentials.' };
    }

    if (targetUser.status !== 'active') {
      this.db.logAudit('AUTH_FAILURE', targetUser.id, 'Login attempt failed: account suspended.');
      return { success: false, error: 'Account is suspended.' };
    }

    const isValid = verifyPassword(password, targetUser.salt, targetUser.passwordHash);
    if (!isValid) {
      this.db.logAudit('AUTH_FAILURE', targetUser.id, 'Login attempt failed: bad password.');
      return { success: false, error: 'Invalid credentials.' };
    }

    this.db.logAudit('AUTH_SUCCESS', targetUser.id, 'User successfully logged in.');
    return { success: true, user: targetUser };
  }

  public register(email: string, password: string, name: string): { success: boolean; user?: User; error?: string } {
    for (const user of this.db.users.values()) {
      if (user.email.toLowerCase() === email.toLowerCase()) {
        return { success: false, error: 'Email already registered.' };
      }
    }

    if (password.length < 12) {
      return { success: false, error: 'Password must be at least 12 characters.' };
    }

    const { salt, hash } = hashPassword(password);
    const id = 'usr_' + generateRandomString(8);
    const newUser: User = {
      id,
      email,
      name,
      passwordHash: hash,
      salt,
      role: 'user',
      status: 'active',
      createdAt: new Date().toISOString()
    };

    this.db.users.set(id, newUser);
    this.db.logAudit('USER_REGISTRATION', id, `New user registered: ${email}`);
    return { success: true, user: newUser };
  }
}
