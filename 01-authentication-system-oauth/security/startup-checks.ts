export interface SystemConfig {
  nodeEnv: string;
  port: number;
  issuerUrl: string;
  keyEncryptionKey: string;
  sessionSecret: string;
  databasePath: string;
  auditLogPath: string;
  tokenExpirySeconds: number;
  refreshTokenExpirySeconds: number;
  codeExpirySeconds: number;
}

export function validateStartupConfig(config: SystemConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (config.nodeEnv === 'production') {
    if (!config.issuerUrl.startsWith('https://')) {
      errors.push('CRITICAL: In production, ISSUER_URL must use HTTPS.');
    }
    if (!config.keyEncryptionKey || config.keyEncryptionKey.length < 64) {
      errors.push('CRITICAL: KEY_ENCRYPTION_KEY must be a 64-character (256-bit) hex string.');
    }
    if (!config.sessionSecret || config.sessionSecret.length < 32) {
      errors.push('CRITICAL: SESSION_SECRET must be at least 32 characters in production.');
    }
  }

  if (config.keyEncryptionKey && !/^[0-9a-fA-F]{64}$/.test(config.keyEncryptionKey)) {
    errors.push('CRITICAL: KEY_ENCRYPTION_KEY must be valid 64-char hex format.');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
