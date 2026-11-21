import crypto from 'node:crypto';

export interface KeyPairRecord {
  kid: string;
  alg: string;
  status: 'active' | 'retired' | 'revoked';
  encryptedPrivateKey: string; // AES-256-GCM encrypted PEM
  iv: string;
  tag: string;
  publicKeyPem: string;
  publicKeyJwk: any;
  createdAt: string;
  retiredAt?: string;
}

export class KeyManagementService {
  private kek: Buffer;
  private keys: Map<string, KeyPairRecord> = new Map();
  private activeKid: string | null = null;

  constructor(kekHex: string) {
    if (!kekHex || kekHex.length !== 64) {
      throw new Error('KEK must be a 64-character hex string (256 bits).');
    }
    this.kek = Buffer.from(kekHex, 'hex');
  }

  /**
   * Generates a new RSA 2048 keypair, envelope-encrypts the private key with AES-256-GCM
   */
  public generateKey(alg: string = 'RS256'): KeyPairRecord {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const kid = 'key_' + crypto.randomBytes(8).toString('hex');
    
    // Envelope-encrypt private key with KEK using AES-256-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.kek, iv);
    let encrypted = cipher.update(privateKey, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');

    // Export public JWK
    const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
    jwk.kid = kid;
    jwk.alg = alg;
    jwk.use = 'sig';

    const record: KeyPairRecord = {
      kid,
      alg,
      status: 'active',
      encryptedPrivateKey: encrypted,
      iv: iv.toString('hex'),
      tag,
      publicKeyPem: publicKey,
      publicKeyJwk: jwk,
      createdAt: new Date().toISOString()
    };

    if (this.activeKid && this.keys.has(this.activeKid)) {
      const currentActive = this.keys.get(this.activeKid)!;
      currentActive.status = 'retired';
      currentActive.retiredAt = new Date().toISOString();
    }

    this.keys.set(kid, record);
    this.activeKid = kid;
    return record;
  }

  public getActiveKey(): KeyPairRecord {
    if (!this.activeKid || !this.keys.has(this.activeKid)) {
      return this.generateKey();
    }
    return this.keys.get(this.activeKid)!;
  }

  public getDecryptedPrivateKey(kid: string): string {
    const record = this.keys.get(kid);
    if (!record) {
      throw new Error(`Key ${kid} not found.`);
    }
    if (record.status === 'revoked') {
      throw new Error(`Key ${kid} has been revoked and cannot be used.`);
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.kek,
      Buffer.from(record.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(record.tag, 'hex'));
    let decrypted = decipher.update(record.encryptedPrivateKey, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
  }

  public getJWKS(): { keys: any[] } {
    const activeAndRetired = Array.from(this.keys.values())
      .filter(k => k.status === 'active' || k.status === 'retired')
      .map(k => k.publicKeyJwk);
    return { keys: activeAndRetired };
  }

  public rotateKey(emergency: boolean = false): KeyPairRecord {
    if (emergency && this.activeKid && this.keys.has(this.activeKid)) {
      const revoked = this.keys.get(this.activeKid)!;
      revoked.status = 'revoked';
      revoked.retiredAt = new Date().toISOString();
    }
    return this.generateKey();
  }

  public getAllKeysMetadata(): Omit<KeyPairRecord, 'encryptedPrivateKey' | 'iv' | 'tag'>[] {
    return Array.from(this.keys.values()).map(k => ({
      kid: k.kid,
      alg: k.alg,
      status: k.status,
      publicKeyPem: k.publicKeyPem,
      publicKeyJwk: k.publicKeyJwk,
      createdAt: k.createdAt,
      retiredAt: k.retiredAt
    }));
  }
}
