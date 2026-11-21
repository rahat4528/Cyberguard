export interface EncryptedEnvelope {
  ciphertext: string; // hex
  iv: string;         // hex (96-bit)
  tag: string;        // hex (128-bit)
  aad: string;        // bound metadata
  version: number;
}

export interface VaultItem {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes?: string;
  category: 'login' | 'note' | 'card' | 'identity';
  folder?: string;
  favorite: boolean;
  tags: string[];
  revision: number;
  updatedAt: string;
}

export interface PasswordHealthSummary {
  total: number;
  weakCount: number;
  reusedCount: number;
  incompleteCount: number;
  healthScore: number; // 0-100
  flaggedItems: { itemId: string; title: string; issues: string[] }[];
}
