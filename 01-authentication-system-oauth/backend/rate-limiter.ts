export class RateLimiter {
  private attempts: Map<string, { count: number; firstAttempt: number }> = new Map();

  constructor(private maxAttempts: number = 5, private windowMs: number = 60000) {}

  public checkLimit(key: string): { allowed: boolean; remaining: number; retryAfterMs: number } {
    const now = Date.now();
    const entry = this.attempts.get(key);

    if (!entry) {
      this.attempts.set(key, { count: 1, firstAttempt: now });
      return { allowed: true, remaining: this.maxAttempts - 1, retryAfterMs: 0 };
    }

    if (now - entry.firstAttempt > this.windowMs) {
      this.attempts.set(key, { count: 1, firstAttempt: now });
      return { allowed: true, remaining: this.maxAttempts - 1, retryAfterMs: 0 };
    }

    if (entry.count >= this.maxAttempts) {
      const retryAfterMs = this.windowMs - (now - entry.firstAttempt);
      return { allowed: false, remaining: 0, retryAfterMs };
    }

    entry.count += 1;
    return { allowed: true, remaining: this.maxAttempts - entry.count, retryAfterMs: 0 };
  }

  public reset(key: string): void {
    this.attempts.delete(key);
  }
}
