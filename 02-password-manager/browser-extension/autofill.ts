/**
 * Browser Extension Autofill Security: Exact Approved Origin Matching
 * Strictly validates scheme, host, and port to block phishing and iframe attacks.
 */
export function isExactOriginMatch(savedUrl: string, currentUrl: string): boolean {
  try {
    const saved = new URL(savedUrl);
    const current = new URL(currentUrl);

    // 1. Strict Scheme Match (must be https or http)
    if (saved.protocol !== current.protocol) {
      return false;
    }

    // 2. Strict Host Match (blocks lookalike domains, punycode attacks, subdomains)
    if (saved.hostname.toLowerCase() !== current.hostname.toLowerCase()) {
      return false;
    }

    // 3. Strict Port Match
    const savedPort = saved.port || (saved.protocol === 'https:' ? '443' : '80');
    const currentPort = current.port || (current.protocol === 'https:' ? '443' : '80');
    if (savedPort !== currentPort) {
      return false;
    }

    return true;
  } catch {
    return false; // Malformed URLs fail closed
  }
}
