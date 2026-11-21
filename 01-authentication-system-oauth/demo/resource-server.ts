import * as jose from 'jose';

export class DemoResourceServer {
  private jwks: any;

  constructor(private issuerUrl: string, jwks: any) {
    this.jwks = jose.createLocalJWKSet(jwks);
  }

  public async validateTokenAndAuthorize(bearerToken: string, requiredScope: string): Promise<{ authorized: boolean; claims?: any; error?: string }> {
    try {
      const { payload } = await jose.jwtVerify(bearerToken, this.jwks, {
        issuer: this.issuerUrl
      });

      const scopes = ((payload.scope as string) || '').split(' ');
      if (!scopes.includes(requiredScope)) {
        return { authorized: false, error: 'insufficient_scope' };
      }

      return { authorized: true, claims: payload };
    } catch (err: any) {
      return { authorized: false, error: err.message };
    }
  }
}
