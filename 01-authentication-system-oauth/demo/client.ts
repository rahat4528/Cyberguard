import { computeS256CodeChallenge, generateRandomBase64Url } from '../security/crypto-utils.js';

export class DemoPublicClient {
  public codeVerifier: string;
  public codeChallenge: string;

  constructor(public clientId: string, public redirectUri: string) {
    this.codeVerifier = generateRandomBase64Url(32);
    this.codeChallenge = computeS256CodeChallenge(this.codeVerifier);
  }

  public buildAuthorizationUrl(issuerUrl: string, scope: string = 'openid profile'): string {
    const url = new URL(`${issuerUrl}/oauth/authorize`);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scope);
    url.searchParams.set('code_challenge', this.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', generateRandomBase64Url(16));
    return url.toString();
  }
}
