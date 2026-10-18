import { importJWK, jwtVerify, SignJWT, type JWK } from 'jose';
import type { Knex } from 'knex';
import type { AccessIdentity, AuthorizationRequest, Client, Grant, OAuthServerOptions, Services, User } from '../types';
import { active, challenge, digest, equal, expires, loopback, OAuthError, permitted, random, splitScope, validRedirect } from './security';

export class OAuthService {
  readonly options;
  readonly scopes;
  private signingKey: Promise<CryptoKey | Uint8Array>;
  readonly publicJwks: { keys: JWK[] };
  constructor(options: OAuthServerOptions) {
    const issuer = new URL(options.issuer);
    if (issuer.origin !== options.issuer || issuer.username || issuer.password ||
      (issuer.protocol !== 'https:' && !(options.allowInsecureLocalhost && issuer.protocol === 'http:' && loopback(issuer)))) {
      throw new Error('issuer must be an HTTPS origin (or explicitly allowed local HTTP origin)');
    }
    const keys = options.jwks?.keys;
    if (!keys?.length || !keys[0].d || keys.some((k) => k.kty !== 'RSA' || !k.kid || !k.n || !k.e || (k.alg && k.alg !== 'RS256')) ||
        new Set(keys.map((k) => k.kid)).size !== keys.length || keys.some((k) => Buffer.from(k.n!, 'base64url').length < 256)) {
      throw new Error('jwks requires unique kid values and RSA keys >= 2048 bits; first key must be private');
    }
    const jwtSecret = options.jwtSecret ?? process.env.JWT_SECRET;
    if (!jwtSecret) throw new Error('JWT_SECRET or jwtSecret is required to verify the-api-users login tokens');
    const loginPath = options.loginPath ?? '/login';
    if (!loginPath.startsWith('/') || loginPath.startsWith('//') || new URL(loginPath, options.issuer).origin !== options.issuer) throw new Error('loginPath must be same-origin');
    this.options = {
      ...options, jwtSecret, loginPath,
      accessTokenTtl: options.accessTokenTtl ?? 600,
      refreshTokenTtl: options.refreshTokenTtl ?? 2592000,
      sessionTtl: options.sessionTtl ?? 28800,
      interactionTtl: options.interactionTtl ?? 600,
      codeTtl: options.codeTtl ?? 60,
      idTokenTtl: options.idTokenTtl ?? 600,
    };
    for (const key of ['accessTokenTtl', 'refreshTokenTtl', 'sessionTtl', 'interactionTtl', 'codeTtl', 'idTokenTtl'] as const) {
      if (!Number.isSafeInteger(this.options[key]) || this.options[key] <= 0) throw new Error(`${key} must be positive seconds`);
    }
    this.scopes = {
      openid: { description: 'Sign you in' }, profile: { description: 'Read your profile' },
      email: { description: 'Read your email address' }, offline_access: { description: 'Keep access until you revoke it' },
      ...options.scopes,
    };
    for (const scope of Object.keys(this.scopes)) if (!/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope)) throw new Error('Invalid scope name');
    this.signingKey = importJWK({ ...keys[0], alg: 'RS256' }, 'RS256');
    this.publicJwks = { keys: keys.map(({ kty, kid, n, e }) => ({ kty, kid, n, e, use: 'sig', alg: 'RS256' })) };
  }

  async client(db: Knex, id: string): Promise<Client> {
    const client = await db('oauthClients').where({ id }).first();
    if (!client || client.disabled) throw new OAuthError('invalid_client', 401);
    return client;
  }

  async authenticateClient(db: Knex, body: Record<string, string>, authorization?: string): Promise<Client> {
    let id = body.client_id; let secret = body.client_secret;
    if (authorization) {
      if (!/^Basic /i.test(authorization) || secret !== undefined) throw new OAuthError('invalid_client', 401);
      try {
        const pair = Buffer.from(authorization.slice(6), 'base64').toString();
        const colon = pair.indexOf(':');
        if (colon < 0) throw new Error();
        const decode = (s: string) => decodeURIComponent(s.replace(/\+/g, ' '));
        const basicId = decode(pair.slice(0, colon));
        if (id && id !== basicId) throw new Error();
        id = basicId; secret = decode(pair.slice(colon + 1));
      } catch { throw new OAuthError('invalid_client', 401); }
    }
    const client = await this.client(db, id || '');
    if (client.type === 'confidential') {
      if (!secret || !client.secretHash || !equal(digest(secret), client.secretHash)) throw new OAuthError('invalid_client', 401);
    } else if (secret !== undefined || authorization) throw new OAuthError('invalid_client', 401);
    return client;
  }

  async authorization(db: Knex, p: Record<string, string>): Promise<AuthorizationRequest> {
    const client = await this.client(db, p.client_id || '');
    if (!client.redirectUris.includes(p.redirect_uri)) throw new OAuthError('invalid_request', 400, 'Unregistered redirect_uri');
    if (p.response_type !== 'code') throw new OAuthError('unsupported_response_type');
    if (p.response_mode && p.response_mode !== 'query') throw new OAuthError('invalid_request');
    if (p.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge || '')) throw new OAuthError('invalid_request', 400, 'PKCE S256 is required');
    const scopes = splitScope(p.scope || '');
    if (!scopes.length || scopes.some((s) => !Object.hasOwn(this.scopes, s) || !client.scopes.includes(s))) throw new OAuthError('invalid_scope');
    if (p.prompt && !['login', 'consent', 'none'].includes(p.prompt)) throw new OAuthError('invalid_request', 400, 'Unsupported prompt');
    if (p.max_age !== undefined && (!/^\d+$/.test(p.max_age) || !Number.isSafeInteger(Number(p.max_age)))) throw new OAuthError('invalid_request');
    for (const unsupported of ['request', 'request_uri', 'claims', 'resource', 'registration']) {
      if (p[unsupported] !== undefined) throw new OAuthError('invalid_request', 400, `${unsupported} is not supported`);
    }
    return { client_id: client.id, redirect_uri: p.redirect_uri, scope: scopes.join(' '), code_challenge: p.code_challenge,
      state: p.state, nonce: p.nonce, prompt: p.prompt, max_age: p.max_age === undefined ? undefined : Number(p.max_age) };
  }

  async localUser(db: Knex, token: string): Promise<{ user: User; authTime: Date }> {
    try {
      const { payload } = await jwtVerify(token, new TextEncoder().encode(this.options.jwtSecret), { algorithms: ['HS256'], requiredClaims: ['exp', 'iat'] });
      if (!payload.userId || !Array.isArray(payload.roles) || payload.roles.includes('guest')) throw new Error();
      const user = await db('users').where({ id: payload.userId }).first();
      // JWT iat is seconds; password change timestamps are milliseconds.
      const authTime = new Date(Number(payload.iat) * 1000 + 999);
      if (!active(user, authTime)) throw new Error();
      return { user, authTime };
    } catch { throw new OAuthError('access_denied', 401, 'A valid the-api-users login token is required'); }
  }

  checkScopes(services: Services, user: User, scope: string) {
    for (const name of splitScope(scope)) {
      const definition = this.scopes[name as keyof typeof this.scopes];
      if (!definition || ('permission' in definition && definition.permission && !permitted(services.roles, user, definition.permission as string))) {
        throw new OAuthError('invalid_scope', 403);
      }
    }
  }

  async createCode(db: Knex, request: AuthorizationRequest, user: User, authTime: Date) {
    const id = random(); const code = random();
    await db('oauthGrants').insert({ id, clientId: request.client_id, userId: user.id, scope: request.scope, authTime, expiresAt: expires(this.options.refreshTokenTtl) });
    await db('oauthCredentials').insert({ hash: digest(code), kind: 'code', grantId: id, expiresAt: expires(this.options.codeTtl), data: JSON.stringify({ redirectUri: request.redirect_uri, challenge: request.code_challenge, nonce: request.nonce }) });
    return code;
  }

  async tokens(db: Knex, grant: Grant, scope: string, nonce?: string, withId = true) {
    const accessToken = random();
    const accessExpires = new Date(Math.min(+expires(this.options.accessTokenTtl), +new Date(grant.expiresAt)));
    await db('oauthCredentials').insert({ hash: digest(accessToken), kind: 'access', grantId: grant.id, data: JSON.stringify({ scope }), expiresAt: accessExpires });
    const response: Record<string, unknown> = { access_token: accessToken, token_type: 'Bearer', expires_in: Math.max(0, Math.floor((+accessExpires - Date.now()) / 1000)), scope };
    if (splitScope(scope).includes('offline_access')) {
      const refresh = random();
      await db('oauthCredentials').insert({ hash: digest(refresh), kind: 'refresh', grantId: grant.id, data: JSON.stringify({ scope }), expiresAt: grant.expiresAt });
      response.refresh_token = refresh;
    }
    if (withId && splitScope(scope).includes('openid')) {
      response.id_token = await new SignJWT({ auth_time: Math.floor(+new Date(grant.authTime) / 1000), ...(nonce !== undefined ? { nonce } : {}) })
        .setProtectedHeader({ alg: 'RS256', kid: this.publicJwks.keys[0].kid, typ: 'JWT' })
        .setIssuer(this.options.issuer).setSubject(String(grant.userId)).setAudience(grant.clientId)
        .setIssuedAt().setExpirationTime(`${this.options.idTokenTtl}s`).sign(await this.signingKey);
    }
    return response;
  }

  async exchange(services: Services, client: Client, body: Record<string, string>) {
    const kind = body.grant_type === 'authorization_code' ? 'code' : body.grant_type === 'refresh_token' ? 'refresh' : undefined;
    if (!kind) throw new OAuthError('unsupported_grant_type');
    const raw = kind === 'code' ? body.code : body.refresh_token;
    if (!raw) throw new OAuthError('invalid_request');
    const result = await services.db.transaction(async (tx) => {
      const initial = await tx('oauthCredentials').where({ hash: digest(raw), kind }).first();
      if (!initial) throw new OAuthError('invalid_grant');
      // Lock family first: serializes refresh, revocation, and authorization-code replay.
      const grant: Grant = await tx('oauthGrants').where({ id: initial.grantId }).forUpdate().first();
      const credential = await tx('oauthCredentials').where({ hash: initial.hash }).first();
      if (!grant || grant.clientId !== client.id || grant.revoked || +new Date(grant.expiresAt) <= Date.now()) throw new OAuthError('invalid_grant');
      if (kind === 'code' && (body.redirect_uri !== credential.data.redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier || '') || !equal(challenge(body.code_verifier), credential.data.challenge))) throw new OAuthError('invalid_grant');
      if (credential.consumedAt) {
        await tx('oauthGrants').where({ id: grant.id }).update({ revoked: true });
        return null; // Commit replay revocation before returning an error.
      }
      if (+new Date(credential.expiresAt) <= Date.now()) throw new OAuthError('invalid_grant');
      const user = await tx('users').where({ id: grant.userId }).first();
      if (!active(user, grant.authTime)) throw new OAuthError('invalid_grant');
      let scope = kind === 'code' ? grant.scope : credential.data.scope;
      if (kind === 'refresh' && body.scope !== undefined) {
        const requested = splitScope(body.scope);
        if (!requested.length || requested.some((s) => !splitScope(scope).includes(s))) throw new OAuthError('invalid_scope');
        scope = requested.join(' ');
      }
      if (splitScope(scope).some((s) => !client.scopes.includes(s))) throw new OAuthError('invalid_scope');
      this.checkScopes(services, user, scope);
      await tx('oauthCredentials').where({ hash: initial.hash }).update({ consumedAt: new Date() });
      return this.tokens(tx, grant, scope, credential.data.nonce, kind === 'code');
    });
    if (!result) throw new OAuthError('invalid_grant');
    return result;
  }

  async access(services: Services, token: string, required: string[] = []): Promise<AccessIdentity> {
    const credential = await services.db('oauthCredentials').where({ hash: digest(token), kind: 'access' }).first();
    if (!credential || +new Date(credential.expiresAt) <= Date.now()) throw new OAuthError('invalid_token', 401);
    const grant: Grant = await services.db('oauthGrants').where({ id: credential.grantId }).first();
    if (!grant || grant.revoked || +new Date(grant.expiresAt) <= Date.now()) throw new OAuthError('invalid_token', 401);
    const client = await services.db('oauthClients').where({ id: grant.clientId, disabled: false }).first();
    const user = await services.db('users').where({ id: grant.userId }).first();
    if (!client || !active(user, grant.authTime)) throw new OAuthError('invalid_token', 401);
    const scopes = splitScope(credential.data.scope);
    if (scopes.some((s) => !client.scopes.includes(s))) throw new OAuthError('invalid_token', 401);
    if (required.some((s) => !scopes.includes(s))) throw new OAuthError('insufficient_scope', 403);
    this.checkScopes(services, user, scopes.join(' '));
    // Identity callbacks receive profile/status fields, never password/code/refresh fields.
    const safeUser: User = { id: user.id, role: user.role, fullName: user.fullName, displayName: user.displayName,
      email: user.email, isEmailVerified: user.isEmailVerified, avatar: user.avatar, locale: user.locale,
      timezone: user.timezone, isBanned: user.isBanned, isDeleted: user.isDeleted };
    return { userId: user.id, clientId: client.id, grantId: grant.id, scopes, user: safeUser };
  }

  profile(identity: AccessIdentity) {
    const { user, scopes } = identity;
    return {
      sub: String(user.id),
      ...(scopes.includes('profile') ? { name: user.fullName ?? undefined, preferred_username: user.displayName ?? undefined, picture: user.avatar ?? undefined, locale: user.locale ?? undefined, zoneinfo: user.timezone ?? undefined } : {}),
      ...(scopes.includes('email') ? { email: user.email ?? undefined, email_verified: !!user.isEmailVerified } : {}),
    };
  }

  validateClient(body: Record<string, unknown>) {
    const type = body.type ?? 'confidential';
    if (!['confidential', 'public', 'native'].includes(String(type)) || typeof body.name !== 'string' || !body.name.trim() || body.name.length > 255 ||
      !Array.isArray(body.redirectUris) || !body.redirectUris.length || body.redirectUris.length > 20 ||
      body.redirectUris.some((u) => typeof u !== 'string' || u.length > 2048 || !validRedirect(u, String(type), !!this.options.allowInsecureLocalhost)) ||
      !Array.isArray(body.scopes) || !body.scopes.length || body.scopes.some((s) => typeof s !== 'string' || !Object.hasOwn(this.scopes, s))) throw new OAuthError('invalid_client_metadata');
    return { name: body.name.trim(), type, redirectUris: JSON.stringify([...new Set(body.redirectUris)]), scopes: JSON.stringify([...new Set(body.scopes)]) };
  }
}
