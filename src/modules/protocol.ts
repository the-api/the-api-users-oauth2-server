import { Hono, type Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import type { Knex } from 'knex';
import type { AuthorizationRequest, PageModel, Services, User } from '../types';
import { OAuthService } from '../lib/server';
import { active, digest, equal, expires, form, OAuthError, random, singleParams, splitScope } from '../lib/security';
import { renderConsent, renderLogin } from '../lib/pages';

export type ServicesGetter = () => Services;
const bearer = (c: Context) => {
  const match = /^Bearer ([^\s]+)$/i.exec(c.req.header('authorization') || '');
  if (!match) throw new OAuthError('invalid_token', 401);
  return match[1];
};
export { bearer };

export function protocol(service: OAuthService, getServices: ServicesGetter) {
  const app = new Hono();
  const { options: o } = service;
  const secure = o.issuer.startsWith('https:');
  const sessionCookie = secure ? '__Secure-oauth-session' : 'oauth-session';
  const interactionCookie = (id: string) => `${secure ? '__Secure-' : ''}oauth-i-${id}`;
  const cookieOptions = { httpOnly: true, secure, sameSite: 'Lax' as const, path: '/oauth' };
  const origin = (c: Context) => {
    if (c.req.header('origin') !== o.issuer) throw new OAuthError('access_denied', 403, 'Same-origin request required');
  };
  const redirect = (request: AuthorizationRequest, values: Record<string, string>) => {
    const url = new URL(request.redirect_uri);
    for (const [k, v] of Object.entries({ ...values, iss: o.issuer, ...(request.state !== undefined ? { state: request.state } : {}) })) url.searchParams.set(k, v);
    return url.toString();
  };
  const session = async (c: Context, db: Knex) => {
    const raw = getCookie(c, sessionCookie);
    if (!raw) return undefined;
    const row = await db('oauthSessions').where({ hash: digest(raw) }).first();
    if (!row || +new Date(row.expiresAt) <= Date.now()) return undefined;
    const user = await db('users').where({ id: row.userId }).first();
    return active(user, row.authTime) ? { user, authTime: new Date(row.authTime) } : undefined;
  };
  const interaction = async (c: Context, db: Knex, csrf?: string, lock = false) => {
    const id = c.req.param('id') || '';
    let query = db('oauthInteractions').where({ id });
    if (lock) query = query.forUpdate();
    const row = await query.first();
    const browser = getCookie(c, interactionCookie(id));
    if (!row || row.finished || +new Date(row.expiresAt) <= Date.now() || !browser || !equal(row.browserHash, digest(browser)) ||
      (csrf !== undefined && !equal(row.csrfHash, digest(csrf)))) throw new OAuthError('invalid_request', 400, 'Expired or invalid interaction');
    return row;
  };
  app.use('*', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    c.header('Pragma', 'no-cache');
    c.header('Referrer-Policy', 'no-referrer');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    await next();
  });
  app.onError((error, c) => {
    const known = error instanceof OAuthError;
    if (!known) o.onError?.(error);
    if (known && error.status === 401) c.header('WWW-Authenticate', error.error === 'invalid_client' ? 'Basic realm="oauth"' : 'Bearer error="invalid_token"');
    return c.json({ error: known ? error.error : 'server_error', error_description: known ? error.message : 'Unexpected server error' }, (known ? error.status : 500) as any);
  });

  const discovery = () => ({
    issuer: o.issuer, authorization_endpoint: `${o.issuer}/oauth/authorize`, token_endpoint: `${o.issuer}/oauth/token`,
    userinfo_endpoint: `${o.issuer}/oauth/userinfo`, jwks_uri: `${o.issuer}/oauth/jwks`,
    revocation_endpoint: `${o.issuer}/oauth/revoke`, introspection_endpoint: `${o.issuer}/oauth/introspect`,
    scopes_supported: Object.keys(service.scopes), response_types_supported: ['code'], response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'], subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'], token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'], authorization_response_iss_parameter_supported: true,
    claims_supported: ['sub', 'iss', 'aud', 'iat', 'exp', 'auth_time', 'nonce', 'name', 'preferred_username', 'picture', 'locale', 'zoneinfo', 'email', 'email_verified'],
    claims_parameter_supported: false, request_parameter_supported: false, request_uri_parameter_supported: false,
  });
  app.get('/.well-known/openid-configuration', (c) => c.json(discovery()));
  app.get('/.well-known/oauth-authorization-server', (c) => c.json(discovery()));
  app.get('/oauth/jwks', (c) => c.json(service.publicJwks));

  // Public clients can call token and userinfo from registered web origins only.
  app.use('/oauth/*', async (c, next) => {
    if (['/oauth/token', '/oauth/userinfo', '/oauth/revoke'].includes(c.req.path) && c.req.header('origin')) {
      const requestOrigin = c.req.header('origin')!;
      if (requestOrigin !== 'null') {
        const clients: { redirectUris: string[] }[] = await getServices().db('oauthClients').where({ type: 'public', disabled: false }).select('redirectUris');
        if (clients.some((client) => client.redirectUris.some((uri) => new URL(uri).origin === requestOrigin))) {
          c.header('Access-Control-Allow-Origin', requestOrigin); c.header('Vary', 'Origin');
          c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
          c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        }
      }
      if (c.req.method === 'OPTIONS') return c.body(null, 204);
    }
    await next();
  });

  app.get('/oauth/authorize', async (c) => {
    const services = getServices();
    const params = singleParams(new URL(c.req.url).searchParams);
    let request: AuthorizationRequest;
    try { request = await service.authorization(services.db, params); }
    catch (error) {
      // Redirect protocol errors only after independently establishing a trusted callback.
      const client = params.client_id ? await services.db('oauthClients').where({ id: params.client_id, disabled: false }).first() : undefined;
      if (error instanceof OAuthError && client?.redirectUris.includes(params.redirect_uri)) {
        return c.redirect(redirect({ redirect_uri: params.redirect_uri, state: params.state } as AuthorizationRequest, { error: error.error }), 303);
      }
      throw error;
    }
    let signedIn = await session(c, services.db);
    if (request.prompt === 'login' || (request.max_age !== undefined && signedIn && (Date.now() - +signedIn.authTime) / 1000 >= request.max_age)) signedIn = undefined;
    if (request.prompt === 'none') return c.redirect(redirect(request, { error: signedIn ? 'consent_required' : 'login_required' }), 303);
    const id = random(); const browser = random(); const csrf = random();
    await services.db('oauthInteractions').insert({ id, browserHash: digest(browser), csrfHash: digest(csrf), request: JSON.stringify(request), userId: signedIn?.user.id, authTime: signedIn?.authTime, expiresAt: expires(o.interactionTtl) });
    setCookie(c, interactionCookie(id), browser, { ...cookieOptions, maxAge: o.interactionTtl });
    return c.redirect(`/oauth/interaction/${id}`, 303);
  });

  app.get('/oauth/interaction/:id', async (c) => {
    const services = getServices();
    const row = await interaction(c, services.db);
    const client = await service.client(services.db, row.request.client_id);
    let user = row.userId ? await services.db('users').where({ id: row.userId }).first() : undefined;
    if (!active(user, row.authTime)) user = undefined;
    const csrf = random();
    await services.db('oauthInteractions').where({ id: row.id }).update({ csrfHash: digest(csrf), ...(user ? {} : { userId: null, authTime: null }) });
    const nonce = random();
    c.header('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
    const model: PageModel = {
      interactionId: row.id, csrf, nonce, clientName: client.name,
      scopes: splitScope(row.request.scope).map((name) => ({ name, description: service.scopes[name as keyof typeof service.scopes].description })),
      loginEndpoint: o.loginPath, sessionEndpoint: `/oauth/interaction/${row.id}/login`, consentEndpoint: `/oauth/interaction/${row.id}/consent`,
    };
    const renderer = user ? (o.renderConsent ?? renderConsent) : (o.renderLogin ?? renderLogin);
    return c.html(await renderer(model));
  });

  app.post('/oauth/interaction/:id/login', async (c) => {
    origin(c); const body = await form(c); const services = getServices();
    if (!body.csrf || !body.token) throw new OAuthError('invalid_request');
    const { user, authTime } = await service.localUser(services.db, body.token);
    const raw = random();
    await services.db.transaction(async (tx) => {
      const row = await interaction(c, tx, body.csrf, true);
      // prompt=login and max_age cannot be satisfied with an old local JWT.
      if ((row.request.prompt === 'login' || row.request.max_age !== undefined) && Date.now() - +authTime > 60000) throw new OAuthError('login_required', 401);
      const old = getCookie(c, sessionCookie);
      if (old) await tx('oauthSessions').where({ hash: digest(old) }).delete();
      await tx('oauthSessions').insert({ hash: digest(raw), userId: user.id, authTime, expiresAt: expires(o.sessionTtl) });
      await tx('oauthInteractions').where({ id: row.id }).update({ userId: user.id, authTime, csrfHash: digest(random()) });
    });
    setCookie(c, sessionCookie, raw, { ...cookieOptions, maxAge: o.sessionTtl });
    return c.json({ continue: `/oauth/interaction/${c.req.param('id')}` });
  });

  app.post('/oauth/interaction/:id/consent', async (c) => {
    origin(c); const body = await form(c); const services = getServices();
    if (!body.csrf || !['allow', 'deny'].includes(body.decision)) throw new OAuthError('invalid_request');
    const target = await services.db.transaction(async (tx) => {
      const row = await interaction(c, tx, body.csrf, true);
      const client = await service.client(tx, row.request.client_id);
      if (!client.redirectUris.includes(row.request.redirect_uri) || splitScope(row.request.scope).some((s) => !client.scopes.includes(s))) throw new OAuthError('invalid_request');
      await tx('oauthInteractions').where({ id: row.id }).update({ finished: true });
      if (body.decision === 'deny') return redirect(row.request, { error: 'access_denied' });
      const signedIn = await session(c, tx);
      const user = row.userId ? await tx('users').where({ id: row.userId }).first() : undefined;
      if (!active(user, row.authTime) || !signedIn || signedIn.user.id !== user.id) throw new OAuthError('login_required', 401);
      service.checkScopes(services, user, row.request.scope);
      return redirect(row.request, { code: await service.createCode(tx, row.request, user, row.authTime) });
    });
    setCookie(c, interactionCookie(c.req.param('id')), '', { ...cookieOptions, maxAge: 0 });
    return c.redirect(target, 303);
  });

  app.post('/oauth/token', async (c) => {
    const body = await form(c); const services = getServices();
    const client = await service.authenticateClient(services.db, body, c.req.header('authorization'));
    return c.json(await service.exchange(services, client, body));
  });
  const userinfo = async (c: Context) => c.json(service.profile(await service.access(getServices(), bearer(c), ['openid'])));
  app.get('/oauth/userinfo', userinfo);
  app.post('/oauth/userinfo', userinfo);

  app.post('/oauth/revoke', async (c) => {
    const body = await form(c); const { db } = getServices();
    const client = await service.authenticateClient(db, body, c.req.header('authorization'));
    if (!body.token) throw new OAuthError('invalid_request');
    await db.transaction(async (tx) => {
      const credential = await tx('oauthCredentials').where({ hash: digest(body.token) }).whereIn('kind', ['access', 'refresh']).first();
      if (!credential) return;
      await tx('oauthGrants').where({ id: credential.grantId, clientId: client.id }).update({ revoked: true });
    });
    return c.body(null, 200);
  });
  app.post('/oauth/introspect', async (c) => {
    const body = await form(c); const services = getServices();
    const client = await service.authenticateClient(services.db, body, c.req.header('authorization'));
    if (client.type !== 'confidential') throw new OAuthError('invalid_client', 401);
    if (!body.token) throw new OAuthError('invalid_request');
    try {
      const identity = await service.access(services, body.token);
      if (identity.clientId !== client.id) return c.json({ active: false });
      const credential = await services.db('oauthCredentials').where({ hash: digest(body.token) }).first();
      return c.json({ active: true, sub: String(identity.userId), client_id: identity.clientId, scope: identity.scopes.join(' '), token_type: 'Bearer', iss: o.issuer, aud: o.issuer, exp: Math.floor(+new Date(credential.expiresAt) / 1000) });
    } catch (error) { if (error instanceof OAuthError) return c.json({ active: false }); throw error; }
  });
  app.post('/oauth/logout', async (c) => {
    origin(c);
    const raw = getCookie(c, sessionCookie);
    if (raw) await getServices().db('oauthSessions').where({ hash: digest(raw) }).delete();
    setCookie(c, sessionCookie, '', { ...cookieOptions, maxAge: 0 });
    return c.json({ ok: true });
  });
  return app;
}
