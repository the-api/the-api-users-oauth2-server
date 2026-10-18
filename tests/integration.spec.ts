import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import knex, { type Knex } from 'knex';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { createOAuthServer, migrationDir, migrationUpdateDir } from '../src';
import { challenge } from '../src/lib/security';

// Dynamic import below ensures the-api's JWT middleware sees the test secret.
process.env.JWT_SECRET = 'oauth-integration-test-secret';
process.env.AUTH_REQUIRE_EMAIL_VERIFICATION = 'false';
// Never let integration tests connect the-api to a developer's configured DB.
delete process.env.DB_HOST;
delete process.env.DB_WRITE_HOST;
const enabled = !!process.env.OAUTH_TEST_DATABASE_URL;
const suite = enabled ? describe : describe.skip;
suite('OAuth2/OIDC with PostgreSQL and TheAPI', () => {
  let db: Knex; let adminDb: Knex; let api: any; let server: ReturnType<typeof createOAuthServer>;
  let token: string; let userId: number; let client: any;
  const schema = `oauth_test_${randomBytes(8).toString('hex')}`;
  const issuer = 'https://accounts.example.test';
  const redirectUri = 'https://client.example.test/callback';
  const privateJwk = { ...generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' }), kid: 'integration', alg: 'RS256' };
  const req = (path: string, init?: RequestInit) => api.app.request(`${issuer}${path}`, init) as Promise<Response>;
  const admin = (method: string, path: string, body?: unknown, auth = token) => req(path, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${auth}` }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) => req(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body).toString() });
  beforeAll(async () => {
    adminDb = knex({ client: 'pg', connection: process.env.OAUTH_TEST_DATABASE_URL });
    await adminDb.raw('CREATE SCHEMA ??', [schema]);
    db = knex({ client: 'pg', connection: process.env.OAUTH_TEST_DATABASE_URL, searchPath: [schema], pool: { min: 0, max: 10 } });
    const { TheAPI } = await import('the-api');
    const { login, migrationDir: usersMigrationDir } = await import('the-api-users');
    const { default: Roles } = await import('the-api-roles');
    await db.migrate.latest({ directory: [usersMigrationDir, migrationDir, migrationUpdateDir], loadExtensions: ['.js'], schemaName: schema });
    const update = await import('../migrationsUpdate/20261018000001_oauth2_indexes.js');
    await update.up(db); // idempotent maintenance
    server = createOAuthServer({ issuer, jwks: { keys: [privateJwk] }, scopes: { 'projects.read': { description: 'Read projects', permission: 'projects.get' } }, onError: console.error });
    server.resource('GET', '/delegated/projects', ['projects.read'], async (c, identity) => c.json({ ownerId: identity.userId }));
    api = new TheAPI({ roles: new Roles({ registered: ['oauthClients.*', 'oauthGrants.*', 'projects.get'], reader: ['oauthClients.get'], nobody: [] }), routings: [login, server.routings] });
    // Tests supply their isolated connection without changing application env/dbs.
    api.db = { db, dbWrite: db };
    server.mount(api);
    api.app.use('*', async (c: any, next: any) => { c.set('db', db); c.set('dbWrite', db); await next(); });
    await api.init();
    const response = await req('/login/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'oauth@test.local', password: 'test-password' }) });
    const result = (await response.json()).result;
    token = result.token; userId = result.id;
    expect(typeof token).toBe('string');
    const signedIn = await req('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'oauth@test.local', password: 'test-password' }) });
    token = (await signedIn.json()).result.token;
    expect(typeof token).toBe('string');
    const created = await admin('POST', '/oauth/clients', { name: 'Test client', type: 'confidential', redirectUris: [redirectUri], scopes: ['openid', 'profile', 'email', 'offline_access', 'projects.read'] });
    client = (await created.json()).result;
    expect(typeof client.clientSecret).toBe('string');
  }, 30000);
  afterAll(async () => {
    await db?.destroy();
    if (adminDb) { await adminDb.raw('DROP SCHEMA IF EXISTS ?? CASCADE', [schema]); await adminDb.destroy(); }
  });

  const credentials = (selected = client) => ({ client_id: selected.id, ...(selected.clientSecret ? { client_secret: selected.clientSecret } : {}) });
  async function authorize(selected = client, scope = 'openid profile email offline_access projects.read', existingCookies = '') {
    const verifier = randomBytes(40).toString('base64url');
    const query = new URLSearchParams({ response_type: 'code', client_id: selected.id, redirect_uri: selected.redirectUris[0], scope, state: 'state-value', nonce: 'nonce-value', code_challenge: challenge(verifier), code_challenge_method: 'S256' });
    const start = await req(`/oauth/authorize?${query}`, { headers: { Cookie: existingCookies } });
    expect(start.status).toBe(303);
    const interaction = start.headers.get('location')!;
    let cookies = [existingCookies, start.headers.get('set-cookie')!.split(';')[0]].filter(Boolean).join('; ');
    let page = await req(interaction, { headers: { Cookie: cookies } });
    let html = await page.text();
    if (html.includes('id="login"')) {
      const csrf = JSON.parse(html.match(/const config = (.*);/)![1]).csrf;
      const signedIn = await post(`${interaction}/login`, { csrf, token }, { Cookie: cookies, Origin: issuer });
      expect(signedIn.status).toBe(200);
      cookies += `; ${signedIn.headers.get('set-cookie')!.split(';')[0]}`;
      page = await req(interaction, { headers: { Cookie: cookies } }); html = await page.text();
    }
    const csrf = html.match(/name="csrf" value="([^"]+)"/)![1];
    const consent = await post(`${interaction}/consent`, { csrf, decision: 'allow' }, { Cookie: cookies, Origin: issuer });
    expect(consent.status).toBe(303);
    const location = new URL(consent.headers.get('location')!);
    expect(location.searchParams.get('state')).toBe('state-value');
    expect(location.searchParams.get('iss')).toBe(issuer);
    return { code: location.searchParams.get('code')!, verifier, cookies, interaction, csrf };
  }
  async function exchange(flow: Awaited<ReturnType<typeof authorize>>, selected = client) {
    return post('/oauth/token', { ...credentials(selected), grant_type: 'authorization_code', code: flow.code, code_verifier: flow.verifier, redirect_uri: selected.redirectUris[0] });
  }
  async function tokens(selected = client, scope?: string) {
    const flow = await authorize(selected, scope);
    const response = await exchange(flow, selected);
    expect(response.status).toBe(200);
    return { ...await response.json(), flow };
  }

  test('discovery and JWKS are raw standard responses with public keys only', async () => {
    const metadata = await (await req('/.well-known/openid-configuration')).json();
    expect(metadata.issuer).toBe(issuer); expect(metadata.result).toBeUndefined();
    const jwks = await (await req('/oauth/jwks')).json();
    expect(jwks.keys[0].kid).toBe('integration'); expect(jwks.keys[0].d).toBeUndefined();
  });
  test('permission names control client management; secret hashes never exposed', async () => {
    const listed = (await (await admin('GET', '/oauth/clients')).json()).result;
    expect(listed[0].secretHash).toBeUndefined(); expect(listed[0].clientSecret).toBeUndefined();
    await db('users').where({ id: userId }).update({ role: 'reader' });
    const denied = await admin('POST', '/oauth/clients', { name: 'Denied', redirectUris: [redirectUri], scopes: ['openid'] });
    expect((await denied.json()).result.name).toBe('ACCESS_DENIED');
    await db('users').where({ id: userId }).update({ role: 'registered' });
  });
  test('full login, consent, signed OIDC ID token, userinfo, protected API and SSO', async () => {
    const result = await tokens();
    expect(result.access_token).toBeString(); expect(result.refresh_token).toBeString();
    const jwks = await (await req('/oauth/jwks')).json();
    const verified = await jwtVerify(result.id_token, createLocalJWKSet(jwks), { issuer, audience: client.id });
    expect(verified.payload.sub).toBe(String(userId)); expect(verified.payload.nonce).toBe('nonce-value');
    const profile = await (await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).json();
    expect(profile.sub).toBe(String(userId)); expect(profile.email).toBe('oauth@test.local'); expect(profile.password).toBeUndefined();
    const resource = await req('/delegated/projects', { headers: { Authorization: `Bearer ${result.access_token}` } });
    expect((await resource.json()).ownerId).toBe(userId);
    const second = await authorize(client, 'openid', result.flow.cookies);
    expect(second.code).toBeString();
    const idAsAccess = await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.id_token}` } });
    expect(idAsAccess.status).toBe(401);
  });
  test('rejects redirect mismatch, missing PKCE, duplicate parameters', async () => {
    const params = new URLSearchParams({ client_id: client.id, redirect_uri: 'https://evil.example/cb', response_type: 'code', scope: 'openid' });
    const bad = await req(`/oauth/authorize?${params}`);
    expect(bad.status).toBe(400); expect(bad.headers.get('location')).toBeNull();
    params.set('redirect_uri', redirectUri);
    const missingPkce = await req(`/oauth/authorize?${params}`);
    expect(missingPkce.status).toBe(303);
    expect(new URL(missingPkce.headers.get('location')!).searchParams.get('error')).toBe('invalid_request');
    params.append('client_id', client.id);
    expect((await req(`/oauth/authorize?${params}`)).status).toBe(400);
  });
  test('PKCE and code replay; replay revocation is persisted', async () => {
    const flow = await authorize();
    const wrong = await exchange({ ...flow, verifier: 'x'.repeat(43) });
    expect((await wrong.json()).error).toBe('invalid_grant');
    const result = await (await exchange(flow)).json();
    expect((await exchange(flow)).status).toBe(400);
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(401);
  });
  test('refresh rotates, scope cannot expand, reuse revokes entire family', async () => {
    const initial = await tokens();
    const expanded = await post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: initial.refresh_token, scope: 'other' });
    expect((await expanded.json()).error).toBe('invalid_scope');
    const response = await post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: initial.refresh_token });
    const rotated = await response.json(); expect(response.status).toBe(200);
    expect(rotated.refresh_token).not.toBe(initial.refresh_token);
    expect((await post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: initial.refresh_token })).status).toBe(400);
    expect((await post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: rotated.refresh_token })).status).toBe(400);
  });
  test('parallel refreshes issue at most one response and revoke family on reuse', async () => {
    const initial = await tokens();
    const responses = await Promise.all([1, 2].map(() => post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: initial.refresh_token })));
    expect(responses.map((r) => r.status).sort()).toEqual([200, 400]);
    const successful = await responses.find((r) => r.status === 200)!.json();
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${successful.access_token}` } })).status).toBe(401);
  });
  test('browser CSRF, browser binding, and repeated consent are rejected', async () => {
    const flow = await authorize();
    expect((await post(`${flow.interaction}/consent`, { csrf: flow.csrf, decision: 'allow' }, { Cookie: flow.cookies, Origin: issuer })).status).toBe(400);
    expect((await post(`${flow.interaction}/login`, { csrf: flow.csrf, token }, { Cookie: flow.cookies, Origin: 'https://evil.test' })).status).toBe(403);
    expect((await req(flow.interaction)).status).toBe(400);
  });
  test('revocation, introspection and grant ownership', async () => {
    const result = await tokens();
    const active = await post('/oauth/introspect', { ...credentials(), token: result.access_token });
    expect((await active.json()).active).toBe(true);
    const revoked = await post('/oauth/revoke', { ...credentials(), token: result.refresh_token });
    expect(revoked.status).toBe(200);
    expect((await (await post('/oauth/introspect', { ...credentials(), token: result.access_token })).json()).active).toBe(false);
    const owned = await tokens();
    const identity = await server.verifyAccessToken(owned.access_token);
    expect((await admin('DELETE', `/oauth/grants/${identity.grantId}`)).status).toBe(200);
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${owned.access_token}` } })).status).toBe(401);
  });
  test('SPA and native clients have no secret; CORS permits registered SPA origin', async () => {
    for (const type of ['public', 'native']) {
      const callback = type === 'native' ? 'com.example.app:/callback' : redirectUri;
      const selected = (await (await admin('POST', '/oauth/clients', { name: type, type, redirectUris: [callback], scopes: ['openid', 'offline_access'] })).json()).result;
      expect(selected.clientSecret).toBeUndefined();
      const result = await tokens(selected, 'openid offline_access');
      expect(result.access_token).toBeString();
    }
    const preflight = await req('/oauth/token', { method: 'OPTIONS', headers: { Origin: 'https://client.example.test', 'Access-Control-Request-Method': 'POST' } });
    expect(preflight.status).toBe(204); expect(preflight.headers.get('access-control-allow-origin')).toBe('https://client.example.test');
    const badOrigin = await req('/oauth/token', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } });
    expect(badOrigin.headers.get('access-control-allow-origin')).toBeNull();
  });
  test('current user state and scope permission are enforced after issuance', async () => {
    const result = await tokens();
    await db('users').where({ id: userId }).update({ isBanned: true });
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(401);
    await db('users').where({ id: userId }).update({ isBanned: false, role: 'reader' });
    expect((await req('/delegated/projects', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(403);
    await db('users').where({ id: userId }).update({ role: 'registered' });
    await db('users').where({ id: userId }).update({ timePasswordChanged: new Date(Date.now() + 2000) });
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(401);
    await db('users').where({ id: userId }).update({ timePasswordChanged: null });
  });
  test('custom renderers receive escaped-by-template data and useful endpoints', async () => {
    const { Hono } = await import('hono');
    const replacement = createOAuthServer({ issuer, jwks: { keys: [privateJwk] }, renderLogin: (model) => `<h1>Custom login</h1><p>${model.sessionEndpoint}</p>` });
    const host = { app: new Hono(), db: { db, dbWrite: db } };
    replacement.mount(host);
    const params = new URLSearchParams({ response_type: 'code', client_id: client.id, redirect_uri: redirectUri, scope: 'openid', code_challenge: challenge('x'.repeat(43)), code_challenge_method: 'S256' });
    const started = await host.app.request(`${issuer}/oauth/authorize?${params}`);
    const page = await host.app.request(`${issuer}${started.headers.get('location')}`, { headers: { Cookie: started.headers.get('set-cookie')!.split(';')[0] } });
    expect(await page.text()).toContain('<h1>Custom login</h1>');
    expect(page.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
  });

  test('credentials cannot cross clients; secrets and grant types are validated', async () => {
    const flow = await authorize();
    const another = (await (await admin('POST', '/oauth/clients', { name: 'Other', type: 'confidential', redirectUris: [redirectUri], scopes: ['openid'] })).json()).result;
    expect((await exchange(flow, another)).status).toBe(400);
    expect((await post('/oauth/token', { ...credentials(), client_secret: 'incorrect', grant_type: 'authorization_code', code: flow.code })).status).toBe(401);
    expect((await post('/oauth/token', { ...credentials(), grant_type: 'password' })).status).toBe(400);
    const response = await exchange(flow);
    expect(response.status).toBe(200);
    const result = await response.json();
    const foreign = await post('/oauth/introspect', { ...credentials(another), token: result.access_token });
    expect((await foreign.json()).active).toBe(false);
    await post('/oauth/revoke', { ...credentials(another), token: result.access_token });
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(200);
    const header = `Basic ${Buffer.from(`${encodeURIComponent(client.id)}:${encodeURIComponent(client.clientSecret)}`).toString('base64')}`;
    const basic = await post('/oauth/introspect', { token: result.access_token }, { Authorization: header });
    expect((await basic.json()).active).toBe(true);
  });

  test('expiration and cleanup, without losing live replay records', async () => {
    const result = await tokens();
    const identity = await server.verifyAccessToken(result.access_token);
    await db('oauthCredentials').where({ grantId: identity.grantId, kind: 'access' }).update({ expiresAt: new Date(0) });
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(401);
    await server.cleanup();
    expect(await db('oauthCredentials').where({ grantId: identity.grantId, kind: 'code' }).first()).toBeDefined();
    await db('oauthGrants').where({ id: identity.grantId }).update({ expiresAt: new Date(0) });
    expect((await post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: result.refresh_token })).status).toBe(400);
    await server.cleanup();
    expect(await db('oauthCredentials').where({ grantId: identity.grantId }).first()).toBeUndefined();
    const flow = await authorize();
    const { digest } = await import('../src/lib/security');
    await db('oauthCredentials').where({ hash: digest(flow.code) }).update({ expiresAt: new Date(0) });
    expect((await exchange(flow)).status).toBe(400);
  });

  test('scope filtering and consent denial, prompt=none, logout', async () => {
    const result = await tokens(client, 'openid');
    expect(result.refresh_token).toBeUndefined();
    expect((await (await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).json()).email).toBeUndefined();
    expect((await req('/delegated/projects', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(403);
    const params = new URLSearchParams({ client_id: client.id, redirect_uri: redirectUri, response_type: 'code', scope: 'openid', code_challenge: challenge('x'.repeat(43)), code_challenge_method: 'S256', prompt: 'none' });
    const silent = await req(`/oauth/authorize?${params}`);
    expect(new URL(silent.headers.get('location')!).searchParams.get('error')).toBe('login_required');
    const signed = await req(`/oauth/authorize?${params}`, { headers: { Cookie: result.flow.cookies } });
    expect(new URL(signed.headers.get('location')!).searchParams.get('error')).toBe('consent_required');
    params.delete('prompt');
    const start = await req(`/oauth/authorize?${params}`, { headers: { Cookie: result.flow.cookies } });
    const target = start.headers.get('location')!;
    const cookies = `${result.flow.cookies}; ${start.headers.get('set-cookie')!.split(';')[0]}`;
    const page = await req(target, { headers: { Cookie: cookies } });
    const csrf = (await page.text()).match(/name="csrf" value="([^"]+)"/)![1];
    const wrong = await post(`${target}/consent`, { csrf: 'wrong', decision: 'allow' }, { Cookie: cookies, Origin: issuer });
    expect(wrong.status).toBe(400);
    const denied = await post(`${target}/consent`, { csrf, decision: 'deny' }, { Cookie: cookies, Origin: issuer });
    expect(new URL(denied.headers.get('location')!).searchParams.get('error')).toBe('access_denied');
    expect((await req('/oauth/logout', { method: 'POST', headers: { Cookie: result.flow.cookies, Origin: issuer } })).status).toBe(200);
    params.set('prompt', 'none');
    const loggedOut = await req(`/oauth/authorize?${params}`, { headers: { Cookie: result.flow.cookies } });
    expect(new URL(loggedOut.headers.get('location')!).searchParams.get('error')).toBe('login_required');
  });

  test('editing or disabling a client revokes existing tokens', async () => {
    const result = await tokens();
    const response = await admin('PATCH', `/oauth/clients/${client.id}`, { disabled: true });
    expect(response.status).toBe(200);
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(401);
    expect((await post('/oauth/token', { ...credentials(), grant_type: 'refresh_token', refresh_token: result.refresh_token })).status).toBe(401);
    await admin('PATCH', `/oauth/clients/${client.id}`, { disabled: false });
    expect((await req('/oauth/userinfo', { headers: { Authorization: `Bearer ${result.access_token}` } })).status).toBe(401);
  });
});
