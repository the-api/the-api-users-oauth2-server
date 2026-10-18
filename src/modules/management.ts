import { Routings } from 'the-api-routings';
import type { AppContext } from 'the-api-routings';
import type { Knex } from 'knex';
import { OAuthService } from '../lib/server';
import { active, digest, OAuthError, permitted, random } from '../lib/security';

export function management(service: OAuthService) {
  const routes = new Routings();
  routes.use('/oauth/*', async (c, next) => { c.header('Cache-Control', 'no-store'); await next(); });
  routes.errors({
    ACCESS_DENIED: { code: 403, status: 403, description: 'Permission required' },
    OAUTH_INVALID_CLIENT: { code: 400, status: 400, description: 'Invalid client metadata' },
    OAUTH_NOT_FOUND: { code: 404, status: 404, description: 'OAuth record not found' },
  });
  const dbFor = (c: AppContext): Knex => c.var.dbWrite || c.env?.dbWrite || c.var.db || c.env?.db;
  const authorize = async (c: AppContext, permission: string) => {
    const db = dbFor(c);
    const user = c.var.user?.userId ? await db('users').where({ id: c.var.user.userId }).first() : undefined;
    if (!active(user) || !permitted(c.var.roles || c.env?.roles, user, permission)) throw new Error('ACCESS_DENIED');
    return { db, user };
  };
  const publicClient = ({ secretHash, ...client }: Record<string, unknown>) => client;
  routes.get('/oauth/clients', async (c: AppContext) => {
    const { db } = await authorize(c, 'oauthClients.get');
    c.set('result', (await db('oauthClients').orderBy('timeCreated', 'desc').limit(100)).map(publicClient));
  });
  routes.post('/oauth/clients', async (c: AppContext) => {
    const { db, user } = await authorize(c, 'oauthClients.post');
    let data;
    try { data = service.validateClient(c.var.body || {}); } catch { throw new Error('OAUTH_INVALID_CLIENT'); }
    const id = random(); const secret = data.type === 'confidential' ? random() : undefined;
    const [client] = await db('oauthClients').insert({ ...data, id, secretHash: secret ? digest(secret) : null, createdBy: user.id }).returning('*');
    c.set('result', { ...publicClient(client), ...(secret ? { clientSecret: secret } : {}) });
  });
  routes.get('/oauth/clients/:id', async (c: AppContext) => {
    const { db } = await authorize(c, 'oauthClients.get');
    const client = await db('oauthClients').where({ id: c.req.param('id') }).first();
    if (!client) throw new Error('OAUTH_NOT_FOUND');
    c.set('result', publicClient(client));
  });
  routes.patch('/oauth/clients/:id', async (c: AppContext) => {
    const { db } = await authorize(c, 'oauthClients.patch');
    const body = c.var.body || {};
    if (Object.keys(body).some((k) => !['name', 'redirectUris', 'scopes', 'disabled'].includes(k)) ||
        (body.disabled !== undefined && typeof body.disabled !== 'boolean')) throw new Error('OAUTH_INVALID_CLIENT');
    const client = await db.transaction(async (tx) => {
      const old = await tx('oauthClients').where({ id: c.req.param('id') }).forUpdate().first();
      if (!old) throw new Error('OAUTH_NOT_FOUND');
      let data;
      try { data = service.validateClient({ ...old, ...body }); } catch { throw new Error('OAUTH_INVALID_CLIENT'); }
      // Existing grants never silently inherit newly edited client metadata.
      await tx('oauthGrants').where({ clientId: old.id }).update({ revoked: true });
      const [updated] = await tx('oauthClients').where({ id: old.id }).update({ ...data, disabled: body.disabled ?? old.disabled }).returning('*');
      return updated;
    });
    c.set('result', publicClient(client));
  });
  routes.delete('/oauth/clients/:id', async (c: AppContext) => {
    const { db } = await authorize(c, 'oauthClients.delete');
    if (!await db('oauthClients').where({ id: c.req.param('id') }).delete()) throw new Error('OAUTH_NOT_FOUND');
    c.set('result', { ok: true });
  });
  routes.get('/oauth/grants', async (c: AppContext) => {
    const { db, user } = await authorize(c, 'oauthGrants.get');
    c.set('result', await db('oauthGrants').where({ userId: user.id }).orderBy('timeCreated', 'desc').limit(100));
  });
  routes.delete('/oauth/grants/:id', async (c: AppContext) => {
    const { db, user } = await authorize(c, 'oauthGrants.delete');
    if (!await db('oauthGrants').where({ id: c.req.param('id'), userId: user.id }).update({ revoked: true })) throw new Error('OAUTH_NOT_FOUND');
    c.set('result', { ok: true });
  });
  return routes;
}
