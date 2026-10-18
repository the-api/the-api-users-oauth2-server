import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Hono, type Context } from 'hono';
import type { ApiHost, OAuthServer, OAuthServerOptions, ResourceEnv, ResourceHandler, Services } from './types';
import { OAuthService } from './lib/server';
import { OAuthError } from './lib/security';
import { bearer, protocol } from './modules/protocol';
import { management } from './modules/management';

const moduleDir = dirname(fileURLToPath(import.meta.url));
export const migrationDir = resolve(moduleDir, '../migrations');
export const migrationUpdateDir = resolve(moduleDir, '../migrationsUpdate');
export type * from './types';
export { renderLogin, renderConsent } from './lib/pages';
export { escapeHtml } from './lib/security';

/** Create one instance per issuer; call mount before TheAPI.init/up. */
export function createOAuthServer(options: OAuthServerOptions): OAuthServer {
  const service = new OAuthService(options);
  const routings = management(service);
  const resources = new Hono<ResourceEnv>();
  let getServices: (() => Services) | undefined;
  let mounted = false;
  const resourcePaths = new Set<string>();
  const services = () => {
    if (!getServices) throw new Error('OAuth server is not mounted');
    return getServices();
  };
  const protocolApp = protocol(service, services);
  const server: OAuthServer = {
    routings,
    /** Mounts protocol routes ahead of the-api's JWT/envelope middleware. */
    mount(api: ApiHost) {
      if (mounted) throw new Error('OAuth server is already mounted');
      mounted = true;
      getServices = () => {
        if (!api.db) throw new Error('OAuth server requires a PostgreSQL connection');
        return { db: api.db.dbWrite || api.db.db, roles: api.roles };
      };
      // Scope dispatch explicitly so the protocol app cannot intercept management or unrelated paths.
      api.app.use('*', async (c: Context, next: () => Promise<void>) => {
        const path = c.req.path;
        if (path === '/.well-known/openid-configuration' || path === '/.well-known/oauth-authorization-server' ||
          /^\/oauth\/(authorize|token|userinfo|jwks|revoke|introspect|logout)$/.test(path) || path.startsWith('/oauth/interaction/')) {
          return protocolApp.fetch(c.req.raw);
        }
        await next();
      });
      api.app.route('/', resources);
    },
    /** Register before mount. Resources receive OAuth identity without converting it into a local JWT. */
    resource(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, scopes: string[], handler: ResourceHandler) {
      if (mounted) throw new Error('Register resources before mount');
      if (!path.startsWith('/') || path.startsWith('/oauth') || path.startsWith('/.well-known')) throw new Error('Invalid resource path');
      if (scopes.some((scope) => !Object.hasOwn(service.scopes, scope))) throw new Error('Unknown resource scope');
      if (!resourcePaths.has(path)) {
        resourcePaths.add(path);
        resources.use(path, async (c, next) => {
          const origin = c.req.header('origin');
          if (origin && origin !== 'null') {
            const clients = await services().db('oauthClients').where({ type: 'public', disabled: false }).select('redirectUris');
            if (clients.some((client: { redirectUris: string[] }) => client.redirectUris.some((uri) => new URL(uri).origin === origin))) {
              c.header('Access-Control-Allow-Origin', origin); c.header('Vary', 'Origin');
              c.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
              c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            }
          }
          c.header('Cache-Control', 'no-store');
          await next();
        });
        resources.options(path, (c) => c.body(null, 204));
      }
      resources.on(method, path, async (c) => {
        try {
          const identity = await service.access(services(), bearer(c), scopes);
          c.set('db', services().db);
          c.set('dbWrite', services().db);
          c.set('oauth', identity);
          return await handler(c, identity);
        } catch (error) {
          const known = error instanceof OAuthError;
          if (!known) options.onError?.(error);
          const name = known ? error.error : 'server_error';
          c.header('WWW-Authenticate', `Bearer error="${name}"`);
          return c.json({ error: name }, (known ? error.status : 500) as any);
        }
      });
      return server;
    },
    /** For custom API adapters: validate opaque access token and required scopes. */
    verifyAccessToken(token: string, scopes: string[] = []) { return service.access(services(), token, scopes); },
    /** Run periodically; retain consumed tokens until family expiry for replay detection. */
    async cleanup() {
      const db = services().db;
      await db.transaction(async (tx) => {
        await tx('oauthInteractions').where('expiresAt', '<', new Date()).delete();
        await tx('oauthSessions').where('expiresAt', '<', new Date()).delete();
        await tx('oauthGrants').where('expiresAt', '<', new Date()).delete();
      });
    },
  };
  return server;
}
