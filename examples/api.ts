import { TheAPI, middlewares } from 'the-api';
import Roles from 'the-api-roles';
import { login, users, migrationDir as usersMigrationDir } from 'the-api-users';
import { createOAuthServer, migrationDir as oauthMigrationDir } from '../src';

const roles = new Roles({
  root: ['*'],
  applicationManager: ['oauthClients.get', 'oauthClients.post', 'oauthClients.patch', 'oauthClients.delete'],
  registered: ['oauthGrants.get', 'oauthGrants.delete', 'projects.get'],
});

const oauth = createOAuthServer({
  issuer: process.env.OAUTH_ISSUER!,
  jwks: JSON.parse(process.env.OAUTH_JWKS_JSON!),
  scopes: { 'projects.read': { description: 'Read your projects', permission: 'projects.get' } },
});

oauth.resource('GET', '/integrations/projects', ['projects.read'], async (c, identity) => {
  const projects = await c.get('db')('projects').where({ ownerId: identity.userId });
  return c.json({ result: projects });
});

const api = new TheAPI({
  roles,
  migrationDirs: [usersMigrationDir, oauthMigrationDir],
  routings: [middlewares.email, users, login, oauth.routings],
});
oauth.mount(api);
await api.up();
