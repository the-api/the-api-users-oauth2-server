# the-api-users-oauth2-server

OAuth2 authorization server and OpenID Connect code flow for `the-api` and
`the-api-users`. Supports shared sign-in (SSO) and delegated API access for
server applications, browser SPAs and native/mobile applications.

Uses the existing `users` table and `/login` routes. Provides separate OAuth
client, grant, credential, browser-session and interaction tables. Built-in
login and consent pages can be replaced with your own HTML renderers.

## Install and local development

This is a new, unpublished package. The current sibling `the-api`,
`the-api-routings`, and `the-api-users` versions are also ahead of npm.
The repository uses Bun `link:` overrides for local development:

```bash
# Run from this package's directory, with the sibling repositories present.
for package in the-api the-api-routings the-api-users the-api-roles; do
  (cd ../"$package" && bun link)
done
bun install
bun run build
bun link

# From your application:
bun link the-api-users-oauth2-server
```

Build the sibling packages first if their `dist` folders are missing. Requires
Node.js 22+ or Bun 1.3+, PostgreSQL and the existing `the-api-users` setup.
Linked repositories may each contain their own `the-api-routings`, Hono and Knex types;
TypeScript treats their private members as incompatible. Align dependency
versions/deduplicate them in the consuming app. For this linked workspace,
`tsconfig.examples.json` maps these types to a single copy; verify the runnable
example with `bun run check:examples`.
Before publishing, publish compatible sibling dependency versions and remove
the development `overrides`. Normal installation after publication will be:

```bash
npm i the-api the-api-users the-api-users-oauth2-server the-api-roles
```

## Generate signing keys

OAuth ID tokens use dedicated RSA keys, separate from `JWT_SECRET`. Generate a
key once and keep it in your secret store; do not generate a new key on restart.

```bash
node --input-type=module -e '
import { generateKeyPairSync, randomUUID } from "node:crypto";
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
console.log(JSON.stringify({ keys: [{ ...privateKey.export({ format: "jwk" }),
  kid: randomUUID(), alg: "RS256", use: "sig" }] }));
'
```

Save the JSON securely as `OAUTH_JWKS_JSON`. Never commit it. JWKS served to
clients contains only public key fields. For rotation, put a new private key
first and retain the previous public key until all old ID tokens have expired.
Every key must have a unique `kid`. Share keys between all server instances.

## Connect the module

```ts
import { TheAPI, middlewares } from 'the-api';
import Roles from 'the-api-roles';
import { login, users, migrationDir as usersMigrationDir } from 'the-api-users';
import {
  createOAuthServer,
  migrationDir as oauthMigrationDir,
} from 'the-api-users-oauth2-server';

const roles = new Roles({
  root: ['*'],
  // Role names are arbitrary; permissions determine access.
  applicationManager: [
    'oauthClients.get', 'oauthClients.post',
    'oauthClients.patch', 'oauthClients.delete',
  ],
  registered: ['oauthGrants.get', 'oauthGrants.delete', 'projects.get'],
});

const oauth = createOAuthServer({
  issuer: process.env.OAUTH_ISSUER!,
  jwks: JSON.parse(process.env.OAUTH_JWKS_JSON!),
  // Defaults to process.env.JWT_SECRET, matching the-api-users.
  jwtSecret: process.env.JWT_SECRET,
  scopes: {
    'projects.read': {
      description: 'Read your projects',
      permission: 'projects.get',
    },
  },
  onError: (error) => console.error('OAuth internal error', error),
});

// Optional API resources for delegated access. Register BEFORE mount().
oauth.resource('GET', '/integrations/projects', ['projects.read'], async (c, identity) => {
  // Scope permission is checked by the module. Domain ownership remains here.
  const projects = await c.get('db')('projects').where({ ownerId: identity.userId });
  return c.json({ result: projects });
});

const api = new TheAPI({
  roles,
  migrationDirs: [usersMigrationDir, oauthMigrationDir],
  routings: [middlewares.email, users, login, oauth.routings],
});

// REQUIRED: mount before init(), up() or upBun().
oauth.mount(api);
await api.up();
```

`oauth.routings` contains the ordinary management API. `oauth.mount(api)`
installs OAuth/OIDC endpoints and delegated resources before the-api's default
JWT/response middleware. Both steps are required. Mount one instance per API.
Do not add the protocol endpoints as ordinary `Routings`: the-api would reject
opaque access tokens and wrap protocol responses.

The issuer is a stable HTTPS **origin**, without a trailing slash or path, e.g.
`https://accounts.example.com`. Reverse proxies must preserve the public path
and browser Origin header. The module never derives issuer/redirect URLs from
untrusted Host or forwarded headers. Cookies are HttpOnly, Secure and SameSite=Lax.
Use TLS for the application in production. For local development only:

```ts
createOAuthServer({
  issuer: 'http://localhost:3000',
  allowInsecureLocalhost: true,
  jwks: JSON.parse(process.env.OAUTH_JWKS_JSON!),
});
```

Keep the existing `DB_*`, `DB_WRITE_*`, `JWT_SECRET` and `AUTH_*` configuration
for `the-api-users`. The OAuth module always reads and writes state through the
writer connection to avoid replication-lag replay issues. It does not require
Redis or an additional database.

## Migrations

Run the users migration before `migrationDir` from this package. It creates:

| Table | Purpose |
| --- | --- |
| `oauthClients` | Application metadata and hashed client secrets |
| `oauthGrants` | User/client permissions, authentication time, revocation |
| `oauthCredentials` | Hashed codes, access tokens, refresh tokens and consumption state |
| `oauthSessions` | Hashed browser SSO sessions |
| `oauthInteractions` | Short-lived browser-bound login/consent transactions |

The package also exports `migrationUpdateDir` for optional idempotent maintenance
(currently an expiry index). It runs **after** `migrationDir`; it does not
recreate an existing schema or modify `users`. If an existing users table needs
updating, use `migrationUpdateDir` from **the-api-users** separately.

Schedule `await oauth.cleanup()` periodically, e.g. hourly. It deletes expired
interactions/sessions and expired grant families. Do not delete consumed codes
or refresh tokens early: they are needed to detect replay. Actual authorization
checks expiry regardless of cleanup timing.

## Permissions and administration

| Endpoint | Required permission |
| --- | --- |
| `GET /oauth/clients` | `oauthClients.get` |
| `GET /oauth/clients/:id` | `oauthClients.get` |
| `POST /oauth/clients` | `oauthClients.post` |
| `PATCH /oauth/clients/:id` | `oauthClients.patch` |
| `DELETE /oauth/clients/:id` | `oauthClients.delete` |
| `GET /oauth/grants` | `oauthGrants.get` |
| `DELETE /oauth/grants/:id` | `oauthGrants.delete` |

These endpoints use the normal **the-api-users JWT**, not an OAuth access token,
and return the normal `{ result, error, ... }` envelope. Permission checks use
`getPermissions()` and `checkWildcardPermissions()` from `the-api-roles` against
the user's current database role. Missing roles service denies management
access. No role name is special. `oauthClients.*` and `*` work according to
the-api-roles wildcard semantics.

Client permissions grant management of all clients. Grant endpoints always
list/revoke only the current user's grants, even with `*`. Lists currently
return at most 100 newest records. Client secrets/hashes never appear in reads.

Create a server-side client:

```bash
curl "$API/oauth/clients" \
  -H "Authorization: Bearer $LOCAL_USER_JWT" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Project dashboard",
    "type": "confidential",
    "redirectUris": ["https://dashboard.example.com/callback"],
    "scopes": ["openid", "profile", "email", "offline_access", "projects.read"]
  }'
```

`result.id` is the OAuth `client_id`. `result.clientSecret` is returned **once**;
store it on the application's backend. Only its SHA-256 digest is stored here.
To replace a lost secret, create a replacement client and retire the old one.

| `type` | Intended client | Token endpoint authentication |
| --- | --- | --- |
| `confidential` | Server-side web app | `client_secret_basic` or `client_secret_post` |
| `public` | Browser SPA | `client_id`, no secret |
| `native` | Mobile/desktop app | `client_id`, no secret |

Every type must use PKCE S256. Native redirect URIs may use HTTPS, an exact
loopback HTTP URL, or a reverse-domain custom scheme such as
`com.example.app:/callback`. Register loopback ports explicitly; variable ports
are not supported in this version. Use a system browser for native login.

PATCH accepts `name`, `redirectUris`, `scopes`, `disabled`. Every edit revokes
existing grants. Client type and ID cannot be edited. DELETE removes the client
and cascades to grants/credentials. Public/native clients must never embed a
server secret.

## OAuth2 / OIDC flow

Discover the server at:

```
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
GET /oauth/jwks
```

1. The client generates an unpredictable `state`, `nonce` (for OIDC) and a PKCE
   verifier of 43–128 permitted characters. Keep them in its login transaction.
2. Redirect the browser to the following request. `code_challenge` is
   `BASE64URL(SHA256(code_verifier))`, with no padding.

```text
GET /oauth/authorize
  ?response_type=code
  &client_id=...
  &redirect_uri=https%3A%2F%2Fdashboard.example.com%2Fcallback
  &scope=openid%20profile%20email%20offline_access%20projects.read
  &state=...
  &nonce=...
  &code_challenge=...
  &code_challenge_method=S256
```

3. The server shows login and consent. An existing SSO session skips password
   entry. Consent is explicit on every new authorization request.
4. The callback receives `code`, the original `state` and `iss`. The client must
   check `state` and expected issuer, then exchange the code:

```bash
curl "$API/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode 'redirect_uri=https://dashboard.example.com/callback'
```

Omit `client_secret` for SPA/native clients. Token endpoints accept URL-encoded
forms, not JSON. Standard OAuth responses have **no the-api envelope**:

```json
{
  "access_token": "opaque-random-token",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "openid profile email offline_access projects.read",
  "refresh_token": "another-random-token",
  "id_token": "signed-RS256-JWT"
}
```

`expires_in` is the remaining lifetime and may be one second less than the
configured TTL. `id_token` is issued on code exchange only when `openid` was
requested. Validate its signature using JWKS, `iss`, `aud`, expiry and the
original `nonce`. Use a standard OIDC client library for those checks.
The application then establishes its own login session.

`refresh_token` is issued only with `offline_access` (also allowed for pure
OAuth2 requests). Refresh replaces the token and retains the original grant's
absolute expiry. Clients must serialize refreshes and persist the replacement:

```bash
curl "$API/oauth/token" \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN"
```

An optional `scope` can reduce access, never expand it. Reusing a consumed code
or refresh token revokes its whole grant family, including issued access tokens.
Refresh responses do not contain a new ID token. A new sign-in uses the code flow.

`prompt=login` forces the login page; `prompt=consent` shows consent;
`max_age` limits the authentication age. `prompt=none` returns `login_required`
or `consent_required`: silent consent reuse is not implemented. Unsupported
prompts and response modes are rejected.

## User information and delegated API access

```bash
curl "$API/oauth/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN"
curl "$API/integrations/projects" -H "Authorization: Bearer $ACCESS_TOKEN"
```

`/oauth/userinfo` requires `openid`; it returns `sub` plus allowed claims:

- `profile`: `name`, `preferred_username`, `picture`, `locale`, `zoneinfo`.
- `email`: `email`, `email_verified`.

An ID token is not an API credential. OAuth access tokens are opaque and are
not accepted by ordinary `/users` or `/login` endpoints. Use `oauth.resource()`
for delegated endpoints. It checks token lifetime, grant/client status, current
user bans/deletion/password changes, required scopes and their configured
permissions. It passes `{ userId, clientId, grantId, scopes, user }` as the
second argument. `identity.user` omits password/code/token fields, but its profile
fields still require scope-based disclosure. Select only fields your endpoint
is allowed to return. Domain ownership checks remain
the application's responsibility.

Resource handlers receive `db`, `dbWrite`, `oauth` context variables. They run
before ordinary the-api middleware and must return a `Response` such as
`c.json(...)`; they do not receive ordinary middleware services automatically.
For another adapter in the same process, use
`await oauth.verifyAccessToken(token, ['projects.read'])` after mounting.

Access tokens belong to this issuer's API. Arbitrary downstream resource
servers/resource indicators are not supported. Introspection is restricted to
a confidential client inspecting its own access tokens. Browser CORS is enabled
for token/userinfo/revocation and registered resource endpoints only for exact
origins present in active `public` clients' redirect URIs. Cookies are not used
for those API requests.

## Revoke access and end SSO sessions

```bash
curl "$API/oauth/revoke" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "token=$REFRESH_TOKEN"

curl "$API/oauth/introspect" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "token=$ACCESS_TOKEN"
```

Revocation of either access or refresh token revokes that entire grant. Unknown
tokens return HTTP 200. Introspection returns `{ "active": false }` for invalid
or foreign tokens. Users can also revoke their own grants with the management
API and a normal users JWT.

`POST /oauth/logout` ends the current browser SSO session. Call it from the
issuer origin with cookies; Origin must match. It does not revoke OAuth grants
or log the user out of downstream applications. This is a local logout endpoint,
not OIDC RP-Initiated Logout or back-channel logout.

## Replace the login and consent pages

Pass `renderLogin` and/or `renderConsent` to `createOAuthServer`. Each receives
a `PageModel` and returns HTML (or a Promise of HTML). Rendering remains on the
issuer origin so browser cookies and CSRF checks work without cross-site auth.
Only override the page you want to replace. Built-in renderers are exported.

```ts
import { createOAuthServer, escapeHtml as html } from 'the-api-users-oauth2-server';

const oauth = createOAuthServer({
  issuer: process.env.OAUTH_ISSUER!,
  jwks: JSON.parse(process.env.OAUTH_JWKS_JSON!),
  renderConsent: (page) => `<!doctype html>
    <html lang="en"><head><meta charset="utf-8"><title>Permission</title>
      <link rel="stylesheet" href="/assets/oauth.css"></head><body>
    <h1>Allow ${html(page.clientName)}?</h1>
    <ul>${page.scopes.map(s => `<li>${html(s.description)}</li>`).join('')}</ul>
    <form method="post" action="${html(page.consentEndpoint)}">
      <input type="hidden" name="csrf" value="${html(page.csrf)}">
      <button name="decision" value="allow">Allow</button>
      <button name="decision" value="deny">Deny</button>
    </form></body></html>`,
});
```

`PageModel` fields:

| Field | Meaning |
| --- | --- |
| `interactionId` | Server-owned interaction ID |
| `csrf` | Fresh CSRF token, submit unchanged |
| `nonce` | CSP nonce for scripts in this response |
| `clientName` | Untrusted display text: HTML-escape it |
| `scopes` | `{ name, description }[]`, display text to escape |
| `loginEndpoint` | Existing users login endpoint; defaults to `/login` |
| `sessionEndpoint` | POST target to exchange a users JWT for the SSO session |
| `consentEndpoint` | POST target for Allow/Deny |

For a completely custom login page:

1. Render a form and JavaScript with `<script nonce="...page.nonce...">`.
2. Submit credentials as JSON to `page.loginEndpoint`. This is the existing
   `/login`, returning `{ result: { token }, error: false }`.
3. POST URL-encoded `{ token: result.token, csrf: page.csrf }` to
   `page.sessionEndpoint` using same-origin `fetch` and cookies.
4. Read the raw JSON `{ continue: "/oauth/interaction/..." }` and navigate there.
   It renders consent, including a new CSRF token.

Do not put login tokens in URLs/localStorage or expose them to third-party
scripts. The built-in page keeps the token in memory only. Do not send passwords
to the OAuth session endpoint. A custom page can also use the existing social
login routes and pass the resulting local JWT through the same bridge.

Use `escapeHtml` for HTML. For data embedded in a script, use
`JSON.stringify(value).replace(/</g, '\\u003c')`. The CSP allows same-origin
styles/images/fetch, nonce-authorized scripts and same-origin forms; it blocks
frames and external resources. Host your own assets under the issuer origin.
An external SPA can supply its HTML shell through the renderer and serve its
assets on this origin (e.g. via reverse proxy). Arbitrary cross-origin login
page redirects are intentionally not provided.

The default pages handle email/password sign-in and consent only. Registration,
email confirmation, recovery, MFA and provider buttons belong to your existing
identity frontend; add them through custom renderers. `/login` errors such as
`EMAIL_NOT_CONFIRMED` are displayed without bypassing verification.

## Options and scope policy

| Option | Default |
| --- | --- |
| `issuer`, `jwks` | Required |
| `jwtSecret` | `process.env.JWT_SECRET` (must be nonempty) |
| `loginPath` | `/login` (same origin) |
| `accessTokenTtl` | 600 seconds |
| `idTokenTtl` | 600 seconds |
| `codeTtl` | 60 seconds |
| `interactionTtl` | 600 seconds |
| `sessionTtl` | 28,800 seconds |
| `refreshTokenTtl` | 2,592,000 seconds; absolute grant lifetime |
| `allowInsecureLocalhost` | false |
| `scopes` | Additional `{ description, permission? }` definitions |
| `renderLogin`, `renderConsent` | Built-in HTML |
| `onError` | Optional internal-error callback |

Built-in scopes are `openid`, `profile`, `email`, `offline_access`. An application
may request only scopes registered for that client. With `permission`, the user
must additionally have that current permission to consent, refresh and use the
token. Without it, client allowlist + user consent are sufficient. A missing
roles service fails permission-gated scopes closed. Scopes do not turn users
into administrators and do not grant ownership of domain records.

Protocol errors use standard names including `invalid_request`, `invalid_client`,
`invalid_grant`, `invalid_scope`, `invalid_token`, `insufficient_scope`,
`access_denied`. Invalid callbacks are never redirected. Internal errors are
reported as `server_error`; use `onError` for private operational logging.

## Tests and deployment scope

```bash
bun run build
bun run check:examples
bun run test  # unit tests; integration suite is skipped without the URL

# Use a dedicated test database; tests create/drop their own random schema.
OAUTH_TEST_DATABASE_URL=postgres://postgres:password@127.0.0.1:5432/test_db bun run test
```

Tests exercise real PostgreSQL transactions and actual TheAPI/users routes.
This version implements the documented code-flow subset; it is not an
OpenID-certified provider. Implicit/password grants, client_credentials,
dynamic client registration, arbitrary resource audiences, device flow, PAR,
JAR, DPoP, pairwise subjects, silent consent reuse and federated logout are not
implemented or advertised. Public deployment still needs application-level
rate limits on login/authorization, TLS, secret management and normal monitoring.

Protocol references: [OAuth2](https://www.rfc-editor.org/rfc/rfc6749.html),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html),
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).
