# AGENTS.md

This package adds an optional OAuth2 authorization server and an OpenID Connect
authorization-code flow to `the-api-users`. Read README.md before changing its
public API. Do not duplicate user registration, password hashing, email
verification, or external-provider login from `the-api-users`.

## Architecture

- `src/index.ts`: factory, migration exports, framework mounting and resource API.
- `src/modules/management.ts`: ordinary `Routings`, the-api response envelope.
- `src/modules/protocol.ts`: standard OAuth/OIDC HTTP responses and interactions.
- `src/lib/server.ts`: clients, credentials, grants, token validation and signing.
- `src/lib/pages.ts`: replaceable login and consent HTML renderers.
- `src/lib/security.ts`: small cryptographic and request-validation helpers.
- `migrations`: Knex migrations, with a CommonJS package boundary.
- `migrationsUpdate`: optional idempotent maintenance migrations.

The protocol adapter MUST mount before `TheAPI.init()`, `up()` or `upBun()`:
the-api's default middleware otherwise rejects opaque bearer tokens and wraps
OAuth responses. Management routings go in `TheAPI({ routings })`. Use the
writer database for protocol state, even when an application has read replicas.

## Access control

Use named permissions with `the-api-roles`, never hard-code role names such as
admin/root. Management permissions are `oauthClients.get`, `.post`, `.patch`,
`.delete` and `oauthGrants.get`, `.delete`. Missing roles service denies access.
Grant listing/revocation is always restricted to the current user, including
users with wildcard permissions. Optional scope permissions further restrict
delegation using the user's current database role. Scopes never replace domain
ownership checks.

## Security invariants

- Only authorization_code + S256 PKCE and rotating refresh_token grants.
- Exact registered redirect URI comparison; no wildcard redirects.
- Public/native clients never have a secret. Confidential clients authenticate.
- One-use codes and refresh credentials are consumed under a grant row lock.
- Replay revocation must COMMIT, not roll back when returning invalid_grant.
- Retain consumed credentials until grant expiry for replay detection.
- Random credentials and client secrets are stored hashed. Do not log them.
- Separate RSA signing keys from the local users JWT_SECRET. Publish public JWK
  members only. Never commit private keys or production env files.
- Browser interactions require a bound HttpOnly cookie, CSRF token, same-origin
  POST, expiry, and one-use completion. Escape untrusted HTML and script data.
- Never accept userId, scopes or redirect_uri from a consent form as authority.
- Check bans, deletion, password-change invalidation, current scope permissions,
  client status and grant revocation when accepting access tokens.
- Access tokens are opaque and issued only for this issuer's resource adapter.
  ID tokens prove identity to a client and are not API bearer credentials.
- Keep protocol errors outside the-api envelopes; do not expose internal errors.

## Verification

```
bun install
bun run build
bun run test
OAUTH_TEST_DATABASE_URL=postgres://postgres:password@127.0.0.1:5432/test_db bun run test
```

Integration tests require an explicitly selected PostgreSQL database. They use
an isolated random schema and remove it afterwards. Include end-to-end tests
with actual the-api-users login, TheAPI mounting, pages, client permissions,
PKCE, invalid redirects, replay, parallel refreshes, revocation, key discovery,
custom renderers, SPA and native clients. Keep README examples in sync with the
exported API. Do not claim OIDC certification or unimplemented extensions.

Local development currently uses package.json `link:` overrides registered with
`bun link` in the sibling repositories because their versions are not all published. Before
publishing, publish compatible dependency versions and remove local overrides
as documented in README.md. Do not publish automatically.
