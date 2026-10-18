// src/index.ts
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Hono as Hono2 } from "hono";

// src/lib/server.ts
import { importJWK, jwtVerify, SignJWT } from "jose";

// src/lib/security.ts
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

class OAuthError extends Error {
  error;
  status;
  constructor(error, status = 400, description = error) {
    super(description);
    this.error = error;
    this.status = status;
  }
}
var random = () => randomBytes(32).toString("base64url");
var digest = (value) => createHash("sha256").update(value).digest("hex");
var challenge = (value) => createHash("sha256").update(value).digest("base64url");
var equal = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};
var expires = (seconds) => new Date(Date.now() + seconds * 1000);
var active = (user, authTime) => !!user && !user.isDeleted && !user.isBanned && !user.isBlocked && (!authTime || !user.timePasswordChanged || +new Date(user.timePasswordChanged) <= +new Date(authTime));
var permitted = (roles, user, permission) => !!roles && roles.checkWildcardPermissions({ key: permission, permissions: roles.getPermissions(user.role ? [user.role] : []) });
var splitScope = (scope) => [...new Set(scope.split(" ").filter(Boolean))];
var escapeHtml = (value) => value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
var scriptJson = (value) => JSON.stringify(value).replace(/</g, "\\u003c");
function singleParams(params) {
  const result = Object.create(null);
  for (const [key, value] of params) {
    if (Object.hasOwn(result, key))
      throw new OAuthError("invalid_request", 400, "Repeated parameter");
    result[key] = value;
  }
  return result;
}
async function form(c) {
  if (!c.req.header("content-type")?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    throw new OAuthError("invalid_request", 400, "Use application/x-www-form-urlencoded");
  }
  const body = await c.req.text();
  if (Buffer.byteLength(body) > 16384)
    throw new OAuthError("invalid_request", 413);
  return singleParams(new URLSearchParams(body));
}
function loopback(url) {
  return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}
function validRedirect(value, type, insecure) {
  try {
    const url = new URL(value);
    if (url.hash || url.username || url.password || value.includes("*"))
      return false;
    if (url.protocol === "https:")
      return true;
    if (url.protocol === "http:" && loopback(url) && (insecure || type === "native"))
      return true;
    return type === "native" && /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/.test(url.protocol) && !url.host;
  } catch {
    return false;
  }
}

// src/lib/server.ts
class OAuthService {
  options;
  scopes;
  signingKey;
  publicJwks;
  constructor(options) {
    const issuer = new URL(options.issuer);
    if (issuer.origin !== options.issuer || issuer.username || issuer.password || issuer.protocol !== "https:" && !(options.allowInsecureLocalhost && issuer.protocol === "http:" && loopback(issuer))) {
      throw new Error("issuer must be an HTTPS origin (or explicitly allowed local HTTP origin)");
    }
    const keys = options.jwks?.keys;
    if (!keys?.length || !keys[0].d || keys.some((k) => k.kty !== "RSA" || !k.kid || !k.n || !k.e || k.alg && k.alg !== "RS256") || new Set(keys.map((k) => k.kid)).size !== keys.length || keys.some((k) => Buffer.from(k.n, "base64url").length < 256)) {
      throw new Error("jwks requires unique kid values and RSA keys >= 2048 bits; first key must be private");
    }
    const jwtSecret = options.jwtSecret ?? process.env.JWT_SECRET;
    if (!jwtSecret)
      throw new Error("JWT_SECRET or jwtSecret is required to verify the-api-users login tokens");
    const loginPath = options.loginPath ?? "/login";
    if (!loginPath.startsWith("/") || loginPath.startsWith("//") || new URL(loginPath, options.issuer).origin !== options.issuer)
      throw new Error("loginPath must be same-origin");
    this.options = {
      ...options,
      jwtSecret,
      loginPath,
      accessTokenTtl: options.accessTokenTtl ?? 600,
      refreshTokenTtl: options.refreshTokenTtl ?? 2592000,
      sessionTtl: options.sessionTtl ?? 28800,
      interactionTtl: options.interactionTtl ?? 600,
      codeTtl: options.codeTtl ?? 60,
      idTokenTtl: options.idTokenTtl ?? 600
    };
    for (const key of ["accessTokenTtl", "refreshTokenTtl", "sessionTtl", "interactionTtl", "codeTtl", "idTokenTtl"]) {
      if (!Number.isSafeInteger(this.options[key]) || this.options[key] <= 0)
        throw new Error(`${key} must be positive seconds`);
    }
    this.scopes = {
      openid: { description: "Sign you in" },
      profile: { description: "Read your profile" },
      email: { description: "Read your email address" },
      offline_access: { description: "Keep access until you revoke it" },
      ...options.scopes
    };
    for (const scope of Object.keys(this.scopes))
      if (!/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))
        throw new Error("Invalid scope name");
    this.signingKey = importJWK({ ...keys[0], alg: "RS256" }, "RS256");
    this.publicJwks = { keys: keys.map(({ kty, kid, n, e }) => ({ kty, kid, n, e, use: "sig", alg: "RS256" })) };
  }
  async client(db, id) {
    const client = await db("oauthClients").where({ id }).first();
    if (!client || client.disabled)
      throw new OAuthError("invalid_client", 401);
    return client;
  }
  async authenticateClient(db, body, authorization) {
    let id = body.client_id;
    let secret = body.client_secret;
    if (authorization) {
      if (!/^Basic /i.test(authorization) || secret !== undefined)
        throw new OAuthError("invalid_client", 401);
      try {
        const pair = Buffer.from(authorization.slice(6), "base64").toString();
        const colon = pair.indexOf(":");
        if (colon < 0)
          throw new Error;
        const decode = (s) => decodeURIComponent(s.replace(/\+/g, " "));
        const basicId = decode(pair.slice(0, colon));
        if (id && id !== basicId)
          throw new Error;
        id = basicId;
        secret = decode(pair.slice(colon + 1));
      } catch {
        throw new OAuthError("invalid_client", 401);
      }
    }
    const client = await this.client(db, id || "");
    if (client.type === "confidential") {
      if (!secret || !client.secretHash || !equal(digest(secret), client.secretHash))
        throw new OAuthError("invalid_client", 401);
    } else if (secret !== undefined || authorization)
      throw new OAuthError("invalid_client", 401);
    return client;
  }
  async authorization(db, p) {
    const client = await this.client(db, p.client_id || "");
    if (!client.redirectUris.includes(p.redirect_uri))
      throw new OAuthError("invalid_request", 400, "Unregistered redirect_uri");
    if (p.response_type !== "code")
      throw new OAuthError("unsupported_response_type");
    if (p.response_mode && p.response_mode !== "query")
      throw new OAuthError("invalid_request");
    if (p.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge || ""))
      throw new OAuthError("invalid_request", 400, "PKCE S256 is required");
    const scopes = splitScope(p.scope || "");
    if (!scopes.length || scopes.some((s) => !Object.hasOwn(this.scopes, s) || !client.scopes.includes(s)))
      throw new OAuthError("invalid_scope");
    if (p.prompt && !["login", "consent", "none"].includes(p.prompt))
      throw new OAuthError("invalid_request", 400, "Unsupported prompt");
    if (p.max_age !== undefined && (!/^\d+$/.test(p.max_age) || !Number.isSafeInteger(Number(p.max_age))))
      throw new OAuthError("invalid_request");
    for (const unsupported of ["request", "request_uri", "claims", "resource", "registration"]) {
      if (p[unsupported] !== undefined)
        throw new OAuthError("invalid_request", 400, `${unsupported} is not supported`);
    }
    return {
      client_id: client.id,
      redirect_uri: p.redirect_uri,
      scope: scopes.join(" "),
      code_challenge: p.code_challenge,
      state: p.state,
      nonce: p.nonce,
      prompt: p.prompt,
      max_age: p.max_age === undefined ? undefined : Number(p.max_age)
    };
  }
  async localUser(db, token) {
    try {
      const { payload } = await jwtVerify(token, new TextEncoder().encode(this.options.jwtSecret), { algorithms: ["HS256"], requiredClaims: ["exp", "iat"] });
      if (!payload.userId || !Array.isArray(payload.roles) || payload.roles.includes("guest"))
        throw new Error;
      const user = await db("users").where({ id: payload.userId }).first();
      const authTime = new Date(Number(payload.iat) * 1000 + 999);
      if (!active(user, authTime))
        throw new Error;
      return { user, authTime };
    } catch {
      throw new OAuthError("access_denied", 401, "A valid the-api-users login token is required");
    }
  }
  checkScopes(services, user, scope) {
    for (const name of splitScope(scope)) {
      const definition = this.scopes[name];
      if (!definition || "permission" in definition && definition.permission && !permitted(services.roles, user, definition.permission)) {
        throw new OAuthError("invalid_scope", 403);
      }
    }
  }
  async createCode(db, request, user, authTime) {
    const id = random();
    const code = random();
    await db("oauthGrants").insert({ id, clientId: request.client_id, userId: user.id, scope: request.scope, authTime, expiresAt: expires(this.options.refreshTokenTtl) });
    await db("oauthCredentials").insert({ hash: digest(code), kind: "code", grantId: id, expiresAt: expires(this.options.codeTtl), data: JSON.stringify({ redirectUri: request.redirect_uri, challenge: request.code_challenge, nonce: request.nonce }) });
    return code;
  }
  async tokens(db, grant, scope, nonce, withId = true) {
    const accessToken = random();
    const accessExpires = new Date(Math.min(+expires(this.options.accessTokenTtl), +new Date(grant.expiresAt)));
    await db("oauthCredentials").insert({ hash: digest(accessToken), kind: "access", grantId: grant.id, data: JSON.stringify({ scope }), expiresAt: accessExpires });
    const response = { access_token: accessToken, token_type: "Bearer", expires_in: Math.max(0, Math.floor((+accessExpires - Date.now()) / 1000)), scope };
    if (splitScope(scope).includes("offline_access")) {
      const refresh = random();
      await db("oauthCredentials").insert({ hash: digest(refresh), kind: "refresh", grantId: grant.id, data: JSON.stringify({ scope }), expiresAt: grant.expiresAt });
      response.refresh_token = refresh;
    }
    if (withId && splitScope(scope).includes("openid")) {
      response.id_token = await new SignJWT({ auth_time: Math.floor(+new Date(grant.authTime) / 1000), ...nonce !== undefined ? { nonce } : {} }).setProtectedHeader({ alg: "RS256", kid: this.publicJwks.keys[0].kid, typ: "JWT" }).setIssuer(this.options.issuer).setSubject(String(grant.userId)).setAudience(grant.clientId).setIssuedAt().setExpirationTime(`${this.options.idTokenTtl}s`).sign(await this.signingKey);
    }
    return response;
  }
  async exchange(services, client, body) {
    const kind = body.grant_type === "authorization_code" ? "code" : body.grant_type === "refresh_token" ? "refresh" : undefined;
    if (!kind)
      throw new OAuthError("unsupported_grant_type");
    const raw = kind === "code" ? body.code : body.refresh_token;
    if (!raw)
      throw new OAuthError("invalid_request");
    const result = await services.db.transaction(async (tx) => {
      const initial = await tx("oauthCredentials").where({ hash: digest(raw), kind }).first();
      if (!initial)
        throw new OAuthError("invalid_grant");
      const grant = await tx("oauthGrants").where({ id: initial.grantId }).forUpdate().first();
      const credential = await tx("oauthCredentials").where({ hash: initial.hash }).first();
      if (!grant || grant.clientId !== client.id || grant.revoked || +new Date(grant.expiresAt) <= Date.now())
        throw new OAuthError("invalid_grant");
      if (kind === "code" && (body.redirect_uri !== credential.data.redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier || "") || !equal(challenge(body.code_verifier), credential.data.challenge)))
        throw new OAuthError("invalid_grant");
      if (credential.consumedAt) {
        await tx("oauthGrants").where({ id: grant.id }).update({ revoked: true });
        return null;
      }
      if (+new Date(credential.expiresAt) <= Date.now())
        throw new OAuthError("invalid_grant");
      const user = await tx("users").where({ id: grant.userId }).first();
      if (!active(user, grant.authTime))
        throw new OAuthError("invalid_grant");
      let scope = kind === "code" ? grant.scope : credential.data.scope;
      if (kind === "refresh" && body.scope !== undefined) {
        const requested = splitScope(body.scope);
        if (!requested.length || requested.some((s) => !splitScope(scope).includes(s)))
          throw new OAuthError("invalid_scope");
        scope = requested.join(" ");
      }
      if (splitScope(scope).some((s) => !client.scopes.includes(s)))
        throw new OAuthError("invalid_scope");
      this.checkScopes(services, user, scope);
      await tx("oauthCredentials").where({ hash: initial.hash }).update({ consumedAt: new Date });
      return this.tokens(tx, grant, scope, credential.data.nonce, kind === "code");
    });
    if (!result)
      throw new OAuthError("invalid_grant");
    return result;
  }
  async access(services, token, required = []) {
    const credential = await services.db("oauthCredentials").where({ hash: digest(token), kind: "access" }).first();
    if (!credential || +new Date(credential.expiresAt) <= Date.now())
      throw new OAuthError("invalid_token", 401);
    const grant = await services.db("oauthGrants").where({ id: credential.grantId }).first();
    if (!grant || grant.revoked || +new Date(grant.expiresAt) <= Date.now())
      throw new OAuthError("invalid_token", 401);
    const client = await services.db("oauthClients").where({ id: grant.clientId, disabled: false }).first();
    const user = await services.db("users").where({ id: grant.userId }).first();
    if (!client || !active(user, grant.authTime))
      throw new OAuthError("invalid_token", 401);
    const scopes = splitScope(credential.data.scope);
    if (scopes.some((s) => !client.scopes.includes(s)))
      throw new OAuthError("invalid_token", 401);
    if (required.some((s) => !scopes.includes(s)))
      throw new OAuthError("insufficient_scope", 403);
    this.checkScopes(services, user, scopes.join(" "));
    const safeUser = {
      id: user.id,
      role: user.role,
      fullName: user.fullName,
      displayName: user.displayName,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
      avatar: user.avatar,
      locale: user.locale,
      timezone: user.timezone,
      isBanned: user.isBanned,
      isDeleted: user.isDeleted
    };
    return { userId: user.id, clientId: client.id, grantId: grant.id, scopes, user: safeUser };
  }
  profile(identity) {
    const { user, scopes } = identity;
    return {
      sub: String(user.id),
      ...scopes.includes("profile") ? { name: user.fullName ?? undefined, preferred_username: user.displayName ?? undefined, picture: user.avatar ?? undefined, locale: user.locale ?? undefined, zoneinfo: user.timezone ?? undefined } : {},
      ...scopes.includes("email") ? { email: user.email ?? undefined, email_verified: !!user.isEmailVerified } : {}
    };
  }
  validateClient(body) {
    const type = body.type ?? "confidential";
    if (!["confidential", "public", "native"].includes(String(type)) || typeof body.name !== "string" || !body.name.trim() || body.name.length > 255 || !Array.isArray(body.redirectUris) || !body.redirectUris.length || body.redirectUris.length > 20 || body.redirectUris.some((u) => typeof u !== "string" || u.length > 2048 || !validRedirect(u, String(type), !!this.options.allowInsecureLocalhost)) || !Array.isArray(body.scopes) || !body.scopes.length || body.scopes.some((s) => typeof s !== "string" || !Object.hasOwn(this.scopes, s)))
      throw new OAuthError("invalid_client_metadata");
    return { name: body.name.trim(), type, redirectUris: JSON.stringify([...new Set(body.redirectUris)]), scopes: JSON.stringify([...new Set(body.scopes)]) };
  }
}

// src/modules/protocol.ts
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";

// src/lib/pages.ts
var page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;
var renderLogin = (m) => page("Sign in", `
  <p>Continue to ${escapeHtml(m.clientName)}</p>
  <form id="login"><p><label>Email <input name="email" type="email" autocomplete="username" required></label></p>
  <p><label>Password <input name="password" type="password" autocomplete="current-password" required></label></p>
  <button type="submit">Sign in</button></form><p id="error" role="alert"></p>
  <script nonce="${escapeHtml(m.nonce)}">
  const config = ${scriptJson({ login: m.loginEndpoint, session: m.sessionEndpoint, csrf: m.csrf })};
  document.querySelector('#login').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.target.querySelector('button'); button.disabled = true;
    try {
      const fields = new FormData(event.target);
      const response = await fetch(config.login, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: fields.get('email'), password: fields.get('password') }) });
      const data = await response.json();
      if (data.error || !data.result?.token) throw new Error(data.result?.name || 'Sign in failed');
      const session = await fetch(config.session, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ csrf: config.csrf, token: data.result.token }) });
      const result = await session.json();
      if (!session.ok) throw new Error(result.error_description || 'Sign in failed');
      location.assign(result.continue);
    } catch (error) { document.querySelector('#error').textContent = error.message; }
    finally { button.disabled = false; }
  });
  </script>`);
var renderConsent = (m) => page("Allow access?", `
  <p>${escapeHtml(m.clientName)} requests permission to:</p>
  <ul>${m.scopes.map((s) => `<li>${escapeHtml(s.description)} <small>(${escapeHtml(s.name)})</small></li>`).join("")}</ul>
  <form method="post" action="${escapeHtml(m.consentEndpoint)}">
    <input type="hidden" name="csrf" value="${escapeHtml(m.csrf)}">
    <button name="decision" value="allow" type="submit">Allow</button>
    <button name="decision" value="deny" type="submit">Deny</button>
  </form>`);

// src/modules/protocol.ts
var bearer = (c) => {
  const match = /^Bearer ([^\s]+)$/i.exec(c.req.header("authorization") || "");
  if (!match)
    throw new OAuthError("invalid_token", 401);
  return match[1];
};
function protocol(service, getServices) {
  const app = new Hono;
  const { options: o } = service;
  const secure = o.issuer.startsWith("https:");
  const sessionCookie = secure ? "__Secure-oauth-session" : "oauth-session";
  const interactionCookie = (id) => `${secure ? "__Secure-" : ""}oauth-i-${id}`;
  const cookieOptions = { httpOnly: true, secure, sameSite: "Lax", path: "/oauth" };
  const origin = (c) => {
    if (c.req.header("origin") !== o.issuer)
      throw new OAuthError("access_denied", 403, "Same-origin request required");
  };
  const redirect = (request, values) => {
    const url = new URL(request.redirect_uri);
    for (const [k, v] of Object.entries({ ...values, iss: o.issuer, ...request.state !== undefined ? { state: request.state } : {} }))
      url.searchParams.set(k, v);
    return url.toString();
  };
  const session = async (c, db) => {
    const raw = getCookie(c, sessionCookie);
    if (!raw)
      return;
    const row = await db("oauthSessions").where({ hash: digest(raw) }).first();
    if (!row || +new Date(row.expiresAt) <= Date.now())
      return;
    const user = await db("users").where({ id: row.userId }).first();
    return active(user, row.authTime) ? { user, authTime: new Date(row.authTime) } : undefined;
  };
  const interaction = async (c, db, csrf, lock = false) => {
    const id = c.req.param("id") || "";
    let query = db("oauthInteractions").where({ id });
    if (lock)
      query = query.forUpdate();
    const row = await query.first();
    const browser = getCookie(c, interactionCookie(id));
    if (!row || row.finished || +new Date(row.expiresAt) <= Date.now() || !browser || !equal(row.browserHash, digest(browser)) || csrf !== undefined && !equal(row.csrfHash, digest(csrf)))
      throw new OAuthError("invalid_request", 400, "Expired or invalid interaction");
    return row;
  };
  app.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    await next();
  });
  app.onError((error, c) => {
    const known = error instanceof OAuthError;
    if (!known)
      o.onError?.(error);
    if (known && error.status === 401)
      c.header("WWW-Authenticate", error.error === "invalid_client" ? 'Basic realm="oauth"' : 'Bearer error="invalid_token"');
    return c.json({ error: known ? error.error : "server_error", error_description: known ? error.message : "Unexpected server error" }, known ? error.status : 500);
  });
  const discovery = () => ({
    issuer: o.issuer,
    authorization_endpoint: `${o.issuer}/oauth/authorize`,
    token_endpoint: `${o.issuer}/oauth/token`,
    userinfo_endpoint: `${o.issuer}/oauth/userinfo`,
    jwks_uri: `${o.issuer}/oauth/jwks`,
    revocation_endpoint: `${o.issuer}/oauth/revoke`,
    introspection_endpoint: `${o.issuer}/oauth/introspect`,
    scopes_supported: Object.keys(service.scopes),
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    claims_supported: ["sub", "iss", "aud", "iat", "exp", "auth_time", "nonce", "name", "preferred_username", "picture", "locale", "zoneinfo", "email", "email_verified"],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false
  });
  app.get("/.well-known/openid-configuration", (c) => c.json(discovery()));
  app.get("/.well-known/oauth-authorization-server", (c) => c.json(discovery()));
  app.get("/oauth/jwks", (c) => c.json(service.publicJwks));
  app.use("/oauth/*", async (c, next) => {
    if (["/oauth/token", "/oauth/userinfo", "/oauth/revoke"].includes(c.req.path) && c.req.header("origin")) {
      const requestOrigin = c.req.header("origin");
      if (requestOrigin !== "null") {
        const clients = await getServices().db("oauthClients").where({ type: "public", disabled: false }).select("redirectUris");
        if (clients.some((client) => client.redirectUris.some((uri) => new URL(uri).origin === requestOrigin))) {
          c.header("Access-Control-Allow-Origin", requestOrigin);
          c.header("Vary", "Origin");
          c.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
          c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        }
      }
      if (c.req.method === "OPTIONS")
        return c.body(null, 204);
    }
    await next();
  });
  app.get("/oauth/authorize", async (c) => {
    const services = getServices();
    const params = singleParams(new URL(c.req.url).searchParams);
    let request;
    try {
      request = await service.authorization(services.db, params);
    } catch (error) {
      const client = params.client_id ? await services.db("oauthClients").where({ id: params.client_id, disabled: false }).first() : undefined;
      if (error instanceof OAuthError && client?.redirectUris.includes(params.redirect_uri)) {
        return c.redirect(redirect({ redirect_uri: params.redirect_uri, state: params.state }, { error: error.error }), 303);
      }
      throw error;
    }
    let signedIn = await session(c, services.db);
    if (request.prompt === "login" || request.max_age !== undefined && signedIn && (Date.now() - +signedIn.authTime) / 1000 >= request.max_age)
      signedIn = undefined;
    if (request.prompt === "none")
      return c.redirect(redirect(request, { error: signedIn ? "consent_required" : "login_required" }), 303);
    const id = random();
    const browser = random();
    const csrf = random();
    await services.db("oauthInteractions").insert({ id, browserHash: digest(browser), csrfHash: digest(csrf), request: JSON.stringify(request), userId: signedIn?.user.id, authTime: signedIn?.authTime, expiresAt: expires(o.interactionTtl) });
    setCookie(c, interactionCookie(id), browser, { ...cookieOptions, maxAge: o.interactionTtl });
    return c.redirect(`/oauth/interaction/${id}`, 303);
  });
  app.get("/oauth/interaction/:id", async (c) => {
    const services = getServices();
    const row = await interaction(c, services.db);
    const client = await service.client(services.db, row.request.client_id);
    let user = row.userId ? await services.db("users").where({ id: row.userId }).first() : undefined;
    if (!active(user, row.authTime))
      user = undefined;
    const csrf = random();
    await services.db("oauthInteractions").where({ id: row.id }).update({ csrfHash: digest(csrf), ...user ? {} : { userId: null, authTime: null } });
    const nonce = random();
    c.header("Content-Security-Policy", `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
    const model = {
      interactionId: row.id,
      csrf,
      nonce,
      clientName: client.name,
      scopes: splitScope(row.request.scope).map((name) => ({ name, description: service.scopes[name].description })),
      loginEndpoint: o.loginPath,
      sessionEndpoint: `/oauth/interaction/${row.id}/login`,
      consentEndpoint: `/oauth/interaction/${row.id}/consent`
    };
    const renderer = user ? o.renderConsent ?? renderConsent : o.renderLogin ?? renderLogin;
    return c.html(await renderer(model));
  });
  app.post("/oauth/interaction/:id/login", async (c) => {
    origin(c);
    const body = await form(c);
    const services = getServices();
    if (!body.csrf || !body.token)
      throw new OAuthError("invalid_request");
    const { user, authTime } = await service.localUser(services.db, body.token);
    const raw = random();
    await services.db.transaction(async (tx) => {
      const row = await interaction(c, tx, body.csrf, true);
      if ((row.request.prompt === "login" || row.request.max_age !== undefined) && Date.now() - +authTime > 60000)
        throw new OAuthError("login_required", 401);
      const old = getCookie(c, sessionCookie);
      if (old)
        await tx("oauthSessions").where({ hash: digest(old) }).delete();
      await tx("oauthSessions").insert({ hash: digest(raw), userId: user.id, authTime, expiresAt: expires(o.sessionTtl) });
      await tx("oauthInteractions").where({ id: row.id }).update({ userId: user.id, authTime, csrfHash: digest(random()) });
    });
    setCookie(c, sessionCookie, raw, { ...cookieOptions, maxAge: o.sessionTtl });
    return c.json({ continue: `/oauth/interaction/${c.req.param("id")}` });
  });
  app.post("/oauth/interaction/:id/consent", async (c) => {
    origin(c);
    const body = await form(c);
    const services = getServices();
    if (!body.csrf || !["allow", "deny"].includes(body.decision))
      throw new OAuthError("invalid_request");
    const target = await services.db.transaction(async (tx) => {
      const row = await interaction(c, tx, body.csrf, true);
      const client = await service.client(tx, row.request.client_id);
      if (!client.redirectUris.includes(row.request.redirect_uri) || splitScope(row.request.scope).some((s) => !client.scopes.includes(s)))
        throw new OAuthError("invalid_request");
      await tx("oauthInteractions").where({ id: row.id }).update({ finished: true });
      if (body.decision === "deny")
        return redirect(row.request, { error: "access_denied" });
      const signedIn = await session(c, tx);
      const user = row.userId ? await tx("users").where({ id: row.userId }).first() : undefined;
      if (!active(user, row.authTime) || !signedIn || signedIn.user.id !== user.id)
        throw new OAuthError("login_required", 401);
      service.checkScopes(services, user, row.request.scope);
      return redirect(row.request, { code: await service.createCode(tx, row.request, user, row.authTime) });
    });
    setCookie(c, interactionCookie(c.req.param("id")), "", { ...cookieOptions, maxAge: 0 });
    return c.redirect(target, 303);
  });
  app.post("/oauth/token", async (c) => {
    const body = await form(c);
    const services = getServices();
    const client = await service.authenticateClient(services.db, body, c.req.header("authorization"));
    return c.json(await service.exchange(services, client, body));
  });
  const userinfo = async (c) => c.json(service.profile(await service.access(getServices(), bearer(c), ["openid"])));
  app.get("/oauth/userinfo", userinfo);
  app.post("/oauth/userinfo", userinfo);
  app.post("/oauth/revoke", async (c) => {
    const body = await form(c);
    const { db } = getServices();
    const client = await service.authenticateClient(db, body, c.req.header("authorization"));
    if (!body.token)
      throw new OAuthError("invalid_request");
    await db.transaction(async (tx) => {
      const credential = await tx("oauthCredentials").where({ hash: digest(body.token) }).whereIn("kind", ["access", "refresh"]).first();
      if (!credential)
        return;
      await tx("oauthGrants").where({ id: credential.grantId, clientId: client.id }).update({ revoked: true });
    });
    return c.body(null, 200);
  });
  app.post("/oauth/introspect", async (c) => {
    const body = await form(c);
    const services = getServices();
    const client = await service.authenticateClient(services.db, body, c.req.header("authorization"));
    if (client.type !== "confidential")
      throw new OAuthError("invalid_client", 401);
    if (!body.token)
      throw new OAuthError("invalid_request");
    try {
      const identity = await service.access(services, body.token);
      if (identity.clientId !== client.id)
        return c.json({ active: false });
      const credential = await services.db("oauthCredentials").where({ hash: digest(body.token) }).first();
      return c.json({ active: true, sub: String(identity.userId), client_id: identity.clientId, scope: identity.scopes.join(" "), token_type: "Bearer", iss: o.issuer, aud: o.issuer, exp: Math.floor(+new Date(credential.expiresAt) / 1000) });
    } catch (error) {
      if (error instanceof OAuthError)
        return c.json({ active: false });
      throw error;
    }
  });
  app.post("/oauth/logout", async (c) => {
    origin(c);
    const raw = getCookie(c, sessionCookie);
    if (raw)
      await getServices().db("oauthSessions").where({ hash: digest(raw) }).delete();
    setCookie(c, sessionCookie, "", { ...cookieOptions, maxAge: 0 });
    return c.json({ ok: true });
  });
  return app;
}

// src/modules/management.ts
import { Routings } from "the-api-routings";
function management(service) {
  const routes = new Routings;
  routes.use("/oauth/*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    await next();
  });
  routes.errors({
    ACCESS_DENIED: { code: 403, status: 403, description: "Permission required" },
    OAUTH_INVALID_CLIENT: { code: 400, status: 400, description: "Invalid client metadata" },
    OAUTH_NOT_FOUND: { code: 404, status: 404, description: "OAuth record not found" }
  });
  const dbFor = (c) => c.var.dbWrite || c.env?.dbWrite || c.var.db || c.env?.db;
  const authorize = async (c, permission) => {
    const db = dbFor(c);
    const user = c.var.user?.userId ? await db("users").where({ id: c.var.user.userId }).first() : undefined;
    if (!active(user) || !permitted(c.var.roles || c.env?.roles, user, permission))
      throw new Error("ACCESS_DENIED");
    return { db, user };
  };
  const publicClient = ({ secretHash, ...client }) => client;
  routes.get("/oauth/clients", async (c) => {
    const { db } = await authorize(c, "oauthClients.get");
    c.set("result", (await db("oauthClients").orderBy("timeCreated", "desc").limit(100)).map(publicClient));
  });
  routes.post("/oauth/clients", async (c) => {
    const { db, user } = await authorize(c, "oauthClients.post");
    let data;
    try {
      data = service.validateClient(c.var.body || {});
    } catch {
      throw new Error("OAUTH_INVALID_CLIENT");
    }
    const id = random();
    const secret = data.type === "confidential" ? random() : undefined;
    const [client] = await db("oauthClients").insert({ ...data, id, secretHash: secret ? digest(secret) : null, createdBy: user.id }).returning("*");
    c.set("result", { ...publicClient(client), ...secret ? { clientSecret: secret } : {} });
  });
  routes.get("/oauth/clients/:id", async (c) => {
    const { db } = await authorize(c, "oauthClients.get");
    const client = await db("oauthClients").where({ id: c.req.param("id") }).first();
    if (!client)
      throw new Error("OAUTH_NOT_FOUND");
    c.set("result", publicClient(client));
  });
  routes.patch("/oauth/clients/:id", async (c) => {
    const { db } = await authorize(c, "oauthClients.patch");
    const body = c.var.body || {};
    if (Object.keys(body).some((k) => !["name", "redirectUris", "scopes", "disabled"].includes(k)) || body.disabled !== undefined && typeof body.disabled !== "boolean")
      throw new Error("OAUTH_INVALID_CLIENT");
    const client = await db.transaction(async (tx) => {
      const old = await tx("oauthClients").where({ id: c.req.param("id") }).forUpdate().first();
      if (!old)
        throw new Error("OAUTH_NOT_FOUND");
      let data;
      try {
        data = service.validateClient({ ...old, ...body });
      } catch {
        throw new Error("OAUTH_INVALID_CLIENT");
      }
      await tx("oauthGrants").where({ clientId: old.id }).update({ revoked: true });
      const [updated] = await tx("oauthClients").where({ id: old.id }).update({ ...data, disabled: body.disabled ?? old.disabled }).returning("*");
      return updated;
    });
    c.set("result", publicClient(client));
  });
  routes.delete("/oauth/clients/:id", async (c) => {
    const { db } = await authorize(c, "oauthClients.delete");
    if (!await db("oauthClients").where({ id: c.req.param("id") }).delete())
      throw new Error("OAUTH_NOT_FOUND");
    c.set("result", { ok: true });
  });
  routes.get("/oauth/grants", async (c) => {
    const { db, user } = await authorize(c, "oauthGrants.get");
    c.set("result", await db("oauthGrants").where({ userId: user.id }).orderBy("timeCreated", "desc").limit(100));
  });
  routes.delete("/oauth/grants/:id", async (c) => {
    const { db, user } = await authorize(c, "oauthGrants.delete");
    if (!await db("oauthGrants").where({ id: c.req.param("id"), userId: user.id }).update({ revoked: true }))
      throw new Error("OAUTH_NOT_FOUND");
    c.set("result", { ok: true });
  });
  return routes;
}

// src/index.ts
var moduleDir = dirname(fileURLToPath(import.meta.url));
var migrationDir = resolve(moduleDir, "../migrations");
var migrationUpdateDir = resolve(moduleDir, "../migrationsUpdate");
function createOAuthServer(options) {
  const service = new OAuthService(options);
  const routings = management(service);
  const resources = new Hono2;
  let getServices;
  let mounted = false;
  const resourcePaths = new Set;
  const services = () => {
    if (!getServices)
      throw new Error("OAuth server is not mounted");
    return getServices();
  };
  const protocolApp = protocol(service, services);
  const server = {
    routings,
    mount(api) {
      if (mounted)
        throw new Error("OAuth server is already mounted");
      mounted = true;
      getServices = () => {
        if (!api.db)
          throw new Error("OAuth server requires a PostgreSQL connection");
        return { db: api.db.dbWrite || api.db.db, roles: api.roles };
      };
      api.app.use("*", async (c, next) => {
        const path = c.req.path;
        if (path === "/.well-known/openid-configuration" || path === "/.well-known/oauth-authorization-server" || /^\/oauth\/(authorize|token|userinfo|jwks|revoke|introspect|logout)$/.test(path) || path.startsWith("/oauth/interaction/")) {
          return protocolApp.fetch(c.req.raw);
        }
        await next();
      });
      api.app.route("/", resources);
    },
    resource(method, path, scopes, handler) {
      if (mounted)
        throw new Error("Register resources before mount");
      if (!path.startsWith("/") || path.startsWith("/oauth") || path.startsWith("/.well-known"))
        throw new Error("Invalid resource path");
      if (scopes.some((scope) => !Object.hasOwn(service.scopes, scope)))
        throw new Error("Unknown resource scope");
      if (!resourcePaths.has(path)) {
        resourcePaths.add(path);
        resources.use(path, async (c, next) => {
          const origin = c.req.header("origin");
          if (origin && origin !== "null") {
            const clients = await services().db("oauthClients").where({ type: "public", disabled: false }).select("redirectUris");
            if (clients.some((client) => client.redirectUris.some((uri) => new URL(uri).origin === origin))) {
              c.header("Access-Control-Allow-Origin", origin);
              c.header("Vary", "Origin");
              c.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
              c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            }
          }
          c.header("Cache-Control", "no-store");
          await next();
        });
        resources.options(path, (c) => c.body(null, 204));
      }
      resources.on(method, path, async (c) => {
        try {
          const identity = await service.access(services(), bearer(c), scopes);
          c.set("db", services().db);
          c.set("dbWrite", services().db);
          c.set("oauth", identity);
          return await handler(c, identity);
        } catch (error) {
          const known = error instanceof OAuthError;
          if (!known)
            options.onError?.(error);
          const name = known ? error.error : "server_error";
          c.header("WWW-Authenticate", `Bearer error="${name}"`);
          return c.json({ error: name }, known ? error.status : 500);
        }
      });
      return server;
    },
    verifyAccessToken(token, scopes = []) {
      return service.access(services(), token, scopes);
    },
    async cleanup() {
      const db = services().db;
      await db.transaction(async (tx) => {
        await tx("oauthInteractions").where("expiresAt", "<", new Date).delete();
        await tx("oauthSessions").where("expiresAt", "<", new Date).delete();
        await tx("oauthGrants").where("expiresAt", "<", new Date).delete();
      });
    }
  };
  return server;
}
export {
  renderLogin,
  renderConsent,
  migrationUpdateDir,
  migrationDir,
  escapeHtml,
  createOAuthServer
};
