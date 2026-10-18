import type { PageModel } from '../types';
import { escapeHtml as e, scriptJson } from './security';

const page = (title: string, body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(title)}</title></head><body><main><h1>${e(title)}</h1>${body}</main></body></html>`;

export const renderLogin = (m: PageModel) => page('Sign in', `
  <p>Continue to ${e(m.clientName)}</p>
  <form id="login"><p><label>Email <input name="email" type="email" autocomplete="username" required></label></p>
  <p><label>Password <input name="password" type="password" autocomplete="current-password" required></label></p>
  <button type="submit">Sign in</button></form><p id="error" role="alert"></p>
  <script nonce="${e(m.nonce)}">
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

export const renderConsent = (m: PageModel) => page('Allow access?', `
  <p>${e(m.clientName)} requests permission to:</p>
  <ul>${m.scopes.map((s) => `<li>${e(s.description)} <small>(${e(s.name)})</small></li>`).join('')}</ul>
  <form method="post" action="${e(m.consentEndpoint)}">
    <input type="hidden" name="csrf" value="${e(m.csrf)}">
    <button name="decision" value="allow" type="submit">Allow</button>
    <button name="decision" value="deny" type="submit">Deny</button>
  </form>`);
