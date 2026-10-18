import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Context } from 'hono';
import type { RolesService } from 'the-api-routings';
import type { User } from '../types';

export class OAuthError extends Error {
  constructor(public error: string, public status = 400, description = error) { super(description); }
}
export const random = () => randomBytes(32).toString('base64url');
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export const challenge = (value: string) => createHash('sha256').update(value).digest('base64url');
export const equal = (a: string, b: string) => {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};
export const expires = (seconds: number) => new Date(Date.now() + seconds * 1000);
export const active = (user: User | undefined, authTime?: Date | string): user is User =>
  !!user && !user.isDeleted && !user.isBanned && !user.isBlocked &&
  (!authTime || !user.timePasswordChanged || +new Date(user.timePasswordChanged) <= +new Date(authTime));
export const permitted = (roles: RolesService | undefined, user: User, permission: string) =>
  !!roles && roles.checkWildcardPermissions({ key: permission, permissions: roles.getPermissions(user.role ? [user.role] : []) });
export const splitScope = (scope: string) => [...new Set(scope.split(' ').filter(Boolean))];
export const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
export const scriptJson = (value: unknown) => JSON.stringify(value).replace(/</g, '\\u003c');
export function singleParams(params: URLSearchParams): Record<string, string> {
  const result: Record<string, string> = Object.create(null);
  for (const [key, value] of params) {
    if (Object.hasOwn(result, key)) throw new OAuthError('invalid_request', 400, 'Repeated parameter');
    result[key] = value;
  }
  return result;
}
export async function form(c: Context): Promise<Record<string, string>> {
  if (!c.req.header('content-type')?.toLowerCase().startsWith('application/x-www-form-urlencoded')) {
    throw new OAuthError('invalid_request', 400, 'Use application/x-www-form-urlencoded');
  }
  const body = await c.req.text();
  if (Buffer.byteLength(body) > 16384) throw new OAuthError('invalid_request', 413);
  return singleParams(new URLSearchParams(body));
}
export function loopback(url: URL) { return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname); }
export function validRedirect(value: string, type: string, insecure: boolean): boolean {
  try {
    const url = new URL(value);
    if (url.hash || url.username || url.password || value.includes('*')) return false;
    if (url.protocol === 'https:') return true;
    if (url.protocol === 'http:' && loopback(url) && (insecure || type === 'native')) return true;
    return type === 'native' && /^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/.test(url.protocol) && !url.host;
  } catch { return false; }
}
