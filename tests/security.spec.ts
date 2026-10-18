import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { createOAuthServer, renderLogin, renderConsent } from '../src';
import { challenge, singleParams, validRedirect } from '../src/lib/security';

export const privateJwk = { ...generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256' };
describe('configuration and HTML safety', () => {
  test('rejects unsafe issuer and keys', () => {
    expect(() => createOAuthServer({ issuer: 'http://example.com', jwks: { keys: [privateJwk] }, jwtSecret: 'test' })).toThrow();
    expect(() => createOAuthServer({ issuer: 'https://example.com/path', jwks: { keys: [privateJwk] }, jwtSecret: 'test' })).toThrow();
    expect(() => createOAuthServer({ issuer: 'https://example.com', jwks: { keys: [] }, jwtSecret: 'test' })).toThrow();
  });
  test('rejects duplicate protocol parameters', () => {
    expect(() => singleParams(new URLSearchParams('client_id=a&client_id=b'))).toThrow();
  });
  test('redirect schemes are constrained', () => {
    expect(validRedirect('https://client.example/cb', 'public', false)).toBe(true);
    for (const url of ['javascript:alert(1)', 'https://client.example/#fragment', 'https://u:p@client.example/cb', 'https://*.example/cb']) {
      expect(validRedirect(url, 'native', false)).toBe(false);
    }
    expect(validRedirect('com.example.app:/callback', 'native', false)).toBe(true);
    expect(validRedirect('com.example.app:/callback', 'public', false)).toBe(false);
    expect(validRedirect('http://127.0.0.1:1234/cb', 'native', false)).toBe(true);
    expect(validRedirect('http://example.com/cb', 'native', true)).toBe(false);
  });
  test('RFC 7636 PKCE vector', () => {
    expect(challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
  test('escapes client and scope text and script strings', () => {
    const model = { interactionId: 'id', csrf: '</script><script>bad()</script>', nonce: 'nonce', clientName: '<img src=x onerror=bad()>', scopes: [{ name: '<x>', description: '<script>bad()</script>' }], loginEndpoint: '/login', sessionEndpoint: '/session', consentEndpoint: '/consent' };
    expect(renderLogin(model)).not.toContain('<img src=x');
    expect(renderLogin(model)).not.toContain('</script><script>bad');
    expect(renderConsent(model)).not.toContain('<script>bad');
  });
});
