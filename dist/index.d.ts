import type { OAuthServer, OAuthServerOptions } from './types';
export declare const migrationDir: string;
export declare const migrationUpdateDir: string;
export type * from './types';
export { renderLogin, renderConsent } from './lib/pages';
export { escapeHtml } from './lib/security';
/** Create one instance per issuer; call mount before TheAPI.init/up. */
export declare function createOAuthServer(options: OAuthServerOptions): OAuthServer;
//# sourceMappingURL=index.d.ts.map