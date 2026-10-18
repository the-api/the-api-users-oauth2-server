import type { Context } from 'hono';
import type { Knex } from 'knex';
import type { RolesService, Routings } from 'the-api-routings';
import type { JWK } from 'jose';
export type ScopeDefinition = {
    description: string;
    permission?: string;
};
export type PageModel = {
    interactionId: string;
    csrf: string;
    nonce: string;
    clientName: string;
    scopes: {
        name: string;
        description: string;
    }[];
    loginEndpoint: string;
    sessionEndpoint: string;
    consentEndpoint: string;
};
export type PageRenderer = (model: PageModel) => string | Promise<string>;
export type OAuthServerOptions = {
    /** Origin only, e.g. https://accounts.example.com. Stable across deployments. */
    issuer: string;
    /** Dedicated RSA private JWK(s), first key signs; old public keys may remain for rotation. */
    jwks: {
        keys: JWK[];
    };
    jwtSecret?: string;
    /** Existing the-api-users login route, same origin. */
    loginPath?: string;
    scopes?: Record<string, ScopeDefinition>;
    accessTokenTtl?: number;
    refreshTokenTtl?: number;
    sessionTtl?: number;
    interactionTtl?: number;
    codeTtl?: number;
    idTokenTtl?: number;
    /** Explicit loopback HTTP support, only for local development. */
    allowInsecureLocalhost?: boolean;
    renderLogin?: PageRenderer;
    renderConsent?: PageRenderer;
    onError?: (error: unknown) => void;
};
export type ApiHost = {
    app: {
        use: (...args: any[]) => unknown;
        route: (...args: any[]) => unknown;
    };
    db: {
        db: Knex;
        dbWrite: Knex;
    } | null;
    roles?: RolesService;
};
export type Services = {
    db: Knex;
    roles?: RolesService;
};
export type Client = {
    id: string;
    name: string;
    secretHash: string | null;
    type: 'confidential' | 'public' | 'native';
    redirectUris: string[];
    scopes: string[];
    disabled: boolean;
};
export type AuthorizationRequest = {
    client_id: string;
    redirect_uri: string;
    scope: string;
    code_challenge: string;
    state?: string;
    nonce?: string;
    prompt?: string;
    max_age?: number;
};
export type User = {
    id: number;
    role?: string;
    fullName?: string;
    displayName?: string;
    email?: string;
    isEmailVerified?: boolean;
    avatar?: string;
    locale?: string;
    timezone?: string;
    isBanned?: boolean;
    isBlocked?: boolean;
    isDeleted?: boolean;
    timePasswordChanged?: Date | string;
};
export type Grant = {
    id: string;
    clientId: string;
    userId: number;
    scope: string;
    revoked: boolean;
    authTime: Date;
    expiresAt: Date;
};
export type AccessIdentity = {
    userId: number;
    clientId: string;
    grantId: string;
    scopes: string[];
    user: User;
};
export type ResourceEnv = {
    Variables: {
        db: Knex;
        dbWrite: Knex;
        oauth: AccessIdentity;
    };
};
export type ResourceHandler = (c: Context<ResourceEnv>, identity: AccessIdentity) => Response | Promise<Response>;
export interface OAuthServer {
    routings: Routings;
    mount(api: ApiHost): void;
    resource(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, scopes: string[], handler: ResourceHandler): OAuthServer;
    verifyAccessToken(token: string, scopes?: string[]): Promise<AccessIdentity>;
    cleanup(): Promise<void>;
}
//# sourceMappingURL=types.d.ts.map