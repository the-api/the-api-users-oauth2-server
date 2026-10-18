import { type JWK } from 'jose';
import type { Knex } from 'knex';
import type { AccessIdentity, AuthorizationRequest, Client, Grant, OAuthServerOptions, Services, User } from '../types';
export declare class OAuthService {
    readonly options: {
        jwtSecret: string;
        loginPath: string;
        accessTokenTtl: number;
        refreshTokenTtl: number;
        sessionTtl: number;
        interactionTtl: number;
        codeTtl: number;
        idTokenTtl: number;
        issuer: string;
        jwks: {
            keys: JWK[];
        };
        scopes?: Record<string, import("..").ScopeDefinition>;
        allowInsecureLocalhost?: boolean;
        renderLogin?: import("..").PageRenderer;
        renderConsent?: import("..").PageRenderer;
        onError?: (error: unknown) => void;
    };
    readonly scopes: {
        openid: {
            description: string;
        };
        profile: {
            description: string;
        };
        email: {
            description: string;
        };
        offline_access: {
            description: string;
        };
    };
    private signingKey;
    readonly publicJwks: {
        keys: JWK[];
    };
    constructor(options: OAuthServerOptions);
    client(db: Knex, id: string): Promise<Client>;
    authenticateClient(db: Knex, body: Record<string, string>, authorization?: string): Promise<Client>;
    authorization(db: Knex, p: Record<string, string>): Promise<AuthorizationRequest>;
    localUser(db: Knex, token: string): Promise<{
        user: User;
        authTime: Date;
    }>;
    checkScopes(services: Services, user: User, scope: string): void;
    createCode(db: Knex, request: AuthorizationRequest, user: User, authTime: Date): Promise<string>;
    tokens(db: Knex, grant: Grant, scope: string, nonce?: string, withId?: boolean): Promise<Record<string, unknown>>;
    exchange(services: Services, client: Client, body: Record<string, string>): Promise<Record<string, unknown>>;
    access(services: Services, token: string, required?: string[]): Promise<AccessIdentity>;
    profile(identity: AccessIdentity): {
        email?: string | undefined;
        email_verified?: boolean | undefined;
        name?: string | undefined;
        preferred_username?: string | undefined;
        picture?: string | undefined;
        locale?: string | undefined;
        zoneinfo?: string | undefined;
        sub: string;
    };
    validateClient(body: Record<string, unknown>): {
        name: string;
        type: {};
        redirectUris: string;
        scopes: string;
    };
}
//# sourceMappingURL=server.d.ts.map