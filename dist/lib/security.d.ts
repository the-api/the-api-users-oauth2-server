import type { Context } from 'hono';
import type { RolesService } from 'the-api-routings';
import type { User } from '../types';
export declare class OAuthError extends Error {
    error: string;
    status: number;
    constructor(error: string, status?: number, description?: string);
}
export declare const random: () => string;
export declare const digest: (value: string) => string;
export declare const challenge: (value: string) => string;
export declare const equal: (a: string, b: string) => boolean;
export declare const expires: (seconds: number) => Date;
export declare const active: (user: User | undefined, authTime?: Date | string) => user is User;
export declare const permitted: (roles: RolesService | undefined, user: User, permission: string) => boolean;
export declare const splitScope: (scope: string) => string[];
export declare const escapeHtml: (value: string) => string;
export declare const scriptJson: (value: unknown) => string;
export declare function singleParams(params: URLSearchParams): Record<string, string>;
export declare function form(c: Context): Promise<Record<string, string>>;
export declare function loopback(url: URL): boolean;
export declare function validRedirect(value: string, type: string, insecure: boolean): boolean;
//# sourceMappingURL=security.d.ts.map