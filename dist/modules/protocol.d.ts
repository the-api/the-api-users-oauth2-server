import { Hono, type Context } from 'hono';
import type { Services } from '../types';
import { OAuthService } from '../lib/server';
export type ServicesGetter = () => Services;
declare const bearer: (c: Context) => string;
export { bearer };
export declare function protocol(service: OAuthService, getServices: ServicesGetter): Hono<import("hono/types").BlankEnv, import("hono/types").BlankSchema, "/">;
//# sourceMappingURL=protocol.d.ts.map