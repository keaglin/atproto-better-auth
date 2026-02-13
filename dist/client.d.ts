import * as _better_fetch_fetch from '@better-fetch/fetch';
import { atprotoAuth } from './index.js';
import 'better-call';
import 'zod';

/**
 * ATProto Better Auth Client Plugin
 */
interface SignInResponse {
    url?: string;
    redirect?: boolean;
}
declare function atprotoAuthClient(): {
    id: "atproto";
    $InferServerPlugin: ReturnType<typeof atprotoAuth>;
    getActions: ($fetch: _better_fetch_fetch.BetterFetch) => {
        signIn: {
            /**
             * Sign in with ATProto (Bluesky)
             */
            atproto: (options: {
                handle: string;
                callbackURL?: string;
                errorCallbackURL?: string;
            }) => Promise<{
                data: SignInResponse;
                error: null;
            } | {
                data: null;
                error: {
                    message?: string | undefined;
                    status: number;
                    statusText: string;
                };
            }>;
        };
    };
};

export { atprotoAuthClient };
