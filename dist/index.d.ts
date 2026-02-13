import * as better_call from 'better-call';
import { z } from 'zod';

/**
 * ES256 cryptographic utilities for ATProto OAuth
 * Uses Web Crypto API for Cloudflare Workers compatibility
 */
interface JwkWithKid$1 extends JsonWebKey {
    kid?: string;
}
interface ES256KeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicJwk: JwkWithKid$1;
    keyId: string;
}
/**
 * Generate a new ES256 key pair
 */
declare function generateKeyPair(keyId: string): Promise<ES256KeyPair>;
/**
 * Export private key as JWK (for storing)
 */
declare function exportPrivateKeyJwk(privateKey: CryptoKey): Promise<JsonWebKey>;

interface AtprotoAuthOptions {
    /**
     * Your app's public URL (used as client_id)
     */
    clientId: string;
    /**
     * Display name for your app
     */
    clientName: string;
    /**
     * ES256 private key as JWK
     */
    privateKey: JsonWebKey;
    /**
     * Key ID for the private key
     */
    keyId: string;
    /**
     * OAuth scopes to request
     * @default ['atproto', 'transition:generic']
     */
    scopes?: string[];
    /**
     * Redirect URI for OAuth callback
     * @default {clientId}/api/auth/callback/atproto
     */
    redirectUri?: string;
}
interface JwkWithKid extends JsonWebKey {
    kid?: string;
}
/**
 * ATProto OAuth plugin for Better Auth
 */
declare function atprotoAuth(options: AtprotoAuthOptions): {
    id: "atproto";
    endpoints: {
        /**
         * Client metadata endpoint
         */
        atprotoClientMetadata: better_call.StrictEndpoint<"/atproto/client-metadata.json", {
            method: "GET";
        }, {
            client_id: string;
            client_name: string;
            client_uri: string;
            redirect_uris: string[];
            grant_types: string[];
            response_types: string[];
            scope: string;
            token_endpoint_auth_method: string;
            token_endpoint_auth_signing_alg: string;
            dpop_bound_access_tokens: boolean;
            jwks_uri: string;
            application_type: string;
        }>;
        /**
         * JWKS endpoint
         */
        atprotoJwks: better_call.StrictEndpoint<"/atproto/jwks.json", {
            method: "GET";
        }, {
            keys: JwkWithKid[];
        }>;
        /**
         * Sign in with ATProto
         */
        signInAtproto: better_call.StrictEndpoint<"/sign-in/atproto", {
            method: "POST";
            body: z.ZodObject<{
                handle: z.ZodString;
                callbackURL: z.ZodOptional<z.ZodString>;
                errorCallbackURL: z.ZodOptional<z.ZodString>;
            }, z.core.$strip>;
        }, {
            url: string;
            redirect: boolean;
        }>;
        /**
         * OAuth callback
         */
        atprotoCallback: better_call.StrictEndpoint<"/callback/atproto", {
            method: "GET";
            query: z.ZodObject<{
                code: z.ZodOptional<z.ZodString>;
                state: z.ZodOptional<z.ZodString>;
                error: z.ZodOptional<z.ZodString>;
                error_description: z.ZodOptional<z.ZodString>;
                iss: z.ZodString;
            }, z.core.$strip>;
        }, never>;
    };
    $ERROR_CODES: {
        readonly IDENTITY_RESOLUTION_FAILED: "Identity resolution failed";
        readonly PAR_REQUEST_FAILED: "PAR request failed";
        readonly TOKEN_EXCHANGE_FAILED: "Token exchange failed";
        readonly MISSING_CODE: "Authorization code missing";
        readonly STATE_MISMATCH: "State mismatch";
    };
};

export { type AtprotoAuthOptions, atprotoAuth, exportPrivateKeyJwk, generateKeyPair };
