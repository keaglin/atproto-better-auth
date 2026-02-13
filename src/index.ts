/**
 * ATProto OAuth Plugin for Better Auth
 * Cloudflare Workers compatible
 */

import type { BetterAuthPlugin } from 'better-auth'
import type { ES256KeyPair } from './crypto'
import { createAuthEndpoint } from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { generateState, handleOAuthUserInfo, parseState } from 'better-auth/oauth2'

import { z } from 'zod'
import {

  generatePkce,
  generateRandom,
  importPrivateKeyJwk,
  signJwt,
} from './crypto'
import { createDPopProof } from './dpop'
import { getAuthServerMetadata, resolveIdentity } from './identity'

export interface AtprotoAuthOptions {
  /**
   * Your app's public URL (used as client_id)
   */
  clientId: string

  /**
   * Display name for your app
   */
  clientName: string

  /**
   * ES256 private key as JWK
   */
  privateKey: JsonWebKey

  /**
   * Key ID for the private key
   */
  keyId: string

  /**
   * OAuth scopes to request
   * @default ['atproto', 'transition:generic']
   */
  scopes?: string[]

  /**
   * Redirect URI for OAuth callback
   * @default {clientId}/api/auth/callback/atproto
   */
  redirectUri?: string
}

// JWK with kid (TypeScript's JsonWebKey doesn't include kid)
interface JwkWithKid extends JsonWebKey {
  kid?: string
}

// Error codes
const ERROR_CODES = {
  IDENTITY_RESOLUTION_FAILED: 'Identity resolution failed',
  PAR_REQUEST_FAILED: 'PAR request failed',
  TOKEN_EXCHANGE_FAILED: 'Token exchange failed',
  MISSING_CODE: 'Authorization code missing',
  STATE_MISMATCH: 'State mismatch',
} as const

/**
 * Validate callback URL to prevent open redirect attacks.
 * Only allows same-origin relative paths or absolute URLs matching baseUrl.
 */
function validateCallbackURL(callbackURL: string | undefined, baseUrl: string): string {
  if (!callbackURL)
    return '/'

  // Allow relative paths starting with /
  if (callbackURL.startsWith('/') && !callbackURL.startsWith('//')) {
    return callbackURL
  }

  // Allow absolute URLs matching our base URL
  try {
    const url = new URL(callbackURL)
    const base = new URL(baseUrl)
    if (url.origin === base.origin) {
      return url.pathname + url.search + url.hash
    }
  }
  catch {
    // Invalid URL, fall through to default
  }

  // Reject all other URLs (potential open redirect)
  return '/'
}

/**
 * ATProto OAuth plugin for Better Auth
 */
export function atprotoAuth(options: AtprotoAuthOptions) {
  const scopes = options.scopes ?? ['atproto', 'transition:generic']
  // Derive base URL from clientId (which is the metadata URL)
  const baseUrl = options.clientId.replace(/\/api\/auth\/atproto\/client-metadata\.json$/, '')
  const redirectUri = options.redirectUri ?? `${baseUrl}/api/auth/callback/atproto`

  let keyPair: ES256KeyPair | null = null

  async function getKeyPair(): Promise<ES256KeyPair> {
    if (!keyPair) {
      keyPair = await importPrivateKeyJwk(options.privateKey, options.keyId)
    }
    return keyPair
  }

  return {
    id: 'atproto',

    endpoints: {
      /**
       * Client metadata endpoint
       */
      atprotoClientMetadata: createAuthEndpoint(
        '/atproto/client-metadata.json',
        { method: 'GET' },
        async (ctx) => {
          return ctx.json({
            client_id: options.clientId,
            client_name: options.clientName,
            client_uri: baseUrl,
            redirect_uris: [redirectUri],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            scope: scopes.join(' '),
            token_endpoint_auth_method: 'private_key_jwt',
            token_endpoint_auth_signing_alg: 'ES256',
            dpop_bound_access_tokens: true,
            jwks_uri: `${baseUrl}/api/auth/atproto/jwks.json`,
            application_type: 'web',
          })
        },
      ),

      /**
       * JWKS endpoint
       */
      atprotoJwks: createAuthEndpoint(
        '/atproto/jwks.json',
        { method: 'GET' },
        async (ctx) => {
          const kp = await getKeyPair()
          // Add kid to public JWK
          const jwk: JwkWithKid = { ...kp.publicJwk, kid: kp.keyId }
          return ctx.json({ keys: [jwk] })
        },
      ),

      /**
       * Sign in with ATProto
       */
      signInAtproto: createAuthEndpoint(
        '/sign-in/atproto',
        {
          method: 'POST',
          body: z.object({
            handle: z.string().describe('Bluesky handle or DID'),
            callbackURL: z.string().optional(),
            errorCallbackURL: z.string().optional(),
          }),
        },
        async (ctx) => {
          const { handle } = ctx.body
          const kp = await getKeyPair()

          // 1. Resolve identity
          let identity
          try {
            identity = await resolveIdentity(handle)
          }
          catch (error) {
            ctx.context.logger.error('Identity resolution failed', error)
            throw new Error(ERROR_CODES.IDENTITY_RESOLUTION_FAILED)
          }

          // 2. Get auth server metadata
          const authMeta = await getAuthServerMetadata(identity.authorizationServer)

          // 3. Generate PKCE
          const pkce = await generatePkce()

          // 4. Generate state with ATProto-specific data
          const { state, codeVerifier: _codeVerifier } = await generateState(ctx, undefined, {
            atprotoDid: identity.did,
            atprotoHandle: identity.handle,
            atprotoAuthServer: identity.authorizationServer,
            atprotoPkceVerifier: pkce.verifier,
          })

          // 5. Create client assertion JWT
          const now = Math.floor(Date.now() / 1000)
          const clientAssertion = await signJwt(kp.privateKey, kp.keyId, {}, {
            iss: options.clientId,
            sub: options.clientId,
            aud: identity.authorizationServer,
            jti: generateRandom(16),
            iat: now,
            exp: now + 60,
          })

          // 6. Create DPoP proof for PAR
          const dpopProof = await createDPopProof(kp, {
            method: 'POST',
            url: authMeta.pushed_authorization_request_endpoint,
          })

          // 7. Push Authorization Request (PAR)
          const parBody = new URLSearchParams({
            client_id: options.clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: scopes.join(' '),
            state,
            code_challenge: pkce.challenge,
            code_challenge_method: 'S256',
            login_hint: identity.did,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: clientAssertion,
          })

          let parResponse = await fetch(authMeta.pushed_authorization_request_endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'DPoP': dpopProof,
            },
            body: parBody,
          })

          // Handle DPoP nonce requirement
          if (parResponse.status === 400) {
            const dpopNonce = parResponse.headers.get('DPoP-Nonce')
            if (dpopNonce) {
              const dpopProofWithNonce = await createDPopProof(kp, {
                method: 'POST',
                url: authMeta.pushed_authorization_request_endpoint,
                nonce: dpopNonce,
              })

              parResponse = await fetch(authMeta.pushed_authorization_request_endpoint, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'DPoP': dpopProofWithNonce,
                },
                body: parBody,
              })
            }
          }

          if (!parResponse.ok) {
            const errorBody = await parResponse.text()
            ctx.context.logger.error('PAR failed', { status: parResponse.status, body: errorBody })
            throw new Error(ERROR_CODES.PAR_REQUEST_FAILED)
          }

          const parData = await parResponse.json() as { request_uri: string, expires_in: number }

          // 8. Build authorization URL
          const authUrl = new URL(authMeta.authorization_endpoint)
          authUrl.searchParams.set('client_id', options.clientId)
          authUrl.searchParams.set('request_uri', parData.request_uri)

          return ctx.json({
            url: authUrl.toString(),
            redirect: true,
          })
        },
      ),

      /**
       * OAuth callback
       */
      atprotoCallback: createAuthEndpoint(
        '/callback/atproto',
        {
          method: 'GET',
          query: z.object({
            code: z.string().optional(),
            state: z.string().optional(),
            error: z.string().optional(),
            error_description: z.string().optional(),
            iss: z.string(), // Required - must match auth server
          }),
        },
        async (ctx) => {
          const { code, error, iss } = ctx.query
          const kp = await getKeyPair()

          // Handle errors
          if (error || !code) {
            const errorUrl = ctx.context.options.onAPIError?.errorURL ?? '/error'
            const params = new URLSearchParams({ error: error ?? 'missing_code' })
            throw ctx.redirect(`${errorUrl}?${params}`)
          }

          // Parse state (includes our ATProto data)
          let parsedState
          try {
            parsedState = await parseState(ctx)
          }
          catch {
            throw ctx.redirect('/error?error=state_parse_failed')
          }

          const {
            callbackURL,
            atprotoDid: did,
            atprotoHandle: handle,
            atprotoAuthServer: authServer,
            atprotoPkceVerifier: pkceVerifier,
          } = parsedState as any

          // Verify issuer matches (required)
          if (iss !== authServer) {
            throw ctx.redirect('/error?error=issuer_mismatch')
          }

          // Validate callbackURL is same-origin (prevent open redirect)
          const safeCallbackURL = validateCallbackURL(callbackURL, baseUrl)

          // Get auth server metadata
          const authMeta = await getAuthServerMetadata(authServer)

          // Create client assertion
          const now = Math.floor(Date.now() / 1000)
          const clientAssertion = await signJwt(kp.privateKey, kp.keyId, {}, {
            iss: options.clientId,
            sub: options.clientId,
            aud: authServer,
            jti: generateRandom(16),
            iat: now,
            exp: now + 60,
          })

          // Token exchange with DPoP
          let dpopNonce: string | undefined
          const makeDpop = () => createDPopProof(kp, {
            method: 'POST',
            url: authMeta.token_endpoint,
            nonce: dpopNonce,
          })

          const tokenBody = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            code_verifier: pkceVerifier,
            client_id: options.clientId,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: clientAssertion,
          })

          let tokenResponse = await fetch(authMeta.token_endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'DPoP': await makeDpop(),
            },
            body: tokenBody,
          })

          // Handle DPoP nonce
          if (tokenResponse.status === 400 || tokenResponse.status === 401) {
            const nonce = tokenResponse.headers.get('DPoP-Nonce')
            if (nonce) {
              dpopNonce = nonce
              tokenResponse = await fetch(authMeta.token_endpoint, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'DPoP': await makeDpop(),
                },
                body: tokenBody,
              })
            }
          }

          if (!tokenResponse.ok) {
            ctx.context.logger.error('Token exchange failed', { status: tokenResponse.status })
            throw ctx.redirect('/error?error=token_exchange_failed')
          }

          const tokens = await tokenResponse.json() as {
            access_token: string
            refresh_token?: string
            token_type: string
            expires_in: number
            sub: string
            scope: string
          }

          // Verify sub matches expected DID
          if (tokens.sub !== did) {
            throw ctx.redirect('/error?error=sub_mismatch')
          }

          // Use better-auth's handleOAuthUserInfo for user creation/linking
          const result = await handleOAuthUserInfo(ctx, {
            userInfo: {
              id: did,
              email: `${did}@atproto.invalid`, // Pseudo-email from DID
              emailVerified: true, // ATProto handles verification
              name: handle,
            },
            account: {
              providerId: 'atproto',
              accountId: did,
              accessToken: tokens.access_token,
              refreshToken: tokens.refresh_token,
              accessTokenExpiresAt: new Date(Date.now() + tokens.expires_in * 1000),
              scope: tokens.scope,
            },
            callbackURL: safeCallbackURL,
          })

          if (result.error) {
            const params = new URLSearchParams({ error: result.error.replace(/\s+/g, '_') })
            throw ctx.redirect(`/error?${params}`)
          }

          const { session, user } = result.data!

          // Set session cookie and redirect
          await setSessionCookie(ctx, { session, user })
          throw ctx.redirect(safeCallbackURL)
        },
      ),
    },

    $ERROR_CODES: ERROR_CODES,
  } satisfies BetterAuthPlugin
}

export { exportPrivateKeyJwk, generateKeyPair } from './crypto'
