/**
 * DPoP (Demonstrating Proof of Possession) for ATProto OAuth
 * Every token request requires a unique DPoP proof
 */

import type { ES256KeyPair } from './crypto'
import { generateRandom } from './crypto'

export interface DPopOptions {
  method: string
  url: string
  nonce?: string
  accessToken?: string
}

/**
 * Create a DPoP proof JWT
 */
export async function createDPopProof(
  keyPair: ES256KeyPair,
  options: DPopOptions,
): Promise<string> {
  const { method, url, nonce, accessToken } = options

  // htu must not include query string or fragment
  const parsedUrl = new URL(url)
  const htu = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`

  // DPoP header includes public key (no kid for DPoP)
  const header: Record<string, unknown> = {
    typ: 'dpop+jwt',
    jwk: {
      kty: keyPair.publicJwk.kty,
      crv: keyPair.publicJwk.crv,
      x: keyPair.publicJwk.x,
      y: keyPair.publicJwk.y,
    },
  }

  const payload: Record<string, unknown> = {
    jti: generateRandom(16),
    htm: method.toUpperCase(),
    htu,
    iat: Math.floor(Date.now() / 1000),
  }

  if (nonce) {
    payload.nonce = nonce
  }

  if (accessToken) {
    payload.ath = await hashToken(accessToken)
  }

  // Note: signJwt adds alg and kid, but DPoP doesn't use kid
  // We'll override by not passing kid in this case
  return signJwtDpop(keyPair.privateKey, header, payload)
}

/**
 * Sign JWT without kid (for DPoP)
 */
async function signJwtDpop(
  privateKey: CryptoKey,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const fullHeader = { ...header, alg: 'ES256' }

  const encodedHeader = base64UrlEncode(JSON.stringify(fullHeader))
  const encodedPayload = base64UrlEncode(JSON.stringify(payload))
  const signingInput = `${encodedHeader}.${encodedPayload}`

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(signingInput),
  )

  return `${signingInput}.${arrayBufferToBase64Url(signature)}`
}

async function hashToken(token: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
  return arrayBufferToBase64Url(hash)
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
