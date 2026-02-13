/**
 * ES256 cryptographic utilities for ATProto OAuth
 * Uses Web Crypto API for Cloudflare Workers compatibility
 */

// Extended JWK type that includes kid (not in TypeScript's built-in type)
export interface JwkWithKid extends JsonWebKey {
  kid?: string
}

export interface ES256KeyPair {
  privateKey: CryptoKey
  publicKey: CryptoKey
  publicJwk: JwkWithKid
  keyId: string
}

/**
 * Import an ES256 private key from base64-encoded PKCS8
 */
export async function importPrivateKey(
  base64PrivateKey: string,
  keyId: string,
): Promise<ES256KeyPair> {
  const rawKey = base64ToArrayBuffer(base64PrivateKey)

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    rawKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )

  const privateJwk = await crypto.subtle.exportKey('jwk', privateKey) as JsonWebKey

  // Public JWK (remove private 'd' component)
  const publicJwk: JwkWithKid = {
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
    y: privateJwk.y,
    use: 'sig',
    alg: 'ES256',
    kid: keyId,
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  )

  return { privateKey, publicKey, publicJwk, keyId }
}

/**
 * Import from JWK format (common for env vars)
 */
export async function importPrivateKeyJwk(
  jwk: JsonWebKey,
  keyId: string,
): Promise<ES256KeyPair> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )

  const publicJwk: JwkWithKid = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    use: 'sig',
    alg: 'ES256',
    kid: keyId,
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  )

  return { privateKey, publicKey, publicJwk, keyId }
}

/**
 * Generate a new ES256 key pair
 */
export async function generateKeyPair(keyId: string): Promise<ES256KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair

  const exportedJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey) as JsonWebKey
  const publicJwk: JwkWithKid = {
    ...exportedJwk,
    use: 'sig',
    alg: 'ES256',
    kid: keyId,
  }

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicJwk,
    keyId,
  }
}

/**
 * Export private key as JWK (for storing)
 */
export async function exportPrivateKeyJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', privateKey) as Promise<JsonWebKey>
}

/**
 * Create a signed JWT
 */
export async function signJwt(
  privateKey: CryptoKey,
  keyId: string,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const fullHeader = { ...header, alg: 'ES256', kid: keyId }

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

/**
 * Generate PKCE code verifier and challenge
 */
export async function generatePkce(): Promise<{ verifier: string, challenge: string }> {
  const verifier = generateRandom(32)
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: arrayBufferToBase64Url(hash) }
}

/**
 * Generate random base64url string
 */
export function generateRandom(bytes: number = 32): string {
  return arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(bytes)).buffer)
}

// --- Base64 utilities ---

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64UrlDecode(str: string): string {
  const padded = str + '==='.slice(0, (4 - (str.length % 4)) % 4)
  return atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
}
