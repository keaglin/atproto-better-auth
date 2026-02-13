/**
 * ATProto Identity Resolution
 * Resolves handle → DID → PDS authorization server
 */

export interface ResolvedIdentity {
  did: string
  handle: string
  pdsUrl: string
  authorizationServer: string
}

export interface AuthServerMetadata {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  pushed_authorization_request_endpoint: string
  dpop_signing_alg_values_supported: string[]
  scopes_supported: string[]
}

/**
 * Resolve a handle or DID to full identity info
 */
export async function resolveIdentity(handleOrDid: string): Promise<ResolvedIdentity> {
  const did = handleOrDid.startsWith('did:')
    ? handleOrDid
    : await resolveHandle(handleOrDid)

  const didDoc = await resolveDid(did)
  const pdsUrl = extractPdsUrl(didDoc)
  const authorizationServer = await discoverAuthServer(pdsUrl)

  return {
    did,
    handle: handleOrDid.startsWith('did:') ? extractHandle(didDoc) : handleOrDid,
    pdsUrl,
    authorizationServer,
  }
}

/**
 * Resolve handle to DID via DNS or HTTP
 */
async function resolveHandle(handle: string): Promise<string> {
  // Try DNS first via Cloudflare DoH, fall back to HTTP

  // 1. Try DNS TXT record: _atproto.{handle}
  try {
    const did = await resolveDns(handle)
    if (did)
      return did
  }
  catch {
    // DNS failed, try HTTP
  }

  // 2. Fall back to HTTP: https://{handle}/.well-known/atproto-did
  const url = `https://${handle}/.well-known/atproto-did`
  const response = await fetch(url, {
    headers: { 'User-Agent': 'Kern/1.0 (https://kern.pub)' },
  })

  if (!response.ok) {
    throw new Error(`Failed to resolve handle ${handle}: ${response.status}`)
  }

  const did = (await response.text()).trim()
  if (!did.startsWith('did:')) {
    throw new Error(`Invalid DID from handle resolution: ${did}`)
  }

  return did
}

/**
 * Resolve handle via DNS TXT record using Cloudflare DoH
 */
async function resolveDns(handle: string): Promise<string | null> {
  const dohUrl = `https://cloudflare-dns.com/dns-query?name=_atproto.${handle}&type=TXT`
  const response = await fetch(dohUrl, {
    headers: { Accept: 'application/dns-json' },
  })

  if (!response.ok)
    return null

  const data = await response.json() as { Answer?: { data: string }[] }
  const txtRecord = data.Answer?.[0]?.data

  if (!txtRecord)
    return null

  // TXT record format: "did=did:plc:..."
  const match = txtRecord.replace(/"/g, '').match(/^did=(.+)$/)
  return match?.[1] ?? null
}

/**
 * Resolve DID document
 */
async function resolveDid(did: string): Promise<any> {
  if (did.startsWith('did:plc:')) {
    const response = await fetch(`https://plc.directory/${did}`)
    if (!response.ok) {
      throw new Error(`Failed to resolve DID ${did}: ${response.status}`)
    }
    return response.json()
  }

  if (did.startsWith('did:web:')) {
    const domain = did.slice('did:web:'.length).replace(/%3A/g, ':')
    const response = await fetch(`https://${domain}/.well-known/did.json`)
    if (!response.ok) {
      throw new Error(`Failed to resolve DID ${did}: ${response.status}`)
    }
    return response.json()
  }

  throw new Error(`Unsupported DID method: ${did}`)
}

/**
 * Extract PDS URL from DID document
 */
function extractPdsUrl(didDoc: any): string {
  const service = didDoc.service?.find(
    (s: any) => s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer',
  )

  if (!service?.serviceEndpoint) {
    throw new Error('No PDS service found in DID document')
  }

  return service.serviceEndpoint
}

/**
 * Extract handle from DID document
 */
function extractHandle(didDoc: any): string {
  const aka = didDoc.alsoKnownAs?.find((a: string) => a.startsWith('at://'))
  return aka ? aka.slice('at://'.length) : ''
}

/**
 * Discover authorization server from PDS
 */
async function discoverAuthServer(pdsUrl: string): Promise<string> {
  // PDS resource server metadata tells us the auth server
  const response = await fetch(`${pdsUrl}/.well-known/oauth-protected-resource`)

  if (!response.ok) {
    throw new Error(`Failed to discover auth server: ${response.status}`)
  }

  const metadata = await response.json() as { authorization_servers: string[] }

  if (!metadata.authorization_servers?.length) {
    throw new Error('No authorization servers in PDS metadata')
  }

  return metadata.authorization_servers[0]
}

/**
 * Fetch authorization server metadata
 */
export async function getAuthServerMetadata(authServer: string): Promise<AuthServerMetadata> {
  const response = await fetch(`${authServer}/.well-known/oauth-authorization-server`)

  if (!response.ok) {
    throw new Error(`Failed to fetch auth server metadata: ${response.status}`)
  }

  return response.json() as Promise<AuthServerMetadata>
}
