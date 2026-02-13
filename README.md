# atproto-better-auth

ATProto OAuth plugin for [better-auth](https://github.com/better-auth/better-auth). Enables "Sign in with Bluesky" for your app.

Built for Cloudflare Workers, works anywhere with Web Crypto API.

## Install

```bash
bun add github:keaglin/atproto-better-auth
```

## Setup

### 1. Generate keys

ATProto OAuth requires ES256 key pairs for client authentication and DPoP.

```bash
node -e "
const crypto = require('crypto');
crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, (err, pub, priv) => {
  const jwk = priv.export({ format: 'jwk' });
  jwk.kid = 'key-1';
  console.log('ATPROTO_PRIVATE_KEY=' + Buffer.from(JSON.stringify(jwk)).toString('base64'));
  console.log('ATPROTO_KEY_ID=' + jwk.kid);
});
"
```

Add these to your `.env`.

### 2. Server setup

```ts
import { betterAuth } from 'better-auth'
import { atprotoAuth } from 'atproto-better-auth'

export const auth = betterAuth({
  // ... your config
  plugins: [
    atprotoAuth({
      clientId: 'https://your-app.com/api/auth/atproto/client-metadata.json',
      clientName: 'Your App',
      privateKey: JSON.parse(
        Buffer.from(process.env.ATPROTO_PRIVATE_KEY!, 'base64').toString()
      ),
      keyId: process.env.ATPROTO_KEY_ID!,
    }),
  ],
})
```

### 3. Client setup

```ts
import { createAuthClient } from 'better-auth/client'
import { atprotoAuthClient } from 'atproto-better-auth/client'

export const authClient = createAuthClient({
  plugins: [atprotoAuthClient()],
})

// Sign in
await authClient.signIn.atproto({
  handle: 'user.bsky.social',
  callbackURL: '/dashboard',
})
```

## How it works

1. User enters their Bluesky handle
2. Plugin resolves handle → DID → PDS → authorization server
3. Initiates OAuth flow with PAR (Pushed Authorization Request)
4. User authorizes on Bluesky
5. Plugin exchanges code for tokens, creates better-auth session

## Endpoints

The plugin adds these endpoints to your auth server:

| Endpoint | Description |
|----------|-------------|
| `GET /api/auth/atproto/client-metadata.json` | OAuth client metadata (required by ATProto) |
| `GET /api/auth/atproto/jwks.json` | Public keys for client authentication |
| `POST /api/auth/sign-in/atproto` | Initiate sign-in flow |
| `GET /api/auth/callback/atproto` | OAuth callback handler |

## Requirements

- better-auth >= 1.0.0
- Runtime with Web Crypto API (Cloudflare Workers, Node 18+, Deno, Bun)

## License

MIT
