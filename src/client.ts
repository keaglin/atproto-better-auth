/**
 * ATProto Better Auth Client Plugin
 */

import type { BetterAuthClientPlugin } from 'better-auth/client'

interface SignInResponse {
  url?: string
  redirect?: boolean
}

export function atprotoAuthClient() {
  return {
    id: 'atproto',
    $InferServerPlugin: {} as ReturnType<typeof import('./index').atprotoAuth>,
    getActions: $fetch => ({
      signIn: {
        /**
         * Sign in with ATProto (Bluesky)
         */
        atproto: async (options: {
          handle: string
          callbackURL?: string
          errorCallbackURL?: string
        }) => {
          const response = await $fetch<SignInResponse>('/sign-in/atproto', {
            method: 'POST',
            body: options,
          })

          if (response.data?.redirect && response.data?.url) {
            window.location.href = response.data.url
          }

          return response
        },
      },
    }),
  } satisfies BetterAuthClientPlugin
}
