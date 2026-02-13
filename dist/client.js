import "./chunk-MLKGABMK.js";

// src/client.ts
function atprotoAuthClient() {
  return {
    id: "atproto",
    $InferServerPlugin: {},
    getActions: ($fetch) => ({
      signIn: {
        /**
         * Sign in with ATProto (Bluesky)
         */
        atproto: async (options) => {
          const response = await $fetch("/sign-in/atproto", {
            method: "POST",
            body: options
          });
          if (response.data?.redirect && response.data?.url) {
            window.location.href = response.data.url;
          }
          return response;
        }
      }
    })
  };
}
export {
  atprotoAuthClient
};
