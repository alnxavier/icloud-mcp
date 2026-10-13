// The OAuth provider's configuration, as a named object rather than an
// inline literal.
//
// Exported so a later plan's ordering test can compose the REAL production
// configuration — the real gate, the real endpoints, the real handler
// composition — and substitute only the API handler. A test that had to
// rebuild this object would be testing its own copy.

import type { OAuthProviderOptions } from "@cloudflare/workers-oauth-provider";
import type { Env } from "../env";
import { DEPLOYED_HOSTNAME, mcpApiHandler } from "../mcp/api-handler";
import { loginHandler, refuseUnlistedRedirects } from "./login-handler";
import { SAVE_ROUTE_PATH } from "../save/link";
import { handleSaveDownload } from "../save/route";

export const oauthProviderOptions: OAuthProviderOptions<Env> = {
  apiRoute: "/mcp",

  // The adapter, never the raw handler. See src/mcp/api-handler.ts for what
  // assigning the handler directly would silently discard.
  apiHandler: mcpApiHandler,

  // Everything that is not an API request. Two things live here: the
  // attachment download route (Phase 29.1) and the /authorize form.
  //
  // A path that starts with /save/ goes to the download route, and every other
  // path goes to the login handler exactly as before. The check sits in front
  // of the login handler and does not touch it: that handler's timing floor
  // starts at its own first statement, and nothing here runs inside it. This is
  // the only place in src/ that hands a request to the download route.
  defaultHandler: {
    fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      if (env.MAIL_ONLY_MODE !== "true" && new URL(request.url).pathname.startsWith(SAVE_ROUTE_PATH)) {
        return handleSaveDownload(request, env, ctx);
      }
      return loginHandler.fetch(request, env, ctx);
    },
  },

  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",

  // Dynamic Client Registration only. The Client-ID-Metadata-Document option
  // is deliberately left unset: it requires an egress-restricting
  // compatibility flag whose interaction with this Worker's outbound
  // transport is unverified, and this is the one Worker whose entire purpose
  // is proving that transport works. 01-02-SUMMARY.md records the full
  // reasoning and the escape hatch if a client cannot register dynamically.
  clientRegistrationEndpoint: "/oauth/register",

  // LIFE-02. Junk is refused at registration rather than swept up later. The
  // predicate's docstring in ./login-handler.ts carries the reasoning, the live
  // evidence that it refuses nothing real, and the recovery.
  clientRegistrationCallback: refuseUnlistedRedirects,

  // D-05. An access token lasts an hour. That is still the library default,
  // stated here so a change to it is a visible diff. Refresh-token rotation is
  // automatic and not configurable in this library; see 01-02-SUMMARY.md for
  // the one way D-05's stated properties turned out weaker than assumed.
  accessTokenTTL: 3600,

  // LIFE-01. A login lasts until someone revokes it. Both lifetimes below are
  // PRESENT with the value `undefined`, and that is not the same as leaving
  // them out.
  //
  // The library builds its own options by spreading ours over its defaults
  // (oauth-provider.js lines 1348-1353). A spread copies an own key even when
  // its value is `undefined`, so `undefined` here REPLACES the default. An
  // absent key KEEPS it: 30 days for a refresh token, 90 days for a client
  // record. So deleting either line brings the forced logout back, and nothing
  // fails on the way out.
  //
  // Never set either one to zero. A zero refresh lifetime turns refresh tokens
  // off entirely (oauth-provider.js line 1955). Zero is not "no expiry".
  //
  // The two move together because of spike S2. With the client record gone the
  // token endpoint refuses the refresh as an unknown client, even though the
  // grant and the refresh token are both fine. Setting only the refresh token
  // moves the logout from day 30 to day 90; it does not remove it.
  //
  // Grants made before this change keep the expiry they were written with. A
  // refresh does not extend it — the expiry is fixed at the code exchange. There
  // is no migration. The owner reconnects each Claude app once after the deploy.
  //
  // The library also ships a helper that deletes expired records, and its
  // default sweeps up grants whose client record has gone. That is this same
  // logout by another road — and worse than the original, because a registration
  // can be restored while a swept grant cannot. It is called nowhere in this
  // project, and as of phase 12 a scan rule under `scripts/forbidden-tokens.mjs`
  // actually refuses a call to it anywhere in `src/`. That rule was claimed here
  // before it existed; it now exists, which is why this paragraph can no longer
  // NAME the helper — the rule would fire on this very comment.
  //
  // If the reason for reaching for it is client records accumulating, the answer
  // is `prune-clients` in `scripts/grants-core.mjs`. That deletes a client record
  // only when no grant names it, so it cannot sign anybody out.
  refreshTokenTTL: undefined,
  clientRegistrationTTL: undefined,

  scopesSupported: ["mcp"],

  resourceMetadata: {
    // This becomes the RFC 8707 token audience. Changing it after
    // authorization invalidates every issued token and forces the OAuth
    // ceremony to be repeated.
    resource: `https://${DEPLOYED_HOSTNAME}/mcp`,
    scopes_supported: ["mcp"],
    resource_name: "iCloud MCP",
  },

  // Both are already the defaults. Restated so that turning either on is a
  // change someone has to write, and a reviewer can see.
  allowImplicitFlow: false,
  allowPlainPKCE: false,
};
