// The Worker's binding surface.
//
// `Cloudflare.Env` is the type the runtime's ambient `env` (from the
// "cloudflare:workers" module) resolves to. `@cloudflare/workers-types` ships
// it as an empty interface and invites projects to merge their own
// declaration into it. Declaring it once here — rather than declaring a
// separate `Env` interface and a matching global augmentation — means the
// ambient `env` and every explicitly-passed `env` are the same type by
// construction and cannot drift apart.

import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { UserAgent } from "./agent/user-agent";

declare global {
  namespace Cloudflare {
    interface Env {
      /** Mail-only profile; no recall, attachments or autonomy. */
      MAIL_ONLY_MODE?: string;
      /**
       * Token, grant, and client storage for the OAuth provider.
       *
       * The binding name is NOT configurable: the library reads
       * `env.OAUTH_KV` directly in its shipped JavaScript. The one Durable
       * Object this Worker declares, `USER_AGENT` below, never touches this
       * namespace.
       */
      OAUTH_KV: KVNamespace;

      /**
       * Resolved CalDAV / CardDAV discovery metadata (D-58).
       *
       * A namespace of its own rather than a key prefix inside `OAUTH_KV`.
       * That binding holds the OAuth provider's own grants, clients and token
       * records, and the library owns its key prefixes in shipped JavaScript
       * this project does not control — so sharing one keyspace would make
       * isolation a convention only one of the two writers ever agreed to.
       *
       * Entries expire after 24 hours (D-59). Short enough that worst-case
       * staleness stays bounded even if the re-discovery failure path turns
       * out to have a gap, at a cost of two extra PROPFINDs a day.
       *
       * **Discovery metadata only** — the root, principal and home URLs for
       * one service, and nothing else. No event, no contact, no message body
       * is ever written here. PROJECT.md's "local caching is not a product
       * feature" constraint is what draws that line: iCloud stays the system
       * of record, and this namespace only remembers *where* the account
       * lives, never *what* is in it.
       *
       * Typed `KVNamespace`, NOT `KVNamespace | undefined`. The widening on
       * the Secret bindings — those further down, and the three in the narrow
       * interfaces at the end of this file — is a statement about what a Workers
       * Secret is at runtime — unset, deleted, and never-provisioned all
       * arrive absent — and it does not transfer to a namespace binding,
       * which either resolves at deploy time or fails the deploy.
       */
      DAV_CACHE: KVNamespace;

      /**
       * Spent-confirmation records for the calendar write gate (D5-3 option A).
       *
       * A THIRD namespace rather than a key prefix inside `DAV_CACHE`, for the
       * reason `DAV_CACHE` itself gives about `OAUTH_KV`: "just prefix the keys"
       * is a convention only one of the two writers ever agreed to. The argument
       * is weaker here than it was there — both writers are this project's own
       * code, not a library owning its prefixes in shipped JavaScript — but the
       * consequence of a collision is worse. `DAV_CACHE` holds a cache whose
       * corruption costs two extra PROPFINDs; this namespace holds the only
       * record of which capability tokens have already been spent, and a key
       * that collides with a discovery entry is a confirmation that can be
       * replayed.
       *
       * **One key per spent confirmation, and nothing else.** Key
       * `confirm:v1:<jti>`, value `"1"` — the presence of the key is the whole
       * datum, so the value carries no payload to leak and no shape to
       * misparse. The `v1` buys the hedge `DAV_CACHE_KEY_PREFIX` and
       * `TOKEN_VERSION` buy: a future change to the stored shape becomes
       * detectable rather than silently misread as the current one.
       *
       * `expirationTtl` is derived from the token's OWN absolute expiry rather
       * than from a constant, so the record outlives every token it could be
       * asked about and not one second longer, and is floored at 60 because KV
       * refuses less (the same floor `DISCOVERY_TTL_SECONDS` is checked
       * against). A record that expired before its token did would let the
       * token be spent twice.
       *
       * **The honest limitation, stated here rather than left to be
       * discovered:** KV is eventually consistent. A write is not guaranteed
       * visible to a read at another edge location for a short propagation
       * window, so two commits of the same token racing inside that window can
       * BOTH see an absent key and both pass this check. That is not a
       * hypothetical gap this docstring is hedging against; it is how KV works.
       * `If-Match` is the independent second layer that catches it: the loser of
       * the race carries an etag the first write has already invalidated, and
       * the DAV server rejects it with a 412 that no amount of KV staleness can
       * turn into a 200. Neither layer is sufficient alone — this one rejects
       * before any DAV request is issued, which is what the requirement asks
       * for; `If-Match` rejects at the server, which is what actually holds
       * under a race.
       *
       * Typed `KVNamespace`, NOT `KVNamespace | undefined`, for the reason
       * spelled out on `DAV_CACHE` above: the widening on the Secret bindings,
       * here and in the narrow interfaces at the end of this file, is a
       * statement about what a Workers Secret is at runtime, and it
       * does not transfer to a namespace binding, which either resolves at
       * deploy time or fails the deploy.
       */
      CONFIRM_KV: KVNamespace;

      /**
       * Attachment staging bucket (D-83, ATT-03).
       *
       * A bucket of its own rather than a prefix inside an existing store, for
       * the same reason `DAV_CACHE` is a second namespace rather than a key
       * prefix in the first.
       *
       * Holds attachment bytes between the call that stages them and the call
       * that attaches them to a draft — and nothing else, for no longer than it
       * takes. Objects live under a `staging/` prefix that carries a one-day
       * expiration rule; that rule is account state created out of band, is not
       * in git, and its listing is recorded in
       * .planning/phases/04-mail-write-attachments/04-UAT.md. This is a holding
       * area with a sweep behind it, not storage — PROJECT.md's "local caching
       * is not a product feature" constraint draws the same line here it draws
       * for `DAV_CACHE`.
       *
       * Typed `R2Bucket`, NOT `R2Bucket | undefined`, for the reason spelled
       * out on `DAV_CACHE` above: the widening on the Secret bindings, here and
       * in the narrow interfaces at the end of this file, is
       * a statement about what a Workers Secret is at runtime, and it does not
       * transfer to a bucket binding, which either resolves at deploy time or
       * fails the deploy.
       */
      ATTACHMENT_STAGING: R2Bucket;

      /**
       * Everybody who may sign in who is NOT the owner (GATE-01, GATE-03).
       *
       * A FOURTH namespace, and its reason is operational rather than
       * structural. The three above are separate from each other so two writers
       * cannot collide in one keyspace. This one exists because the thing it
       * holds used to be a Workers Secret, and a Secret cannot be read back —
       * not from the dashboard, not from wrangler, not from anywhere — so "who
       * is on the allow list?" was a question the administrator could not
       * answer. The owner reversed that storage decision on 2026-09-20 on that
       * ground alone.
       *
       * **One key, holding a configuration document rather than a person's
       * data.** `allow-list:v1`, whose value is the same JSON array grammar the
       * seed below holds. One grammar, because one parse rule in
       * `src/auth/allow-list.ts` serves both sources and two grammars would be
       * two rules that can drift.
       *
       * **Read at LOGIN ONLY, and that is a constraint rather than a choice.**
       * `src/mcp/api-handler.ts`'s `fetch` has a tested contract that it never
       * awaits, and there is no way to read a namespace synchronously. So the
       * door reads the seed below instead, and the trade the owner accepted is
       * written on `ALLOWED_APPLE_IDS_SEED` and in the module header.
       *
       * **A read that fails means NOBODY, never a pass.** `readStoredAllowList`
       * catches without reading the caught value: a store this server cannot
       * reach admits nobody the store would have admitted, and leaves the
       * seed's own answer untouched — which is why a store outage cannot lock
       * the owner out of his own server.
       *
       * Typed `KVNamespace`, NOT `KVNamespace | undefined`, for the reason
       * spelled out on `DAV_CACHE` above: the widening on the Secret bindings
       * is a statement about what a Workers Secret is at runtime, and it does
       * not transfer to a namespace binding, which either resolves at deploy
       * time or fails the deploy.
       */
      ALLOW_LIST_KV: KVNamespace;

      /**
       * The login flood brake, keyed by the connecting source (GATE-04 layer 1).
       *
       * Five attempts a minute. Consulted at the top of a `/authorize` POST,
       * before the authorization query is re-parsed and before the client is
       * looked up, so a flood buys no round trip to anything. It is the ONE
       * refusal on that surface allowed a status of its own, because it is
       * keyed by who is connecting rather than by which address is being
       * tried and therefore carries nothing about who may sign in.
       *
       * The limit and the window are declared on the binding in wrangler.jsonc
       * and cannot be passed per call: `RateLimitOptions` in the shipped types
       * is `{ key }` and nothing else. The local simulator accepts more, which
       * is a trap rather than a convenience — code using it is green on every
       * local test and fails `npm run typecheck`.
       *
       * Typed `RateLimit`, NOT `RateLimit | undefined`. The widening on every
       * Secret below is a statement about what a Workers Secret is at runtime,
       * and it does not transfer to a binding declared in config, which either
       * resolves at deploy time or fails the deploy.
       */
      LOGIN_IP_LIMITER: RateLimit;

      /**
       * The login guess brake, keyed by the target's user id (GATE-04 layer 2).
       *
       * Three a minute against one address. Consulted only after the shape
       * check and the allow-list check have both passed, so an address nobody
       * listed is never counted against anybody. A trip renders the single
       * credential-path failure string at 401 and NEVER this layer's
       * neighbour's 429: a status that only ever appeared for a listed address
       * would be a list-membership oracle.
       *
       * A second binding rather than a second key space on the one above,
       * because the numbers differ and the numbers live on the binding. This
       * one bounds how many times this Worker may ask Apple about one person's
       * password, against a lockout threshold Apple does not publish.
       *
       * Typed `RateLimit` for the reason given on the binding above.
       */
      LOGIN_ID_LIMITER: RateLimit;

      /**
       * One Durable Object per signed-in person, holding that person's mail
       * connection lease (Phase 24, DOBJ-01).
       *
       * Named ONLY by `agentFor` in `src/agent/lease.ts`, from the signed-in
       * principal's user id. That function is the only reader of this binding
       * under `src/`, so no request field can choose whose object is reached.
       * The object holds a lease record and nothing else: no address, no
       * credential, no socket.
       *
       * Declared in wrangler.jsonc through the `exports` field with SQLite
       * storage. The reason, and why that choice cannot be undone, is written
       * beside the block there.
       *
       * Typed `DurableObjectNamespace<UserAgent>`, NOT `... | undefined`, for
       * the reason spelled out on `DAV_CACHE` above: a binding declared in
       * config either resolves at deploy time or fails the deploy.
       */
      USER_AGENT: DurableObjectNamespace<UserAgent>;

      /**
       * The vector index for semantic recall over each person's recent mail
       * (Phase 25, RCLL-01).
       *
       * Read by ONE module under `src/`: `src/recall/index.ts`. That module puts
       * the signed-in principal's user id into the partition and the filter of
       * every query and write, because the store fails open: a query that names
       * no partition is read as searching everyone. A scan count holds the one
       * reader, and zero readers is a violation too.
       *
       * Tests never read this binding for real work. They pass a fake to the
       * store's factory, and the pool is set so that a call through the real
       * binding fails rather than reaching the account.
       *
       * Typed `Vectorize`, NOT `... | undefined`, for the reason spelled out on
       * `DAV_CACHE` above: a binding declared in config either resolves at
       * deploy time or fails the deploy. The index itself is account state the
       * owner creates by hand; wrangler.jsonc says why.
       */
      RECALL_INDEX: Vectorize;

      /**
       * Workers AI, used for one thing: turning text into the vectors the
       * recall index holds (Phase 25, D-05).
       *
       * Read by ONE module under `src/`: `src/recall/embed.ts`, which also holds
       * the one model id. Tests pass a fake to that module's factory instead.
       *
       * Typed non-optional for the reason given on the binding above.
       */
      AI: Ai;

      /**
       * The Cloudflare account id. A Worker var declared in wrangler.jsonc, not
       * a Secret.
       *
       * Typed `string` with no widening, and the distinction is the point: a
       * `vars` entry is part of the deployed configuration and is present
       * whenever the Worker is, so it does not have the absent-at-runtime
       * property that forces the widening on every binding below. Reading the
       * two apart is easier if the types disagree.
       *
       * Not sensitive — an opaque account handle, not a credential. It is
       * needed to build the host of a presigned upload URL.
       */
      R2_ACCOUNT_ID: string;

      /**
       * The OWNER's own address, as a JSON array. A Worker var declared in
       * wrangler.jsonc, not a Secret.
       *
       * **Half of the allow list, not all of it.** The other half is
       * `ALLOW_LIST_KV` above. The two are read in different places because
       * they answer different questions:
       *
       * - This seed is read SYNCHRONOUSLY, at the login page and on every
       *   served request. It is what keeps `createMcpApiHandler`'s tested
       *   never-awaits contract — the contract that makes an unusable stored
       *   credential surface as a tool error rather than as a 401, which would
       *   tell the client to sign in again when signing in again cannot fix a
       *   password Apple has revoked.
       * - The namespace is read at LOGIN ONLY, which is already an async path.
       *
       * So the STORE decides who may sign in, and the SEED decides whether this
       * deployment serves anybody at all. The consequence the owner accepted on
       * 2026-09-20: the door cannot re-check membership for a store-listed
       * person, so removing someone is two steps — take them out of the store,
       * then revoke their grants. Phase 12's LIFE-05 script is the second half.
       *
       * **It also stops the owner locking himself out.** Whatever state the
       * namespace is in — empty, unreachable, holding nonsense — the seed still
       * answers, and it still names him.
       *
       * **Typed `string | undefined`, and the widening is argued against its
       * neighbour rather than copied from it.** `R2_ACCOUNT_ID` directly above
       * is a `vars` entry typed `string` with no widening, because a var is part
       * of the deployed configuration and is present whenever the Worker is.
       * That argument does not transfer here, for a reason specific to this
       * binding: `wrangler.jsonc` is git-ignored, so NOTHING TRACKED IN THIS
       * REPOSITORY guarantees the key is present at all — the tracked template
       * can carry it and a live config can still be missing it. And this one is
       * a safety gate: its absence must be visible to the compiler rather than
       * discovered at runtime by a locked-out owner. An absent seed parses as
       * NOBODY, so the login page answers 503 above the method dispatch and the
       * door refuses every grant.
       *
       * **A JSON array rather than a bare address, deliberately.** It is the
       * same grammar the namespace's value holds, which is what lets ONE parse
       * rule serve both sources, and it is what keeps GATE-01's rule
       * expressible here: only exactly `["*"]` means open, and a rule that
       * accepted a bare string would make `"*"` — five characters, no brackets,
       * the single easiest typo in a config file — mean everybody.
       *
       * Consumed only through `parseAllowList` in `src/auth/allow-list.ts`,
       * which reads it, answers a three-member verdict, and hands back nothing
       * that carries the raw value.
       */
      ALLOWED_APPLE_IDS_SEED: string | undefined;

      /**
       * Injected by the OAuth provider on every request before it dispatches
       * to a handler. This is how the authorize form reaches
       * `parseAuthRequest` / `completeAuthorization` without the handler
       * holding a reference to the provider instance.
       */
      OAUTH_PROVIDER: OAuthHelpers;

      // The login gate's secret and the two mail secrets are NOT declared
      // here. They live in the narrow interfaces at the end of this file, so
      // code that holds the shared type cannot read them (Phase 9 D-14).

      /**
       * Access key id of the R2 S3 API token. Workers Secret.
       *
       * Source: an R2 API token scoped to the single bucket
       * `icloud-mcp-attachments` with Object Read & Write only — deliberately
       * not the account-wide token the dashboard offers by default, which would
       * be a privilege escalation buying this phase nothing.
       *
       * Admits `undefined` for the same reason the three secrets in the narrow
       * interfaces at the end of this file do, and the
       * absent case is worth naming here because it does not announce itself:
       * a signer handed an absent key produces a syntactically well-formed
       * signature over an empty credential, and the failure surfaces as a
       * rejection from R2 rather than as a missing-configuration error. The
       * compiler finding the consumer that assumes presence is the whole
       * benefit of typing it honestly.
       *
       * Consumed only through the write-only signing helper in
       * src/staging/presign.ts, which takes the value, uses it, and returns
       * nothing that carries it. No object holding either half of this pair is
       * ever constructed, so there is nothing to serialise, attach to an error,
       * or spread into a response (./.claude/CLAUDE.md §4).
       */
      R2_ACCESS_KEY_ID: string | undefined;

      /**
       * Secret access key of the R2 S3 API token. Workers Secret.
       *
       * The other half of the pair above, with the same source, the same
       * widening for the same reason, and the same write-only consumption path.
       * The two are declared together because they are useless apart: neither
       * one alone signs anything, so a check for one is a check for both.
       */
      R2_SECRET_ACCESS_KEY: string | undefined;

      /**
       * HMAC key for the calendar confirmation token (CALW-04). Workers Secret.
       *
       * **Its own Secret, and it OUTLIVED the one it was kept apart from.** The
       * login gate had a shared secret of its own until Phase 13, and reusing
       * that one here would have worked and been one fewer thing to provision —
       * which is exactly why it needed an argument against it: the two keys had
       * different rotation consequences. That one gated the authorize form, and
       * rotating it invalidated nothing already granted. This one signs
       * capabilities to write to a calendar, and rotating it must invalidate
       * every outstanding preview immediately — that is the point of rotating
       * it. Sharing one value would have coupled a routine credential change on
       * one path to a silent capability revocation on the other, in whichever
       * direction the rotation came from.
       *
       * The argument is kept rather than deleted with the secret it argued
       * against, because it is the reason this key must not be folded into
       * whatever the NEXT shared secret turns out to be. It is likewise not the
       * signed-in person's app-specific password, which belongs to Apple rather
       * than to this server, and which no longer arrives as a binding at all.
       *
       * Admits `undefined` for the reason every Workers Secret does — unset,
       * deleted,
       * and failed-to-provision all arrive absent, and nothing at runtime
       * distinguishes that from a configured value until something reads it.
       * The specific failure the widening exists to surface is worth naming,
       * because it is silent and it fails OPEN rather than closed:
       * `crypto.subtle.importKey` accepts a zero-length raw HMAC key in some
       * implementations rather than throwing, so a server that both signs and
       * verifies with the empty key verifies its own forgeries perfectly and
       * accepts anyone else's too. Every signature is valid; nothing errors;
       * the gate is simply not there. That is CR-01 one module over, on a path
       * whose consequence is a write to the user's real calendar rather than a
       * login form. `src/confirm.ts` therefore fails closed on BOTH mint and
       * verify when this is absent, rather than only on verify — minting under
       * an absent key would produce tokens that outlive the misconfiguration.
       *
       * Consumed only through `src/confirm.ts`, which imports it once as a
       * NON-EXTRACTABLE `CryptoKey` and returns nothing that carries it — the
       * same write-only consumption path `R2_ACCESS_KEY_ID` describes. No
       * object holding this value is ever constructed, so there is nothing to
       * serialise, attach to an error, or spread into a response
       * (./.claude/CLAUDE.md §4). Non-extractable is what makes that structural
       * rather than a habit: the key material cannot be read back out of the
       * `CryptoKey` even by code that holds it.
       */
      CONFIRM_SECRET: string | undefined;

      /**
       * A service binding to THIS Worker (Phase 27, D-22; SPIKE-08).
       *
       * The autonomy key is redeemed at this Worker's own token endpoint and
       * used at its own `/mcp`, in-process, through this binding. The person's
       * Durable Object is the only caller, through one seam on the object.
       *
       * It must name this Worker. A binding to any other Worker would hand that
       * Worker a person's token. And it carries no identity: the caller builds
       * the exact deployed hostname and the exact path itself, and presents a
       * real token for the person it acts for (SPIKE-08's findings, in the
       * header of `test/self-binding.test.ts`).
       *
       * Typed `Fetcher` and not widened: a service binding either resolves at
       * deploy time or fails the deploy, like the namespaces above.
       */
      SELF: Fetcher;

      /**
       * The autonomy client's secret (Phase 27, D-07). Workers Secret.
       *
       * Source: set once by the owner's setup command in plan 27-03, which puts
       * it through `wrangler secret put` on standard input and never prints it.
       * The same value's hash is what the library stores on the autonomy
       * client's record.
       *
       * The autonomy client is confidential, so a refresh token that leaked on
       * its own cannot be cashed in at the public token endpoint: the endpoint
       * also wants this secret, on the code exchange, on every refresh and on a
       * revocation.
       *
       * Admits `undefined` for the reason every Workers Secret does: unset,
       * deleted and never-provisioned all arrive absent. `isConfiguredSecret`
       * narrows it. Consumed by the person's object through
       * `src/agent/autonomy.ts`, and by the sign-in's one "is autonomy set up"
       * predicate. No object holding it is ever built to be serialised, attached
       * to an error, or spread into a response (./.claude/CLAUDE.md §4).
       */
      AUTONOMY_CLIENT_SECRET: string | undefined;

      /**
       * The key that seals every stored autonomy refresh token (Phase 27,
       * D-06). Workers Secret: 32 random bytes, base64url.
       *
       * Source: set once by the owner's setup command in plan 27-03, the same
       * way as the secret above. Two separate values rather than one derived
       * pair, so each fails on its own: rotating the client secret destroys no
       * seal, and rotating this key ends everyone's autonomy key until their
       * next sign-in, because nothing sealed under the old key opens any more.
       *
       * With it, reading every store this server has still opens nothing: a
       * sealed token needs this secret, and no store holds it.
       *
       * Admits `undefined`, narrowed by `isConfiguredSecret`, for the reason
       * the secret above gives. Consumed only by `src/agent/autonomy.ts`, which
       * imports it as a non-extractable key and returns nothing that carries
       * it, and by the sign-in's one "is autonomy set up" predicate.
       */
      AUTONOMY_SEAL_KEY: string | undefined;

      /**
       * The spent marks for attachment save links (Phase 29.1, 29.1-WORDING.md
       * decision 1).
       *
       * Holds only spent marks: one per link that has been downloaded, keyed by
       * the SHA-256 of the link's token, gone after ten minutes. Nothing is
       * written when a link is made, so a new link never waits for this store
       * to reach another Cloudflare location. A miss means "not spent".
       *
       * Read and written only by `src/save/link.ts`. Typed `KVNamespace`, not
       * widened, for the reason spelled out on `DAV_CACHE` above.
       */
      SAVE_LINK_KV: KVNamespace;

      /**
       * The key that seals every attachment save link (Phase 29.1, 29.1-WORDING.md
       * decision 1a). Workers Secret: 32 random bytes, base64url with no padding.
       *
       * A link carries whose copy it is, the copy's name, its expiry and its
       * size, sealed with AES-GCM under this key. Nobody can read those from the
       * URL, or make a link, without it.
       *
       * Source: set with `wrangler secret put` on standard input, generated from
       * a random source and never printed. Admits `undefined` for the reason
       * every Workers Secret does; `saveLinksConfigured` in `src/save/link.ts`
       * narrows it and also checks the length. Read only by `src/save/link.ts`,
       * which imports it as a non-extractable key and returns nothing that
       * carries it (./.claude/CLAUDE.md §4).
       */
      SAVE_LINK_SEAL_KEY: string | undefined;

      /**
       * The download route's brake, keyed by the connecting address (Phase 29.1,
       * 29.1-WORDING.md decision 3).
       *
       * Thirty requests a minute from one address. Consulted by
       * `src/save/route.ts` after the method and shape checks and before the
       * link is opened, so a refused request reads nothing and never spends a
       * link. A request with no address header is counted under one fixed key,
       * never let through unbraked.
       *
       * The limit and the window live on the binding in wrangler.jsonc. Pass a
       * key and nothing else, for the reason given on `LOGIN_IP_LIMITER`.
       * Typed `RateLimit` for the reason given there too.
       */
      SAVE_IP_LIMITER: RateLimit;

      // The single write-only Secret that used to hold the whole allow list is
      // GONE from this type, along with its two readers, in one commit — a
      // half-removed binding is a name the compiler still accepts and nobody
      // reads. `ALLOWED_APPLE_IDS_SEED` above plus `ALLOW_LIST_KV` replace it.
      // The argument that put it here was a privacy one, and it did not
      // survive: the replacement keeps real addresses out of the tracked
      // template anyway, and a Secret could not be read back from anywhere,
      // which made "who is on the allow list?" unanswerable.
    }
  }
}

export type Env = Cloudflare.Env;

// The three narrow secret types are GONE, in one commit with the last thing that
// could spell them (Phase 13, CUT-01).
//
// Two of them held the account credentials and the login gate's shared secret,
// and the third was their union with the shared type above — what the runtime
// really handed the entry point. They were declared outside the global block on
// purpose, so that code holding the shared type could not spell the names and a
// new reader would not compile (Phase 9 D-14). That worked, and then the reason
// for the names themselves went away: the credentials arrive per person in a
// grant's encrypted props, and the gate the shared secret guarded was replaced by
// the login page.
//
// THE UNION TYPE WAS DELETED RATHER THAN ALIASED to the shared type. The same
// argument the removed allow-list Secret above settles: a half-removed binding is
// a name the compiler still accepts and nobody reads. There is no longer an entry
// environment distinct from the shared one, and keeping the name would say there
// is — so the entry point, the OAuth provider's options, the door and the login
// handler all take the plain shared type now.
//
// The bindings are gone from the platform too, not merely from this file, and the
// scan refuses a read of either account name under this tree. That rule was a
// COUNT permitting exactly one reader until the reader was deleted; zero became
// the correct number, so it became a ban. This file is inside its scope, which is
// why the paragraph above describes the account bindings by role rather than
// spelling them.
