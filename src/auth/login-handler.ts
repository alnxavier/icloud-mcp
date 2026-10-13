// The /authorize surface: a person signs in with their OWN Apple ID and app-
// specific password, and the credentials go into the grant's encrypted props.
//
// **Phase 11 replaced what this file asks for.** It used to ask for one shared
// secret and compare it against a Workers Secret (D-01), which is how a
// single-user server against one Apple ID identified its one user. The server
// now has N users, and identity moved out of the environment and into the
// grant. So the form asks for an Apple ID and an app-specific password, the
// address is checked against an allow list before anything else is spent on it,
// one IMAP login proves the pair, and `completeAuthorization` stores both in
// props that only this server can decrypt. `src/principal.ts` is where they
// come back out.
//
// **This file renders nothing.** Every byte the reader sees is built by
// `src/auth/login-page.ts`, which owns the approved design contract, the copy
// and the security headers; this file decides WHICH response happens and in
// what order, and calls into the page for the one that has a body worth
// designing. That split is a locked decision rather than a tidiness: this file
// was already 32 KB before the phase added a credential form and three limiter
// layers to it.
//
// The full OAuth 2.1 ceremony still happens around this — dynamic client
// registration, PKCE-protected code exchange, refresh rotation, revocation —
// all owned by the provider. Only the identity step is ours.
//
// **The submitted credentials are spent and nothing else**: never echoed, never
// reflected into the rendered page, never logged, never included in an error,
// and never put in any store but the grant's own props. No object holding the
// password is constructed here — `principalFromProps` builds the one principal
// and keeps the password in its own holder, and this file never asks for it
// back. The password reader is not imported here and must never be.
//
// The credentials are NOT, however, the only untrusted input in the flow. The
// redirect URI
// is attacker-chosen too — client registration is unauthenticated by spec —
// and it decides where the authorization code is delivered. That is why the
// page names the client and the destination before it asks for anything
// (CR-04). The consent screen is now the second of two controls in front of
// that URI, not the sole one: an origin allowlist refuses the class outright
// before the form is ever rendered. The screen still earns its place, because
// the allowlist's loopback entry is a CLASS rather than an exact value — an
// attacker can register a client whose callback is a loopback address on some
// port, and that passes the allowlist. The code would then be delivered to a
// listener on the owner's OWN machine, which is small residual risk but not
// zero, and the screen is what surfaces it: the owner sees a loopback address
// on the page when they expected the remote origin.
//
// ---------------------------------------------------------------------------
// An omission stood here until plan 11-05. Plan 11-05 NARROWED it; it did not
// close it, and this paragraph said "closed" until the phase review of
// 2026-09-21 found otherwise. It is kept rather than erased — the same
// treatment the redirect-origin paragraph below records, and for the same
// reason: a reader who finds the fix has to be able to find what it replaced.
//
// This file used to record that its failure counter was not atomic and was not
// being made atomic. `get` -> compare -> `put` is a read-modify-write over an
// eventually-consistent store, so concurrent attempts all read the same value
// and the cap does not engage under parallel load. The omission was accepted
// while the thing behind the form was a high-entropy shared secret compared in
// constant time, against which two hundred parallel guesses a round is nothing.
// That argument left with the secret. What sits behind the form now is a real
// Apple app-specific password, and the cost of a guess is no longer this
// server's alone: every attempt lands at Apple, whose own lockout threshold is
// unpublished and must be assumed small.
//
// **What narrowed it is not an atomic counter either.** A burst now meets a
// platform rate-limit binding first, and the store counter was kept only for
// the hour that binding's window cannot reach. Three layers stand in front of
// Apple: the connecting source, the target address in a minute, and the target
// address across an hour. Each is argued where it is wired below.
//
// **None of the three is exact, and this file used to say otherwise.** It
// called the binding atomic. Cloudflare does not promise that. Its rate-limit
// binding keeps a counter per Cloudflare location, and those counters are
// eventually consistent. Cloudflare says plainly it is not for exact
// accounting. So:
//
// - Requests that land on different locations are counted separately.
// - Requests fired in parallel can all pass one window before the count
//   catches up.
// - The store counter cannot catch the overflow. It reads its value before the
//   login runs, so a parallel burst all reads the same number.
//
// What that means in practice: against one address, the three-a-minute and
// five-in-any-sixty-minutes figures hold for a patient, serial guesser (the
// hourly one exactly; see layer 3). They do NOT hold
// for a parallel or many-location burst. How far over they go depends on how
// many locations the attacker can reach and how fast they fire, and nothing in
// this file can measure that. Apple's lockout threshold is unpublished. If it
// is hit, what breaks is the owner's own Mail on his own devices.
//
// That is recorded as an ACCEPTED COST on 2026-09-21, not as a solved problem.
// The only exact per-target count on this platform is a Durable Object per
// person. 11-CONTEXT.md compared that design and declined it for v2.0 on
// deploy risk, on the belief that the binding was exact. That belief was
// wrong. So the comparison should be reopened with the real guarantee in hand,
// not treated as settled.
//
// 11-CONTEXT.md records that Durable Object comparison in full, deliberately,
// so a later phase that wants one does not have to re-derive it.
//
// A second omission stood here until 2026-08-14, and it was closed rather than
// quietly erased: this file used to record that it carried no allowlist of
// permitted redirect origins. What blocked that allowlist was never its cost —
// it was one constant then and it is one constant now. It was that the
// legitimate origin set was genuinely unobserved, and narrowing against a
// guess locks the owner out of their own server, which is worse than the
// outcome being prevented. Enumerating the live registration store on
// 2026-08-14 produced the real values and cleared the blocker. The observed
// set, the reasoning behind the matching rule, and the recovery for a wrong
// value now all live at ALLOWED_REDIRECT_ORIGINS below.
// ---------------------------------------------------------------------------

import { AuthorizationError } from "@cloudflare/workers-oauth-provider";
import type {
  ClientInfo,
  ClientRegistrationCallbackOptions,
  ClientRegistrationCallbackResult,
} from "@cloudflare/workers-oauth-provider";
import {
  AUTONOMY_CLIENT_ID,
  AUTONOMY_CLIENT_NAME,
  AUTONOMY_REDIRECT_PATH,
} from "../agent/autonomy-client";
import { sealKeyUsable } from "../agent/autonomy";
import { agentFor } from "../agent/lease";
import { isConfiguredSecret } from "../configured-secret";
import { DEPLOYED_HOSTNAME } from "../deployed-hostname.generated";
import type { Env } from "../env";
import { ImapConnectError, ImapThrottleError } from "../errors";
import type { SessionGate } from "../mail/service";
import { createSessionGate, withMailSession } from "../mail/service";
import { clearPause } from "../password-pause";
import type { Principal } from "../principal";
import { normaliseAppleId, principalFromProps, userIdOf } from "../principal";
import type { AllowList } from "./allow-list";
import { isAllowed, parseAllowList, readStoredAllowList } from "./allow-list";
import type { SignInNotice } from "./login-page";
import {
  AUTONOMY_NOTICE,
  AUTONOMY_NOTICE_FIELD,
  AUTONOMY_NOTICE_VERSION,
  RECALL_NOTICE,
  MAIL_ONLY_NOTICE,
  RESPONSE_HEADERS,
  SOURCE_REFUSAL_BODY,
  renderForm,
  responseHeadersFor,
} from "./login-page";

/** The only scope this server issues. */
const SUPPORTED_SCOPES = ["mcp"];

/** The version every props object this server writes carries. */
const PROPS_VERSION = 1;

/**
 * The form field carrying the Apple ID.
 *
 * Exported so `src/auth/login-page.ts` writes the very name this file reads.
 * Two spellings of a field name are two rules, and the failure is silent: the
 * form renders, the person types, and the submitted value arrives under a name
 * nothing looks for, which reaches the reader as the generic failure body.
 */
export const APPLE_ID_FIELD = "apple_id";

/** The form field carrying the app-specific password. Exported for the same reason. */
export const APP_PASSWORD_FIELD = "app_password";

/**
 * The shortest a submitted value may MEASURE, once dashes are stripped.
 *
 * This bound exists to refuse a FRAGMENT: a paste that caught half the value,
 * a couple of characters typed into the wrong box, a value that was cut short
 * by a copy that ended early. Eight is well under the one length anyone here
 * has ever seen from Apple, so it refuses nothing plausible.
 *
 * "Measure" rather than "canonical", because this project no longer has a
 * canonical form. See `couldBeAppPassword` for what changed and why.
 */
const MIN_MEASURED_APP_PASSWORD = 8;

/**
 * The longest a submitted value may MEASURE, once dashes are stripped.
 *
 * This bound exists for an entirely different reason from the one above, and
 * the pair is deliberately not one rule with two ends. It refuses a
 * PASSPHRASE — a sentence, a paragraph, a whole paste of something that was
 * never a credential. Sixty-four is four times the one observed length, so an
 * Apple grammar with twice the groups, or twice the characters per group,
 * still passes.
 *
 * Neither bound tries to tell an app-specific password from a real Apple ID
 * password. It cannot be done by length — Apple's account password is eight or
 * more characters and can be sixteen too — and pretending otherwise is exactly
 * the over-tight rule the locked decision refuses.
 */
const MAX_MEASURED_APP_PASSWORD = 64;

/**
 * Could this be an app-specific password at all? (LOGIN-03)
 *
 * **This server no longer transforms the password, and that is a decision
 * rather than an omission.** What the person types is what reaches Apple, byte
 * for byte, and it is the same bytes the grant stores. There is no canonical
 * form, no stripping and no inserting.
 *
 * **Why there is nothing to invert here any more.** The value used to be
 * reduced — separators dropped, ends trimmed — on the way to Apple, and the
 * direction of that reduction was gated on spike S5: a manual check of whether
 * iCloud accepts the dashless form, which no automated job in this repository
 * may run (D-09). S5 was NOT RUN. The owner declined it on 2026-09-20, after
 * finding that the planned procedure could not work: it said to re-enter the
 * password in Mail.app, and Mail.app signs in through the Mac's system iCloud
 * account and never sees an app-specific password at all.
 *
 * Rather than measure it, the transformation was removed. Apple publishes no
 * format for these values — its own support page covers creating, managing and
 * revoking them and says nothing about length, character set or grouping — so
 * a server that edits the value is guessing at a grammar on the person's
 * behalf. Passing it through is the honest position when the measurement is
 * absent: Apple decides, because Apple is the only party that knows.
 *
 * **How to get the measurement later**, if somebody is refused at sign-in and
 * suspects the dash form is why: sign in through the login page with the
 * dashless form. Nothing in this file has to change first, because both forms
 * now reach Apple as typed. It costs one real attempt at Apple and one tick of
 * that person's hourly counter, so do it once, deliberately. If it signs in,
 * call `mail_imap_diagnose` and `dav_diagnose` from that session to check the
 * IMAP and DAV halves; both act for the credentials stored in the grant.
 *
 * Do NOT measure it by changing the `APPLE_APP_PASSWORD` secret. An earlier
 * version of this note said to. Since phase 11 nothing that serves a request
 * reads that secret — every tool, the two diagnose tools included, acts for
 * the grant's stored credentials — so a swap changes nothing, and the two
 * identical results would be misread as "both forms work".
 *
 * **What this function still does, and why it is not the same act.** It derives
 * its own MEASUREMENT form — trim the ends, drop the separators — purely to
 * count characters, and that derived string never leaves this function. That
 * containment is the one structural property worth protecting: no variable
 * anywhere in this handler holds a transformed password, so there is nothing
 * for a later session to pick up and send onward by accident. Stripping
 * separators to COUNT and stripping them before SENDING are different acts, and
 * they were separated on purpose. Do not fold them back together.
 *
 * The cost of passing through, accepted: a value carrying a stray leading or
 * trailing space measures fine and reaches Apple with the space still on it,
 * where it is refused. The page's help copy is what pays that down — it tells
 * the reader to paste the value exactly as Apple showed it, and it is the only
 * place they can learn that, because every credential failure answers with the
 * same silent string.
 *
 * **This check is LOOSE on purpose, and this is the rule a later session will
 * be most tempted to tighten.** The argument, written here because a planning
 * file is not where the tempted reader will be looking:
 *
 * - **Apple publishes no format.** Its own support page for app-specific
 *   passwords covers creating, managing and revoking them and says nothing
 *   about length, character set or grouping. The four-groups-of-four shape is
 *   training knowledge plus exactly one observed sample — the owner's own.
 * - **The question it answers is "is this clearly not an app-specific
 *   password", never "is this exactly the grammar I remember".** A strict rule
 *   that is wrong refuses a legitimate family member behind a failure message
 *   that deliberately will not say why, and they have no way to learn the
 *   reason.
 * - **The requirement is still satisfied.** A clearly-wrong value is refused
 *   before any socket opens, because this function does no I/O and sits above
 *   the one proof call site.
 * - **The cost accepted:** a typo inside the band costs one attempt at Apple
 *   and one tick of the per-target counter, instead of being caught locally.
 * - **Do not tighten this into the observed grammar to catch more typos.** That
 *   reverses a decision made on 2026-09-20 with the silent-failure cost in
 *   view. Refusing more is safe for a user id, where a refusal is a fresh start;
 *   it is not safe here, where a refusal is a person locked out of a page that
 *   will not tell them why.
 *
 * Exactly three classes are refused and there is no fourth: an empty value; a
 * value still carrying white space once the dashes are gone; and a length
 * outside the band the two constants above describe.
 *
 * **It does not duplicate `isUsablePassword`**, which lives in
 * `src/principal.ts` and refuses a whitespace-only value and any control
 * character. That one runs SECOND, inside the principal constructor, and it is
 * the deeper of the two: it guards every construction site, including the
 * props read at the door on a later request, where no form was ever submitted.
 * This one runs FIRST because it is the only one of the two that can refuse
 * before a principal is built at all — which is what makes "nothing was opened
 * to Apple" true of the shape refusal rather than merely likely.
 */
function couldBeAppPassword(submitted: string): boolean {
  // The measurement form, and it is a `const` inside this function on purpose:
  // it is not in scope anywhere a credential could be sent from.
  const measured = submitted.trim().replaceAll("-", "");

  if (measured.length === 0) return false;
  if (/\s/.test(measured)) return false;
  return (
    measured.length >= MIN_MEASURED_APP_PASSWORD &&
    measured.length <= MAX_MEASURED_APP_PASSWORD
  );
}

/**
 * What it takes to prove a credential pair is real: one login, at Apple.
 *
 * Resolves to nothing on success and REJECTS on failure, so the caller branches
 * on the error's type and never on a returned flag. There is no value here to
 * carry a credential out on: the principal goes in, the session spends it, and
 * what comes back is either nothing or a throw built with no argument.
 *
 * It exists as a type so the one call can be INJECTED. D-09 forbids any
 * automated login to a real Apple ID — no test, CI job, pre-commit hook or
 * post-deploy check ever authenticates against one — so the tests that drive
 * this whole path substitute a counting stub here. That substitution is also
 * what makes "an unlisted address opened zero sockets" an assertion a test can
 * actually make, rather than an inference from a status code.
 */
export type LoginProof = (
  principal: Principal,
  gate: SessionGate,
) => Promise<void>;

/**
 * The production proof: open one session, authenticate, close it.
 *
 * `withMailSession` is named literally at this one call site, and that is
 * deliberate rather than incidental. The `concurrent-session` scan rule matches
 * a concurrency combinator within a bounded distance of that exact name, so
 * naming it here puts this call under the existing rule with no alternation to
 * extend — and a rule whose entry points are enumerated by name is invisible to
 * every other assertion in the suite for a name it does not list.
 *
 * A fresh gate per call, from `createSessionGate()`. The gate is a closure over
 * one local boolean, so two sign-ins get two gates because they get two
 * construction sites, with no bookkeeping to reason about.
 *
 * `null` for the mailbox and `null` for the expected validity, together. That
 * skips the mailbox open and its validity gate entirely: this is
 * authenticated-state-only work, and opening a mailbox would be a second round
 * trip that proves nothing the login did not already prove.
 *
 * The callback does nothing and returns nothing. Reaching it at all IS the
 * proof — the session only exists once the server answered the login with OK.
 *
 * `oneAttemptPerGuess` is the login-path option plan 11-03 added, and THIS is
 * the one call site that passes it. A wrong password costs Apple two attempts
 * by default, because the session falls back to a second mechanism when the
 * first is refused; on this path that fallback buys nothing — the caller
 * already treats both refusals as the same answer — and it doubles what Apple
 * sees per guess against an account whose lockout threshold Apple does not
 * publish. The tools keep both mechanisms: a tool call is not a guess.
 *
 * **No second session helper.** Convention 3 permits exactly one orchestrator
 * and this calls it. Nothing here opens a socket, holds one, or fans out.
 */
async function proveWithApple(
  principal: Principal,
  gate: SessionGate,
): Promise<void> {
  await withMailSession(principal, gate, null, null, async () => {}, {
    oneAttemptPerGuess: true,
  });
}

/**
 * How long a failed sign-in takes, at minimum, measured from the handler's
 * entry.
 *
 * A FLOOR rather than the fixed penalty this replaces, and the difference is
 * the whole of what it buys. A fixed delay added to whatever the work already
 * cost leaves the work's own duration visible: an allow-list refusal returns
 * almost instantly plus the delay, a real login returns after a round trip to
 * Apple plus the delay, and a stopwatch sorts listed addresses from unlisted
 * ones by the gap. A floor measured from entry makes every failing answer take
 * the same wall-clock no matter which branch produced it.
 *
 * Three seconds, not the one it replaces, and the asymmetry argument carries
 * forward unchanged: a person typing a password does not notice three seconds,
 * and a parallel guesser is not slowed by a shorter one either way — two
 * hundred concurrent guesses pay the delay in parallel, so the round costs
 * whatever one request costs. The only party a short delay was ever gentle to
 * was the one it was aimed at.
 *
 * **The figure is sized by spike S6 in plan 11-07**, which measures a real IMAP
 * login from the deployed Worker. If a real login turns out to exceed this, the
 * leftover leak is accepted IN WRITING rather than the floor being raised
 * indefinitely: a floor that chases the slowest observed login grows without
 * bound and makes the page unusable to defend against a stopwatch nobody has
 * been observed holding.
 *
 * Exported so a test asserts the production default against the value the
 * handler actually sleeps rather than a retyped number, and so the injected
 * floor below has something to default to.
 *
 * This is also the limiter that does not depend on a durable counter
 * succeeding, which is why the counter's write is allowed to fail below and
 * this is not.
 */
export const FAILURE_FLOOR_MS = 3000;

/**
 * Sleep whatever is left of the floor, counted from ONE timestamp.
 *
 * **The arithmetic looks wrong without the runtime fact beside it.** In this
 * runtime the clock returns the time of the last input or output and does not
 * advance during code execution. On the shape-refusal path there is no I/O at
 * all between the handler's entry and the refusal, so the elapsed time reads as
 * exactly zero and this sleeps the whole floor. That is the correct answer for
 * a path that did no work, and it is the direction the arithmetic fails in:
 * safe, not leaky.
 *
 * The remainder is computed from `started` at each failing return and is NEVER
 * accumulated per step. A running total would drift with every branch that
 * forgot to add to it, and the branch that forgot would be the fast one — the
 * refusal — which is precisely the one the floor exists to slow down.
 *
 * The sleep idiom is the one this file already used twice before the floor
 * replaced them.
 */
async function holdFloor(started: number, floorMs: number): Promise<void> {
  const remaining = Math.max(0, floorMs - (Date.now() - started));
  await new Promise((resolve) => setTimeout(resolve, remaining));
}

/**
 * The source-connection limiter's window, in seconds.
 *
 * It is NOT the thing that enforces the window — the binding is, and the
 * binding's own window is declared in `wrangler.jsonc`. This constant exists
 * only so the refusal can say when to come back, and it is therefore a COPY of
 * a value that lives somewhere this module cannot read. Nothing makes the two
 * agree: no test can see the deployed config, and a mismatch is silent in both
 * directions — too small and the reader comes back early for nothing, too large
 * and they wait longer than they had to. The config carries the same figure
 * with a comment pointing back here.
 *
 * Sixty because the binding's window accepts only ten or sixty.
 */
const SOURCE_WINDOW_SECONDS = 60;

/**
 * Width of the per-target failure counter's window, in seconds.
 *
 * An hour, which is where this counter earns its place: the platform limiter
 * above it tops out at a sixty-second window, so an hour is not something a
 * binding can express. The two layers are therefore not redundant — one bounds
 * a burst and this one bounds a day's worth of patient guessing.
 *
 * Sized as if Apple's own lockout threshold is small, because Apple publishes
 * none. The thing that breaks if the guess is wrong in the generous direction
 * is the owner's own Mail app on their own devices.
 */
const FAILURE_WINDOW_SECONDS = 3600;

/**
 * Failed guesses tolerated against one address in any rolling sixty minutes.
 *
 * Exact for a serial guesser. The counter stores the time of each of the last
 * five failures, so there are no fixed hours and no boundary to straddle. The
 * sixth attempt is refused until the oldest of the five is sixty minutes old,
 * so a lockout lasts exactly an hour from the first of the five. A parallel or
 * many-location burst can still go over it; see the layer-3 comment in the
 * handler for why, and for the owner's decision.
 */
const MAX_FAILURES_PER_WINDOW = 5;

/**
 * The per-target failure counter's key prefix.
 *
 * **The user id must be interpolated with NOTHING between it and this
 * constant**, not even a space. The store-key rule in
 * `scripts/forbidden-tokens.mjs` anchors on a prefix constant spelled like this
 * one and requires the id on the very next character; its lookahead used to
 * tolerate whitespace and was tightened deliberately, because a key with a
 * space in it is not the key the rule claims to require. Until this constant
 * existed the rule did not see this counter at all — the old key was built from
 * plain literals — and the rule's own comment names that gap as this phase's to
 * close.
 *
 * The version segment is the same hedge the confirmation slot's own prefix and
 * the DAV discovery cache's carry — both named by role rather than spelled,
 * because each has already moved and a spelled cross-reference goes stale in
 * silence when it moves again. This paragraph spelled the confirmation one until
 * that prefix reached v4, which is the staleness it was warning about happening
 * to itself: a
 * later change to the shape becomes detectable rather than silently misread as
 * the current one. It has been needed twice. The keys before `v2` were
 * keyed by source rather than by target. `v2` keys held a plain count per
 * clock hour. `v3` holds a list of failure times, one key per person. No older
 * shape is read, so a leftover key is ignored and expires on its own TTL.
 */
const LOGIN_FAILURE_KEY_PREFIX = "authorize-failures:v3:";

/**
 * The exact origins this server will deliver an authorization code to.
 *
 * These values were OBSERVED, not guessed. On 2026-08-14 the live registration
 * store was enumerated and the legitimate redirect shapes read off the clients
 * that actually hold grants; everything else in there was a throwaway
 * verification registration. That measurement is the whole reason this
 * allowlist exists now and did not exist before — narrowing against a guess
 * was the risk that kept it deferred.
 *
 * Matching is EXACT EQUALITY on the origin derived by `originOf`, never a
 * substring test. That single choice is what makes three separate bypasses
 * fail without any of them being enumerated as a negative: a host that merely
 * ends with an allowed one is a different string, a cleartext scheme is a
 * different string, and `URL.origin` carries the port so an added port is a
 * different string too.
 *
 * The `.com` sibling of the entry below is deliberately ABSENT. It was
 * considered and declined, not missed: it was not observed, and pre-adding an
 * unobserved origin is the mirror image of the error this deferral existed to
 * avoid — widening against a guess instead of narrowing against one.
 *
 * If this value is ever wrong, the recovery is small and worth knowing before
 * panicking. This is a source constant, not stored state, so nothing saved has
 * to be edited or deleted. A wrong entry blocks only a NEW authorization: the
 * gate is on `/authorize` alone, while token refresh is served by the provider
 * at the token endpoint and never reaches this handler, so an already-issued
 * token keeps working. The fix is to read the refused origin out of the
 * refusal body this server just served, add it here, and deploy.
 */
const ALLOWED_REDIRECT_ORIGINS: readonly string[] = ["https://claude.ai", "https://chatgpt.com"];

/**
 * The one origin CLASS admitted alongside the exact entries above: loopback.
 *
 * The port is optional and deliberately unpinned. A local client binds an
 * ephemeral port and re-binds a different one next session, so pinning the
 * value observed on any given day breaks the very next authorization —
 * reproducing exactly the lockout this work was deferred to avoid. This is the
 * standard OAuth native-app carve-out and not laxness invented here: RFC 8252
 * section 7.3 states that a loopback redirect's port is assigned at runtime and
 * that the authorization server MUST allow any port.
 *
 * This is also the only place the cleartext scheme is permitted, and it is safe
 * precisely because a loopback address is unreachable from anywhere but the
 * owner's own machine. Traffic on that interface never leaves the host, so
 * there is no transport to expose; an attacker positioned to receive on it
 * already has the machine.
 *
 * The TLS form of loopback is deliberately NOT admitted. It was not observed,
 * and this rule stays the observed shape plus the RFC's carve-out.
 *
 * Anchored at both ends on purpose. Without the anchors a public host that
 * merely BEGINS with a loopback name would be admitted, which is the bypass
 * `test/authorize-redirect-allowlist.test.ts` pins with its own named cases.
 */
const LOOPBACK_REDIRECT_ORIGIN =
  /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/;

/**
 * The entire body served when this deployment has no configured secret.
 *
 * Exported so the test asserts against the value the handler actually serves
 * rather than a second copy of the sentence that could drift from it. It is a
 * fixed constant: it names no binding, interpolates nothing, and never varies.
 */
export const UNCONFIGURED_BODY =
  "This server is not configured to issue authorizations.";

/**
 * The entire body served for any path this server does not have.
 *
 * Exported for the same reason `UNCONFIGURED_BODY` is: so the test asserts
 * against the value the handler actually serves rather than a second copy of
 * the sentence that could drift from it. Unlike that constant this one varies —
 * with the request's own origin — so it is a function rather than a string, and
 * the origin is a parameter rather than a hostname read from anywhere else.
 *
 * Naming the endpoint here discloses nothing new. The
 * `/.well-known/oauth-protected-resource/mcp` document already publishes
 * `resource: <origin>/mcp` to any unauthenticated caller — `test/auth-ordering.test.ts`
 * asserts exactly that — so the URL is already public and a 404 that repeats it
 * gives a stranger nothing they could not fetch with one request. Recorded here
 * because a bare 404 looks like the more cautious choice and is not: it is the
 * same disclosure posture with the legitimate user removed from it.
 *
 * The origin is taken from the caller rather than pinned to a constant, and the
 * pinned alternative was specifically declined. Importing the deployed hostname
 * from the MCP module would make this module depend on that one for a display
 * string, and would go silently stale the day the hostname changes; the
 * reflected value is one the sender supplied in their own Host header, so it
 * tells them nothing, and it is served as plain text with no redirect and no
 * markup interpretation anywhere.
 *
 * The response body is the only channel available for saying any of this:
 * Convention 4 forbids logging on this path, exactly as it does on the
 * unconfigured-deployment path below, so a self-describing response is what
 * stands in for a diagnostic nobody can read.
 */
export function notFoundBody(origin: string): string {
  return `This path does not exist on this server.

The MCP endpoint is ${origin}/mcp

Point your MCP client at that full URL, including the /mcp path. Authorization is served from ${origin} itself, so a client configured with the bare origin can complete the entire authorization ceremony successfully and still be unable to open a session.`;
}

/**
 * The configured-secret predicate, re-exported unchanged from where it now
 * lives.
 *
 * This is a compatibility surface and nothing else — no wrapper, no second
 * implementation. The definition now lives in the root module
 * `src/configured-secret.ts`. The four source importers (`src/confirm.ts`,
 * `src/staging/presign.ts`, `src/mail/credentials.ts` and
 * `src/dav/transport.ts`) and `test/authorize-secret.test.ts` resolve the
 * name from this module, and keeping them unedited is the evidence that the
 * move was mechanical. It was five until Phase 10: `src/dav/discovery.ts`
 * stopped importing it when its cache key moved to the user id. This handler also calls the function itself, which is
 * why it holds an import above as well as this statement.
 */
export { isConfiguredSecret };

/**
 * The source-connection limiter's key: who is connecting, and nothing else.
 *
 * No time bucket, because the binding owns the window. This used to build a
 * store key carrying a bucket as well as the address, and both halves of that
 * are now somebody else's job.
 *
 * Keying on the connecting party is WR-02 and it still matters. The key was
 * once the time bucket alone, which made every failure everyone's failure: ten
 * failed POSTs a bucket, from anyone who knew the hostname, at a cost of ten
 * HTTP requests and sustainable indefinitely, put every later `/authorize` POST
 * behind a 429 — the owner's own included. No secret was ever guessed; the
 * denial was the whole attack.
 *
 * The fallback literal is load-bearing. A request arriving without the header
 * must still be counted, or the cheapest way past the limiter would be to send
 * one fewer header.
 *
 * **An IPv6 source is keyed on its /64, not its full address.** An ISP or a
 * cloud host usually hands one customer a whole /64. So a full-address key
 * lets one attacker rotate through 2^64 addresses, each with a fresh budget,
 * and the "five a minute per source" figure means nothing. The /64 is the
 * smallest block one party normally controls, so that is the unit counted.
 * The cost is that people sharing one /64 share one budget. That is rare
 * outside a single household, and a household is one budget anyway.
 *
 * An IPv4 address is kept whole. So is anything that does not parse as IPv6:
 * it is still counted, under its own spelling, which is the same fail-safe as
 * the missing-header fallback.
 */
function sourceLimiterKey(request: Request): string {
  const source = request.headers.get("cf-connecting-ip");
  if (source === null) return "unknown-source";
  if (!source.includes(":")) return source;
  const prefix = ipv6Slash64(source);
  return prefix === null ? source : `${prefix}::/64`;
}

/**
 * The first four groups of an IPv6 address, in one canonical spelling.
 *
 * Canonical so that two spellings of the same /64 — leading zeros, upper or
 * lower case, `::` in a different place — land on one key. Without that, an
 * attacker could multiply their budget just by re-spelling their own address.
 *
 * Returns null for anything that is not a well-formed IPv6 address. A zone
 * suffix (`%eth0`) is dropped first; it names a local interface and is not
 * part of the address. A dotted IPv4 tail counts as the last two groups, which
 * is how RFC 4291 spells it, and it never reaches the first four.
 */
function ipv6Slash64(address: string): string | null {
  const bare = address.split("%")[0]!.toLowerCase();
  const halves = bare.split("::");
  if (halves.length > 2) return null;

  const groupsOf = (part: string): string[] | null => {
    if (part === "") return [];
    const out: string[] = [];
    const pieces = part.split(":");
    for (let i = 0; i < pieces.length; i += 1) {
      const piece = pieces[i]!;
      if (i === pieces.length - 1 && piece.includes(".")) {
        // A dotted IPv4 tail stands for two groups. Its value never matters
        // here, because it can only ever sit in groups seven and eight.
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(piece)) return null;
        out.push("0", "0");
      } else if (/^[0-9a-f]{1,4}$/.test(piece)) {
        out.push(piece);
      } else {
        return null;
      }
    }
    return out;
  };

  const head = groupsOf(halves[0]!);
  const tail = halves.length === 2 ? groupsOf(halves[1]!) : [];
  if (head === null || tail === null) return null;

  let groups: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }

  return groups
    .slice(0, 4)
    .map((group) => parseInt(group, 16).toString(16))
    .join(":");
}

/**
 * The per-target failure counter's key: who is being guessed at.
 *
 * The derived user id and never the address. This key name is stored in plain
 * text — `props` is the only field this server writes that is encrypted — so an
 * address here would put a real person's Apple ID in a store listing, which is
 * the same rule audit row S6 holds the OAuth library's own key names to.
 *
 * **The id sits immediately after the prefix constant with nothing between
 * them.** See the constant's own note: the scan rule that enforces that starts
 * its lookahead on the very next character, and a key that fails it does not
 * fail one commit, it fails every commit in the repository.
 *
 * One key per person, with nothing after the id. The value carries the failure
 * times, so the key needs no hour in it. The owner's escape in the phase
 * runbook stays a prefix listing.
 */
function failureCounterKey(userId: string): string {
  return `${LOGIN_FAILURE_KEY_PREFIX}${userId}`;
}

/**
 * How long a counter record lives: one window plus a minute.
 *
 * The record stops mattering when its newest entry is one window old, and the
 * newest entry is the one written with this TTL. The extra minute is margin, so
 * the record never expires a moment before its newest entry stops counting. It
 * is also well clear of the store's sixty-second minimum TTL.
 */
const FAILURE_RECORD_TTL_SECONDS = FAILURE_WINDOW_SECONDS + 60;

/**
 * The failure times a counter value holds, or `null` if it cannot be trusted.
 *
 * An absent key is an empty list: nobody has failed. Anything else must parse
 * as a JSON array whose every entry is a finite number. Text that is not JSON,
 * an object, a bare number, or an array holding a string or a `null` is all
 * `null`, and the caller refuses on `null`. Reading a corrupted value as empty
 * would switch this layer off for that person for good.
 *
 * `JSON.parse` throws on bad text. That throw is caught here, and the caught
 * value is never read.
 */
function failureTimesFrom(raw: string | null): number[] | null {
  if (raw === null) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  const times: unknown[] = parsed;
  return times.every((t) => Number.isFinite(t)) ? (times as number[]) : null;
}

/**
 * The failures that still count at `now`: those at most one window old.
 *
 * Inclusive at the edge. A failure exactly sixty minutes old still counts, and
 * one a millisecond older does not. So after five failures the next attempt is
 * refused until the oldest of the five is sixty minutes old, and allowed from
 * the millisecond after.
 *
 * A time later than `now` is kept, because `now - t` is negative. That is the
 * safe direction for a clock that stepped backwards.
 */
function failuresWithinWindow(times: number[], now: number): number[] {
  return times.filter((t) => now - t <= FAILURE_WINDOW_SECONDS * 1000);
}

/**
 * Record one failed guess against one address. Never throws.
 *
 * **Swallowed deliberately and swallowed silently.** The store throttles writes
 * to a single key, so a burst makes this write reject. Unhandled, that
 * rejection turned a 401 into a 500 for identical input — an observable oracle
 * telling an attacker their burst landed, which is precisely the signal a
 * brute-force counter must not hand out (WR-01). Convention 4 forbids logging
 * anywhere under `src/`, and there is nothing here worth a response field
 * either: the time floor is the limiter that does not depend on this write
 * succeeding, and it is applied outside this function.
 *
 * Non-atomic. Read, compare and write over an eventually-consistent store means
 * concurrent attempts all read the same list, and the last write wins, so this
 * layer UNDER-counts a parallel burst. The platform limiter one layer up is the
 * only other brake on a burst, and it is not exact either: it counts per
 * Cloudflare location and is eventually consistent. This layer exists for the
 * hour the platform's window cannot reach, and it counts a patient, serial
 * attacker exactly. The file header records the parallel case as an accepted
 * cost.
 *
 * What is written: the failures still inside the window, then this one, newest
 * last, trimmed to the newest five. Entries that have aged out are dropped
 * here, so the value never grows. The trim does not bite today: the check
 * refuses at five, so at most four in-window entries ever reach this write. It
 * stays as a guard, so the value remains bounded if the check ever changes.
 *
 * `failedAt` is a fresh clock reading taken after Apple answered, so the entry
 * records when the failure happened rather than when the request arrived. If
 * the clock ever returns something that is not a finite number, the entry is
 * written as `null` and the next read refuses: fail closed.
 */
async function countFailedGuess(
  store: KVNamespace,
  key: string,
  recent: number[],
  failedAt: number,
): Promise<void> {
  try {
    const times = [...recent, failedAt].slice(-MAX_FAILURES_PER_WINDOW);
    await store.put(key, JSON.stringify(times), {
      expirationTtl: FAILURE_RECORD_TTL_SECONDS,
    });
  } catch {
    /* See the paragraph above: this rejection must not change the response. */
  }
}

/**
 * Who is asking, and where authorizing will send the browser.
 *
 * Both values originate outside this server: the name arrives through
 * unauthenticated dynamic client registration, and the redirect URI is the one
 * the code will be delivered to. They are display-only — nothing branches on
 * either — and both are escaped at the interpolation.
 *
 * Exported as a type so the page module can take one without rebuilding the
 * shape. It is built here, by `identityOf`, because resolving who is asking is
 * flow control; displaying it is not.
 */
export interface ClientIdentity {
  /** The registered name, or the client id when the client registered none. */
  name: string;
  /** The full redirect URI. Only its origin is ever displayed. */
  redirectUri: string;
}

/**
 * The body served when the provider cannot resolve the requesting client.
 *
 * The wording, the status and the plain-text shape are unchanged: this is an
 * owner diagnostic with carefully argued text, and restyling it is scope this
 * phase did not ask for. What it gains is the header set, which it did not
 * carry before.
 */
function unknownClientResponse(): Response {
  return new Response("Unknown OAuth client", {
    status: 400,
    headers: { ...RESPONSE_HEADERS },
  });
}

function identityOf(client: ClientInfo, redirectUri: string): ClientIdentity {
  // Falling back to the id rather than to a placeholder: a client that
  // registered no name is still identified, and a blank space where an
  // identity should be is exactly what CR-04 is about.
  return { name: client.clientName ?? client.clientId, redirectUri };
}

/**
 * The destination, reduced to an origin — the ONE derivation, shared.
 *
 * The path and query are deliberately dropped. A long attacker-chosen path
 * would push the origin — the only part that says who receives the code — out
 * of view on a narrow screen, which would leave the identity technically
 * present and practically invisible.
 *
 * Null means only that `new URL()` could not read the value. Callers decide
 * what to do with that: the page renders a sentence saying so, and the
 * allowlist check treats it as not-allowed, so an unreadable destination fails
 * closed rather than falling through some parsing accident into permitted.
 *
 * Exported, but only so the sharing below can cross a module boundary. There is
 * exactly one derivation of a destination origin under `src/auth/`, and a
 * second one anywhere would let the allowlist check and the consent line
 * disagree about what they are talking about.
 */
export function originOf(redirectUri: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return null;
  }

  // `origin` is the literal string "null" for a non-special scheme, which is
  // the shape a native client's custom-scheme callback has. Scheme and host
  // are still bounded, and still not the path.
  if (parsed.origin && parsed.origin !== "null") return parsed.origin;
  return parsed.host ? `${parsed.protocol}//${parsed.host}` : parsed.protocol;
}

/**
 * The destination as the consent screen shows it.
 *
 * The reduction itself lives in `originOf`, and the sharing is the point
 * rather than a tidiness: the allowlist check evaluates the value this
 * function displays. Were the two to derive the origin separately, the page
 * could name an origin the check never looked at — a mitigation that lies
 * about what it mitigated.
 *
 * Exported for the page module to call. It stays HERE rather than moving with
 * the rendering, because the value it answers is the one
 * `refusedRedirectResponse` decides on two functions down, and the sharing is
 * the entire point of the function existing.
 */
export function displayDestination(redirectUri: string): string {
  // Showing the raw string instead would reintroduce the very
  // push-the-origin-out-of-view problem origin-only display exists to stop.
  return originOf(redirectUri) ?? "an address this server could not read";
}

/**
 * Whether a derived origin is one this server will send a code to.
 *
 * Null is false, which is the fail-closed edge: a redirect URI this server
 * cannot parse is refused rather than admitted.
 *
 * Exported so a test can drive a table of shapes straight at the predicate.
 * That is both cheaper and far more exhaustive than routing every bypass
 * candidate through the handler; the handler-level cases still exist, and are
 * what prove the predicate is actually wired to anything.
 */
export function isAllowedRedirectOrigin(origin: string | null): boolean {
  if (origin === null) return false;
  return (
    ALLOWED_REDIRECT_ORIGINS.includes(origin) ||
    LOOPBACK_REDIRECT_ORIGIN.test(origin)
  );
}

/**
 * The entire description served when a registration is refused (LIFE-02).
 *
 * Exported for the reason `UNCONFIGURED_BODY` is: so the test asserts the value
 * the server actually serves rather than a second copy of the sentence, which
 * could drift from it.
 *
 * It is a CONSTANT and it interpolates nothing. Two reasons. The caller supplied
 * the redirect address, so echoing it back would put a stranger's own text into
 * a response — and the library's default error handler prints this description,
 * so anything interpolated here is also printed. A fixed string has nothing to
 * carry.
 */
export const REGISTRATION_REFUSED_DESCRIPTION =
  "This server does not accept a client registration for that redirect address.";

/**
 * The longest `client_name` this server will store.
 *
 * Exported so a test asserts against the bound the code uses rather than a
 * second copy of the number.
 *
 * 256 is chosen to be obviously above every real value and obviously below the
 * 1 MiB body the registration endpoint would otherwise accept. It is a cap on
 * what gets STORED FOREVER, not an opinion about names.
 *
 * **It bounds one field and nothing else, which is why the three constants
 * below exist** (code review WR-01, iteration 2). `client_name` was the only
 * field capped when the cap was added, and the comment at the gate claimed it
 * stopped the record being large. It did not: `redirect_uris` entries, the
 * `contacts` array and every `client_name#<lang>` i18n key are stored verbatim
 * in the same permanent record and were all unbounded.
 */
export const MAX_CLIENT_NAME_LENGTH = 256;

/**
 * The longest redirect address this server will store.
 *
 * The gate above reduces a URI to its ORIGIN, which discards the path entirely —
 * `new URL("https://claude.ai/" + "a".repeat(200)).origin` is
 * `"https://claude.ai"` — so `https://claude.ai/<900 KB of path>` passes the
 * allowlist and the library only checks the scheme and control characters. This
 * is the bound on what is left.
 *
 * 512 is far above anything real. On 2026-09-21 all 21 live records held one
 * address each in three known shapes, the longest of them a Claude web callback
 * well under a hundred characters (12-RESEARCH.md § Finding 2).
 */
export const MAX_REDIRECT_URI_LENGTH = 512;

/**
 * The most redirect addresses one registration may hold.
 *
 * Every live record held exactly one. A client can only ever authorize to an
 * address it registered, so a long list buys a real client nothing; what it buys
 * a stranger is `MAX_REDIRECT_URI_LENGTH` bytes each, stored forever.
 */
export const MAX_REDIRECT_URIS = 8;

/**
 * The largest registration body this server will store, serialized.
 *
 * The backstop, and the only one of the four bounds that cannot be evaded by a
 * field nobody thought of. The other three name fields; this one measures the
 * whole shape, so a stored value this gate has never heard of — a new i18n
 * variant, a `contacts` array of ten thousand strings, some future member of the
 * metadata schema — is bounded on the day it appears rather than on the day
 * somebody notices.
 *
 * 8 KiB: roughly an order of magnitude above a real registration body, and two
 * orders below the 1 MiB the endpoint would otherwise accept. Twenty-one records
 * at this ceiling is under 200 KB, which is a nuisance rather than an incident —
 * and `prune-clients` removes them.
 */
export const MAX_REGISTRATION_BYTES = 8192;

/**
 * Refuse a registration whose redirect addresses are not all on the allowlist.
 *
 * ONE RULE, TWO CALL SITES. The authorize page and the registration endpoint
 * ask the same question — will this server ever send a code to that address —
 * so this reuses the same `isAllowedRedirectOrigin(originOf(uri))` expression
 * `refusedRedirectResponse` uses. A second junk heuristic written here would
 * drift from the first, and then one of the two would be wrong.
 *
 * WHY EVERY AND NOT SOME. A client can only ever authorize to an address it
 * registered, so a list with one good entry and one junk entry buys the client
 * nothing it could use. And now that client records never expire, the junk half
 * would be stored forever. So every address must pass.
 *
 * THE EVIDENCE THAT THIS REFUSES NOTHING REAL. On 2026-09-21 all 21 live client
 * records held exactly ONE redirect address each, in three shapes: the Claude
 * web callback, a Claude Code loopback port, and a Hermes loopback port. All
 * three pass (12-RESEARCH.md § Finding 2).
 *
 * THE RECOVERY IF A REAL CLIENT IS EVER REFUSED. Add its origin to
 * `ALLOWED_REDIRECT_ORIGINS` above and deploy. That is the same fix the
 * authorize refusal already documents, and nothing stored has to change.
 *
 * ORIGIN-ONLY MATCHING, AND WHAT THAT DOES NOT BOUND (IN-04). Both this gate and
 * the consent screen reduce a redirect URI to its origin, deliberately: a long
 * attacker-chosen path would push the origin itself out of view on the screen
 * where the user is deciding. The consequence is that `https://claude.ai/anything`
 * registers successfully and displays on the consent screen identically to the
 * genuine callback. Harm still requires an open redirect or a code-logging
 * endpoint ON THAT ORIGIN, so this stays residual and is not a reason to start
 * matching paths. It is written down because a client record no longer expires,
 * so such a registration is permanent where it used to age out — and because a
 * later reader could otherwise conclude the origin gate bounds the destination
 * exactly. It does not. It bounds the ORIGIN exactly.
 *
 * IT NEVER THROWS. `clientMetadata` is the RAW JSON body a stranger posted, and
 * a throw here becomes a 500 whose description is the error's own message —
 * text that stranger wrote, served back out. So the whole body sits in a
 * try/catch, the caught value is never read, and anything malformed is refused.
 * That is the same never-throw shape `servesThisGrant` uses in
 * `src/mcp/api-handler.ts`, for the same reason.
 *
 * The callback is handed no environment, so it cannot reach a store or a
 * limiter. That is fine for a question about an origin.
 */
export function refuseUnlistedRedirects(
  options: ClientRegistrationCallbackOptions,
): ClientRegistrationCallbackResult | undefined {
  try {
    // THE ARGUMENT IS TAKEN WHOLE AND READ INSIDE THE TRY (IN-03). Destructuring
    // in the parameter list happens BEFORE the try runs, so a non-object
    // argument threw straight past the never-throw claim above. What held that
    // claim up was the library's own wrapper turning the throw into a 500 whose
    // description is Node's destructuring message — which carries no caller
    // text, so the effect was nil. The claim is now held by this function, which
    // is where it is written.
    const clientMetadata = options.clientMetadata;
    const uris: unknown = clientMetadata.redirect_uris;
    const allowed =
      Array.isArray(uris) &&
      uris.length > 0 &&
      uris.every(
        (uri: unknown) =>
          typeof uri === "string" && isAllowedRedirectOrigin(originOf(uri)),
      );

    // A SIZE BOUND, and the redirect gate is not one. The registration endpoint
    // is unauthenticated by the OAuth spec and accepts a body up to 1 MiB, the
    // library puts no length cap on any stored field, and a client record never
    // expires now — so one accepted registration can park most of a megabyte in
    // the namespace that holds the grants and the tokens, permanently. The
    // loopback half of the redirect gate admits any port, so passing it costs a
    // stranger nothing. `prune-clients` in `scripts/grants.mjs` is the removal;
    // this is the cheap half that stops the record being that large to begin
    // with.
    //
    // **Four bounds, not one (code review WR-01, iteration 2).** The version of
    // this comment that shipped with iteration 1 said a `client_name` cap
    // "stops the record being that large to begin with". It did not, and saying
    // so would have stopped the next reader looking any further: the gate above
    // reduces each redirect URI to its ORIGIN and throws the path away, so a URI
    // carrying most of a megabyte of path passed it; and `contacts` and every
    // `client_name#<lang>` i18n key are stored verbatim with no cap on their
    // number or their length. Only the one field nobody was abusing was bounded.
    //
    // Three of the four name a field; the fourth measures the whole body, and
    // that one is the only one a field nobody thought of cannot walk around.
    //
    // NONE OF THEM TOUCHES THE REDIRECT CLASS. The loopback pattern and the
    // claude.ai origin decide WHERE a code may be sent; these decide HOW MUCH
    // may be stored. A registration refused here would have been stored, not
    // redirected to.
    //
    // The ceilings are far above anything real. On 2026-09-21 all 21 live client
    // records held one redirect address each in three known shapes and a name
    // well under 256 characters (12-RESEARCH.md § Finding 2). If a real client is
    // ever refused, these four numbers are what to raise, and nothing stored has
    // to change.
    //
    // A field that is present and not the type it should be is refused rather
    // than ignored: this function's job is deciding whether to store the body,
    // and a field it cannot measure is one it cannot vouch for. (The non-string
    // `client_name` branch is unreachable through the endpoint, since the
    // library's own `optionalString` answers `invalid_client_metadata` above this
    // callback — IN-05. It is defence in depth, and this is not where that
    // shape's behaviour is defined.)
    const name: unknown = clientMetadata.client_name;
    const namedSafely =
      name === undefined ||
      name === null ||
      (typeof name === "string" && name.length <= MAX_CLIENT_NAME_LENGTH);

    // Measured as a LIST and as STRINGS, separately from `allowed` above, which
    // asks a different question about the same array and must stay readable as
    // the redirect rule it is.
    const boundedUris =
      Array.isArray(uris) &&
      uris.length <= MAX_REDIRECT_URIS &&
      uris.every(
        (uri: unknown) =>
          typeof uri === "string" && uri.length <= MAX_REDIRECT_URI_LENGTH,
      );

    // The backstop. `clientMetadata` is parsed JSON, so it has no cycles and
    // this cannot throw on one — and the try around the whole body is what
    // covers it if that assumption ever stops holding. It is measured in UTF-16
    // code units rather than bytes, which under-counts nothing that matters: a
    // non-ASCII character costs at least as many bytes as units.
    const boundedWhole =
      JSON.stringify(clientMetadata).length <= MAX_REGISTRATION_BYTES;

    // THE AUTONOMY CLIENT'S NAME IS NOT FOR REGISTRANTS (Phase 27, D-23). The
    // owner's grant listing shows a grant's client name, and only the fixed
    // autonomy id may carry this one. A registration whose name reads the
    // same is refused. Both sides go through `foldClientName` first (review
    // IN-02, R2-IN-02), so doubled or unusual spaces, blank-looking letters,
    // full-width letters, and the invisible characters it names cannot make a
    // name that looks identical but compares different. Look-alike letters
    // from other scripts are NOT caught: that needs a confusables table, and
    // the listing labels autonomy by id anyway. `foldClientName` names what
    // else it misses.
    const posingAsAutonomy =
      typeof name === "string" &&
      foldClientName(name) === foldClientName(AUTONOMY_CLIENT_NAME);

    return allowed && namedSafely && boundedUris && boundedWhole && !posingAsAutonomy
      ? undefined
      : { description: REGISTRATION_REFUSED_DESCRIPTION };
  } catch {
    // Never read the caught value. A registration this cannot inspect is not
    // one to store, so it is answered exactly as every other refusal is.
    return { description: REGISTRATION_REFUSED_DESCRIPTION };
  }
}

/**
 * Letters that draw as an empty space: the Hangul fillers (U+115F, U+1160,
 * U+3164 and the half-width U+FFA0) and the Braille blank (U+2800). They are
 * not white space to the regex engine, so a name that puts one where a space
 * goes would otherwise fold to a different string (review R2-IN-02).
 */
const BLANK_LETTERS = /[\u115F\u1160\u3164\uFFA0\u2800]/gu;

/**
 * A client name reduced to what a person reading it would see (review IN-02),
 * for the autonomy-name refusal above and nothing else.
 *
 * In order: NFKC, which turns full-width and other compatibility letters and
 * spaces into their plain forms; every letter that draws as an empty space
 * (`BLANK_LETTERS`) turned into a space; every format character and every
 * default-ignorable code point removed (`\p{Cf}`: zero-width spaces and
 * joiners, the soft hyphen, the byte-order mark; `\p{Default_Ignorable_Code_Point}`:
 * the combining grapheme joiner, variation selectors, the Khmer inherent
 * vowels, and the rest of the characters a renderer is told to draw as
 * nothing, review R2-IN-02); every run of white space collapsed to one space;
 * the ends trimmed; letter case folded to lower case. The blanks become
 * spaces BEFORE the invisible characters go, because the Hangul fillers are
 * default-ignorable too, and stripping one that stands in for a space would
 * join the two words either side of it.
 *
 * WHAT IT DOES NOT CATCH. Look-alike letters from other scripts, such as a
 * Cyrillic letter that looks like a Latin one. NFKC leaves those alone, and
 * catching them needs a confusables table this project does not carry. Nor
 * does it catch a blank-looking character this list does not name, or a
 * combining mark that draws as nothing in some fonts but is not
 * default-ignorable. It is a residual, not a hole: the owner's listing labels
 * a grant as autonomy by its client id, never by its name, so a look-alike
 * name fools only a person reading the consent page.
 */
function foldClientName(value: string): string {
  return value
    .normalize("NFKC")
    .replace(BLANK_LETTERS, " ")
    .replace(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

/**
 * The entire body served when a redirect origin is refused.
 *
 * Exported for the reason `notFoundBody` is: so the test asserts the value the
 * handler actually serves rather than a second copy of the sentence, which
 * could drift from it. It is a function rather than a constant because the
 * value varies — with the destination that was refused.
 *
 * It takes an ALREADY-REDUCED destination, never the raw URI, and both
 * consequences are the point: the attacker's chosen path never reaches this
 * body, and an unparseable URI arrives pre-rendered as a sentence rather than
 * needing a second null branch here.
 *
 * The body carries the recovery in full because there is nowhere else to put
 * it. Convention 4 forbids logging anywhere under src/, so the response is the
 * only diagnostic channel that exists, and the only party a refusal can lock
 * out is the owner — who has nothing else to read. Naming the source file to
 * an unauthenticated caller is the same disclosure posture `notFoundBody`
 * already takes and the same reasoning: a stranger cannot edit that file, and
 * withholding it helps only against the party it cannot hurt.
 */
export function refusedRedirectBody(destination: string): string {
  return `This server is not permitted to send an authorization code to that destination.

Refused destination: ${destination}

Existing authorizations are unaffected. This check gates /authorize only — token refresh is served by the OAuth token endpoint and never reaches it — so a client that already holds a token keeps working. Nothing has been revoked and the server is not down.

If that destination is genuinely yours, add its origin to ALLOWED_REDIRECT_ORIGINS in src/auth/login-handler.ts and deploy. The allowlist is a source constant rather than stored state, so nothing saved has to be edited or deleted to recover.`;
}

/**
 * Refuse a destination outside the allowlist — or null to carry on.
 *
 * Rendered LOCALLY, and never as a redirect. This file already states the rule
 * this obeys one function down: redirecting an unvalidated URI is what
 * CVE-class bugs in this problem space are made of. Redirecting to an origin
 * that was just refused would be that bug with an extra step, so nothing here
 * constructs a URL from the redirect URI, sets a Location header, or calls
 * `Response.redirect`.
 *
 * 403 rather than 400, because 400 is already this file's answer for a
 * MALFORMED request. A refused origin is well-formed and understood, and
 * declined by policy. The distinction costs nothing and lets a test tell the
 * two apart — which matters, because a regression that silently turned the
 * allowlist off would otherwise hide behind a status this file returns for
 * three other reasons.
 *
 * Placement is load-bearing at all three of its edges. BELOW the POST cap
 * check, so an over-cap source still gets its 429 without the provider being
 * consulted. ABOVE `lookupClient`, so a doomed request does not buy a store
 * round trip — the same argument the resolution comment below already makes
 * about free amplification. ABOVE the secret comparison, so a CORRECT secret
 * cannot purchase a code for a destination this server will not send to. That
 * last edge discloses nothing: the answer is a pure function of the
 * requester's own redirect URI.
 *
 * The failure counter is deliberately not touched here. It counts guesses at
 * the secret, and a refused destination is not one.
 */
function refusedRedirectResponse(redirectUri: string): Response | null {
  if (isAllowedRedirectOrigin(originOf(redirectUri))) return null;

  return new Response(refusedRedirectBody(displayDestination(redirectUri)), {
    status: 403,
    headers: {
      ...RESPONSE_HEADERS,
      "content-type": "text/plain; charset=utf-8",
    },
  });
}

function authorizationErrorResponse(error: AuthorizationError): Response {
  // An unknown client or an unregistered redirect URI must be rendered
  // locally — redirecting an unvalidated URI is what CVE-class bugs in this
  // problem space are made of.
  if (!error.redirectUri) {
    return new Response(error.description, {
      status: 400,
      headers: { ...RESPONSE_HEADERS },
    });
  }

  const redirect = new URL(error.redirectUri);
  redirect.searchParams.set("error", error.code);
  redirect.searchParams.set("error_description", error.description);
  if (error.state) redirect.searchParams.set("state", error.state);
  if (error.issuer) redirect.searchParams.set("iss", error.issuer);

  // Constructed explicitly rather than through the static redirect helper, and
  // for one reason: that helper builds a response this code cannot put a header
  // on, and this phase's requirement is that EVERY response carries the four.
  // The location header is set by hand and the body is empty, which is what the
  // helper produces anyway — a caller reading `location` off this response sees
  // the identical value.
  //
  // `responseHeadersFor` rather than the bare constant, because on the POST path
  // this IS a form-submission redirect and a directive that forbids its own
  // destination refuses it silently in WebKit — the same defect measured on
  // 2026-09-23 and argued at the constant. The URI is handed over RAW and
  // validated inside that helper, so an error redirect to an origin the
  // allowlist has never seen gets the bare directive rather than a widened one.
  return new Response(null, {
    status: 302,
    headers: {
      ...responseHeadersFor(error.redirectUri),
      location: redirect.toString(),
    },
  });
}

/**
 * Build the provider's `defaultHandler`: everything that is not an API request.
 *
 * Only `/authorize` is ours. The token, registration, and metadata endpoints
 * are implemented by the provider itself and never reach this handler.
 *
 * `proof` is the one injection seam, and it defaults to the production one, so
 * production calls this factory with no argument at all — the same shape
 * `createMcpApiHandler(extraTools)` already has one tree over. A test hands in
 * a counting stub instead, which is how D-09 is kept (no automated login to a
 * real Apple ID, ever) and how "zero sockets were opened for that request"
 * becomes something a test can assert rather than infer.
 *
 * `floorMs` is the second seam, and it has the same default-to-the-exported-
 * value property the mail session options already have: production passes
 * nothing and behaves exactly as the constant says. A test can then exercise
 * every failure path for a few milliseconds each instead of three seconds each,
 * while one case still drives the default and asserts the real figure.
 *
 * `clock` is the third seam, and it feeds the hourly counter (layer 3) and
 * nothing else. It is read once before the counter is checked, and once more
 * to stamp a failure that Apple turned down. Production passes nothing and
 * gets the real wall clock. A test pins it to a chosen millisecond, which is
 * the only way to show exactly when a lockout ends without waiting an hour.
 * The time floor keeps the real clock on purpose: it has to measure real
 * elapsed time.
 */
export function createLoginHandler(
  proof: LoginProof = proveWithApple,
  floorMs: number = FAILURE_FLOOR_MS,
  clock: () => number = () => Date.now(),
): {
  fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response>;
} {
  return {
    async fetch(
      request: Request,
      env: Env,
      // The request's execution context. The provider always passes it to its
      // default handler, and the arming of the autonomy key needs it: the arm
      // runs through its `waitUntil`, after the answer has gone. Optional
      // because many tests call this handler with two arguments, and with no
      // context nothing is minted and nothing is armed; the sign-in answers
      // exactly as before. The tracer in test/autonomy.test.ts drives the real
      // provider, and is what proves production passes it.
      ctx?: ExecutionContext,
    ): Promise<Response> {
      // The floor's clock starts HERE, as the first statement of the request
      // handler, before the pathname is read and before any branch exists to
      // be timed. Anything taken later would start the clock after some of the
      // work, and the amount of work already done is exactly what the floor is
      // hiding.
      const started = Date.now();
      return handleAuthorize(request, env, proof, floorMs, started, clock, ctx);
    },
  };
}

/**
 * Whether autonomy is set up on this deployment (Phase 27, D-17).
 *
 * The client secret must pass `isConfiguredSecret`, and the seal key must pass
 * `sealKeyUsable`: set, AND the exact shape the seal accepts, checked by the
 * seal's own decoder (review WR-03). A seal key that is set but the wrong shape
 * is not set up. Otherwise the page would promise a key that could never arm,
 * and every sign-in would mint a grant, fail at the seal, and end the key the
 * person already had.
 *
 * This is the ONE place this file decides it, so the sign-in page's notice
 * (plan 27-02) and the arming below cannot disagree. Not set up means the
 * sign-in works exactly as it always did, and nothing is minted.
 */
export function autonomyConfigured(env: Env): boolean {
  return env.MAIL_ONLY_MODE !== "true" && isConfiguredSecret(env.AUTONOMY_CLIENT_SECRET) && sealKeyUsable(env.AUTONOMY_SEAL_KEY);
}

/**
 * Arm the autonomy key, after the sign-in's answer has gone (D-26).
 *
 * Asks the person's own object to arm from `code`. Unless it answers `armed`
 * for exactly the grant this sign-in minted, that grant is revoked, so a
 * failed arming leaves no autonomy grant behind. That includes a call that
 * rejects. Every step sits inside a `try` whose `catch` reads nothing, and this
 * never rejects: it runs under `waitUntil`, where a rejection would reach
 * nobody who could act on it.
 */
async function armAfterAnswer(
  env: Env,
  principal: Principal,
  userId: string,
  code: string,
): Promise<void> {
  const grantId = code.split(":")[1] ?? "";
  let armed = false;
  try {
    const answer = await agentFor(principal).armAutonomy(code);
    armed = answer.kind === "armed" && answer.grantId === grantId;
  } catch {
    // Not armed. The caught value is not read.
  }
  if (armed || grantId.length === 0) return;
  try {
    await env.OAUTH_PROVIDER.revokeGrant(grantId, userId);
  } catch {
    // Nothing left to try. A grant that was never exchanged ends on its own
    // when its ten-minute code record expires.
  }
}

/**
 * The production handler, built from the factory above with no argument.
 *
 * Kept as a named export because `src/auth/oauth.ts` wires this exact value as
 * the provider's `defaultHandler`, and several tests drive it directly.
 */
export const loginHandler = createLoginHandler();

/**
 * The notices the sign-in page shows above its fields, in order.
 *
 * The ONE place this list is built. Both `renderForm` call sites pass it: the
 * first load, and the re-render after a failed attempt. So a notice added here
 * reaches every render, and nothing else has to change.
 *
 * Called only inside a request, never at module load, per the import-cycle note
 * at the top of `./login-page`: `RECALL_NOTICE` is imported across that cycle.
 *
 * Phase 27 appends its autonomy notice here, after the recall notice, when
 * autonomy is configured, and only then (D-17, D-30). `autonomyConfigured` is
 * the same predicate the arming uses, and this is the one place the list is
 * built, so the page and the arming cannot disagree. The page renders the
 * autonomy notice's hidden field exactly when the notice is in this list. The
 * recall notice is always first and always present, because recall is
 * inherent: it does not depend on any setting.
 */
export function signInNotices(env: Env): readonly SignInNotice[] {
  if (env.MAIL_ONLY_MODE === "true") return [MAIL_ONLY_NOTICE];
  return autonomyConfigured(env) ? [RECALL_NOTICE, AUTONOMY_NOTICE] : [RECALL_NOTICE];
}

/**
 * One `/authorize` request, from the pathname check to the redirect.
 *
 * A plain function rather than a method so the factory above is the only thing
 * that closes over `proof`, and so the whole flow reads top to bottom in one
 * place. The environment parameter keeps its current type: the login gate's own
 * secret is no longer read anywhere in this file, but `test/env-narrowing.test.ts`
 * and `test/authorize-not-found.test.ts` both spell that type, and Phase 13
 * (CUT-01) removes the binding, the interface and every mention of it together
 * rather than leaving a half-removed name behind.
 */
async function handleAuthorize(
  request: Request,
  env: Env,
  proof: LoginProof,
  floorMs: number,
  started: number,
  clock: () => number,
  ctx: ExecutionContext | undefined,
): Promise<Response> {
  {
    const url = new URL(request.url);

    // Still a 404 — the path genuinely does not exist — but one that says where
    // the client should have gone. The condition is left exactly as it was:
    // every non-/authorize path gets this, with no special case for the bare
    // origin, because "the client was pointed somewhere wrong" is the whole
    // failure class and the bare origin is only its most common member.
    if (url.pathname !== "/authorize") {
      return new Response(notFoundBody(url.origin), {
        status: 404,
        headers: {
          ...RESPONSE_HEADERS,
          "content-type": "text/plain; charset=utf-8",
        },
      });
    }

    // The SEED is read ONCE, here, and the verdict is carried down. Gate
    // first: an unconfigured deployment has nothing to protect, so nothing is
    // spent on the request before this — not a parse, not a store round trip,
    // and certainly not a socket to Apple.
    //
    // **THE STORE IS DELIBERATELY NOT CONSULTED HERE, and the reason is not
    // cost alone.** A deployment whose seed is unusable cannot serve its own
    // owner, so it is unconfigured whatever the store holds — a store full of
    // family members on a server the owner himself cannot reach is still a
    // server nobody should be signing in to. The cost argument comes second and
    // is also real: this gate runs on every GET, and a store read here would
    // spend a round trip on rendering a page.
    //
    // Fail closed above method dispatch, so neither verb can reach the form
    // while this deployment cannot say who may sign in. A seed that is missing,
    // empty, malformed, or holding one unusable entry all mean NOBODY, so all
    // of them answer here.
    //
    // 503 rather than 401 is deliberate, and it matters more now than it did
    // under the shared secret: 401 would tell the owner they mistyped their own
    // Apple password, sending them to Apple to make a new one, when what is
    // actually wrong is a binding on this server. The distinction gives nothing
    // exploitable to a party who cannot authenticate either way. It has to be
    // the status code carrying that signal — Convention 4 forbids logging on
    // this path, so a self-describing response is the only channel left. The
    // body is `UNCONFIGURED_BODY` unchanged, byte for byte: it names no binding
    // and interpolates nothing, so it is as true of an absent allow list as it
    // was of an absent secret.
    const allowed = parseAllowList(env.ALLOWED_APPLE_IDS_SEED);
    if (allowed.kind === "nobody") {
      return new Response(UNCONFIGURED_BODY, {
        status: 503,
        headers: {
          ...RESPONSE_HEADERS,
          "content-type": "text/plain; charset=utf-8",
        },
      });
    }

    if (request.method === "GET") {
      let oauthRequest;
      try {
        oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      } catch (error) {
        if (!(error instanceof AuthorizationError)) throw error;
        return authorizationErrorResponse(error);
      }

      // Refuse a destination outside the allowlist before anything else is
      // spent on this request. `parseAuthRequest` has already confirmed the URI
      // is one this client actually registered, so what happens here is a
      // NARROWING of what may be registered-and-used — not a replacement for
      // that validation.
      const refusedGet = refusedRedirectResponse(oauthRequest.redirectUri);
      if (refusedGet) return refusedGet;

      // Resolve who is asking BEFORE rendering, not after the secret has been
      // accepted (CR-04). A client the provider cannot resolve cannot be
      // named, and a form that cannot say what it is authorizing is worse than
      // no form: it invites a submission the owner has no way to evaluate.
      const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
      if (!client) return unknownClientResponse();

      // The raw query is round-tripped rather than the parsed object, so the
      // POST re-runs the provider's own client, redirect-URI, response-type
      // and PKCE validation against it. A tampered hidden field is then
      // rejected by the library rather than trusted by this handler.
      return renderForm(
        url.search.replace(/^\?/, ""),
        null,
        identityOf(client, oauthRequest.redirectUri),
        signInNotices(env),
      );
    }

    if (request.method !== "POST") {
      // One of the two sites that carried no caching header at all before this
      // phase. The spread goes first and the site's own header follows, so a
      // site can never silently drop one of the four.
      return new Response("Method not allowed", {
        status: 405,
        headers: { ...RESPONSE_HEADERS, allow: "GET, POST" },
      });
    }

    // LAYER 1, the connecting source. The first of the three, and the only one
    // that answers with a status of its own.
    //
    // It runs here, above the form read and above everything below it, so a
    // flood buys no round trip: not the provider's parse, not the client
    // lookup, not a store read. It is a platform counter with no store round
    // trip, which makes it the cheapest brake on a burst. It is not exact: it
    // counts per Cloudflare location and is eventually consistent, so a burst
    // spread across locations or fired in parallel gets past it by some
    // margin. The file header records that as an accepted cost.
    //
    // Keyed on the /64 for an IPv6 source, not the full address. One IPv6
    // client usually holds a whole /64, so a full-address key would give one
    // attacker 2^64 separate budgets. `sourceLimiterKey` carries the detail.
    //
    // The allow-list gate still runs ABOVE this, up at the top of the handler,
    // and that ordering is deliberate too: a deployment with no configured list
    // has nothing to protect, and spending a binding call to protect it would
    // be spending something on a request that can never succeed.
    //
    // Keyed by the connecting party and never by the address being tried, which
    // is the whole reason this refusal is allowed a status of its own. It
    // carries no information about who is on the list, because it is decided
    // before any address has been read.
    //
    // A key and nothing else. The limit and the window live on the binding, and
    // the local simulator's per-call overrides would pass every test here and
    // fail the typecheck.
    const flood = await env.LOGIN_IP_LIMITER.limit({
      key: sourceLimiterKey(request),
    });
    if (!flood.success) {
      // The floor applies HERE too, and that is decided rather than incidental.
      // A floor applied only after the allow-list check would let a stopwatch
      // sort listed addresses from unlisted ones, which is the exact leak the
      // floor exists to close, and a refusal that returned early would be the
      // fastest answer this surface has.
      //
      // The cost is real and is recorded so the next reader does not optimise
      // it away: during a flood this holds N requests open for the floor each,
      // consuming concurrent-request capacity precisely when the limiter is
      // trying to make requests cheap. It is wall-clock rather than processor
      // time, this runtime bills processor time, and the code this replaces
      // already slept before the very same refusal — so it is a change of
      // degree and not of kind.
      await holdFloor(started, floorMs);
      return new Response(SOURCE_REFUSAL_BODY, {
        status: 429,
        headers: {
          ...RESPONSE_HEADERS,
          // A copy of a figure that really lives in `wrangler.jsonc`. Nothing
          // makes the two agree; see the constant.
          "retry-after": String(SOURCE_WINDOW_SECONDS),
        },
      });
    }

    const form = await request.formData();
    const submittedAppleId = String(form.get(APPLE_ID_FIELD) ?? "");
    const submittedPassword = String(form.get(APP_PASSWORD_FIELD) ?? "");
    const query = String(form.get("oauth_request") ?? "");
    const noticeVersion = String(form.get(AUTONOMY_NOTICE_FIELD) ?? "");

    // Resolution sits BELOW the flood brake and ABOVE the credential checks,
    // and both edges are deliberate.
    //
    // Below the flood brake, because a flooding source must not buy a provider
    // round trip per request — that is free amplification precisely when the
    // limiter is trying to make requests cheap.
    //
    // Above the credential checks, because the failure re-render has to carry
    // the same identity the first render did; a second attempt should be no
    // less informed than the first.
    const rebuilt = new Request(`${url.origin}/authorize?${query}`);
    let oauthRequest;
    try {
      oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(rebuilt);
    } catch (error) {
      if (!(error instanceof AuthorizationError)) throw error;
      // Deliberate status change on an unauthenticated path, and not an
      // accident: a request whose oauth_request cannot be resolved used to
      // reach the comparison first and, with a wrong secret, came back as the
      // 401 form. It now comes back as this local 400 instead. There is no
      // identity to render and no comparison worth running, and the 400
      // discloses nothing new — it is a function purely of the request's own
      // well-formedness, which its sender already knows, and it says nothing
      // about whether the submitted secret was right, wrong, or absent. It is
      // rendered locally rather than redirected, exactly as before.
      return authorizationErrorResponse(error);
    }

    // Same check as the GET path, and the second call site is the whole point:
    // a check on one verb only is a hole, because the POST is what actually
    // issues the code. It sits above the comparison as well as above the
    // lookup, so a correct secret buys nothing for a refused destination.
    const refusedPost = refusedRedirectResponse(oauthRequest.redirectUri);
    if (refusedPost) return refusedPost;

    const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
    if (!client) return unknownClientResponse();

    const identity = identityOf(client, oauthRequest.redirectUri);

    /**
     * The ONE place a credential-path response is built. Wait the floor,
     * re-render.
     *
     * One helper for every refusal on this path, because they are the SAME
     * answer. A stopwatch, a status code and a body must not sort the causes
     * apart, and the cheapest way to hold all three true is for there to be one
     * place the answer is written.
     *
     * **It no longer counts anything.** The counter it used to bump was keyed
     * by the connecting source and was bumped by every caller alike — which
     * meant a shape refusal, which never touches Apple, spent the same budget a
     * wrong password did. The counter is now keyed by the TARGET and is bumped
     * at exactly one call site: the one that has just found out Apple turned a
     * password down. The last column below is the whole of that rule.
     *
     * | Cause                               | Error class        | Renders     | Status | Bumps the per-target hourly counter |
     * |-------------------------------------|--------------------|-------------|--------|-------------------------------------|
     * | Badly-shaped app password           | — (Apple untouched)| the string  | 401    | No                                  |
     * | Address not on the list             | — (Apple untouched)| the string  | 401    | No                                  |
     * | Address unparseable or empty        | —                  | the string  | 401    | No                                  |
     * | Per-target burst trip (layer 2)     | —                  | the string  | 401    | No                                  |
     * | Per-target hourly cap (layer 3)     | —                  | the string  | 401    | No                                  |
     * | Wrong password                      | `ImapAuthError`    | the string  | 401    | Yes                                 |
     * | Apple refusing on availability      | `ImapThrottleError`| the throttle| 401    | No                                  |
     * | Connect, TLS or read failure        | `ImapConnectError` | the throttle| 401    | No                                  |
     *
     * **Why the four "No" rows above the wrong-password row are not an
     * oversight.** The counter bounds what APPLE sees. A refusal that happened
     * before the proof ran cost Apple nothing, so counting it would spend a
     * real person's budget on something that never reached Apple — and since
     * layers 2 and 3 are keyed by target, the person whose budget was spent is
     * not the person who spent it. Counting a limiter trip would be worse
     * still: the cap would refill itself, and an address that tripped once
     * could never come back inside the window.
     *
     * A throttle and a connect failure are both excluded for the same reason
     * read the other way: Apple either declined to answer or was never reached,
     * so neither is a guess. That is the same rule the dead-password marker is
     * given in the next phase.
     *
     * **The last row is decided here, and research left it open.** The throttle
     * wording — Apple is not answering right now, wait a few minutes — is
     * LITERALLY TRUE of a connect failure. The single failure string tells the
     * reader to check the address and the password, which is false on that path
     * and sends a family member hunting for a typo that does not exist. It
     * leaks no more than the throttle message already does, because a connect
     * failure can only happen after the allow-list check has passed.
     *
     * The branch reads the error's TYPE and never a caught value's text. The
     * mail tree classifies from the parsed reply, response codes before prose
     * hints, and this handler consumes that classification rather than
     * repeating it.
     *
     * The source-connection refusal is NOT built here. It is keyed by the
     * connecting source rather than by the address being tried, so it carries
     * no information about who is on the list, and it is answered above — before
     * any credential check exists to leak anything.
     */
    async function refuseCredential(
      failure: "credentials" | "throttled" = "credentials",
    ): Promise<Response> {
      await holdFloor(started, floorMs);

      // Where the single failure string is built: a per-target limiter trip
      // renders this string and never a source-connection refusal status. A
      // refusal status that only ever appears for a listed address is a
      // membership oracle, which is exactly what success criterion 3 forbids.
      //
      // Where the throttle message is built: criterion 3 binds this server's
      // own limiter, not Apple's reply. The throttle message does reveal that
      // the address passed the allow list, and that is accepted, because it can
      // only be built after Apple has already answered — which already means
      // the address was listed.
      return renderForm(query, failure, identity, signInNotices(env));
    }

    // The shape check sits ABOVE the allow-list check, and the placement is
    // argued rather than assumed, the way the redirect refusal argues its own
    // three edges.
    //
    // It is the cheapest refusal in the chain: a pure function of ONE submitted
    // field that consults no configuration, reads no stored state and does no
    // I/O. Neither this nor the allow-list check can open a socket, so the
    // ordering is a question of cost and not of safety — and because every
    // refusal below answers with the same body at the same status under the
    // same floor, the order is not observable from outside either.
    //
    // Nothing is derived here, and the absence is the point. What the person
    // typed is what reaches Apple and what the grant stores, so the two cannot
    // disagree — there is no second derivation for them to disagree about.
    // `couldBeAppPassword` carries the argument for why this server stopped
    // transforming the value, and how to take the measurement that would be
    // needed before transforming it again.
    //
    // The shape check is handed the RAW value and measures inside itself. That
    // keeps every transformed form out of scope on this line, which is what
    // stops a later session reaching for one.
    if (!couldBeAppPassword(submittedPassword)) return refuseCredential();

    // The allow-list check sits ABOVE every use of the credentials, and that
    // placement is the whole of GATE-02: an address that is not on the list
    // must never reach Apple, so no principal is built and no session is opened
    // for one. The folded address is what gets compared and what gets stored,
    // so the comparison and the grant cannot disagree about who this is.
    //
    // **Two sources, asked in this order, and the order is a cost argument.**
    // The seed is synchronous and already parsed, so asking it first costs
    // nothing; the store is a round trip. Because the seed holds the owner, HIS
    // OWN SIGN-IN NEVER COSTS A STORE READ, and an address in neither source
    // costs exactly one. This short-circuits — the store is not read at all
    // when the seed already said yes.
    //
    // **One await, sequentially, and never a combinator.** Convention 3 forbids
    // one anywhere in `src/auth/`, and there is nothing here to combine anyway:
    // the first read is not I/O, and the second only happens if the first said
    // no.
    //
    // **The null is refused explicitly, above both questions.** The predicate
    // would refuse it under either verdict, so this is not the safety net — it
    // is what lets the fold happen once and be narrowed once, instead of twice
    // through two calls that could drift.
    //
    // **THE STORE READ SITS ABOVE THE PER-TARGET BURST LIMITER**, which means
    // an unlisted address does buy one store round trip. That is affordable
    // because of what runs far above it: LAYER 1, the source limiter, caps a
    // single connecting source at five attempts a minute before the
    // authorization query is even re-parsed. So the round trip is bounded per
    // source, not per guess. It cannot move BELOW the limiters either — that
    // would count an unlisted address against somebody, which is exactly what
    // GATE-04's "a per-ID trip never reveals list membership" forbids.
    const appleId = normaliseAppleId(submittedAppleId);
    if (appleId === null) return refuseCredential();
    if (
      !isAllowed(allowed, appleId) &&
      !isAllowed(await readStoredAllowList(env.ALLOW_LIST_KV), appleId)
    ) {
      return refuseCredential();
    }

    // The user id is DERIVED from the address, never invented and never read
    // back off anything, and it is derived exactly ONCE — here, above the two
    // per-target layers, and carried all the way down to the grant. It is the
    // same folded string the allow-list check just accepted, so the id that
    // keys this person's counter, the id that names their stored objects and
    // the address in their grant cannot disagree.
    //
    // Derived through the shared function rather than hashed here. A second
    // hashing site under `src/` is exactly what the previous phase closed, and
    // the scan counts that ownership in both directions.
    //
    // It cannot be null at this point: the folding already answered a string,
    // and this refuses exactly what the folding refuses. The check is kept
    // rather than asserted away, because a null would otherwise become the
    // literal string "null" in a key name.
    const userId = await userIdOf(appleId);
    if (userId === null) return refuseCredential();

    // LAYER 2, the target address in a minute. Three attempts against one
    // address per Cloudflare location, eventually consistent rather than exact
    // (see the file header), and answered with the SAME body at the SAME status as
    // every other credential-path failure — never this surface's 429. A status
    // that only ever appeared for a listed address would tell a stranger who is
    // on the list, which is precisely what success criterion 3 forbids.
    //
    // It runs below the shape check and the allow-list check so an unlisted
    // address is never counted against anybody, and above the store counter
    // because it is the cheaper of the two: a burst should be refused before it
    // buys a store read.
    //
    // ---------------------------------------------------------------------
    // THE ACCEPTED COST, AND WHOSE IT IS.
    //
    // This layer and the one below it count by TARGET rather than by attacker.
    // So a stranger who knows a listed address can spend that person's login
    // attempts: enough POSTs carrying somebody else's Apple ID and a wrong
    // password, and that person cannot sign in until the window rolls.
    //
    // That is accepted by the owner, on 2026-09-20, and the bound is what makes
    // it acceptable. It blocks NEW sign-ins only. An existing grant never
    // touches this path — it is served by the token endpoint and the API
    // handler, neither of which consults a limiter — so nobody already signed
    // in loses anything, and the person locked out is locked out for an hour
    // rather than indefinitely: layer 3 below refuses until the oldest of the
    // last five failures is sixty minutes old. The owner chose an hour's
    // lockout on 2026-09-21, after the hour-boundary fix had briefly stretched
    // it towards two. The owner's own escape from a counter they tripped
    // themselves is in the phase runbook.
    //
    // Re-keying by attacker instead would not bound Apple attempts at all,
    // which is the one thing these layers exist to do: a guesser spread thin
    // across addresses would be counted as a guesser and never as a threat to
    // any one account, while Apple would see every attempt.
    //
    // A SECOND ACCEPTED COST: THIS LAYER COUNTS SUCCESSES TOO. Recorded after
    // the phase review of 2026-09-21. The binding is asked before the login
    // runs, and it has no way to give a slot back, so a correct password spends
    // a slot exactly as a wrong one does. The client is known to submit a
    // successful form twice (see `revokeExistingGrants` below). So a person who
    // mistypes twice and then types the right password spends slots one to
    // three, and the client's repeat submission is refused. The browser shows
    // the LAST response, so they read "check the address and the password"
    // even though the first correct submission already signed them in. Trying
    // again after a minute works.
    //
    // Why it is left alone. Counting only failures is not possible with this
    // binding. Raising the limit to make room would loosen the only brake on a
    // parallel burst, which is already weaker than it looks (see the file
    // header). A confusing message once in a while is the cheaper of the two.
    //
    // THE LAYER THAT IS NOT HERE. A fourth layer was considered and declined
    // for this milestone: a ceiling on total sign-in attempts across every
    // listed address at once. Recorded as a decision rather than left as an
    // absence, because an absence reads as an oversight. The allow list holds
    // exactly one address for the whole of this milestone, so a ceiling across
    // several has nothing to bind that the per-target layer does not already
    // bind. Revisit when the list grows past one.
    // ---------------------------------------------------------------------
    //
    // A BINDING THAT THROWS IS A REFUSAL, and it takes the same exit as a trip.
    // This line runs only for a listed address. So a throw that escaped here
    // would come back as a fast 500 for listed addresses and never for unlisted
    // ones, which sorts the list by status and by stopwatch. Refusing through
    // the one helper keeps the body, the status and the floor the same. The
    // caught value is never read.
    let burstOk = false;
    try {
      burstOk = (await env.LOGIN_ID_LIMITER.limit({ key: userId })).success;
    } catch {
      /* Fail closed. See the paragraph above. */
    }
    if (!burstOk) return refuseCredential();

    // LAYER 3, the target address across an hour. At most five failed guesses
    // reach Apple in any rolling sixty minutes, and the next is refused.
    //
    // This is the layer the platform cannot supply: a rate-limit binding's
    // window accepts ten seconds or sixty and nothing longer, so an hour has to
    // be a record in a store. It is read AFTER the binding above, deliberately
    // — the binding costs no round trip and this does.
    //
    // A SLIDING LOG, NOT A COUNT. One key per person holds the times of their
    // last five failures, newest last. A failure counts while it is at most
    // sixty minutes old. Five that count means refuse. So, for a serial
    // guesser:
    //
    // - At most five failures reach Apple in any sixty minutes. There are no
    //   fixed hours, so there is no boundary to straddle.
    // - A lockout lasts until the oldest of the five is sixty minutes old, and
    //   the next attempt is allowed a millisecond later.
    // - A success writes nothing, and a refusal writes nothing.
    //
    // Why this and not a count per clock hour. The owner chose a lockout of
    // about an hour on 2026-09-21. The first design read two hourly buckets
    // and summed them, which held a lockout for up to two hours. The second
    // weighted the previous hour instead. That brought the lockout back to
    // about an hour but let a patient guesser place nine attempts at Apple in
    // forty-nine minutes, because a count with no times in it cannot tell a
    // burst at 10:59 from one at 10:00. It was replaced with this log the same
    // day. Keeping the times is what makes the bound exact.
    //
    // Non-atomic. It counts a patient attacker's serial attempts exactly. It
    // does not catch a parallel or many-location burst, because every request
    // in the burst reads the same list before any of them writes, and the store
    // is eventually consistent. Such a burst can go over five. That is the same
    // accepted cost as layer 2, and the file header records it.
    //
    // One read and, on a failure at Apple, one write. Never a combinator:
    // convention 3 forbids one anywhere in `src/auth/`.
    //
    // A STORE THAT THROWS IS A REFUSAL too, for the same reason as the binding
    // above: only a listed address gets here. An unreadable record reads as a
    // full one. So does one that is not a JSON list of finite numbers, and so
    // does a clock reading that is not a finite number. Each of those would
    // otherwise make every entry look old or absent, which would switch this
    // layer off for that person for good.
    const now = clock();
    const counterKey = failureCounterKey(userId);
    let recent: number[] | null = null;
    try {
      const times = failureTimesFrom(await env.OAUTH_KV.get(counterKey));
      if (times !== null && Number.isFinite(now)) {
        recent = failuresWithinWindow(times, now);
      }
    } catch {
      /* Fail closed. The caught value is never read. */
    }
    if (recent === null || recent.length >= MAX_FAILURES_PER_WINDOW) {
      return refuseCredential();
    }
    const failuresInWindow: number[] = recent;

    // Whether a real attempt was spent at Apple. It decides, and is the only
    // thing that decides, whether the counter above moves.
    let askedApple = false;

    // Declared here and assigned inside the `try`, so the principal the proof
    // used is still in scope after it: the autonomy arm below names the
    // person's object from it, and from nothing else.
    let principal: Principal;

    try {
      // `principalFromProps` is the ONE constructor, and it refuses before any
      // socket exists: an unusable password — empty, whitespace-only, or
      // carrying a control character — throws here (D-19). What it is handed is
      // the SUBMITTED value itself, which is also what the props below carry,
      // so the login this proves and every later request replay the identical
      // bytes. They are the same expression, not two derivations that happen to
      // agree.
      principal = await principalFromProps({
        v: PROPS_VERSION,
        appleId,
        appPassword: submittedPassword,
      });

      // Set BEFORE the call rather than after it, because the moment the call
      // is made the attempt is in flight and the answer cannot un-spend it.
      // The constructor above is excluded on purpose: a password it refuses
      // never reaches Apple, so it is a local refusal wearing a throw.
      askedApple = true;

      // One login, at Apple. This is the only place in the whole flow that
      // talks to Apple, and it is reached only for an address already on the
      // list carrying a password already judged usable.
      await proof(principal, createSessionGate());
    } catch (error) {
      // NEVER read the caught value's TEXT. The type is all that is consulted,
      // and `instanceof` is the whole of the test — no `.message`, no `.stack`,
      // no prose hint re-derived here. The mail tree already decided a throttle
      // from a credential refusal by reading the parsed tagged reply, response
      // codes before prose hints, and this handler consumes that decision
      // rather than making a second one that could disagree with it.
      //
      // Anything that is not one of these two named types falls through to the
      // single failure string, which is the silent answer. Failing toward the
      // silent one is deliberate: no live refusal has ever been observed from
      // iCloud, so every code the classifier matches is taken from the
      // specification rather than from evidence.
      const throttled =
        error instanceof ImapThrottleError || error instanceof ImapConnectError;

      // The ONE site that moves the per-target counter, and the two conditions
      // are different claims. `askedApple` says an attempt was really spent —
      // a password the constructor refused never left this Worker. `throttled`
      // says Apple declined to answer or was never reached, which is not a
      // guess either way.
      //
      // An unfamiliar error type DOES count. It falls through to the silent
      // body above for a disclosure reason, and that reason does not apply
      // here: the proof ran, so whatever came back, this person's budget at
      // Apple was spent and the counter should say so.
      //
      // Awaited rather than left floating. The write is allowed to fail and
      // swallows its own rejection; what it must not do is settle after the
      // response has gone.
      if (askedApple && !throttled) {
        await countFailedGuess(
          env.OAUTH_KV,
          counterKey,
          failuresInWindow,
          clock(),
        );
      }

      return refuseCredential(throttled ? "throttled" : "credentials");
    }

    // The session is already closed. `withMailSession` runs teardown and
    // releases its gate in its own `finally` BEFORE it returns, so reaching
    // this line means the socket is gone. The trap this avoids is completing
    // the ceremony inside the session callback, which would hold a connection
    // open against iCloud's low, undocumented per-account ceiling while a store
    // write and a redirect were built.

    // The dead-password pause ends here, and only here (LIFE-04). Reaching this
    // line means Apple ACCEPTED the password, so whatever pause an earlier dead
    // one started no longer describes anything. Without this clear, someone who
    // has just made a fresh app-specific password still waits out the fifteen
    // minutes and reasonably concludes the fix did not work.
    //
    // The id is the one derived above the limiter layers, never a second
    // derivation — the paragraph below this block says why, and it applies to
    // this reader exactly as it applies to the ceremony's.
    //
    // Awaited rather than left floating, like the counter write in the branch
    // above and for the same reason: it may fail, but it must not settle after
    // the response has gone. It swallows its own failure.
    //
    // **The login page never SETS the pause**, and that asymmetry is the whole
    // defence against a stranger who knows a listed address pausing that
    // person's working apps from this form. It is structural: the principal
    // built above is never armed to report, so the refusal branch has nothing to
    // report through. Do not "balance" this clear with a set in the catch.
    await clearPause(env.OAUTH_KV, userId);

    // Grant what was asked for, narrowed to what this server supports. A
    // client that asks for nothing gets the one scope that exists, because a
    // single-user single-scope server has nothing meaningful to withhold.
    const requested = oauthRequest.scope.filter((scope) =>
      SUPPORTED_SCOPES.includes(scope),
    );
    const granted = requested.length > 0 ? requested : [...SUPPORTED_SCOPES];

    // Exactly the three keys `principalFromProps` accepts, and no fourth. It
    // derives the user id from the address every time, so a props object
    // carrying one of its own is refused for having an extra key.
    //
    // Built ONCE, and the same object goes to both authorizations below: the
    // ordinary one and, when autonomy is set up, the autonomy one. So the two
    // grants cannot carry different credentials.
    //
    // `submittedPassword` is named here for the SECOND and last time — the
    // proof above named it once. Both sites name the same expression rather
    // than a derived variable, which is what makes "the grant replays exactly
    // what Apple accepted" true by construction instead of by inspection.
    const props = {
      v: PROPS_VERSION,
      appleId,
      appPassword: submittedPassword,
    };

    // The user id is the one derived above the limiter layers, not a second
    // derivation. It used to be computed here, which was harmless while it had
    // one reader; with three readers a second derivation is how the id that
    // keys somebody's counter and the id that names their grant come to be
    // different strings.
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthRequest,
      userId,
      // Only the client's name, and nothing else. Metadata is not encrypted
      // the way props are, so nothing about the person goes in it — not the
      // address, not the id derived from it.
      metadata: { clientName: client.clientName },
      scope: granted,
      // The one props object built above. See the comment there.
      props,
      // TRUE was the default and it locked the owner out of his own server on
      // 2026-09-21, hours after the phase shipped. Measured, not theorised.
      //
      // The client submits this form TWICE, about 1.4 seconds apart, after
      // registering twice. Both submissions SUCCEED — each completed in ~1s,
      // well under the three-second floor every failure is held to, so neither
      // was a retry after a refusal. Under the default, the second grant's
      // creation revoked the first. The client was holding a token for the one
      // that lost, and because this store is eventually consistent it kept
      // working for about sixty seconds and four calls before the delete caught
      // up. Then: 401, re-discovery, two more registrations, another
      // authorization, and round again.
      //
      // The library's own note on the default says it "prevents stale tokens
      // from causing infinite re-auth loops when props change". Here it CAUSED
      // that loop. The condition it guards against is a second sign-in carrying
      // DIFFERENT props; the condition it met was a second sign-in carrying
      // identical ones, which is not a stale token at all.
      //
      // What is given up, stated plainly because it is real: when someone
      // rotates their app-specific password and signs in again, the old grant
      // holding the dead password is no longer swept away in the same step. It
      // is not a hole — the dead password fails at Apple — but grants now
      // accumulate, and clearing them is phase 12's revoke script (LIFE-05).
      // LIFE-03 already promises one Apple ID may be signed in from several
      // Claude apps at once, so concurrent grants are the intended shape; this
      // makes that explicit rather than accidental.
      //
      // Do not restore the default to "tidy up" grant accumulation. That is
      // LIFE-05's job, and putting it back reinstates the lockout above.
      revokeExistingGrants: false,
    });

    // THE AUTONOMY KEY (Phase 27, D-26). Autonomy is inherent, so this runs on
    // every sign-in, for every client, whenever autonomy is set up.
    //
    // WHY HERE AND NOWHERE ELSE (AUTO-01). This is the only place outside the
    // door that holds a principal Apple has just proved, and the only place a
    // person has just read the sign-in page. A Claude app refreshing its own
    // token never reaches this line, so nothing is minted without an
    // interactive sign-in.
    //
    // A second authorization, for the autonomy client, with the same user id
    // and the same props object as the ordinary one above. The ordinary grant,
    // its props, its metadata and the 302 below are not changed by it.
    //
    // `revokeExistingGrants: false` here too, for a reason of its own: the
    // library's sweep would revoke the autonomy grant a second sign-in is still
    // arming (the client submits this form twice). The object's arm is the only
    // sweep of autonomy grants (D-13, D-28).
    //
    // THE CODE NEVER REACHES THE BROWSER. It is read out of the library's
    // redirect URL here, in memory, and handed to the person's own object. The
    // redirect URI is never served and no browser is ever sent there (D-29).
    //
    // The whole call sits in a `try` whose `catch` reads nothing: a missing
    // client record, a store error, anything, means this sign-in arms nothing
    // and answers exactly as it would have.
    //
    // THE NOTICE FIELD (D-30). Arming also needs the hidden field the page
    // renders only when it shows the autonomy notice, carrying that notice's
    // version. Nobody is armed from a page that did not show the words, such as
    // one opened before autonomy was set up, and the field costs nothing to a
    // person who saw them.
    let autonomyCode: string | null = null;
    if (
      ctx !== undefined &&
      autonomyConfigured(env) &&
      noticeVersion === AUTONOMY_NOTICE_VERSION
    ) {
      try {
        const autonomy = await env.OAUTH_PROVIDER.completeAuthorization({
          request: {
            responseType: "code",
            clientId: AUTONOMY_CLIENT_ID,
            redirectUri: `https://${DEPLOYED_HOSTNAME}${AUTONOMY_REDIRECT_PATH}`,
            scope: [...SUPPORTED_SCOPES],
            state: "",
          },
          userId,
          metadata: { clientName: AUTONOMY_CLIENT_NAME },
          scope: [...SUPPORTED_SCOPES],
          props,
          revokeExistingGrants: false,
        });
        autonomyCode = new URL(autonomy.redirectTo).searchParams.get("code");
      } catch {
        autonomyCode = null;
      }
    }

    // Constructed explicitly rather than through the static redirect helper,
    // and this is the site where that matters most: this location header
    // carries the authorization code, so a cached copy of this redirect is a
    // cached copy of a credential-equivalent. The helper builds a response
    // nothing can put a caching header on. A caller reading `location` off this
    // response sees the same value the helper would have set.
    //
    // This is the redirect that was being blocked. `form-action 'self'` on the
    // page that submitted the form made Safari refuse to follow this 302 to
    // claude.ai, silently, so the code was issued and never exchanged
    // (measured 2026-09-23; the argument is at `RESPONSE_HEADERS`). The page is
    // where the fix has to land, and this response carries the matching
    // directive so the whole surface answers with one value per destination.
    // The URI is the one the allowlist already accepted twice on this path.
    const answer = new Response(null, {
      status: 302,
      headers: {
        ...responseHeadersFor(oauthRequest.redirectUri),
        location: redirectTo,
      },
    });

    // The mint above is awaited before this answer is built. It is one store
    // read, one props encryption and one store write, so it adds a little time
    // to the sign-in, and its `catch` means it cannot fail it. Only the arm
    // runs after the answer, through the request's `waitUntil`, so the arm can
    // neither slow nor fail the person's sign-in. It never rejects.
    if (autonomyCode !== null && ctx !== undefined) {
      ctx.waitUntil(armAfterAnswer(env, principal, userId, autonomyCode));
    }
    return answer;
  }
}
