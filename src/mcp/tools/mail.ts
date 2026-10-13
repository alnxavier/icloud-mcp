// The mail tool boundary: the error shaper and the registrations.
//
// The untrusted fence itself no longer lives here. D-56 moved it up to
// `../untrusted`, because the framing is a statement about stranger-authored
// text rather than about mail, and the calendar and contacts tools carry
// exactly that text. What this module re-exports below is a compatibility
// surface, not a second copy.
//
// ONE module, every mail registration. D-17 constrains the MCP tool *surface* —
// registered tools with distinct names — not the file count, and D-17 itself
// says the unread tool shares the listing implementation internally rather than
// duplicating it. That sharing is cheapest and least drift-prone inside one
// module, and all of them copy the same analog from `./diagnose.ts` either way:
// exported transport-free shapers, plus a registration function. Later plans
// add registrations here rather than creating siblings.
//
// A sibling file is also the most likely way to break the property phase 2
// verified and this phase inherits: the untrusted fence is called from exactly
// ONE place, and every shaper routes through it.
//
// This module contains no logging calls of any kind and must never acquire any.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import type { LeasedMail } from "../../agent/lease";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  ConfirmationInvalidError,
  changeHashMatches,
  composeConfirmationLine,
  draftChangeHashOf,
  mailMoveChangeHashOf,
  mintConfirmation,
  reserveConfirmation,
  verifyConfirmation,
} from "../../confirm";
import type {
  MailConfirmPayload,
  MailSetEntry,
  NormalizedDraftChange,
  NormalizedMailMove,
} from "../../confirm";
import type { Env } from "../../env";
import {
  ImapAuthError,
  ImapCredentialRefusedError,
  ImapGoneError,
  ImapNotFoundError,
  MailConfirmationError,
  toErrorCategory,
} from "../../errors";
import type { BuildResult, DraftAttachment } from "../../mail/compose";
import {
  buildDraft,
  quoteOriginal,
  replyRecipients,
  replySubject,
} from "../../mail/compose";
import { draftFromAddress } from "../../mail/credentials";
import {
  EXTRACTABLE_TYPES,
  extractAttachmentText,
} from "../../mail/extract";
import type { FolderRole, RoleSource } from "../../mail/imap-parser";
import { decodeModifiedUtf7 } from "../../mail/imap-parser";
import type { MessageRef } from "../../mail/ids";
import {
  STAGED_ID_TTL_MS,
  decodeAttachmentId,
  decodeFolderId,
  decodeMessageId,
  decodeStagedId,
  decodeUploadId,
  encodeFolderId,
  encodeMessageId,
  encodeUploadId,
} from "../../mail/ids";
import { transferDecode } from "../../mail/mime";
import type {
  AppendOutcome,
  AttachmentContent,
  DraftPreviewRefusal,
  FolderListing,
  MessageDetail,
  MessagePage,
  SearchPage,
} from "../../mail/service";
import {
  DEFAULT_MAILBOX,
  appendDraft,
  getAttachmentContent,
  getMessage,
  getReplyParent,
  listFolders,
  listMessages,
  listUnread,
  readDraftForChange,
  readMoveSet,
  resolveRoleFolder,
  searchMessages,
} from "../../mail/service";
import type { FolderSummary } from "../../mail/service";
import type {
  DraftDeleteOutcome,
  FlagStateOutcome,
  MessageMoveResult,
  MoveOutcome,
  ReadStateOutcome,
} from "../../mail/triage";
import {
  MOVE_SET_CAP,
  deleteDraft,
  flagMessage,
  markRead,
  markUnread,
  moveMessages,
  unflagMessage,
} from "../../mail/triage";
import type { Principal } from "../../principal";
import { forgetDeadRef } from "../../recall/dead-ref";
import type { ConfirmRefusal } from "../../staging/presign";
import {
  UPLOAD_URL_TTL_SECONDS,
  confirmStagedUpload,
  mintUploadUrl,
  presignedKeyFor,
  uploadHeadersFor,
} from "../../staging/presign";
import type { StageRefusal, StageResult } from "../../staging/r2";
import {
  MAX_INLINE_BASE64_BYTES,
  MAX_STAGED_FILE_BYTES,
  deleteStaged,
  getStaged,
  putStaged,
} from "../../staging/r2";
import type { ToolResult } from "../untrusted";
import {
  UNTRUSTED_NOTICE,
  untrustedBlock,
  untrustedToolResult,
} from "../untrusted";

/**
 * The fence, re-exported unchanged from where it now lives.
 *
 * This is a compatibility surface and nothing else — no wrapper, no second
 * implementation. Phase 2's suite resolves both names from this module, and
 * that suite is the regression fence proving D-56's move did not alter the
 * framing; requiring it to be edited would have thrown away the only evidence
 * that the move was mechanical.
 */
export { untrustedBlock, UNTRUSTED_NOTICE };

/**
 * The single translation boundary for every mail tool.
 *
 * Dispatches on the error's TYPE and never on any message text — the same
 * discipline `diagnosticResult` keeps, and for the same reason: a caught value
 * on this path can carry a raw IMAP command line, and IMAP puts the password
 * inline in it. `toErrorCategory` is contractually forbidden from reading
 * `.message` or `.stack`, and nothing here reads them either.
 *
 * `detail` is the server's own reply text, and it is attached only for an
 * authentication refusal. It originates with Apple — the credential travels in
 * the command we sent, never in the reply — and it is what distinguishes a
 * wrong app-specific password from a username format iCloud will not accept.
 */
export function mailErrorResult(
  err: unknown,
  detail: string | null = null,
): ToolResult {
  const { category, message } = toErrorCategory(err);
  const authDetail = err instanceof ImapAuthError ? detail : null;
  // One more fact, set only when Apple refused the saved password and named
  // the refusal with a response code (28-REVIEW CR-01, 28-REVIEW-2 WR-01). The
  // category is the same `auth_failed` either way, so nothing an interactive
  // caller reads changes. The rules job reads this field and counts only these
  // toward ending a key: a bare NO at the sign-in, a server fault there, the
  // dead-password pause and a calendar refusal answer `auth_failed` without
  // it. Dispatched on the error's type, like everything else here.
  const refused = err instanceof ImapCredentialRefusedError ? { credentialRefused: true } : {};

  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify(
          authDetail === null
            ? { category, message, ...refused }
            : { category, message, authFailureDetail: authDetail, ...refused },
        ),
      },
    ],
  };
}

/**
 * The half of a fetched message this server can vouch for.
 *
 * Three of these are statements about this server's OWN work rather than about
 * the message: `truncated` says whether the whole message was obtained,
 * `attachmentsDisagree` says whether the two independent derivations of the
 * attachment list described the same files, and `fetchPath` says which content
 * command ran. Fencing them would frame the server's own answer as a stranger's
 * claim — the same reasoning `roleSource` carries in the folder listing.
 */
function trustedPart(detail: MessageDetail): Record<string, unknown> {
  return {
    id: detail.id,
    uid: detail.uid,
    unread: detail.unread,
    internalDate: detail.internalDate,
    wireSizeBytes: detail.wireSizeBytes,
    bodySource: detail.bodySource,
    truncated: detail.truncated,
    fetchPath: detail.fetchPath,
    attachmentsDisagree: detail.attachmentsDisagree,
    attachmentCount: detail.attachments.length,
    attachmentSizesBytes: detail.attachments.map((one) => one.sizeBytes),
    // The same derived-count-beside-a-fenced-list split the two lines above
    // already make, applied to the threading chain (D-70). The tokens
    // themselves are stranger-authored and sit inside the fence; this number is
    // one this server produced by counting a parsed header, and fencing it
    // would frame its own arithmetic as somebody else's claim.
    //
    // It is also the field that makes the cap honest. `references` carries at
    // most `REFERENCES_PREVIEW_LIMIT` tokens, so without this the model would
    // read a forty-message thread as a five-message one.
    referencesCount: detail.referencesCount,
  };
}

/**
 * The half a stranger wrote.
 *
 * The declared media type and disposition are in here alongside the filename,
 * because a sender chooses all three. Only the decoded size — which this server
 * measured — is reported on the trusted side.
 *
 * `html` is here for the same reason `text` is, and it is the field most likely
 * to be waved through as "just formatting": raw markup is exactly where an
 * injected instruction sits comfortably, and the flag that requests it changes
 * nothing about who wrote it.
 */
function untrustedPart(detail: MessageDetail): Record<string, unknown> {
  return {
    subject: detail.subject,
    fromName: detail.fromName,
    fromAddress: detail.fromAddress,
    date: detail.date,
    messageId: detail.messageId,
    text: detail.text,
    html: detail.html,
    // D-70's recipients. A display name in a To header is a string whoever sent
    // the message chose, and an address is what the message CLAIMS rather than
    // what any check confirmed — the same reasoning `fromAddress` two lines up
    // already carries, and the reason an address that looks like a fact is not
    // one. D-41 applies to all four values unchanged.
    to: detail.to,
    cc: detail.cc,
    // Stranger-authored for the same reason: every token in the chain was
    // written by whichever client composed the message that carried it.
    references: detail.references,
    attachments: detail.attachments.map((one) => ({
      // A server-minted token, repeated INSIDE the fence, and the precedent is
      // written out in this file's folder shaper: it is what lets the model
      // address a row BY IDENTITY rather than by array position, which is the
      // correlation hazard that once put one folder's counts on another.
      // Repeating a value this server generated inside the fence costs nothing
      // — the fence marks content as data, and an opaque token read as data is
      // still the same token.
      //
      // The part path it was minted from is NOT here and is not anywhere else
      // either. The model holds the token instead, exactly as it holds a folder
      // id rather than a wire mailbox name (D-18).
      id: one.id,
      filename: one.filename,
      mimeType: one.mimeType,
      disposition: one.disposition,
      sizeBytes: one.sizeBytes,
    })),
  };
}

/**
 * Shape a fetched message into the tool's response.
 *
 * Exported for the same reason `folderToolResult` is, and for one more: the
 * containment assertion over this shape is a WALK, and a walk run against a
 * test-local copy of this mapping proves nothing about the mapping that ships.
 * A field added below and forgotten in the copy would pass a test built on the
 * copy — which is precisely the failure the walk exists to catch.
 */
export function messageToolResult(detail: MessageDetail): ToolResult {
  return untrustedToolResult(trustedPart(detail), untrustedPart(detail));
}

/** The half of a folder listing this server derived or the protocol guarantees. */
function folderTrustedPart(listing: FolderListing): Record<string, unknown> {
  return {
    countsSource: listing.countsSource,
    delimiter: listing.delimiter,
    folderCount: listing.folders.length,
    folders: listing.folders.map((one) => ({
      // The value a later call round-trips. It is opaque by construction, so
      // the model names a folder without ever holding — or constructing — the
      // wire name that reaches a mailbox selection (T-02-34, D-18).
      id: one.id,
      // The server's own answer about its own mailbox, verbatim. This is the
      // measurement that settles whether this account's server emits
      // special-use attributes at all, so it is reported rather than summarised.
      attributes: one.attributes,
      role: one.role,
      // D-30: the role and the path that resolved it travel together, so a
      // name-matched role is distinguishable from a server-stated one at the
      // point of USE rather than only in a code read (T-02-24).
      roleSource: one.roleSource,
      totalCount: one.totalCount,
      unreadCount: one.unreadCount,
    })),
  };
}

/**
 * The half whoever created the folder wrote.
 *
 * The `id` is repeated here deliberately, and it is the only value that appears
 * on both sides. It is what lets the model join a display name to its role and
 * counts BY IDENTITY rather than by array position — the same correlation
 * hazard that, one layer down, put one folder's counts on another. Repeating a
 * value this server generated inside the fence costs nothing: the fence marks
 * content as data, and an opaque token read as data is still the same token.
 */
function folderUntrustedPart(listing: FolderListing): Record<string, unknown> {
  return {
    folders: listing.folders.map((one) => ({
      id: one.id,
      displayName: one.displayName,
    })),
  };
}

/**
 * Shape a finished folder listing into the tool's response.
 *
 * Exported for the same reason `diagnosticResult` is: no automated job in this
 * repository may authenticate against the real Apple ID, so a response shaper
 * welded to the transport would be untestable rather than merely awkward — and
 * a test that rebuilt this mapping instead would stay green against a shaper
 * that put a folder name in the wrong half.
 */
export function folderToolResult(listing: FolderListing): ToolResult {
  return untrustedToolResult(
    folderTrustedPart(listing),
    folderUntrustedPart(listing),
  );
}

/**
 * The half of a listing this server derived or the protocol guarantees.
 *
 * `hasMore` and `nextCursor` belong here for the reason `roleSource` does one
 * shape over: they are this server's own statements — one about what it found,
 * one a token it minted — and fencing the cursor in particular would frame the
 * value a model needs in order to ask for the next page as a stranger's claim.
 *
 * Note what is NOT here that the message shape carries: there is no `text`, no
 * `html`, and no field of any body-carrying kind on either side of this
 * response. MAIL-02 says "metadata only — never full bodies by default", and
 * the shape is where that is enforced rather than promised.
 */
function pageTrustedPart(page: MessagePage): Record<string, unknown> {
  return {
    hasMore: page.hasMore,
    nextCursor: page.nextCursor,
    messageCount: page.messages.length,
    messages: page.messages.map((one) => ({
      // The value a later call round-trips, opaque by construction. Repeated
      // inside the fence below so the two halves join BY IDENTITY rather than
      // by array position — the same correlation hazard the folder listing
      // names, on the response a model reads most.
      id: one.id,
      uid: one.uid,
      unread: one.unread,
      internalDate: one.internalDate,
      wireSizeBytes: one.wireSizeBytes,
      // Derived here from the structure walk, so it is this server's reading of
      // the message rather than the sender's claim about it. The filenames and
      // media types themselves stay out of a listing entirely.
      hasAttachments: one.hasAttachments,
    })),
  };
}

/**
 * The half a stranger wrote.
 *
 * Every value here arrives BEFORE any body is fetched, which is what makes a
 * listing the cheapest injection vector this server has: a sender chooses their
 * own display name, and a display name is exactly the kind of short,
 * authoritative-looking string an instruction hides well in (T-02-02).
 *
 * The snippet is here for the same reason the body is one shape over. It is
 * shorter, not safer.
 */
function pageUntrustedPart(page: MessagePage): Record<string, unknown> {
  return {
    messages: page.messages.map((one) => ({
      id: one.id,
      subject: one.subject,
      fromName: one.fromName,
      fromAddress: one.fromAddress,
      snippet: one.snippet,
    })),
  };
}

/**
 * Shape one page into the tool's response.
 *
 * Exported for the reason `messageToolResult` is: the containment assertions
 * over this shape are WALKS, and a walk run against a test-local copy of this
 * mapping proves nothing about the mapping that ships. A field added below and
 * forgotten in the copy would pass a test built on the copy.
 *
 * **One fence for the whole page, not one per row or per field.** Fencing each
 * value would cost roughly nine kilobytes of pure delimiter on a 25-row page —
 * paid on the response the model reads most often — while the property D-41
 * asks for is unchanged, because the fence bounds a REGION rather than a value.
 */
export function messagePageToolResult(page: MessagePage): ToolResult {
  return untrustedToolResult(pageTrustedPart(page), pageUntrustedPart(page));
}

/**
 * Shape one page of search results.
 *
 * The listing's shape plus one field, because a search result IS a listing —
 * same rows, same metadata-only discipline, same cursor contract — and a model
 * should read one shape whichever tool it reached for. Delegating rather than
 * copying is what keeps that true: a field added to a listing row appears here
 * without anyone remembering to add it.
 *
 * `unsupportedCharset` is in the TRUSTED half for the reason `hasMore` is. It
 * is this server's own statement about what the exchange did — the search ran
 * and the server declined the encoding — not a claim anyone else made. It is
 * also the field that keeps the error vocabulary closed at four values, so
 * framing it as a stranger's claim would undercut the whole reason it exists.
 */
export function searchPageToolResult(page: SearchPage): ToolResult {
  return untrustedToolResult(
    { ...pageTrustedPart(page), unsupportedCharset: page.unsupportedCharset },
    pageUntrustedPart(page),
  );
}

/**
 * Everything the compose tool has to report, once the write is decided.
 *
 * One shape for both outcomes rather than a union, because the tool CALL
 * succeeds either way: a size refusal is a structured field on a successful
 * result, not an error. That is the shipped `unsupportedCharset` precedent, and
 * it is what keeps the error vocabulary closed at four values while still
 * handing the model a reason it can act on.
 */
export interface ComposeReport {
  /** Whether the draft reached the folder. */
  appended: boolean;
  /**
   * The opaque id of the draft just written, or `null`.
   *
   * `null` on a refusal, and also on a successful write whose server did not
   * name the result — RFC 4315 permits that, and the draft exists either way.
   */
  id: string | null;
  /** The resolved role of the folder written to, or `null`. */
  role: FolderRole;
  /**
   * How that role was resolved, or `null`.
   *
   * Reported because it is not a detail: iCloud emits no special-use attribute
   * for the drafts folder, so a `name-match` here means the target rested on
   * this client's own name ladder rather than on a statement by the server.
   */
  roleSource: RoleSource;
  /** The assembled message size, or `null` when nothing was assembled. */
  sizeBytes: number | null;
  /** Why nothing was written, or `null`. */
  refusal: string | null;
  /** The ceiling a size refusal exceeded, or `null`. */
  limitBytes: number | null;
  /**
   * The parent's own `Message-ID`, or `null` for a new message.
   *
   * In the TRUSTED half, which is the one placement in this shape worth
   * arguing about — a FETCHED message reports its `messageId` inside the fence.
   * Two things make the difference. The value only reaches this field after
   * matching the angle-bracket token pattern, which admits no whitespace, so
   * unlike the fetched field it cannot carry a sentence. And it is what the
   * model needs in order to check that the reply threaded at all, on a path
   * where every failure mode returns a successful write.
   */
  parentMessageId: string | null;
  /**
   * How many tokens the emitted `References` carried, or `null`.
   *
   * A count rather than the chain: a long thread's chain is a run of opaque
   * ids the model cannot act on, and the number is the part that answers "did
   * the whole chain survive". This server counted it, so it is trusted.
   */
  referencesCount: number | null;
  /** How many staged files travelled with the draft. Zero when none did. */
  attachedCount: number;
  /**
   * Their combined DECODED size, before the transfer encoding inflates it.
   *
   * The decoded number rather than the wire one, because it is the number the
   * user recognises as the size of their own file — `AttachmentMeta.sizeBytes`
   * is emphatic about what reporting the other one does to a person reading
   * about a document they have on disk. The assembled message's own size is
   * reported separately in `sizeBytes`, and the two are deliberately different
   * quantities rather than one number doing both jobs.
   */
  attachedBytes: number;
  /**
   * The staged ids this write consumed, and which now name nothing.
   *
   * In the TRUSTED half, and it is the second placement in this shape worth
   * arguing about. These strings arrived from the caller — but only a token
   * this server minted survives the decoder, and a token that decodes is
   * base64url and therefore cannot carry a space, so like `parentMessageId` it
   * cannot carry a sentence. It is also the fact the model most needs after a
   * successful write: a staged file attaches ONCE, so a transcript showing
   * which ids are spent is what stops the model retrying with one of them.
   *
   * Empty on every path that did not write, which is the true statement — a
   * refused compose consumes nothing.
   */
  consumedStagedIds: string[];
  /** The caller's own subject, echoed back. */
  subject: string;
  /** The caller's own recipients, echoed back. */
  to: string[];
  /** The caller's own copied recipients, echoed back. */
  cc: string[];
}

/**
 * Shape a compose attempt into the tool's response.
 *
 * The split runs along authorship, as it does for the five shapes above. The
 * trusted half is entirely this server's own work — a token it minted, a role
 * it resolved, a size it measured, a refusal it decided. The untrusted half is
 * the subject and the recipients, which are strings the CALLER wrote: they came
 * in through this tool's own schema, went into a message, and are echoed back
 * so the model can confirm what was written. Echoed caller text is not this
 * server's claim about anything, so it goes inside the fence.
 *
 * Exported even though only this module uses it, for the reason recorded twice
 * elsewhere in this file: the containment assertions are WALKS, and a walk over
 * a test-local copy of this mapping proves nothing about the mapping that
 * ships.
 */
export function composeToolResult(report: ComposeReport): ToolResult {
  return untrustedToolResult(
    {
      appended: report.appended,
      id: report.id,
      role: report.role,
      roleSource: report.roleSource,
      sizeBytes: report.sizeBytes,
      refusal: report.refusal,
      limitBytes: report.limitBytes,
      parentMessageId: report.parentMessageId,
      referencesCount: report.referencesCount,
      attachedCount: report.attachedCount,
      attachedBytes: report.attachedBytes,
      consumedStagedIds: report.consumedStagedIds,
    },
    {
      // The recipients are inside the fence on a reply for a SECOND reason
      // beyond the echo argument above: when they were derived rather than
      // supplied, the strings came off the parent's own headers and a stranger
      // wrote them. Same placement, two independent reasons for it.
      subject: report.subject,
      to: report.to,
      cc: report.cc,
    },
  );
}

/**
 * What one attachment read produced, before the fence splits it.
 *
 * Every field is nullable on some path and that is deliberate rather than lazy:
 * a part-too-large refusal never reaches the extractor, so `extracted`,
 * `truncated` and `text` have no honest value, and reporting `false`/`""` there
 * would be a claim this server cannot make. `null` says "this question was not
 * reached", which is the true answer.
 */
export interface AttachmentReport {
  /** The opaque id the caller passed, echoed so the model can match it up. */
  id: string;
  /** The DECODED file size, from the server's own structure. */
  sizeBytes: number;
  /**
   * The wire octet count for the same part.
   *
   * Both sizes are reported, and the pairing is the point: `limitBytes` is
   * compared against THIS one for a `part-too-large` refusal, which is decided
   * in wire octets, and against `sizeBytes` for a `source-too-large` one, which
   * is decided in decoded bytes. Reporting one number would force the model to
   * compare quantities in different units without being told, and
   * `AttachmentMeta.sizeBytes`'s docstring is emphatic about what that does to a
   * user reading about their own file.
   */
  encodedOctets: number;
  /** Whether text was produced. `null` when the part was never fetched. */
  extracted: boolean | null;
  /** Whether the extracted-text ceiling cut it. `null` when nothing was read. */
  truncated: boolean | null;
  /** Why there is no text, or `null`. Four values across two layers. */
  refusal: string | null;
  /** The ceiling that refusal exceeded, or `null`. See `encodedOctets`. */
  limitBytes: number | null;
  /** The document's text, or `null`. Stranger-authored. */
  text: string | null;
  /** The sender's filename, or `null`. Stranger-authored. */
  filename: string | null;
  /** The declared media type. Sender-declared, so stranger-authored. */
  mimeType: string;
}

/**
 * Shape one attachment read into the tool's response.
 *
 * **The extracted text goes INSIDE the fence, and PITFALLS #12 names this case
 * explicitly:** text pulled out of a PDF attachment carries the same risk as
 * email body text and gets the same framing. It is the higher-risk half of that
 * pair if anything — a message body arrives in a listing the user is at least
 * skimming, whereas an attachment's contents reach the model only after an
 * explicit call and read as a document rather than as correspondence. The
 * sender's `filename` and declared `mimeType` join it, on the same footing they
 * already sit on inside `mail_get_message`'s attachment rows.
 *
 * The trusted half is this server's own work throughout: an id it was given
 * back, two sizes the server read off the protocol, and three statements about
 * what this server did or declined to do. `refusal` in particular belongs
 * outside the fence for the reason `unsupportedCharset` records: it is the field
 * that keeps the error vocabulary closed at four values, so framing it as a
 * stranger's claim would undercut the whole reason it exists.
 *
 * **No raw bytes on either half** (T-04-07-05). `AttachmentReport` has no
 * bytes-typed field at all, so the property is the typechecker's rather than
 * this function's.
 *
 * Exported for the reason recorded three times above in this file: the
 * containment assertions are WALKS, and a walk over a test-local copy of this
 * mapping proves nothing about the mapping that ships.
 */
export function attachmentToolResult(report: AttachmentReport): ToolResult {
  return untrustedToolResult(
    {
      id: report.id,
      sizeBytes: report.sizeBytes,
      encodedOctets: report.encodedOctets,
      extracted: report.extracted,
      truncated: report.truncated,
      refusal: report.refusal,
      limitBytes: report.limitBytes,
    },
    {
      text: report.text,
      filename: report.filename,
      mimeType: report.mimeType,
    },
  );
}

/**
 * The name a staged object takes when the sender declared none.
 *
 * A default rather than a refusal, and the difference matters: a part with no
 * declared filename is ordinary — an inline image, a calendar invitation — and
 * it is still a real file the user asked for. The caller can rename at staging
 * time, which is the better answer than either refusing or inventing something
 * that looks specific.
 */
const DEFAULT_STAGED_FILENAME = "attachment";

/**
 * The most staged files one draft may carry.
 *
 * **DERIVED, not chosen**, and the derivation is the reason the number may not
 * be raised casually. `MAX_STAGED_FILE_BYTES` bounds ONE file at 4 MiB, and its
 * docstring does the isolate arithmetic for exactly one — "six times four
 * mebibytes is about 25 MB against a 128 MB isolate" — and then never
 * multiplies by an attachment count, because until this constant existed there
 * was nothing to multiply by. Without a cap here that per-file ceiling bounds
 * nothing at all: the resolver reads every id it is given.
 *
 * Three, because three times the per-file cap is 12 MiB, which is exactly
 * `MAX_APPEND_LITERAL_BYTES`. That equality is the whole point rather than a
 * coincidence to note. It makes the peak allocation STATICALLY bounded by a
 * ceiling the builder already enforces, so no running total has to be carried
 * through the read loop and no second refusal has to be invented for it —
 * D-35's closed error vocabulary stays closed. Raising this constant breaks
 * that equality and puts the peak above the ceiling the message is measured
 * against, which is a decision about the isolate rather than a limit on a tool.
 *
 * Three is also far above the case this project exists to serve: a resume and a
 * job description is two.
 *
 * **The refusal belongs at the SCHEMA**, before the handler runs and before a
 * single object is read, which makes an over-long list cost nothing — the same
 * reasoning `searchTerm` gives for refusing a null byte there rather than in
 * the service layer.
 */
export const MAX_ATTACHMENTS_PER_DRAFT = 3;

/**
 * Every refusal the staging tool can report, from BOTH layers.
 *
 * The staging module decides the first three; the mail service decides
 * `part-too-large`, before it writes a fetch line for a part it has already
 * judged too large to ask for. They are unioned here rather than merged into one
 * vocabulary because the two layers refuse for genuinely different reasons and
 * against genuinely different ceilings — one is a decoded file size, the other a
 * wire octet count — and flattening them would make the two numbers that travel
 * with a refusal ambiguous about their units.
 *
 * **`not-base64` is declared HERE rather than in the staging module**, and the
 * boundary is the point: that module takes bytes and knows nothing about how
 * they were transported, so a transport-encoding failure is not a refusal it
 * could ever return. Declaring it there would put a member in a union that its
 * own code cannot produce, which reads as dead code to the next person through.
 *
 * The union stays CLOSED. A free-text reason field was the obvious alternative
 * and is exactly what D-35's closed vocabulary exists to refuse: a sentence is a
 * thing the model has to parse, and a closed set is a thing it can branch on.
 */
export type StageToolRefusal =
  | StageRefusal
  | ConfirmRefusal
  | "part-too-large"
  | "not-base64";

/** What one staging attempt produced, across both layers. */
export type StageOutcome =
  | Extract<StageResult, { staged: true }>
  | {
      staged: false;
      refusal: StageToolRefusal;
      sizeBytes: number;
      limitBytes: number;
    };

/**
 * What one staging attempt produced, before the fence splits it.
 *
 * Every field is nullable on some path, for `AttachmentReport`'s reason rather
 * than out of laziness: a refusal has no identifier and no expiry, and reporting
 * an empty string or a zero there would be a claim this server cannot make.
 * `null` says "this question was not reached", which is the true answer.
 */
export interface StageReport {
  /**
   * Which branch ran.
   *
   * Named `stagedFrom` rather than `source`, and not for taste: the standing
   * no-body key walk treats `source` as a body-shaped field name across every
   * list response in this module, so publishing one here would either fail that
   * gate or force it to grow an exception. The INPUT parameter keeps D-80's
   * spelling, because a schema key is not walked by that gate and the model
   * reads it as the discriminator.
   */
  stagedFrom: "message" | "bytes" | "presigned";
  /** Whether bytes reached the bucket. */
  staged: boolean;
  /** The opaque staged id, or `null` on a refusal. */
  id: string | null;
  /** The decoded size that was written, or that was offered and refused. */
  sizeBytes: number;
  /** When the id stops decoding, or `null` on a refusal. */
  expiresAt: string | null;
  /** Why nothing was staged, or `null`. From a closed set across two layers. */
  refusal: string | null;
  /** The ceiling that refusal exceeded, or `null`. */
  limitBytes: number | null;
  /** The filename as OFFERED, never as stored. Stranger- or caller-authored. */
  filename: string | null;
  /** The declared media type. Declared, never verified, so untrusted. */
  mimeType: string | null;
}

/**
 * Shape one staging attempt into the tool's response.
 *
 * **No bytes on either half, and the type is what holds it** (T-04-08 mirrors
 * `AttachmentReport`'s T-04-07-05 here): `StageReport` has no bytes-typed field
 * at all, so the property is the typechecker's rather than this function's. That
 * matters more on this path than on any other in the phase, because staging is
 * the one operation that HOLDS a whole file — and the entire reason the
 * from-message ingress exists is that not one of those bytes crosses the
 * transcript.
 *
 * The trusted half is this server's own work throughout: which branch it ran, a
 * token it minted, a size it measured, an instant it computed, and a refusal it
 * decided. `refusal` and `limitBytes` in particular sit outside the fence for the
 * reason the charset field records: they are the fields that keep the error
 * vocabulary closed at four values, so framing them as a stranger's claim would
 * undercut the whole reason they exist.
 *
 * The untrusted half is the offered filename and the declared media type. Both
 * are sender-authored on the message ingress; both are caller-authored on the
 * inline one, and they stay inside the fence there too, for the reason
 * `composeToolResult` already records about echoed caller text: an echo is not
 * this server's claim about anything.
 *
 * **The filename reported is the one that was OFFERED, not the sanitised name
 * the object was stored under.** Publishing the sanitised name would be the more
 * informative answer and is deliberately not given: it is derived from the
 * untrusted original and shares most of its characters, so it would carry
 * stranger-authored text into the trusted block through a derivation — exactly
 * the leak the containment walk exists to catch, arriving by a route that looks
 * like server-derived data. The sanitised name is inside the opaque id, where
 * the model cannot read it and does not need to.
 *
 * Exported for the reason recorded four times above in this file: the
 * containment assertions are WALKS, and a walk over a test-local copy of this
 * mapping proves nothing about the mapping that ships.
 */
export function stageToolResult(report: StageReport): ToolResult {
  return untrustedToolResult(
    {
      stagedFrom: report.stagedFrom,
      staged: report.staged,
      id: report.id,
      sizeBytes: report.sizeBytes,
      expiresAt: report.expiresAt,
      refusal: report.refusal,
      limitBytes: report.limitBytes,
    },
    {
      filename: report.filename,
      mimeType: report.mimeType,
    },
  );
}

/**
 * What one request for an upload grant produced.
 *
 * A SIBLING of `StageReport` rather than a widening of it, and the divergence is
 * real rather than stylistic: the other two ingresses answer "here is the file,
 * staged", and this one answers "here is where to put it". There is no
 * identifier yet, no observed size, and no object — reporting `id: null` and
 * `staged: false` on a call that succeeded perfectly would describe a grant as a
 * failed stage.
 *
 * **This is the second half of the cost D-80 recorded when it departed from
 * D-17.** That decision accepted a three-way discriminated union on the INPUT
 * and said plainly that, because one of the three branches returns an upload URL
 * rather than a ready staged id, the OUTPUT would be a union too. This type is
 * that sentence. It is the recorded consequence of a decision rather than an
 * inconsistency, which is why it is written down here rather than smoothed over.
 */
export interface UploadGrantReport {
  /** Which branch ran. Always the presigned one. */
  stagedFrom: "presigned";
  /** Whether a grant was minted at all. */
  granted: boolean;
  /** The signed URL, or `null` on a refusal. */
  uploadUrl: string | null;
  /** The opaque ticket the confirm tool takes back, or `null` on a refusal. */
  uploadId: string | null;
  /** How long the URL stays usable, or `null` on a refusal. */
  expiresInSeconds: number | null;
  /** The size that was DECLARED. Nothing has been observed at this point. */
  sizeBytes: number;
  /** Why no grant was minted, or `null`. From the same closed set. */
  refusal: string | null;
  /** The ceiling that refusal exceeded, or `null`. */
  limitBytes: number | null;
  /** The name as offered. Caller-authored, so untrusted. */
  filename: string | null;
  /** The declared media type. Declared, never verified, so untrusted. */
  mimeType: string | null;
  /**
   * The offered name, percent-encoded exactly as the signed metadata header
   * requires it.
   *
   * Reported because the signature covers every header, so the uploading client
   * has to reproduce this value character for character — and working out an
   * encoding by hand is the one part of the contract a person or a model will
   * plausibly get wrong. It is a derivation of caller-authored text, so it sits
   * inside the fence beside the value it was derived from.
   */
  encodedFilename: string | null;
}

/**
 * Shape one upload grant into the tool's response.
 *
 * **The minted URL sits in the TRUSTED half, and the argument for that is a
 * property of the key rather than a judgement about the URL.** A value this
 * server generated belongs outside the fence — that is the same footing every
 * token and every measured size in this module sits on. What would undo it is
 * the key inside the URL's path: 04-08 established that a sanitised derivative
 * of untrusted text must not be published in the trusted block, because it
 * shares most of its characters with the original and arrives looking like
 * server-derived data. `presignedKeyFor` is what makes the argument hold — the
 * key on this path carries a user segment taken from the signed-in principal,
 * a fixed stem, random bytes and a timestamp, and not one character of anything
 * a caller supplied.
 *
 * The user segment was added in Phase 10 and it changes the enumeration above
 * without changing the argument: the id comes off the principal through
 * `userIdOf`, so it is server-derived exactly as the other three parts are. The
 * list is kept current because the next person to touch this block will check
 * it rather than re-derive the argument — which is the whole reason the list is
 * written out instead of summarised.
 *
 * Everything the caller offered stays inside the fence: the name, the declared
 * type, and the percent-encoded form of the name. An echo is not this server's
 * claim about anything, which is the reasoning `composeToolResult` already
 * carries for its own echoed subject and recipients.
 *
 * No bytes on either half, and the type is what holds it: `UploadGrantReport`
 * has no bytes-typed field at all. On this path there are no bytes to have —
 * that is the entire reason the path exists.
 */
export function uploadUrlToolResult(report: UploadGrantReport): ToolResult {
  return untrustedToolResult(
    {
      stagedFrom: report.stagedFrom,
      granted: report.granted,
      uploadUrl: report.uploadUrl,
      uploadId: report.uploadId,
      expiresInSeconds: report.expiresInSeconds,
      sizeBytes: report.sizeBytes,
      refusal: report.refusal,
      limitBytes: report.limitBytes,
    },
    {
      filename: report.filename,
      mimeType: report.mimeType,
      encodedFilename: report.encodedFilename,
    },
  );
}

/**
 * Mint one upload grant, or refuse before any credential is read.
 *
 * **The size is decided against the per-file cap HERE, at mint time, and that is
 * what makes an oversized upload unmintable rather than merely refusable.** The
 * signature binds an EXACT length — not a range, because the bucket's S3 surface
 * implements no post-object operation and so has no policy condition that
 * expresses one — so a caller cannot mint for a size under the cap and then
 * upload a larger file without breaking the signature. The confirm step still
 * observes what actually landed, for the three reasons its own docstring gives.
 *
 * Holds no session and imports nothing that could open one, which is the same
 * structural guarantee `stageAttachmentContent` carries and it is held the same
 * way: by the signature. Minting reaches no network at all — signing is
 * arithmetic — so it spends none of the six-connection budget either.
 */
export async function mintUploadGrant(
  env: Env,
  userId: string,
  input: { filename: string; mimeType: string; sizeBytes: number },
  nowMs: number,
): Promise<UploadGrantReport> {
  const refused = (refusal: StageToolRefusal): UploadGrantReport => ({
    stagedFrom: "presigned",
    granted: false,
    uploadUrl: null,
    uploadId: null,
    expiresInSeconds: null,
    sizeBytes: input.sizeBytes,
    refusal,
    limitBytes: MAX_STAGED_FILE_BYTES,
    filename: input.filename,
    mimeType: input.mimeType,
    encodedFilename: null,
  });

  if (!Number.isSafeInteger(input.sizeBytes) || input.sizeBytes <= 0) {
    return refused("empty");
  }
  if (input.sizeBytes > MAX_STAGED_FILE_BYTES) {
    return refused("too-large");
  }

  const key = presignedKeyFor(userId, nowMs);
  if (key === null) throw new ImapNotFoundError();

  const grant = {
    key,
    contentType: input.mimeType,
    contentLength: input.sizeBytes,
    filename: input.filename,
  };

  return {
    stagedFrom: "presigned",
    granted: true,
    uploadUrl: await mintUploadUrl(env, userId, grant),
    // The ticket's expiry is a day out rather than the URL's fifteen minutes,
    // because it bounds the CONFIRM rather than the write — and confirm carries
    // that instant forward as the ceiling on the identifier it mints, which is
    // what keeps D-82's ordering true across the gap this ingress opens.
    uploadId: encodeUploadId({ key, expiresAt: nowMs + STAGED_ID_TTL_MS }, nowMs),
    expiresInSeconds: UPLOAD_URL_TTL_SECONDS,
    sizeBytes: input.sizeBytes,
    refusal: null,
    limitBytes: null,
    filename: input.filename,
    mimeType: input.mimeType,
    // From the one definition, so the value reported and the value signed cannot
    // drift apart into an unexplainable rejection from storage.
    encodedFilename: uploadHeadersFor(grant)["x-amz-meta-filename"],
  };
}

/**
 * Copy an already-fetched attachment into the staging bucket.
 *
 * **This function cannot run inside a mail session, and that is structural
 * rather than conventional.** It takes an `AttachmentContent` that has already
 * been resolved, holds no session and no gate, and imports nothing that could
 * open one — so there is no value a caller can pass that puts a storage round
 * trip inside a conversation with iCloud. The ordering ARCHITECTURE.md states
 * for the read direction, applied symmetrically to the write direction, is
 * therefore a property of the shape rather than a rule somebody has to remember.
 *
 * The reason is the connection budget, and `STATE.md` states it precisely: the
 * production six-connection cap counts object storage against the same six slots
 * as sockets, outbound requests and cache reads, and the OAuth provider has
 * already spent one of them on every authenticated request before any mail code
 * runs. `wrangler dev` does not enforce that cap, so nothing fails locally when
 * the ordering is wrong — which is why it is held by this signature, by the
 * ordering assertion in `test/staging.test.ts`, and by review, rather than by a
 * failing test.
 *
 * Three refusals, in this order and for this reason:
 *
 *   1. A part the service declined to fetch. Reported as a staging refusal
 *      rather than raised, so the four-value vocabulary stays closed.
 *   2. A part whose DECLARED decoded size is over the per-file cap. Decided on
 *      the declared number, so the refusal precedes the decode rather than
 *      following it — decoding several megabytes in order to discover they are
 *      several megabytes is work with a known answer.
 *   3. Everything the staging module itself decides, which it decides again on
 *      the real byte count. The declared number is the server's own, from its
 *      own structure reply, and it is still not the number the object is
 *      written against.
 */
export async function stageAttachmentContent(
  env: Env,
  userId: string,
  content: AttachmentContent,
  filenameOverride: string | null,
  nowMs: number,
): Promise<StageOutcome> {
  if (!content.fetch.fetched) {
    return {
      staged: false,
      refusal: content.fetch.refusal,
      // The wire count, because that is the ceiling this refusal was decided
      // against. Reporting the decoded size beside a wire limit would ask the
      // model to compare two quantities in different units without saying so.
      sizeBytes: content.fetch.encodedOctets,
      limitBytes: content.fetch.limitBytes,
    };
  }

  if (content.sizeBytes > MAX_STAGED_FILE_BYTES) {
    return {
      staged: false,
      refusal: "too-large",
      sizeBytes: content.sizeBytes,
      limitBytes: MAX_STAGED_FILE_BYTES,
    };
  }

  // Outside the session, always. The decode is megabytes of arithmetic and the
  // per-call deadline races only the session callback, so spending it here costs
  // nothing and spending it there would hold a socket open for it.
  return putStaged(env, userId, {
    bytes: transferDecode(content.fetch.bytes, content.encoding),
    filename: filenameOverride ?? content.filename ?? DEFAULT_STAGED_FILENAME,
    mimeType: content.mimeType,
    limitBytes: MAX_STAGED_FILE_BYTES,
    nowMs,
  });
}

/** The base64 alphabet, with at most two characters of padding. */
const BASE64_PAYLOAD = /^[A-Za-z0-9+/]*={0,2}$/;

/** What a file with no declared type is recorded as. Says nothing about it. */
const DEFAULT_INLINE_MEDIA_TYPE = "application/octet-stream";

/** One file handed over inside a tool argument. */
export interface InlineStageInput {
  /** The base64 payload, as it arrived. Whitespace tolerated. */
  base64: string;
  /** The name to stage under. Caller-authored, so untrusted. */
  filename: string;
  /** The declared media type, or `null` when the caller named none. */
  mimeType: string | null;
}

/**
 * Stage a file handed over as base64 inside the tool call.
 *
 * **Bounded by `MAX_INLINE_BASE64_BYTES` and NOT by the per-file cap**, because
 * the binding constraint on this path is the model's context rather than the
 * isolate's heap. Base64 inflates by a third, so a 400 KB file arrives as
 * roughly 533 KB of text in a single tool argument — roughly a hundred and fifty
 * thousand tokens, spent before this server has done anything at all. The other
 * ingress exists precisely so that a real file never has to travel this way.
 *
 * **The declared length is read before the decode allocates.** The encoded
 * length determines the decoded size exactly, so an over-cap payload is refused
 * without materialising it. That ordering is observable rather than internal: a
 * payload that is both over the cap and not valid base64 comes back
 * `too-large`, which is the answer only an implementation that measured first
 * can give.
 *
 * **The declared type is metadata, never a gate.** It is caller-authored here
 * and sender-authored on the other path; nothing branches on it, and it is
 * reported as declared rather than as verified — the same footing
 * `AttachmentMeta.mimeType`'s shipped docstring already puts it on. Sniffing
 * content to check it would be a new capability with no consumer.
 *
 * The character-at-a-time conversion below is the shape 04-PATTERNS warns
 * against for megabytes, and it is correct at this size and only at this size:
 * the cap is a quarter of a mebibyte, which is two orders of magnitude below
 * where that loop becomes the wrong tool. It is reached only after the cap has
 * already refused anything larger.
 */
export async function stageInlineBytes(
  env: Env,
  userId: string,
  input: InlineStageInput,
  nowMs: number,
): Promise<StageOutcome> {
  const compact = input.base64.replace(/\s+/g, "");

  if (compact.length === 0) {
    return {
      staged: false,
      refusal: "empty",
      sizeBytes: 0,
      limitBytes: MAX_INLINE_BASE64_BYTES,
    };
  }
  if (compact.length % 4 !== 0) {
    return {
      staged: false,
      refusal: "not-base64",
      sizeBytes: 0,
      limitBytes: MAX_INLINE_BASE64_BYTES,
    };
  }

  // The declared size, from the encoded length alone. Before any allocation.
  const padding = compact.endsWith("==") ? 2 : compact.endsWith("=") ? 1 : 0;
  const declaredBytes = (compact.length / 4) * 3 - padding;
  if (declaredBytes > MAX_INLINE_BASE64_BYTES) {
    return {
      staged: false,
      refusal: "too-large",
      sizeBytes: declaredBytes,
      limitBytes: MAX_INLINE_BASE64_BYTES,
    };
  }

  if (!BASE64_PAYLOAD.test(compact)) {
    return {
      staged: false,
      refusal: "not-base64",
      sizeBytes: declaredBytes,
      limitBytes: MAX_INLINE_BASE64_BYTES,
    };
  }

  let binary: string;
  try {
    binary = atob(compact);
  } catch {
    // The caught value is never read, for `assertUnderHome`'s reason one tree
    // over: the input is caller-chosen and a decoder's message quotes it.
    return {
      staged: false,
      refusal: "not-base64",
      sizeBytes: declaredBytes,
      limitBytes: MAX_INLINE_BASE64_BYTES,
    };
  }

  const bytes = new Uint8Array(binary.length);
  for (let at = 0; at < binary.length; at += 1) {
    bytes[at] = binary.charCodeAt(at);
  }

  return putStaged(env, userId, {
    bytes,
    filename: input.filename,
    mimeType: input.mimeType ?? DEFAULT_INLINE_MEDIA_TYPE,
    limitBytes: MAX_INLINE_BASE64_BYTES,
    nowMs,
  });
}

/**
 * Every staged file one compose is attaching, resolved and in hand.
 *
 * The keys travel beside the attachments rather than being re-derived later,
 * because the delete that follows a successful write has to name exactly the
 * objects that were read — re-decoding the ids afterwards would ask the same
 * question twice and could answer it differently if the clock crossed an
 * expiry in between.
 */
export interface StagedAttachments {
  /** The files, in the order their ids were given. */
  attachments: DraftAttachment[];
  /** The bucket keys they came from, in the same order. */
  keys: string[];
  /** Their combined decoded size, before any transfer encoding. */
  totalBytes: number;
}

/**
 * Read every staged file named by an id, or refuse.
 *
 * **This function holds no session and imports nothing that could open one**,
 * which is the same structural guarantee `stageAttachmentContent` above carries
 * and it is held the same way: by the signature. The reason is the connection
 * budget — production allows six simultaneous connections per Worker invocation
 * and counts object storage against the same six slots as sockets, and the
 * OAuth provider has already spent one before any mail code runs. `wrangler
 * dev` does not enforce that cap, so nothing fails locally when the ordering is
 * wrong.
 *
 * **Every id is decoded BEFORE the first read**, in a pass of its own. A stale
 * token or one of the wrong kind is then refused at zero cost, without a
 * round trip against an object it was never going to be allowed to name. The
 * expiry lives inside the decoder rather than here (D-81's first layer), so a
 * caller cannot forget to ask. The distinctness check rides in that same pass
 * for the same reason: a repeat costs nothing to spot and a round trip to
 * discover.
 *
 * **The peak allocation is bounded by a COUNT and a per-file ceiling, and both
 * halves are needed.** `MAX_STAGED_FILE_BYTES` bounds one file; without
 * `MAX_ATTACHMENTS_PER_DRAFT` it bounds nothing in aggregate, because this
 * function reads every id it is handed. Without the distinctness check the
 * count bounds nothing either, because one staged file named N times allocates
 * N copies and is base64-encoded N times over — the cheapest attack on this
 * path, since it needs one 4 MiB upload rather than several. With both, the
 * worst case is three times the per-file cap, which is exactly the ceiling
 * `buildDraft` already measures the assembled message against.
 *
 * **The reads are SERIAL, and a concurrent combinator here would be a bug
 * rather than an optimisation.** The scan rule fires on a combinator wrapped
 * around the session specifically, but the argument behind it — every
 * concurrent operation is a connection slot — applies to the bucket for exactly
 * the same reason, and a serial read of two or three small objects costs
 * nothing worth having.
 *
 * A missing object raises the same refusal an expired token does, and
 * deliberately: from the caller's side "this id has expired" and "the object it
 * named is gone" are the same situation, and the staging module already returns
 * the missing-object answer for a forged key outside its own prefix rather than
 * a distinguishable one. Repeating that check here would be a second rule to
 * drift; relying on it is what keeps the refusal from being an existence
 * oracle.
 */
export async function resolveStagedAttachments(
  env: Env,
  userId: string,
  ids: string[],
  nowMs: number,
): Promise<StagedAttachments> {
  // The schema is where an over-long list is actually refused, and it refuses
  // before this function is reached. This is the same bound restated for a
  // caller that did not come through MCP — the function is exported, so the
  // schema is not the only door, and a count bound that only one of two
  // entrances holds is a count bound that will eventually be walked around.
  if (ids.length > MAX_ATTACHMENTS_PER_DRAFT) throw new ImapNotFoundError();

  // Pass one: decode everything, and refuse a repeat. Nothing is read until
  // every token is good and every key is distinct.
  const keys: string[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const { key } = decodeStagedId(id, nowMs);

    // **A repeat is refused rather than attached twice**, and the refusal is
    // the honest answer rather than the strict one. D-81's delete-on-attach
    // means the first occurrence consumes the object, so the second names bytes
    // that are already gone — attaching the same file to one message twice is
    // never what the caller meant. It is also the cheaper half of this
    // function's memory bound: without it, one 4 MiB file named three times
    // allocates three separate copies and is then base64-encoded three separate
    // times, which is the same peak as three distinct files for none of the
    // cost of staging them.
    if (seen.has(key)) throw new ImapNotFoundError();
    seen.add(key);
    keys.push(key);
  }

  // Pass two: read, one at a time.
  const attachments: DraftAttachment[] = [];
  let totalBytes = 0;
  for (const key of keys) {
    const object = await getStaged(env, userId, key);
    if (object === null) throw new ImapNotFoundError();

    attachments.push({
      // The name the file was STAGED under, which is either the sender's own or
      // the rename the caller supplied at staging time. Untrusted either way;
      // `contentDispositionParams` is what decides whether it can travel.
      //
      // **An EMPTY name is absent, and `??` alone does not say that.** It
      // catches `null` and `undefined` and passes `""` straight through, and an
      // empty string is reachable on the presigned ingress: the stage schema's
      // refinement only required the field to be present,
      // `uploadHeadersFor` encodes `""` to `""`, and confirm reports it back.
      // `contentDispositionParams` then returns the empty string for it, so the
      // part shipped as a bare `Content-Disposition: attachment` with no
      // filename parameter at all — a file arriving at the recipient unnamed.
      // That function's docstring says "the caller supplies a default before
      // reaching here", and this is the caller.
      filename:
        object.filename === null || object.filename.length === 0
          ? DEFAULT_STAGED_FILENAME
          : object.filename,
      // Declared at stage time and never verified, which is the footing the
      // builder puts it on too.
      mimeType: object.mimeType,
      content: object.bytes,
    });
    totalBytes += object.sizeBytes;
  }

  return { attachments, keys, totalBytes };
}

/**
 * Remove the staged objects a successful write consumed. D-81's second layer.
 *
 * **D-81 is THREE layers that fail differently, and all three are named here so
 * a later reader does not remove one believing another covers it.** The staged
 * identifier carries its own expiry and is refused at compose once past it; the
 * object is deleted the moment a compose successfully writes it into the drafts
 * folder; and the bucket's own prefix-scoped lifecycle rule sweeps whatever was
 * abandoned. Defence in depth against different failures, not three spellings
 * of one idea: the first covers a token that leaked into a transcript, the
 * second covers ordinary use, and the third covers everything nobody came back
 * for.
 *
 * **Two ordering rules, and both are the kind a later reader "fixes".**
 *
 * 1. **A write that failed must not delete.** On the presigned ingress the
 *    staged bytes are the only copy, and losing them means re-uploading a file
 *    the user already uploaded once. `appended` is the server's own report, and
 *    nothing else decides it.
 * 2. **A delete that fails AFTER a successful write must not fail the tool
 *    call.** The write happened. The draft is real and sitting in the user's
 *    Drafts folder, and turning a failed cleanup into a failed tool call would
 *    tell the user their draft does not exist. The lifecycle rule is the
 *    backstop for exactly this case, which is what makes swallowing the failure
 *    correct rather than sloppy — **and this paragraph is here because a
 *    swallowed error is the single most likely thing in this phase to be
 *    "corrected" by a reader who has not read D-81.**
 *
 * The swallowed value is never inspected, never logged — there are no logging
 * calls under this tree and there must not be — and gets no error category of
 * its own. D-35's vocabulary stays at four.
 *
 * The loop continues past a failure rather than stopping at it, so one declined
 * delete does not leave every later object for the sweep as well.
 *
 * **D-81's accepted cost, recorded where the delete happens:** the same staged
 * file cannot be attached to two drafts, because the first attach consumes it.
 * Staging it twice is the workaround, and the compose tools say so. That is
 * foreclosed deliberately rather than by oversight.
 */
export async function releaseStagedAttachments(
  env: Env,
  userId: string,
  keys: string[],
  appended: boolean,
): Promise<void> {
  if (!appended) return;

  for (const key of keys) {
    try {
      await deleteStaged(env, userId, key);
    } catch {
      // Deliberately swallowed. See rule 2 above before changing this.
    }
  }
}

/** What one compose produced, across the three steps it is made of. */
export interface DraftComposition {
  /** The assembled bytes, or the stated reason there are none. */
  built: BuildResult;
  /**
   * What the write reported, or `null` when the build refused first.
   *
   * **`null` exactly when `built.built` is false, and that pairing is a
   * convention rather than a type.** `built` is an object, so it cannot serve
   * as a discriminant TypeScript will narrow this interface on — which means a
   * caller that has checked `built.built` still holds `AppendOutcome | null`
   * here, and the tempting fix is a cast that throws the nullable away. Both
   * compose handlers check the nullable itself instead. A third early return
   * added to `composeWithAttachments` is therefore a safe change rather than a
   * silent `TypeError` at two call sites.
   */
  outcome: AppendOutcome | null;
  /** The staged ids consumed. Empty unless the write reported success. */
  consumed: string[];
  /** How many files travelled with the draft. */
  attachedCount: number;
  /** Their combined decoded size. */
  attachedBytes: number;
}

/**
 * The whole compose lifecycle, in the one order it is allowed to happen in.
 *
 * Decode, read, assemble, open the session, write, close, delete. Both compose
 * tools route through here rather than each keeping their own copy of the
 * sequence, because the ordering is the correctness and a second copy is a
 * second place for it to be subtly different.
 *
 * **Every storage operation sits outside the session** — the reads before it
 * opens and the deletes after it has closed — which is what keeps the
 * login-write-logout exchange tight and what stops one tool call spending the
 * six-slot per-invocation connection budget twice over. `append` is injected
 * rather than called directly so the session boundary is a value this function
 * can see the edges of, and so the ordering is assertable against a recorded
 * exchange rather than against timing.
 *
 * The size ceiling is checked by `build` itself, with the attachments already
 * folded in, and its refusal returns before `append` is ever called — so a set
 * of individually legal files that together exceed the message ceiling costs no
 * connection at all. That is the difference between this server's stated
 * refusal in the same response as the request and Apple's silent rejection
 * hours later in Mail.app, with nothing connecting it to the call that caused
 * it.
 *
 * A raise from `append` propagates untouched, and the release below is
 * therefore never reached — which is the correct disposition rather than an
 * accident: a write this server could not confirm is a write that must not
 * consume anything.
 */
export async function composeWithAttachments(
  env: Env,
  userId: string,
  attachmentIds: string[],
  build: (attachments: DraftAttachment[]) => BuildResult,
  append: (message: Uint8Array) => Promise<AppendOutcome>,
  nowMs: number,
): Promise<DraftComposition> {
  const staged = await resolveStagedAttachments(
    env,
    userId,
    attachmentIds,
    nowMs,
  );
  const attached = {
    attachedCount: staged.attachments.length,
    attachedBytes: staged.totalBytes,
  };

  const built = build(staged.attachments);
  if (!built.built) {
    return { built, outcome: null, consumed: [], ...attached };
  }

  const outcome = await append(built.bytes);
  await releaseStagedAttachments(env, userId, staged.keys, outcome.appended);

  return {
    built,
    outcome,
    consumed: outcome.appended ? attachmentIds : [],
    ...attached,
  };
}

/**
 * A free-text search term, refused at the SCHEMA if it carries a null byte.
 *
 * This is not general input hygiene — it is the one character that cannot be
 * sent at all. `CHAR8 = %x01-ff` excludes NUL from an IMAP literal, and NUL is
 * outside the quotable range too, so there is no path to the wire for it. CR
 * and LF are deliberately NOT refused: they are legal inside a literal, which
 * is precisely what literals are for, so unlike on the credential path there is
 * nothing here to guard against.
 *
 * Refused at the schema means refused before the handler runs, which means
 * refused before a socket is opened — the cheapest possible refusal, and the
 * one that spends none of the connection budget. The service layer repeats the
 * check for callers that do not come through MCP.
 */
const searchTerm = z
  .string()
  .refine((value) => !value.includes("\u0000"), {
    message: "must not contain a null byte",
  })
  .optional();

/**
 * A calendar day, as `YYYY-MM-DD`.
 *
 * The pattern rejects the shapes a model most plausibly produces — `1 Feb 2026`
 * and `2026-2-1` — at the boundary rather than several round trips later. It
 * does not check that the day exists in its month; `parseIsoDay` in the service
 * layer does that, because a round-trip check is the only reliable way to catch
 * `2026-02-31` and it belongs beside the arithmetic it protects.
 */
const isoDay = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "expected YYYY-MM-DD")
  .optional();

/**
 * The staged files to attach, shared by both compose registrations.
 *
 * One constant rather than two literals, for the reason the search term above
 * is one: a description written twice is a description that will eventually
 * disagree with itself, and the model would be acting on whichever copy nobody
 * updated.
 *
 * **The description states that a staged file attaches ONCE, and that sentence
 * is load-bearing rather than informative.** D-81's delete-on-attach makes
 * attaching the same staged file to two drafts impossible by design; staging it
 * twice is the workaround. Without the sentence the model retries with a spent
 * id, meets a not-found, and has no way to tell that from a typo.
 *
 * **`.max` is a memory bound, not an ergonomic one.** See
 * `MAX_ATTACHMENTS_PER_DRAFT` for the arithmetic it comes from. Refusing at the
 * schema means refusing before the handler runs, which means before any object
 * is read — an over-long list costs nothing.
 */
const attachmentIdList = z
  .array(z.string())
  .max(MAX_ATTACHMENTS_PER_DRAFT)
  .optional()
  .describe(
    `Opaque staged ids from mail_stage_attachment, at most ${MAX_ATTACHMENTS_PER_DRAFT}. ` +
      "Each staged file attaches ONCE: a successful draft consumes it, so " +
      "attaching the same file to a second draft means staging it again. " +
      "Naming the same id twice in one draft is refused rather than " +
      "attaching it twice. They expire 24 hours after staging.",
  );

/**
 * The wire mailbox name a folder token names, or the Inbox when none was given.
 *
 * Decoded here, before the socket, so a malformed or foreign token is refused
 * without spending any of the connection budget. The default is the one
 * mailbox name RFC 3501 mandates — see `DEFAULT_MAILBOX` for why that is not
 * the model constructing a wire name.
 */
function resolveMailbox(folderId: string | undefined): string {
  return folderId === undefined ? DEFAULT_MAILBOX : decodeFolderId(folderId).mailbox;
}

/**
 * The fixed sentence a read-only refusal carries. Plain ASCII.
 *
 * It says what happened, that nothing changed, and that trying again will not
 * help. The last part matters most: without it a model reads a refusal as a
 * passing fault and retries.
 */
const READ_ONLY_REASON =
  "iCloud opened this folder read-only, so nothing was changed. " +
  "Retrying will not help.";

/**
 * The fixed sentence an unconfirmed change carries. Plain ASCII.
 *
 * iCloud accepted the change and then would not say what the flag is now. The
 * sentence says both, so the `state` beside it is not read as iCloud's word,
 * and it says that asking again is safe. It is: setting a flag that is already
 * set changes nothing, and the next answer reports iCloud's own state.
 */
const UNCONFIRMED_NOTE =
  "iCloud accepted the change but did not report the read state afterwards, " +
  "so state is what was asked for, not what iCloud said. Calling again with " +
  "the same value is safe and reports iCloud's own answer.";

/**
 * The answer to marking one message read or unread.
 *
 * Plain JSON, not the untrusted fence. Every field is this server's own: the id
 * the caller passed, which decoded as a well-formed id (strict base64url, so it
 * cannot carry a sentence); the boolean the caller chose; and what iCloud
 * reported. No stranger-authored text reaches this answer.
 *
 * The id is NOT signed. Any caller can build one that decodes, for any mailbox
 * and uid in the signed-in account. The server checks its shape when it
 * decodes it, and checks its folder's validity when the mailbox opens. Neither
 * check says where the id came from. What stands between a prompt-injected
 * message and a mark-read is the instructions line "Change read status only
 * when the user asks", not the id's origin.
 *
 * `state` is what iCloud said after the change, and it can differ from
 * `requested`. When it does, the answer shows both, so nobody reads the request
 * as the result (PITFALLS #33). `stateSource` says which reply that came from.
 *
 * One exception, and it is labelled. When iCloud accepted the change but then
 * would not report the flag, `stateSource` is `unconfirmed`, `state` is the
 * request, and a fixed `note` says exactly that. It is not `not_found`: the
 * message was there and was just changed.
 *
 * Neither arm is `isError`, following the `AppendOutcome` precedent: a
 * read-only folder is a successful call that reports a stated reason.
 */
export function readStateToolResult(
  id: string,
  requestedRead: boolean,
  outcome: ReadStateOutcome,
): ToolResult {
  const requested = requestedRead ? "read" : "unread";
  let body: Record<string, string>;
  if (!outcome.applied) {
    body = {
      id,
      requested,
      refusal: outcome.refusal,
      reason: READ_ONLY_REASON,
    };
  } else if (outcome.source === "unconfirmed") {
    body = {
      id,
      requested,
      state: requested,
      stateSource: outcome.source,
      note: UNCONFIRMED_NOTE,
    };
  } else {
    body = {
      id,
      requested,
      state: outcome.seen ? "read" : "unread",
      stateSource: outcome.source,
    };
  }
  return { content: [{ type: "text", text: JSON.stringify(body) }] };
}

/**
 * The fixed sentence a flag-not-kept refusal carries. Plain ASCII.
 *
 * The folder opened for changing, but iCloud said the flag would not last past
 * this session. It says that, that nothing changed, and that retrying will not
 * help, for `READ_ONLY_REASON`'s reason.
 */
const FLAG_NOT_KEPT_REASON =
  "iCloud said this folder does not keep the flag past the session, so " +
  "nothing was changed. Retrying will not help.";

/**
 * The fixed sentence an unconfirmed flag change carries. Plain ASCII.
 *
 * `UNCONFIRMED_NOTE`'s meaning, for the flagged flag.
 */
const FLAG_UNCONFIRMED_NOTE =
  "iCloud accepted the change but did not report the flag afterwards, so " +
  "state is what was asked for, not what iCloud said. Calling again with the " +
  "same value is safe and reports iCloud's own answer.";

/**
 * The answer to flagging or unflagging one message.
 *
 * `readStateToolResult`'s shape and reasons, for the flagged flag. `state` is
 * what iCloud said after the change and can differ from `requested`; an
 * unconfirmed change says so in a fixed `note`. Every field is this server's
 * own, and neither arm is `isError`.
 */
export function flagStateToolResult(
  id: string,
  requestedFlagged: boolean,
  outcome: FlagStateOutcome,
): ToolResult {
  const requested = requestedFlagged ? "flagged" : "unflagged";
  let body: Record<string, string>;
  if (!outcome.applied) {
    body = {
      id,
      requested,
      refusal: outcome.refusal,
      reason:
        outcome.refusal === "flag-not-kept" ? FLAG_NOT_KEPT_REASON : READ_ONLY_REASON,
    };
  } else if (outcome.source === "unconfirmed") {
    body = {
      id,
      requested,
      state: requested,
      stateSource: outcome.source,
      note: FLAG_UNCONFIRMED_NOTE,
    };
  } else {
    body = {
      id,
      requested,
      state: outcome.flagged ? "flagged" : "unflagged",
      stateSource: outcome.source,
    };
  }
  return { content: [{ type: "text", text: JSON.stringify(body) }] };
}

// ---------------------------------------------------------------------------
// Moving mail: the preview and the mail commit (Phase 21, D-02, D-05, D-09)
//
// A move is previewed first and applied only by `mail_commit` with the
// preview's confirmation, passed back unaltered. The preview reads on the read
// path and writes nothing. The commit checks the confirmation fully, claims its
// one-time slot, and makes one verb call. This module never imports the
// mutating orchestrator; the verbs come from `../../mail/triage`.
// ---------------------------------------------------------------------------

/**
 * Run something that may raise the NEUTRAL confirmation refusal, and translate.
 *
 * The mail tree's copy of calendar's boundary, for the same reason:
 * `toErrorCategory` dispatches on TYPE, and a neutral refusal that escaped
 * untranslated would reach the model as a failed connection. Wrapped around the
 * preview's mint as well as the commit, because minting raises the same class
 * when the signing key is unusable. Nothing is read off the caught value.
 */
async function withMailConfirmationBoundary<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof ConfirmationInvalidError) throw new MailConfirmationError();
    throw err;
  }
}

/** The mail-arm fields a preview supplies; the rest are filled in here. */
type MailConfirmationFields = Omit<MailConfirmPayload, "v" | "t" | "j" | "x" | "u">;

/**
 * Mint a mail confirmation for the signed-in person.
 *
 * Fills the version, the target, a fresh single-use id, an absolute expiry and
 * the principal's own id, and signs with the Worker's confirmation key. The
 * user id comes from the principal and from nothing else.
 */
async function mintMailConfirmation(
  actor: Principal,
  fields: MailConfirmationFields,
): Promise<string> {
  return mintConfirmation(
    {
      v: CONFIRM_VERSION,
      t: "mail",
      j: crypto.randomUUID(),
      x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
      u: actor.userId,
      ...fields,
    },
    env.CONFIRM_SECRET,
  );
}

/** The fixed reason for each move refusal. ASCII, and no server text. */
const MOVE_REFUSAL_REASONS = {
  "too-many": `A move takes at most ${MOVE_SET_CAP} messages. Split the list and preview each part.`,
  "duplicate-ids": "The same message is named more than once. Name each message once.",
  "mixed-folders":
    "The messages are in different folders. One move takes messages from one folder.",
  "messages-not-found": "These messages are no longer in the folder. List the folder again.",
  "already-marked-for-removal":
    "These messages are already marked for removal by another app. Moving them would " +
    "carry that mark to the copy, where another app could remove it for good.",
  "no-change-numbers":
    "This folder does not report change numbers, so a move cannot be checked against " +
    "later changes. Nothing was moved.",
  "destination-not-found": "The destination folder was not found. List the folders again.",
  "destination-is-source": "The destination is the folder the messages are already in.",
  "destination-not-selectable": "The destination folder cannot hold messages.",
  "mailbox-read-only": "The folder opened read-only, so nothing was moved.",
  "removal-not-kept": "The folder does not keep the mark a move needs, so nothing was moved.",
  "commands-unavailable":
    "iCloud did not offer the commands a safe move needs, so nothing was moved.",
  "changed-since-preview":
    "These messages changed after the preview, so nothing was moved. Preview the move again.",
  "already-in-destination":
    "The messages are already in the folder this would move them to. Nothing was moved.",
} as const;

type MoveRefusal = keyof typeof MOVE_REFUSAL_REASONS;

/**
 * The fixed reasons for the refusals that depend on which role was asked for.
 * ASCII, no server text, and no Trash reason says the mail is gone (D-04).
 */
const ROLE_REFUSAL_REASONS = {
  archive: {
    "no-archive-folder":
      "The account's folder list shows no archive folder, so nothing was moved and no " +
      "folder was guessed. mail_move with a folder id from mail_list_folders moves mail " +
      "to a folder the user names.",
    "ambiguous-role-folder":
      "Two folders both look like the archive folder, so none was picked and nothing was " +
      "moved. mail_move with a folder id from mail_list_folders moves mail to the one the " +
      "user names.",
  },
  trash: {
    "no-trash-folder":
      "The account's folder list shows no Trash folder, so nothing was moved and no " +
      "folder was guessed. mail_move with a folder id from mail_list_folders moves mail " +
      "to a folder the user names.",
    "ambiguous-role-folder":
      "Two folders both look like the Trash folder, so none was picked and nothing was " +
      "moved. mail_move with a folder id from mail_list_folders moves mail to the one the " +
      "user names.",
  },
} as const;

/** A refusal answer: plain JSON, never `isError`. */
function moveRefusalResult(
  refusal: MoveRefusal,
  extra: Record<string, unknown> = {},
): ToolResult {
  return refusalAnswer(refusal, MOVE_REFUSAL_REASONS[refusal], extra);
}

/** A refusal answer with its reason already chosen. Plain JSON, never `isError`. */
function refusalAnswer(
  refusal: string,
  reason: string,
  extra: Record<string, unknown> = {},
): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify({ refusal, reason, ...extra }) }],
  };
}

/**
 * Where a move is going: a folder the caller named, or a role the server
 * resolves from the account's own folder list (archive and Trash, D-03, D-04).
 */
export type MoveDestination =
  | { kind: "folder"; mailbox: string }
  | { kind: "role"; role: "archive" | "trash" };

/** What the caller named, decoded, in the caller's order. */
export interface MoveRequest {
  /** The caller's message ids, verbatim. */
  ids: string[];
  /** The same ids, decoded. All from one folder and one validity. */
  refs: MessageRef[];
  /**
   * The caller's destination id, verbatim. It goes into the change. `null` for
   * a role destination: the caller named no folder, and the change carries the
   * id of the folder the preview resolved instead.
   */
  destinationId: string | null;
}

/**
 * The refusals every move tool gives before any socket opens: too many ids,
 * the same message twice, and messages from more than one folder. `null` when
 * the list passes all three.
 */
function moveListRefusal(ids: readonly string[], refs: readonly MessageRef[]): ToolResult | null {
  if (ids.length > MOVE_SET_CAP) {
    return moveRefusalResult("too-many", { cap: MOVE_SET_CAP });
  }
  const keys = refs.map((ref) => JSON.stringify([ref.mailbox, ref.uidValidity, ref.uid]));
  const repeated = ids.filter((_id, index) => keys.indexOf(keys[index]!) !== index);
  if (repeated.length > 0) {
    return moveRefusalResult("duplicate-ids", { ids: repeated });
  }
  const first = refs[0]!;
  if (
    refs.some((ref) => ref.mailbox !== first.mailbox || ref.uidValidity !== first.uidValidity)
  ) {
    return moveRefusalResult("mixed-folders");
  }
  return null;
}

/** Whether a folder's attributes say it cannot hold messages. */
function isUnselectable(attributes: readonly string[]): boolean {
  return attributes.some((attribute) => {
    const lowered = attribute.toLowerCase();
    return lowered === "\\noselect" || lowered === "\\nonexistent";
  });
}

/**
 * Preview a move: one read session, then a confirmation, and nothing written.
 *
 * The read opens the source read-only, lists the folders and fetches each
 * message's fingerprint with a peek at three headers. Every refusal is a
 * plain-JSON answer. Otherwise the confirmation seals the source folder, its
 * validity, the destination and each message's size, internal date and MODSEQ,
 * in the caller's order.
 *
 * The lease is taken around the one read session and nothing else (Phase 24):
 * it is given back before the confirmation is minted.
 */
export async function buildMovePreview(
  actor: Principal,
  mail: LeasedMail,
  request: MoveRequest,
  destination: MoveDestination,
  op: "move",
): Promise<ToolResult> {
  const first = request.refs[0]!;
  const source = { mailbox: first.mailbox, uidValidity: first.uidValidity };
  const facts = await mail.withConnectionLease(actor, (leased) =>
    readMoveSet(
      actor,
      leased,
      source,
      request.refs.map((ref) => ref.uid),
    ),
  );

  const idOf = new Map(request.refs.map((ref, index) => [ref.uid, request.ids[index]!]));
  const idsFor = (uids: readonly number[]): string[] => uids.map((uid) => idOf.get(uid)!);

  if (facts.missing.length > 0) {
    return moveRefusalResult("messages-not-found", { ids: idsFor(facts.missing) });
  }
  const marked = facts.found.filter((candidate) =>
    candidate.fingerprint.flags.some((flag) => flag.toLowerCase() === "\\deleted"),
  );
  if (marked.length > 0) {
    return moveRefusalResult("already-marked-for-removal", {
      ids: idsFor(marked.map((candidate) => candidate.fingerprint.uid)),
    });
  }
  if (facts.changeNumbers === "unavailable") {
    return moveRefusalResult("no-change-numbers", { ids: [...request.ids] });
  }

  // A folder destination is looked up by its wire name. A role destination is
  // resolved from the SAME listing this read already holds, so it costs no
  // further command, and it refuses rather than guesses (D-03).
  let target: FolderSummary;
  let role: "archive" | "trash" | null;
  if (destination.kind === "folder") {
    const named = facts.listing.folders.find(
      (folder) => folder.wireName === destination.mailbox,
    );
    if (named === undefined) return moveRefusalResult("destination-not-found");
    if (destination.mailbox === source.mailbox) {
      return moveRefusalResult("destination-is-source");
    }
    target = named;
    role = null;
  } else {
    const resolved = resolveRoleFolder(facts.listing, destination.role);
    if ("refusal" in resolved) {
      const reasons = ROLE_REFUSAL_REASONS[destination.role];
      if (resolved.refusal === "ambiguous") {
        return refusalAnswer("ambiguous-role-folder", reasons["ambiguous-role-folder"]);
      }
      return destination.role === "archive"
        ? refusalAnswer("no-archive-folder", ROLE_REFUSAL_REASONS.archive["no-archive-folder"])
        : refusalAnswer("no-trash-folder", ROLE_REFUSAL_REASONS.trash["no-trash-folder"]);
    }
    if (resolved.folder.wireName === source.mailbox) {
      return moveRefusalResult("already-in-destination");
    }
    target = resolved.folder;
    role = destination.role;
  }
  if (isUnselectable(target.attributes)) {
    return moveRefusalResult("destination-not-selectable");
  }

  const byUid = new Map(facts.found.map((candidate) => [candidate.fingerprint.uid, candidate]));
  const l: MailSetEntry[] = request.refs.map((ref) => {
    const fingerprint = byUid.get(ref.uid)!.fingerprint;
    return {
      i: ref.uid,
      z: fingerprint.size,
      d: fingerprint.internalDate,
      n: fingerprint.modSeq,
    };
  });

  const sourceId = encodeFolderId({ mailbox: source.mailbox });
  const destinationId = encodeFolderId({ mailbox: target.wireName });
  const change: NormalizedMailMove = {
    op,
    ids: [...request.ids],
    // A named folder goes back verbatim; a resolved role carries the id of the
    // folder this listing resolved, which is also what the confirmation seals.
    destination: request.destinationId ?? destinationId,
  };

  const confirmToken = await mintMailConfirmation(actor, {
    k: "move",
    h: await mailMoveChangeHashOf(change),
    m: sourceId,
    uv: source.uidValidity,
    q: destinationId,
    qr: role,
    l,
  });

  const sourceFolder = facts.listing.folders.find(
    (folder) => folder.wireName === source.mailbox,
  );
  const sourceName = sourceFolder?.displayName ?? decodeModifiedUtf7(source.mailbox);
  const destinationName = target.displayName;
  const confirmationLine = composeConfirmationLine(
    {
      kind: "move",
      noun: "message",
      from: sourceName,
      to: destinationName,
      role,
      count: l.length,
      outcome: null,
    },
    "would",
  );

  return untrustedToolResult(
    {
      confirmToken,
      expiresInSeconds: CONFIRM_TTL_SECONDS,
      change,
      confirmationLine,
      source: { id: sourceId },
      destination: { id: destinationId, role },
      count: l.length,
    },
    {
      sourceName,
      destinationName,
      messages: request.refs.map((ref, index) => {
        const candidate = byUid.get(ref.uid)!;
        return {
          id: request.ids[index],
          subject: candidate.subject,
          from: candidate.from,
          date: candidate.date,
          size: candidate.fingerprint.size,
        };
      }),
    },
  );
}

/** A mail commit's change, as the schema admits it: a move, or a draft delete. */
export type MailCommitChange =
  | { op: "move"; ids: string[]; destination: string }
  | { op: "draft-delete"; id: string; subject: string | null };

/** What a move commit produced, with the names its answer needs. */
export interface MailCommitApplied {
  op: "move";
  /** The caller's ids, in the caller's order, from the handed-back change. */
  ids: string[];
  outcome: MoveOutcome;
  /** The destination folder id the confirmation sealed. */
  destinationId: string;
  sourceMailbox: string;
  destinationMailbox: string;
  /** The destination's role as the preview resolved it, from the sealed `qr`. */
  role: "archive" | "trash" | null;
}

/** What a draft-delete commit produced, with the names its answer needs. */
export interface DraftDeleteApplied {
  op: "draft-delete";
  /** The caller's draft id, from the handed-back change. */
  id: string;
  /** The subject the preview read, from the handed-back change. */
  subject: string | null;
  outcome: DraftDeleteOutcome;
  /** The Trash folder id the confirmation sealed. */
  trashId: string;
  trashMailbox: string;
}

/**
 * Check a mail confirmation fully, claim its slot, and make one verb call.
 *
 * `applyCommit`'s order, one tree over: verify (seal, version, target, user,
 * expiry); the signed kind and the supplied op; a destination; the change hash;
 * the ids agreeing with the sealed list, position by position; then the
 * reservation; then one call. Every refusal before the reservation is the one
 * `ConfirmationInvalidError`, so none of them spends the slot and none of them
 * says which check failed.
 *
 * The lease (Phase 24) is taken AFTER every check and BEFORE the reservation,
 * and held across the reservation and the one move session. That order is the
 * point. A busy refusal must not spend the confirmation: its sentence says
 * nothing was started or changed, and a spent slot would be a change the user
 * then has to repair with a fresh preview. The reservation is one small
 * storage write, not a session and not staged-file work.
 *
 * A draft delete (Phase 22) takes its own branch, in the same order: kind
 * `delete` and op `draft-delete`; Trash as the sealed role; exactly one sealed
 * entry; the hash in the draft-delete domain; the caller's id agreeing with the
 * sealed folder, validity and UID; then the lease, the reservation and one
 * `deleteDraft` call.
 */
export async function applyMailCommit(
  actor: Principal,
  mail: LeasedMail,
  confirmToken: string,
  change: MailCommitChange,
): Promise<MailCommitApplied | DraftDeleteApplied> {
  const payload = await verifyConfirmation(
    confirmToken,
    env.CONFIRM_SECRET,
    actor.userId,
    "mail",
  );

  // The draft-delete arm (Phase 22, D-06, D-16), in the move arm's order. A
  // delete token is refused as a move and a move token as a delete, by kind
  // and op here and again by hash domain below.
  if (change.op === "draft-delete") {
    if (payload.k !== "delete") throw new ConfirmationInvalidError();
    if (payload.qr !== "trash" || payload.q === null) throw new ConfirmationInvalidError();
    if (payload.l.length !== 1) throw new ConfirmationInvalidError();
    const entry = payload.l[0]!;

    const normalized: NormalizedDraftChange = {
      op: change.op,
      id: change.id,
      subject: change.subject,
    };
    if (!(await changeHashMatches(await draftChangeHashOf(normalized), payload.h))) {
      throw new ConfirmationInvalidError();
    }

    let draftsMailbox: string;
    let trashMailbox: string;
    let ref: MessageRef;
    try {
      draftsMailbox = decodeFolderId(payload.m).mailbox;
      trashMailbox = decodeFolderId(payload.q).mailbox;
      ref = decodeMessageId(change.id);
    } catch {
      throw new ConfirmationInvalidError();
    }
    if (
      ref.mailbox !== draftsMailbox ||
      ref.uidValidity !== payload.uv ||
      ref.uid !== entry.i
    ) {
      throw new ConfirmationInvalidError();
    }

    // The lease after every check and before the reservation, held across
    // the reservation and the one delete session, exactly as the move arm
    // below: a busy refusal never spends the confirmation (C-14).
    const trashId = payload.q;
    const outcome = await mail.withConnectionLease(actor, async (leased) => {
      await reserveConfirmation(env.CONFIRM_KV, actor.userId, payload.j, payload.x);

      return deleteDraft(actor, leased, {
        draftsMailbox,
        uidValidity: payload.uv,
        entry: { uid: entry.i, size: entry.z, internalDate: entry.d, modSeq: entry.n },
        trashMailbox,
      });
    });
    return {
      op: "draft-delete",
      id: change.id,
      subject: change.subject,
      outcome,
      trashId,
      trashMailbox,
    };
  }

  if (payload.k !== "move" || change.op !== "move") {
    throw new ConfirmationInvalidError();
  }
  if (payload.q === null) throw new ConfirmationInvalidError();

  const normalized: NormalizedMailMove = {
    op: change.op,
    ids: [...change.ids],
    destination: change.destination,
  };
  if (!(await changeHashMatches(await mailMoveChangeHashOf(normalized), payload.h))) {
    throw new ConfirmationInvalidError();
  }

  let sourceMailbox: string;
  let destinationMailbox: string;
  try {
    sourceMailbox = decodeFolderId(payload.m).mailbox;
    destinationMailbox = decodeFolderId(payload.q).mailbox;
  } catch {
    throw new ConfirmationInvalidError();
  }

  if (change.ids.length !== payload.l.length) throw new ConfirmationInvalidError();
  for (let index = 0; index < change.ids.length; index += 1) {
    let ref: MessageRef;
    try {
      ref = decodeMessageId(change.ids[index]!);
    } catch {
      throw new ConfirmationInvalidError();
    }
    if (
      ref.mailbox !== sourceMailbox ||
      ref.uidValidity !== payload.uv ||
      ref.uid !== payload.l[index]!.i
    ) {
      throw new ConfirmationInvalidError();
    }
  }

  const outcome = await mail.withConnectionLease(actor, async (leased) => {
    await reserveConfirmation(env.CONFIRM_KV, actor.userId, payload.j, payload.x);

    return moveMessages(
      actor,
      leased,
      { mailbox: sourceMailbox, uidValidity: payload.uv },
      payload.l.map((entry) => ({
        uid: entry.i,
        size: entry.z,
        internalDate: entry.d,
        modSeq: entry.n,
      })),
      destinationMailbox,
    );
  });
  return {
    op: "move",
    ids: [...change.ids],
    outcome,
    destinationId: payload.q,
    sourceMailbox,
    destinationMailbox,
    role: payload.qr,
  };
}

/** The per-message tally a did-tense line is built from. */
function tallyOf(results: readonly MessageMoveResult[]): {
  moved: number;
  copiedNotRemoved: number;
  notCopied: number;
  unknown: number;
} {
  const tally = { moved: 0, copiedNotRemoved: 0, notCopied: 0, unknown: 0 };
  for (const result of results) {
    if (result.outcome === "moved") tally.moved += 1;
    else if (result.outcome === "copied_not_removed") tally.copiedNotRemoved += 1;
    else if (result.outcome === "not_copied") tally.notCopied += 1;
    else tally.unknown += 1;
  }
  return tally;
}

/**
 * The mail commit's answer. Plain JSON; a refusal is not `isError`.
 *
 * Each result carries the caller's id at its position, what happened, why, and
 * the copy's new id when the server's reply proved it. The new id is minted
 * with the DESTINATION's validity from that reply, never the source's.
 */
function mailCommitResult(ids: readonly string[], applied: MailCommitApplied): ToolResult {
  const { outcome } = applied;
  if (!outcome.applied) {
    const extra =
      outcome.refusal === "changed-since-preview"
        ? {
            changedIds: ids.filter((id) =>
              outcome.changedUids.includes(decodeMessageId(id).uid),
            ),
          }
        : {};
    return moveRefusalResult(outcome.refusal, extra);
  }

  const confirmationLine = composeConfirmationLine(
    {
      kind: "move",
      noun: "message",
      from: decodeModifiedUtf7(applied.sourceMailbox),
      to: decodeModifiedUtf7(applied.destinationMailbox),
      role: applied.role,
      count: outcome.results.length,
      outcome: tallyOf(outcome.results),
    },
    "did",
  );
  const results = outcome.results.map((result, index) => ({
    id: ids[index],
    outcome: result.outcome,
    reason: result.reason,
    newId:
      result.newUid !== null && result.destinationUidValidity !== null
        ? encodeMessageId({
            mailbox: applied.destinationMailbox,
            uidValidity: result.destinationUidValidity,
            uid: result.newUid,
          })
        : null,
    destination: applied.destinationId,
  }));
  return {
    content: [{ type: "text", text: JSON.stringify({ confirmationLine, results }) }],
  };
}

// ---------------------------------------------------------------------------
// Deleting one draft: the preview and the commit's answer (Phase 22)
//
// A draft delete is a move of one draft to Trash, previewed first and applied
// by `mail_commit` like every mail change. The preview reads on the read path
// and writes nothing. The draft must be in the drafts folder, carry the draft
// flag, and go to the folder the server itself marks as Trash. Nothing here
// finds a draft by subject or header: a draft that changed or went away is
// refused, never searched for (D-14).
// ---------------------------------------------------------------------------

/**
 * The guarantee every draft preview and commit answer carries, word for word
 * (D-14, DRFT-07).
 *
 * It says what the tool checks and what it does not. It cannot fit into the
 * tool's description beside the untrusted notice, so it lives in the answers,
 * and no description may claim anything stronger.
 */
export const DRAFT_GUARANTEE =
  "This acts only on a draft, in the drafts folder, exactly as you were just shown it. " +
  "It does not check who wrote the draft.";

/** The fixed reason for each draft refusal. ASCII, and no server text. */
const DRAFT_REFUSAL_REASONS = {
  "not-in-drafts":
    "This message is not in the drafts folder, so nothing was changed. Only a draft in " +
    "Drafts can be moved to Trash this way.",
  "not-a-draft": "This message is not marked as a draft, so nothing was changed.",
  "already-marked-for-removal":
    "This draft is already marked for removal by another app. Moving it would carry that " +
    "mark to the copy in Trash, where another app could remove it for good. Nothing was " +
    "changed.",
  "no-change-numbers":
    "The drafts folder does not report change numbers, so this cannot be checked against " +
    "later changes. Nothing was changed.",
  "no-trash-folder":
    "The account's folder list shows no folder the server marks as Trash, so nothing was " +
    "changed and no folder was guessed.",
  "ambiguous-role-folder":
    "Two folders are both marked as Trash, so none was picked and nothing was changed.",
  "mailbox-read-only": "The drafts folder opened read-only, so nothing was changed.",
  "removal-not-kept":
    "The drafts folder does not keep the mark a move needs, so nothing was changed.",
  "commands-unavailable":
    "iCloud did not offer the commands a safe move needs, so nothing was changed.",
  "changed-since-preview":
    "The draft changed or is gone since the preview. Nothing was changed. Preview it again.",
} as const;

type DraftRefusal = keyof typeof DRAFT_REFUSAL_REASONS;

/** A draft refusal answer: plain JSON with the guarantee, never `isError`. */
function draftRefusalResult(
  refusal: DraftRefusal,
  extra: Record<string, unknown> = {},
): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          refusal,
          reason: DRAFT_REFUSAL_REASONS[refusal],
          ...extra,
          guarantee: DRAFT_GUARANTEE,
        }),
      },
    ],
  };
}

/**
 * Preview moving one draft to Trash: one read session, then a confirmation,
 * and nothing written.
 *
 * The lease is taken around the one read session and nothing else, as
 * `buildMovePreview` does: it is given back before the confirmation is minted.
 * The confirmation is the mail arm's set shape with exactly one entry: the
 * drafts folder, its validity, the Trash folder and its role, and the draft's
 * UID, size, internal date and MODSEQ, every value read from the server here.
 */
async function buildDraftDeletePreview(
  actor: Principal,
  mail: LeasedMail,
  id: string,
  ref: MessageRef,
): Promise<ToolResult> {
  const facts = await mail.withConnectionLease(actor, (leased) =>
    readDraftForChange(actor, leased, ref),
  );
  if ("refusal" in facts) {
    const refusal: DraftPreviewRefusal = facts.refusal;
    return draftRefusalResult(refusal, { id });
  }

  const { draft } = facts;
  const change: NormalizedDraftChange = { op: "draft-delete", id, subject: draft.subject };
  const draftsId = encodeFolderId({ mailbox: draft.draftsMailbox });
  const trashId = encodeFolderId({ mailbox: draft.trashMailbox });
  const confirmToken = await mintMailConfirmation(actor, {
    k: "delete",
    h: await draftChangeHashOf(change),
    m: draftsId,
    uv: ref.uidValidity,
    q: trashId,
    qr: "trash",
    l: [
      {
        i: ref.uid,
        z: draft.fingerprint.size,
        d: draft.fingerprint.internalDate,
        n: draft.fingerprint.modSeq,
      },
    ],
  });
  const confirmationLine = composeConfirmationLine(
    { kind: "draft", name: draft.subject, outcome: null },
    "would",
  );

  return untrustedToolResult(
    {
      confirmToken,
      expiresInSeconds: CONFIRM_TTL_SECONDS,
      change,
      confirmationLine,
      guarantee: DRAFT_GUARANTEE,
    },
    {
      subject: draft.subject,
      to: draft.to,
      cc: draft.cc,
      date: draft.date,
      size: draft.fingerprint.size,
      trashName: draft.trashDisplayName,
    },
  );
}

/**
 * A draft-delete commit's answer. Plain JSON; a refusal is not `isError`.
 *
 * The move answer's shape for one message, plus the guarantee: the caller's
 * id, what happened, why, and the copy's new id in Trash when the server's
 * reply proved it, minted with Trash's validity from that reply.
 */
function draftCommitResult(applied: DraftDeleteApplied): ToolResult {
  const { outcome } = applied;
  if (!outcome.applied) {
    return draftRefusalResult(
      outcome.refusal,
      outcome.refusal === "changed-since-preview" ? { changedIds: [applied.id] } : {},
    );
  }

  const { result } = outcome;
  const confirmationLine = composeConfirmationLine(
    { kind: "draft", name: applied.subject, outcome: result.outcome },
    "did",
  );
  const results = [
    {
      id: applied.id,
      outcome: result.outcome,
      reason: result.reason,
      newId:
        result.newUid !== null && result.destinationUidValidity !== null
          ? encodeMessageId({
              mailbox: applied.trashMailbox,
              uidValidity: result.destinationUidValidity,
              uid: result.newUid,
            })
          : null,
      destination: applied.trashId,
    },
  ];
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({ confirmationLine, results, guarantee: DRAFT_GUARANTEE }),
      },
    ],
  };
}

/**
 * Register the mail tools on a per-request server instance.
 *
 * **No tool here is handed a session gate.** `mail` is the per-person
 * connection lease (Phase 24), built in `createServerFactory` over that
 * request's gate. A tool reaches the gate only through
 * `mail.withConnectionLease`, which takes the person's lease first and hands
 * the gate to the one service call inside. So a tool cannot open an iCloud
 * mail connection without the lease: there is no gate in scope to open one
 * with. That is structural on purpose. PITFALLS #52 names the failure the
 * gate alone could not see, two overlapping REQUESTS from one Apple ID, and
 * ./.claude/CLAUDE.md §3 says why a second connection is costly: iCloud's
 * per-account ceiling is low, undocumented, and locks the user out of Mail.app
 * when it is exhausted.
 *
 * The rules each call site keeps:
 * - The lease is taken after `await principal` and after every id is decoded,
 *   so the cheap refusals still run first and spend nothing, and a refused
 *   principal never reaches the object.
 * - One lease per service call, around that call and nothing else. A tool that
 *   runs two sessions takes it twice, because the lease's expiry is sized to
 *   one session. Staged-file work in R2 is never done under the lease.
 * - The lease is taken outside the orchestrator, never inside
 *   `withMailSession`'s check-and-acquire span.
 *
 * The gate itself is unchanged and still built per request; see
 * `createSessionGate` for why an isolate-wide counter would refuse legitimate
 * concurrent requests. The lease is added beside it, never in its place.
 *
 * `principal` is a promise of who the request acts for, made once per request
 * at the door. Every callback awaits it as the first line of its `try`, and
 * hands the resolved object to each mail function it calls. A refusal is
 * already the auth error, and each `catch` already maps that to
 * `auth_failed`, so an unset secret answers before the lease or the gate is
 * touched and before a socket opens. The await lives HERE and nowhere below:
 * the session orchestrator must not await ahead of its gate (see
 * `withMailSession`).
 *
 * The staging helpers still take the ambient `env`. They reach R2, not mail,
 * and hold no credential.
 */
export function registerMailTools(
  server: McpServer,
  mail: LeasedMail,
  principal: Promise<Principal>,
  mailOnly = false,
): void {
  server.registerTool(
    "mail_get_message",
    {
      description: `Read one iCloud email by its opaque id. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        id: z.string().describe("The opaque message id from a listing."),
        // Optional, and off by default (D-33). The readable text is what a
        // caller wants on almost every call; this is for the cases that
        // genuinely need the markup itself. Nothing renders it.
        includeHtml: z
          .boolean()
          .optional()
          .describe("Also return the raw HTML part, for markup-sensitive work."),
      }),
    },
    async ({ id, includeHtml }) => {
      // Held outside the `try` so the catch can see who asked and which
      // message, but only once each is known: a principal refusal or a token
      // that does not decode leaves them null, and nothing is removed.
      let actor: Principal | null = null;
      let ref: MessageRef | null = null;
      try {
        actor = await principal;
        // Decoding first means a malformed or stale token is refused before a
        // socket is opened, which is the cheapest possible refusal and the one
        // that spends none of the connection budget.
        ref = decodeMessageId(id);
        const decoded = ref;
        const reader = actor;
        const detail = await mail.withConnectionLease(reader, (leased) =>
          getMessage(reader, leased, decoded, { includeHtml }),
        );
        return messageToolResult(detail);
      } catch (err) {
        // A message that no longer opens is removed from this person's recall
        // index at once (RCLL-08, ARCHITECTURE §4.6(a)). Only for a not-found
        // that is certain (26-REVIEW WR-03): the mailbox's validity changed,
        // the mailbox does not exist, or the fetch came back with no row. A
        // transient refusal is not-found too, and removing on it would drop a
        // live message for good, since nothing re-indexes it. Only when the id
        // decoded. It never throws, and the answer below is exactly the one
        // this catch gave before recall existed.
        if (!mailOnly && err instanceof ImapGoneError && actor !== null && ref !== null) {
          await forgetDeadRef(actor, ref);
        }
        // The same backstop shape `registerDiagnoseTool` uses: one boundary,
        // one fixed vocabulary, nothing of the caught value escaping.
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_list_folders",
    {
      // NO `inputSchema` key at all — not an empty object. `./diagnose.ts`'s
      // header records that the two are not equivalent, and D-19 chose zero
      // parameters over an `includeCounts` flag precisely because a tool with
      // no knob is a meaningfully stronger shape than one with an optional one.
      // There is no value a caller can supply that reaches the listing command.
      description: `List iCloud mail folders with role, counts and how each role was resolved. ${UNTRUSTED_NOTICE}`,
    },
    async () => {
      try {
        const actor = await principal;
        return folderToolResult(
          await mail.withConnectionLease(actor, (leased) =>
            listFolders(actor, leased),
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_list_messages",
    {
      description:
        "List a folder's messages, newest first: metadata and a capped " +
        `snippet, never bodies. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        folderId: z
          .string()
          .describe("The opaque folder id from mail_list_folders."),
        pageSize: z
          .number()
          .int()
          .optional()
          .describe(mailOnly ? "Rows per page. Default 5, maximum 5, clamped." : "Rows per page. Default 25, maximum 100, clamped."),
        cursor: z
          .string()
          .optional()
          .describe("The nextCursor from a previous page. Omit for page one."),
      }),
    },
    async ({ folderId, pageSize, cursor }) => {
      try {
        const actor = await principal;
        // Decoded before a socket is opened, so a malformed or foreign token is
        // refused without spending any of the connection budget.
        const folder = decodeFolderId(folderId);
        return messagePageToolResult(
          await mail.withConnectionLease(actor, (leased) =>
            listMessages(actor, leased, folder.mailbox, { pageSize: mailOnly ? Math.min(5, Math.max(1, pageSize ?? 5)) : pageSize, cursor }),
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_find",
    {
      // The name is the contract (SEED-006 D-1). This tool is exhaustive in the
      // one folder it searches, so an empty answer means no such mail is there.
      // The ranked, best-effort lookup is `mail_recall`, and its empty answer
      // promises much less. The name this tool had before recall existed said
      // neither, and it is not registered and has no alias: a model reading an
      // empty answer must know which promise it was given.
      //
      // The description leads with that promise. The rest stays terse, because
      // a description is a tax paid on every call for the life of the server,
      // and every registered tool is held under a 280-character ceiling. The
      // promise and the untrusted notice fill most of it.
      //
      // So the date rule lives on `startDate` and `endDate`. It is a RELATION
      // between those two parameters: both ends inclusive, day-granular, on
      // iCloud's receipt time rather than the sender's own header. A caller
      // cannot infer any of that from the names, and the input schema travels
      // to the model alongside this description anyway.
      //
      // The keyword semantics are the same class of unguessable fact, and they
      // are stated on that PARAMETER for the same reason: they are a fact about
      // ONE parameter. The next person to add a fact here will meet the same
      // ceiling. Do not raise it to make room.
      description:
        "Every match in one folder, so an empty answer means none there. " +
        UNTRUSTED_NOTICE,
      inputSchema: z.object({
        folderId: z
          .string()
          .optional()
          .describe("Opaque folder id from mail_list_folders. Omit for Inbox."),
        keyword: searchTerm.describe(
          "Matches header or body text. The matching is iCloud's own, not " +
            "this tool's: token-based rather than phrase-based, and accent- " +
            "and case-insensitive. Every term must appear, anywhere in the " +
            "header or body, in any order and not necessarily adjacent, so " +
            "adding a word narrows the results rather than widening them.",
        ),
        sender: searchTerm.describe("Matches the sender address or name."),
        startDate: isoDay.describe(
          "Earliest day to include, YYYY-MM-DD. Both ends are inclusive, " +
            "day-granular, and on iCloud's receipt time.",
        ),
        endDate: isoDay.describe(
          "Latest day to include, YYYY-MM-DD. Both ends are inclusive, " +
            "day-granular, and on iCloud's receipt time.",
        ),
        pageSize: z
          .number()
          .int()
          .optional()
          .describe(mailOnly ? "Rows per page. Default 5, maximum 5, clamped." : "Rows per page. Default 25, maximum 100, clamped."),
        cursor: z
          .string()
          .optional()
          .describe("The nextCursor from a previous page. Omit for page one."),
      }),
    },
    async ({ folderId, keyword, sender, startDate, endDate, pageSize, cursor }) => {
      try {
        const actor = await principal;
        // Decoded before the lease is taken, so a bad folder id is refused at
        // no cost to the object or the connection budget.
        const mailbox = resolveMailbox(folderId);
        return searchPageToolResult(
          await mail.withConnectionLease(actor, (leased) =>
            searchMessages(
              actor,
              leased,
              mailbox,
              { keyword, sender, startDate, endDate },
              { pageSize: mailOnly ? Math.min(5, Math.max(1, pageSize ?? 5)) : pageSize, cursor },
            ),
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_list_unread",
    {
      description:
        "List a folder's unread mail, newest first: metadata and a capped " +
        `snippet, never bodies. ${UNTRUSTED_NOTICE}`,
      // No keyword and no date range, deliberately. This tool answers one
      // question; the tool that answers the other one is registered above it.
      inputSchema: z.object({
        folderId: z
          .string()
          .optional()
          .describe("Opaque folder id from mail_list_folders. Omit for Inbox."),
        pageSize: z
          .number()
          .int()
          .optional()
          .describe(mailOnly ? "Rows per page. Default 5, maximum 5, clamped." : "Rows per page. Default 25, maximum 100, clamped."),
        cursor: z
          .string()
          .optional()
          .describe("The nextCursor from a previous page. Omit for page one."),
      }),
    },
    async ({ folderId, pageSize, cursor }) => {
      try {
        const actor = await principal;
        // Decoded before the lease is taken, as the search above does it.
        const mailbox = resolveMailbox(folderId);
        return messagePageToolResult(
          await mail.withConnectionLease(actor, (leased) =>
            listUnread(actor, leased, mailbox, { pageSize: mailOnly ? Math.min(5, Math.max(1, pageSize ?? 5)) : pageSize, cursor }),
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_compose_new",
    {
      // **Two compose tools, not one, and the line is held here deliberately.**
      // D-80 departed from D-17 on the staging side and named its price: a
      // three-way discriminated input whose OUTPUT type is also a union,
      // justified on schema-token cost with two more tool sets queued behind
      // it. Compose has neither property — it is a single optional parent
      // parameter with one output shape — so the cost that justified that
      // departure is simply not present, and D-17's original argument still
      // applies: a capability buried as a parameter is one the model reaches
      // for less. Holding the line here is what keeps D-80 a decision rather
      // than the first step of a drift. The reply tool arrives in plan 04-04.
      description:
        "Compose a new iCloud email into Drafts. Never sent; a human " +
        `reviews it. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        to: z
          .array(z.string())
          .min(1)
          .describe(
            "Recipient addresses, plain and bare — no display-name form. " +
              "An address carrying a line break is refused, never repaired.",
          ),
        cc: z.array(z.string()).optional().describe("Copied addresses."),
        subject: z.string().describe("The subject line."),
        // D-74's stated tradeoff belongs here because the description strings
        // are the only channel the model reads, and this is a fact it cannot
        // infer from the parameter names.
        text: z
          .string()
          .optional()
          .describe(
            "The plain-text body. You author this and the HTML body " +
              "independently — neither is derived from the other, and nothing " +
              "checks that they say the same thing. Supply at least one.",
          ),
        html: z
          .string()
          .optional()
          .describe(
            "The HTML body, authored by you. Supply at least one of text or " +
              "html; supplying both produces a message carrying each.",
          ),
        attachmentIds: mailOnly
          ? z.array(z.string()).max(0).optional().describe("Attachments are disabled in mail-only mode; omit.")
          : attachmentIdList,
        folderId: z
          .string()
          .optional()
          .describe(
            "Opaque folder id from mail_list_folders. Omit for Drafts.",
          ),
      })
        // At least one body half, refused at the SCHEMA rather than in the
        // handler, which means refused before a socket is opened. D-75 makes
        // either half alone legal and both together legal; it does not make
        // NEITHER legal, and a draft with no body at all is a message the user
        // would have to notice for themselves.
        .refine((value) => value.text !== undefined || value.html !== undefined, {
          message: "supply at least one of text or html",
        })
        .refine((value) => !mailOnly || (value.folderId === undefined &&
          (value.text?.length ?? 0) <= 16000 && (value.html?.length ?? 0) <= 16000), {
          message: "Mail-only mode: omit folderId to use Drafts, and keep each body under 16000 characters",
        }),
    },
    async ({ to, cc, subject, text, html, attachmentIds, folderId }) => {
      try {
        const actor = await principal;
        // Decoded before a socket is opened, exactly as the fetch tool decodes
        // a message id first: a malformed or stale token is refused at zero
        // connection cost.
        const mailbox =
          folderId === undefined ? null : decodeFolderId(folderId).mailbox;
        // A new message threads under nothing, so both threading fields are
        // absent rather than zero: `0` would claim a chain was emitted and
        // found empty, which is a different statement and not a true one.
        const echo = {
          subject,
          to,
          cc: cc ?? [],
          parentMessageId: null,
          referencesCount: null,
        };

        // Every staged read happens inside here and BEFORE the session; every
        // delete happens inside here and after it has closed. See
        // `composeWithAttachments` for why the ordering is the correctness.
        const composed = await composeWithAttachments(
          env,
          actor.userId,
          attachmentIds ?? [],
          (attachments) =>
            buildDraft({
              // Fixed, from the principal. See `draftFromAddress`.
              from: draftFromAddress(actor),
              to,
              cc: cc ?? [],
              subject,
              // Absent stays absent rather than becoming an empty part: a
              // message with an empty body half is a different message from one
              // with only the other half (D-75).
              text: text ?? null,
              html: html ?? null,
              // Wired, and supplied by plan 04-04's reply tool.
              inReplyTo: null,
              references: [],
              attachments,
              // A new message quotes nothing. The reply tool supplies one.
              quoted: null,
              now: new Date(),
            }),
          // The lease is taken HERE, around the one write session, and not
          // around this whole call: the staged reads before it and the
          // deletes after it are R2 work and never hold the lease.
          (message) =>
            mail.withConnectionLease(actor, (leased) =>
              appendDraft(actor, leased, mailbox, message),
            ),
          Date.now(),
        );

        const attached = {
          attachedCount: composed.attachedCount,
          attachedBytes: composed.attachedBytes,
          consumedStagedIds: composed.consumed,
        };

        if (!composed.built.built) {
          return composeToolResult({
            ...echo,
            ...attached,
            appended: false,
            id: null,
            role: null,
            roleSource: null,
            sizeBytes: composed.built.sizeBytes ?? null,
            refusal: composed.built.refusal,
            limitBytes: composed.built.limitBytes ?? null,
          });
        }

        // **A narrowing rather than an assertion.** `outcome` is
        // `AppendOutcome | null` — null when the build refused first — and the
        // bare cast erased exactly the nullable the type system was tracking.
        // The invariant holds today only because `composeWithAttachments`
        // returns early on a refused build and this handler checks
        // `composed.built.built` above; nothing enforced the pairing, so a
        // third early return added inside that function would produce a null
        // here and a `TypeError` on `.appended`, reported to the model as
        // `connection_failed`.
        //
        // A discriminated `DraftComposition` was the reviewer's first
        // suggestion and does NOT work: `built` is an object rather than a
        // literal, so `composed.built.built` is not a discriminant TypeScript
        // can narrow the outer union on, and the cast would have to come back.
        // Checking the nullable itself is a narrowing the compiler does
        // enforce, and it costs one comparison.
        const { outcome } = composed;
        if (outcome === null) throw new ImapNotFoundError();
        if (!outcome.appended) {
          return composeToolResult({
            ...echo,
            ...attached,
            appended: false,
            id: null,
            role: null,
            roleSource: null,
            sizeBytes: outcome.sizeBytes,
            refusal: outcome.refusal,
            limitBytes: outcome.limitBytes,
          });
        }

        return composeToolResult({
          ...echo,
          ...attached,
          appended: true,
          // Minted only when the server named the result. Absent identifiers
          // are a normal outcome, not a failure — the draft was written.
          id:
            outcome.uidValidity === null || outcome.uid === null
              ? null
              : encodeMessageId({
                  mailbox: outcome.mailbox,
                  uidValidity: outcome.uidValidity,
                  uid: outcome.uid,
                }),
          role: outcome.role,
          roleSource: outcome.roleSource,
          sizeBytes: composed.built.bytes.byteLength,
          refusal: null,
          limitBytes: null,
        });
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_compose_reply",
    {
      // A SEVENTH name rather than an optional parent on the tool above, for
      // the reason recorded at that registration: D-17's argument that a
      // capability buried as a parameter is one the model reaches for less is
      // still live here, and neither of the two properties that justified
      // D-80's departure — a discriminated input and a union output — applies.
      //
      // The description carries only what will not fit on a parameter. Every
      // registered description is under a 280-character ceiling that the
      // standing untrusted-content line already spends most of, and the facts
      // this tool has to state are long — so they live on the parameters, which
      // travel to the model in the same payload.
      description:
        "Reply to a message by id, into Drafts and threaded. Never sent; a " +
        `human reviews it. ${UNTRUSTED_NOTICE}`,
      inputSchema: z
        .object({
          parentId: z
            .string()
            .describe(
              "The opaque message id you are replying to, from a listing or " +
                "mail_get_message. Its headers are read here rather than " +
                "taken from you: the id does not carry them.",
            ),
          // D-74's stated tradeoff, in the same words the new-message tool
          // uses, plus the one fact that is specific to a reply.
          text: z
            .string()
            .optional()
            .describe(
              "The plain-text body: your own words only, because the quoted " +
                "original is added for you. You author this and the HTML body " +
                "independently — neither is derived from the other, and " +
                "nothing checks that they say the same thing. Supply at " +
                "least one.",
            ),
          html: z
            .string()
            .optional()
            .describe(
              "The HTML body, authored by you. Supply at least one of text " +
                "or html; the quoted original is appended to whichever " +
                "halves you supply.",
            ),
          // D-67's precedence, stated where the model reads it. Two ways of
          // filling one field is the thing that goes wrong here.
          to: z
            .array(z.string())
            .optional()
            .describe(
              "Recipient addresses, plain and bare — no display-name form. " +
                "Omit this in the normal case: To is derived from the " +
                "parent's Reply-To, falling back to its From. Supplying it " +
                "replaces the derived value rather than adding to it.",
            ),
          cc: z
            .array(z.string())
            .optional()
            .describe(
              "Copied addresses. Supplying this replaces the derived value " +
                "rather than adding to it, including when replyAll is true.",
            ),
          replyAll: z
            .boolean()
            .default(false)
            .describe(
              "Reply to everyone on the thread. A reply-all adds the " +
                "parent's To and Cc to this draft's Cc, minus your own " +
                "address. Off by default. Prefer it to naming the whole " +
                "list yourself: a mistake here reaches strangers.",
            ),
          attachmentIds: mailOnly
          ? z.array(z.string()).max(0).optional().describe("Attachments are disabled in mail-only mode; omit.")
          : attachmentIdList,
          folderId: z
            .string()
            .optional()
            .describe(
              "Opaque folder id from mail_list_folders. Omit for Drafts.",
            ),
        })
        .refine((value) => value.text !== undefined || value.html !== undefined, {
          message: "supply at least one of text or html",
        })
        .refine((value) => !mailOnly || (value.folderId === undefined &&
          (value.text?.length ?? 0) <= 16000 && (value.html?.length ?? 0) <= 16000), {
          message: "Mail-only mode: omit folderId to use Drafts, and keep each body under 16000 characters",
        }),
    },
    async ({
      parentId,
      text,
      html,
      to,
      cc,
      replyAll,
      attachmentIds,
      folderId,
    }) => {
      try {
        const actor = await principal;
        // Both tokens decoded before a socket is opened, exactly as every other
        // tool in this module does it: a malformed, stale or foreign token is
        // refused at zero connection cost and cannot address another message.
        const ref = decodeMessageId(parentId);
        const mailbox =
          folderId === undefined ? null : decodeFolderId(folderId).mailbox;
        const self = draftFromAddress(actor);

        // D-69. `fetchParentHeaders` inside this call is not an optimisation:
        // the opaque id encodes the mailbox, the validity and the UID and NOT
        // the parent's Message-ID, so the threading headers cannot be built
        // from anything the caller holds. One session, serial, peeking.
        // Its own lease, given back when this session closes. The write below
        // takes a second one: two sessions, two leases (the expiry is sized
        // to one session).
        const parent = await mail.withConnectionLease(actor, (leased) =>
          getReplyParent(actor, leased, ref),
        );

        const recipients = replyRecipients(parent.headers, {
          self,
          replyAll,
          to,
          cc,
        });
        const subject = replySubject(parent.detail.subject);
        const quoted = await quoteOriginal(parent.detail);

        const echo = {
          subject,
          to: recipients.to,
          cc: recipients.cc,
        };

        // The parent's headers were read inside their own session, which has
        // closed. The staged reads happen next and still before the write's
        // session opens — two sessions on this path, never one held across a
        // storage round trip.
        const composed = await composeWithAttachments(
          env,
          actor.userId,
          attachmentIds ?? [],
          (attachments) =>
            buildDraft({
              from: self,
              to: recipients.to,
              cc: recipients.cc,
              subject,
              text: text ?? null,
              html: html ?? null,
              inReplyTo: parent.headers.messageId,
              references: parent.headers.references,
              attachments,
              quoted,
              now: new Date(),
            }),
          // The lease is taken HERE, around the one write session, and not
          // around this whole call: the staged reads before it and the
          // deletes after it are R2 work and never hold the lease.
          (message) =>
            mail.withConnectionLease(actor, (leased) =>
              appendDraft(actor, leased, mailbox, message),
            ),
          Date.now(),
        );

        const attached = {
          attachedCount: composed.attachedCount,
          attachedBytes: composed.attachedBytes,
          consumedStagedIds: composed.consumed,
        };

        if (!composed.built.built) {
          return composeToolResult({
            ...echo,
            ...attached,
            appended: false,
            id: null,
            role: null,
            roleSource: null,
            sizeBytes: composed.built.sizeBytes ?? null,
            refusal: composed.built.refusal,
            limitBytes: composed.built.limitBytes ?? null,
            parentMessageId: null,
            referencesCount: null,
          });
        }

        // Reported off the BUILD rather than off the parent, so the two fields
        // describe what the draft carries. A parent id that was absent or
        // malformed produces a null here even though one was supplied — which
        // is the fact the model needs on a path where a reply that does not
        // thread appends exactly as cleanly as one that does.
        const threading = {
          parentMessageId: composed.built.inReplyTo,
          referencesCount: composed.built.referencesCount,
        };

        // **A narrowing rather than an assertion.** `outcome` is
        // `AppendOutcome | null` — null when the build refused first — and the
        // bare cast erased exactly the nullable the type system was tracking.
        // The invariant holds today only because `composeWithAttachments`
        // returns early on a refused build and this handler checks
        // `composed.built.built` above; nothing enforced the pairing, so a
        // third early return added inside that function would produce a null
        // here and a `TypeError` on `.appended`, reported to the model as
        // `connection_failed`.
        //
        // A discriminated `DraftComposition` was the reviewer's first
        // suggestion and does NOT work: `built` is an object rather than a
        // literal, so `composed.built.built` is not a discriminant TypeScript
        // can narrow the outer union on, and the cast would have to come back.
        // Checking the nullable itself is a narrowing the compiler does
        // enforce, and it costs one comparison.
        const { outcome } = composed;
        if (outcome === null) throw new ImapNotFoundError();
        if (!outcome.appended) {
          return composeToolResult({
            ...echo,
            ...threading,
            ...attached,
            appended: false,
            id: null,
            role: null,
            roleSource: null,
            sizeBytes: outcome.sizeBytes,
            refusal: outcome.refusal,
            limitBytes: outcome.limitBytes,
          });
        }

        return composeToolResult({
          ...echo,
          ...threading,
          ...attached,
          appended: true,
          id:
            outcome.uidValidity === null || outcome.uid === null
              ? null
              : encodeMessageId({
                  mailbox: outcome.mailbox,
                  uidValidity: outcome.uidValidity,
                  uid: outcome.uid,
                }),
          role: outcome.role,
          roleSource: outcome.roleSource,
          sizeBytes: composed.built.bytes.byteLength,
          refusal: null,
          limitBytes: null,
        });
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  // Mail-only mode exposes only reads, searches and the two draft creators above.
  // Returning before registration also makes every other mail tool uncallable.
  if (mailOnly) return;

  server.registerTool(
    "mail_get_attachment",
    {
      // Registered HERE rather than in a sibling file, and this is the
      // registration 04-RESEARCH names as the most likely way to break the
      // property Phase 2 verified: `untrustedBlock` is called from exactly ONE
      // place. A tool that shapes its own response bypasses the fence by
      // OMISSION rather than by intent, which is a failure nobody notices,
      // because nothing about the response looks wrong until a document tells
      // the model what to do and it complies.
      //
      // The supported types are NAMED from `EXTRACTABLE_TYPES` rather than
      // restated in prose, so the description and the dispatcher cannot
      // disagree about what this tool can read. A list written twice is a list
      // that will eventually be wrong in one place, and the model would be
      // acting on whichever copy nobody updated.
      //
      // Terse to the point of clipped, and the ceiling is why: 184 of the 280
      // characters every registered description is held under are already spent
      // by the standing untrusted-content line, which is not optional. The
      // supported-type list is the one fact that has to be here rather than on
      // the parameter, because it is a statement about the TOOL rather than
      // about its single input.
      description:
        `Read one attachment as text: ${EXTRACTABLE_TYPES.join(", ")}. ` +
        `Others refuse. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        // ONE parameter, and D-76 is why there is not a second. No message id,
        // no array index, no part path: an index is a small integer the model
        // can transpose, and a path addresses ANY part of the message including
        // its body, which is precisely the value class the opaque id exists to
        // make unspeakable.
        id: z
          .string()
          .describe(
            "The opaque attachment id from an attachment row on " +
              "mail_get_message. Not a filename and not a number.",
          ),
      }),
    },
    async ({ id }) => {
      try {
        const actor = await principal;
        // Decoded BEFORE the socket opens, so a malformed, foreign or expired
        // token is refused without spending any of the connection budget — the
        // same ordering `resolveMailbox` keeps for a folder token.
        const ref = decodeAttachmentId(id);

        // One session, and everything expensive outside it. The fetch races
        // CALL_DEADLINE_MS while holding a socket against iCloud's low
        // undocumented per-account ceiling; the transfer decode and the
        // extraction are pure CPU over megabytes and race nothing. Moving
        // either inside would spend a connection on arithmetic.
        const content = await mail.withConnectionLease(actor, (leased) =>
          getAttachmentContent(actor, leased, ref),
        );

        if (!content.fetch.fetched) {
          // A part this server declined to ask for. A SUCCESSFUL call carrying
          // a structured field, per `unsupportedCharset`'s precedent — the
          // fetch ran, this client refused to spend the round trip, and none of
          // the four categories describes that honestly.
          return attachmentToolResult({
            id,
            sizeBytes: content.sizeBytes,
            encodedOctets: content.encodedOctets,
            extracted: null,
            truncated: null,
            refusal: content.fetch.refusal,
            limitBytes: content.fetch.limitBytes,
            text: null,
            filename: content.filename,
            mimeType: content.mimeType,
          });
        }

        const decoded = transferDecode(content.fetch.bytes, content.encoding);
        const extraction = await extractAttachmentText(
          decoded,
          content.mimeType,
          content.charset,
        );

        return attachmentToolResult({
          id,
          sizeBytes: content.sizeBytes,
          encodedOctets: content.encodedOctets,
          extracted: extraction.extracted,
          truncated: extraction.extracted ? extraction.truncated : null,
          refusal: extraction.extracted ? null : extraction.refusal,
          limitBytes: extraction.extracted ? null : (extraction.limitBytes ?? null),
          text: extraction.extracted ? extraction.text : null,
          filename: content.filename,
          mimeType: content.mimeType,
        });
      } catch (err) {
        // Only a genuine transport or authentication failure reaches here. Every
        // outcome this server can foresee — a part too large to ask for, a
        // scanned document, a spreadsheet — is a value on a successful result,
        // which is what keeps the FND-05 vocabulary closed at four.
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_stage_attachment",
    {
      // ONE tool discriminated by `source`, plus a separate confirm tool in plan
      // 04-10. **This is D-80's deliberate departure from D-17**, and repeating
      // it here rather than assuming it is the whole point: a departure recorded
      // as a departure is a decision, and the same departure unrecorded is drift
      // — which is exactly how the registration two above justifies NOT
      // departing, on the same page, for a case where the two properties below
      // do not hold.
      //
      // D-17 rejected collapsing distinct operations into parameter flags,
      // because a capability buried as a parameter is one the model reaches for
      // less. D-80 departed anyway, on schema-token cost: phases 5 and 6 add
      // calendar tools to the same list and the per-request budget is shared.
      //
      // **The accepted cost, named — and now actually paid.** A three-way
      // discriminated union is the exact shape D-17 argued hardest against, and
      // because one of the three branches returns an upload URL rather than a
      // ready staged id, the OUTPUT type is a union as well. All three ship now:
      // the presigned branch is additive to the union the first two were
      // designed for, and its response goes through `uploadUrlToolResult`
      // rather than `stageToolResult`. That second shaper IS the output half of
      // D-80's cost, and it is the recorded consequence of a decision rather
      // than an inconsistency — which is why it says so at its own definition
      // as well as here.
      //
      // **Fetch-from-a-URL is DECLINED (D-78) and must not be helpfully added.**
      // It is the server-makes-a-request-to-a-caller-named-host shape that phase
      // 3's own review classified as a credential-exfiltration path; it spends
      // one of the six per-invocation connections; and the response size is
      // unknown until it arrives. If it is ever wanted, the shape to add is an
      // explicit host allowlist, never a bare URL parameter. The prose is the
      // preventive half; the standing schema walk in `test/mail-tools.test.ts`
      // is the detective half, and it fails the suite if a host- or URL-shaped
      // parameter ever appears here.
      //
      // The description carries only what will not fit on a parameter. Every
      // registered description is under a 280-character ceiling that the
      // standing untrusted-content line already spends most of.
      description:
        "Stage a file to attach to a draft: from a message, from bytes, or " +
        `to an upload URL. ${UNTRUSTED_NOTICE}`,
      inputSchema: z
        .object({
          source: z
            .enum(["message", "bytes", "presigned"])
            .describe(
              "Where the file comes from. Prefer message: it copies the file " +
                "server-side, so none of its contents enter this conversation. " +
                "presigned returns a URL to PUT the file to, and a separate " +
                "uploadId; the upload must send exactly these headers, because " +
                "all of them are signed into the URL and any difference is " +
                "rejected: content-type set to the mimeType given here, " +
                "content-length set to sizeBytes, and x-amz-meta-filename set " +
                "to the encodedFilename that comes back. When relaying a curl " +
                "command to a person, QUOTE THE URL — it contains ampersands, " +
                "which an unquoted shell reads as job separators, truncating " +
                "it — and use --data-binary @file or -T file so content-length " +
                "is the exact file size; curl sends no content-type of its own " +
                "with --data-binary, so the header is required, not optional. " +
                "Then call mail_confirm_upload — until it succeeds the file is " +
                "not usable, because this server has not looked at the bytes.",
            ),
          attachmentId: z
            .string()
            .optional()
            .describe(
              "For source=message: the opaque attachment id from an " +
                "attachment row on mail_get_message. Not a filename.",
            ),
          base64: z
            .string()
            .optional()
            .describe(
              "For source=bytes: the file, base64-encoded. Small files only. " +
                "The limit here is deliberately far below the per-file one " +
                "because what it protects is this conversation's context " +
                "rather than the server's memory: base64 inflates by a " +
                "third, so a 400 KB file is roughly 150,000 tokens in this " +
                "one call. Use source=message for anything already in an " +
                "email — it copies the file without any of it passing " +
                "through here.",
            ),
          filename: z
            .string()
            // The cheaper of the two refusals for an empty name, and the one
            // that lands before any bytes move. `resolveStagedAttachments`
            // holds the other, because this schema does not cover the value
            // read back off an object staged before the rule existed.
            .min(1)
            .optional()
            .describe(
              "Rename the file. Required for source=bytes. Optional for " +
                "source=message, where the sender's own name is used by " +
                "default — a rename here is the one place to replace a name " +
                "a stranger chose before it travels into a header of an " +
                "outgoing message.",
            ),
          mimeType: z
            .string()
            .optional()
            .describe(
              "The declared media type. Recorded as declared and never " +
                "verified; nothing branches on it. Required for " +
                "source=presigned, where it is signed into the URL and the " +
                "upload must send exactly this value.",
            ),
          sizeBytes: z
            .number()
            .int()
            .positive()
            .optional()
            .describe(
              "For source=presigned: the file's exact size in bytes. It is " +
                "signed into the URL, so an upload of any other size is " +
                "rejected, and a size over the per-file cap is refused here " +
                "rather than after the bytes have been sent.",
            ),
        })
        .refine(
          (value) => {
            if (value.source === "message") return value.attachmentId !== undefined;
            if (value.source === "presigned") {
              return (
                value.filename !== undefined &&
                value.mimeType !== undefined &&
                value.sizeBytes !== undefined
              );
            }
            return value.base64 !== undefined && value.filename !== undefined;
          },
          {
            message:
              "source=message needs an attachmentId; source=bytes needs base64 and " +
              "filename; source=presigned needs filename, mimeType and sizeBytes",
          },
        ),
    },
    async ({ source, attachmentId, base64, filename, mimeType, sizeBytes }) => {
      try {
        const actor = await principal;
        if (source === "presigned") {
          // Unreachable through MCP — the refinement above rejects it before
          // this handler runs. Present because a narrowing that lives only in a
          // refinement is one the compiler cannot see.
          if (
            filename === undefined ||
            mimeType === undefined ||
            sizeBytes === undefined
          ) {
            throw new ImapNotFoundError();
          }

          // No session and no network. Signing is arithmetic, so this branch
          // spends none of the six-connection budget at all.
          return uploadUrlToolResult(
            await mintUploadGrant(
              env,
              actor.userId,
              { filename, mimeType, sizeBytes },
              Date.now(),
            ),
          );
        }

        if (source === "bytes") {
          // Unreachable through MCP — the refinement above rejects it before
          // this handler runs, which is the cheapest possible refusal and the
          // one that spends none of the connection budget. Present because a
          // narrowing that lives only in a refinement is one the compiler
          // cannot see, and because a direct caller does not go through it.
          if (base64 === undefined || filename === undefined) {
            throw new ImapNotFoundError();
          }

          // No session on this path at all. Nothing is fetched, so nothing
          // opens a socket, and the whole operation is one storage write.
          const inline = await stageInlineBytes(
            env,
            actor.userId,
            { base64, filename, mimeType: mimeType ?? null },
            Date.now(),
          );

          return stageToolResult({
            stagedFrom: "bytes",
            staged: inline.staged,
            id: inline.staged ? inline.id : null,
            sizeBytes: inline.sizeBytes,
            expiresAt: inline.staged ? inline.expiresAt : null,
            refusal: inline.staged ? null : inline.refusal,
            limitBytes: inline.staged ? null : inline.limitBytes,
            // Caller-authored on this path, and inside the fence anyway: an
            // echoed value the caller typed is not this server's claim about
            // anything, which is the reasoning `composeToolResult` records for
            // its own echoed subject and recipients.
            filename,
            mimeType: mimeType ?? null,
          });
        }

        // Unreachable through MCP, for the reason given on the branch above.
        if (attachmentId === undefined) throw new ImapNotFoundError();

        // Decoded BEFORE the socket opens, exactly as every other tool in this
        // module does it: a malformed, foreign or stale token is refused at zero
        // connection cost.
        const ref = decodeAttachmentId(attachmentId);

        // One session, and it is CLOSED before the next line runs. Every storage
        // operation is outside it — see `stageAttachmentContent`, whose
        // signature is what makes that structural rather than remembered.
        const content = await mail.withConnectionLease(actor, (leased) =>
          getAttachmentContent(actor, leased, ref),
        );
        const outcome = await stageAttachmentContent(
          env,
          actor.userId,
          content,
          filename ?? null,
          Date.now(),
        );

        return stageToolResult({
          stagedFrom: "message",
          staged: outcome.staged,
          id: outcome.staged ? outcome.id : null,
          sizeBytes: outcome.sizeBytes,
          expiresAt: outcome.staged ? outcome.expiresAt : null,
          refusal: outcome.staged ? null : outcome.refusal,
          limitBytes: outcome.staged ? null : outcome.limitBytes,
          // The name as OFFERED and the type as DECLARED, both stranger-authored
          // when they came off a message.
          filename: filename ?? content.filename,
          mimeType: content.mimeType,
        });
      } catch (err) {
        // A file too large, a part this server declined to ask for, an unusable
        // name — none of those reach here. They are values on a SUCCESSFUL
        // result, which is what keeps the FND-05 vocabulary closed at four
        // (D-35). Only transport and authentication failures are errors.
        return mailErrorResult(err);
      }
    },
  );

  server.registerTool(
    "mail_confirm_upload",
    {
      // The TENTH registration, and the second half of D-80's two-tool answer:
      // one staging tool discriminated by source, plus this. It is a separate
      // NAME rather than a fourth source value because it is a different
      // operation on a different object — the staging tool answers "where do I
      // put this", and this one answers "what actually arrived". Folding it in
      // would put two verbs behind one name, which is the thing D-17 objects to
      // and which D-80's departure did not license.
      //
      // **The description carries the one fact that is unguessable from the
      // parameter names**: nothing is usable until this call succeeds, and the
      // reason is that the server has not seen the bytes until it looks. A model
      // that does not know this will hand the user an upload URL and then try to
      // attach something.
      description:
        "Finish a presigned upload. The file is unusable until this succeeds. " +
        `${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        uploadId: z
          .string()
          .describe(
            "The opaque uploadId that came back from " +
              "mail_stage_attachment with source=presigned. Not a URL and not " +
              "a filename.",
          ),
        sizeBytes: z
          .number()
          .int()
          .positive()
          .describe(
            "The size that was declared when the URL was minted. The object's " +
              "own size is what actually decides; this is the claim it is " +
              "checked against, and a file bigger than it is deleted.",
          ),
      }),
    },
    async ({ uploadId, sizeBytes }) => {
      try {
        // This tool still opens no session — nothing below it logs in. What
        // changed is that the resolved value is no longer unused: the store
        // call further down has to know WHO is asking, so the id travels to it
        // as an argument. The await was already here for the other reason, and
        // that reason stands unaltered: every mail tool answers a refused
        // principal the same way, and none works for a caller the others turn
        // away. This comment is rewritten rather than deleted because its first
        // sentence stopped being true in plan 10-02, and a reader who finds the
        // await with no explanation will assume one of the two reasons and act
        // on the wrong one.
        const actor = await principal;
        const nowMs = Date.now();

        // Decoded before anything is read, exactly as every other tool in this
        // module does it. A ticket of the WRONG KIND fails here too, which is
        // what stops a staged id being re-confirmed and — far more importantly —
        // stops an upload ticket being handed straight to the compose path,
        // where it would attach bytes nobody has looked at.
        const ref = decodeUploadId(uploadId, nowMs);

        // No session on this path at all. One storage read, one conditional
        // delete, and no socket.
        const outcome = await confirmStagedUpload(
          env,
          actor.userId,
          ref.key,
          sizeBytes,
          nowMs,
          ref.expiresAt,
        );

        return stageToolResult({
          stagedFrom: "presigned",
          staged: outcome.staged,
          id: outcome.staged ? outcome.id : null,
          sizeBytes: outcome.sizeBytes,
          expiresAt: outcome.staged ? outcome.expiresAt : null,
          refusal: outcome.staged ? null : outcome.refusal,
          limitBytes: outcome.staged ? null : outcome.limitBytes,
          // What the UPLOADER recorded on the object, which on this path is the
          // name and type the caller declared at mint time. Inside the fence for
          // the reason every other echo in this module is: an echoed value is
          // not this server's claim about anything.
          filename: outcome.staged ? outcome.offeredFilename : null,
          mimeType: outcome.staged ? outcome.offeredType : null,
        });
      } catch (err) {
        // A missing object and an oversized one are values on a SUCCESSFUL
        // result, not errors — D-35's vocabulary stays closed at four. Only a
        // malformed or expired ticket, and a genuine transport failure, reach
        // here.
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Mark one message read or unread (MUTA-07).
   *
   * The first tool in this project that changes a mailbox. It lives in this
   * module rather than a sibling so there is still one error shaper for mail.
   *
   * **No preview and no confirmation, and that is a decision (D-09).** Every
   * other write in this milestone is previewed first. This one is not, because
   * it changes one flag on one message, it harms nothing, and the same tool
   * puts it back. A reply cannot be unsent and a delete cannot be undone, so
   * those are previewed. This can be undone in one call, with the opposite
   * value. Calling again with the same value changes nothing, so the
   * description says which value undoes it.
   *
   * The input is exactly an id and a boolean. No folder, no search term, no
   * list and no address: one message per call, named by a message id. The id
   * is not signed: the server checks its shape on decode and its folder's
   * validity on open, and that is all. The verbs come from
   * `../../mail/triage`. This module never imports the mutating orchestrator,
   * and the scan would refuse it if it did.
   */
  server.registerTool(
    "mail_mark_read",
    {
      // The standing untrusted-content line too, although this answer carries
      // no stranger-authored text: it is stated over the whole mail surface,
      // so no tool is the one place a model arrives unwarned. That leaves under
      // a hundred characters for the rest, so the answer's own fields say that
      // the state is iCloud's, and the server instructions say that reading
      // never marks mail read.
      description:
        "Mark one email read or unread by id. Writes at once, no preview; " +
        `undo with the opposite read. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        id: z.string().describe("The opaque message id from a listing."),
        read: z
          .boolean()
          .describe("true marks the message read; false marks it unread."),
      }),
    },
    async ({ id, read }) => {
      try {
        const actor = await principal;
        // Decoded before any socket, as every other tool here does it: a bad
        // token is refused without spending a connection.
        const ref = decodeMessageId(id);
        const outcome = await mail.withConnectionLease(actor, (leased) =>
          read ? markRead(actor, leased, ref) : markUnread(actor, leased, ref),
        );
        return readStateToolResult(id, read, outcome);
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Flag or unflag one message (TRIA-01).
   *
   * **No preview, and that is the owner's decision (D-01, 2026-09-26).** It has
   * mail_mark_read's shape for mail_mark_read's reasons: one flag on one
   * message, harmless, and put back by the same tool with the opposite value.
   * No condition on the change either; the conditional change belongs to the
   * removal mark inside a previewed move.
   *
   * The input is exactly an id and a boolean. The flag is named in the verb's
   * code, so a caller chooses only on or off and can reach no other flag
   * (D-05). The verb checks that the folder keeps the flag before it writes.
   */
  server.registerTool(
    "mail_flag",
    {
      description:
        "Flag or unflag one email by id. Writes at once, no preview; " +
        `undo with the opposite flagged. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        id: z.string().describe("The opaque message id from a listing."),
        flagged: z
          .boolean()
          .describe("true flags the message; false clears the flag."),
      }),
    },
    async ({ id, flagged }) => {
      try {
        const actor = await principal;
        // Decoded before any socket: a bad token costs no connection.
        const ref = decodeMessageId(id);
        const outcome = await mail.withConnectionLease(actor, (leased) =>
          flagged
            ? flagMessage(actor, leased, ref)
            : unflagMessage(actor, leased, ref),
        );
        return flagStateToolResult(id, flagged, outcome);
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Preview moving messages to another folder (TRIA-02, D-05).
   *
   * Ids only, as the user supplies them: message ids from a listing and a
   * folder id from mail_list_folders. No search term, no body, no folder name
   * and nothing else this server read can be the source of the set (TRIA-09).
   * Writes nothing; `mail_commit` applies it.
   */
  server.registerTool(
    "mail_move",
    {
      description:
        "Preview moving emails to another folder. Writes nothing; apply with " +
        `mail_commit. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        ids: z
          .array(z.string())
          .min(1)
          .describe(
            `Message ids from a listing, all from one folder, at most ${MOVE_SET_CAP}.`,
          ),
        destination: z
          .string()
          .describe("The destination folder id from mail_list_folders."),
      }),
    },
    async ({ ids, destination }) => {
      try {
        const actor = await principal;
        // Every id and the destination decoded before any socket: a bad token
        // is refused without spending a connection.
        const refs = ids.map((id) => decodeMessageId(id));
        const target = decodeFolderId(destination);

        const refused = moveListRefusal(ids, refs);
        if (refused !== null) return refused;

        return await withMailConfirmationBoundary(() =>
          buildMovePreview(
            actor,
            mail,
            { ids: [...ids], refs, destinationId: destination },
            { kind: "folder", mailbox: target.mailbox },
            "move",
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Preview moving messages to this account's archive folder (TRIA-03, D-03).
   *
   * The folder is resolved from the account's own folder list at preview time,
   * special-use attribute first and then the name ladder, and never hardcoded.
   * No archive folder, or two that tie, is a refusal: nothing moves and nothing
   * is guessed. The move itself is `mail_move`'s, applied by `mail_commit`.
   */
  server.registerTool(
    "mail_archive",
    {
      description:
        "Preview moving emails to this account's archive. Writes nothing; apply " +
        `with mail_commit. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        ids: z
          .array(z.string())
          .min(1)
          .describe(
            `Message ids from a listing, all from one folder, at most ${MOVE_SET_CAP}.`,
          ),
      }),
    },
    async ({ ids }) => {
      try {
        const actor = await principal;
        const refs = ids.map((id) => decodeMessageId(id));
        const refused = moveListRefusal(ids, refs);
        if (refused !== null) return refused;

        return await withMailConfirmationBoundary(() =>
          buildMovePreview(
            actor,
            mail,
            { ids: [...ids], refs, destinationId: null },
            { kind: "role", role: "archive" },
            "move",
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Preview moving messages to this account's Trash folder (D-04).
   *
   * D-04 was decided by the owner on 2026-09-26, overriding FEATURES.md's
   * "deferred": ordinary mail may go to Trash. Trash is a move and nothing
   * more. It is previewed like any other move, resolved from the account's own
   * folder list like the archive, and every sentence says the messages can be
   * moved back out of Trash. There is no way here to empty Trash or to remove a
   * message in place, and adding one is a decision on the safety boundary, not
   * a refactor.
   */
  server.registerTool(
    "mail_trash",
    {
      description:
        "Preview moving emails to Trash; they can be moved back. Writes nothing " +
        `until mail_commit. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        ids: z
          .array(z.string())
          .min(1)
          .describe(
            `Message ids from a listing, all from one folder, at most ${MOVE_SET_CAP}.`,
          ),
      }),
    },
    async ({ ids }) => {
      try {
        const actor = await principal;
        const refs = ids.map((id) => decodeMessageId(id));
        const refused = moveListRefusal(ids, refs);
        if (refused !== null) return refused;

        return await withMailConfirmationBoundary(() =>
          buildMovePreview(
            actor,
            mail,
            { ids: [...ids], refs, destinationId: null },
            { kind: "role", role: "trash" },
            "move",
          ),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Preview moving one draft to Trash (Phase 22, DRFT-03 to DRFT-07).
   *
   * Exactly one input: a draft's message id, as a listing of the drafts folder
   * or a compose answer gave it. No folder, no list, no search term and no
   * subject, so nothing this server read can choose the draft (D-19). Writes
   * nothing; `mail_commit` applies it. The id is decoded before the lease and
   * before any socket, so a bad id costs no connection.
   */
  server.registerTool(
    "mail_delete_draft",
    {
      description:
        "Preview moving one draft to Trash. Writes nothing; apply with " +
        `mail_commit. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        id: z
          .string()
          .describe("A draft's message id, from a listing of the drafts folder."),
      }),
    },
    async ({ id }) => {
      try {
        const actor = await principal;
        const ref = decodeMessageId(id);
        return await withMailConfirmationBoundary(() =>
          buildDraftDeletePreview(actor, mail, id, ref),
        );
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );

  /**
   * Apply a previewed mail change (D-05).
   *
   * A mail commit tool of its own, so a mail confirmation and a calendar or
   * contact one can never be spent at each other's endpoint. The change is a
   * union on `op`: a move (Phase 21) or a draft delete (Phase 22).
   */
  server.registerTool(
    "mail_commit",
    {
      description:
        "Apply a move, archive, trash or draft preview. Pass confirmToken and " +
        `change back unaltered. ${UNTRUSTED_NOTICE}`,
      inputSchema: z.object({
        confirmToken: z
          .string()
          .describe(
            "The confirmToken from the preview, unaltered. The user must have " +
              "seen the preview's confirmationLine word for word. It can be " +
              "spent once.",
          ),
        change: z
          .discriminatedUnion("op", [
            z.object({
              op: z.literal("move"),
              ids: z.array(z.string()),
              destination: z.string(),
            }),
            z.object({
              op: z.literal("draft-delete"),
              id: z.string(),
              subject: z.string().nullable(),
            }),
          ])
          .describe("The change object from the preview, unaltered."),
      }),
    },
    async ({ confirmToken, change }) => {
      try {
        const actor = await principal;
        const applied = await withMailConfirmationBoundary(() =>
          applyMailCommit(actor, mail, confirmToken, change),
        );
        if (applied.op === "draft-delete") return draftCommitResult(applied);
        return mailCommitResult(applied.ids, applied);
      } catch (err) {
        return mailErrorResult(err);
      }
    },
  );
}
