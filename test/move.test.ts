// The move TOOLS, driven from their registered callbacks down to the bytes.
//
// iCloud has no move command, so every move here is an emulation: the copy,
// proven from the server's reply; the removal mark, conditional on the MODSEQ
// the preview sealed; the removal of that one UID; and a re-read of the source.
// The hazard is that a wrong version still looks like success, so the
// assertions are on the RECORDED BYTES and their ORDER, and on what the server
// sent back, never on a tagged OK alone (PITFALLS #31, #34, #35).
//
// The preview runs on the read path and has its own golden here. The read-path
// golden file, test/read-path-wire.test.ts, is not touched.
//
// The socket module is mocked for this file only, so each call's connect step
// hands back an in-memory duplex: the preview's first, then the commit's.
// Nothing here opens a network connection and nothing signs in to a real Apple
// ID (D-13: live Apple testing is owner-only). The login line is redacted
// before every comparison, as in test/triage.test.ts.

import type { McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/mail/socket", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/mail/socket")>()),
  connectImap: vi.fn(),
}));

import {
  decodeMessageId,
  encodeFolderId,
  encodeMessageId,
} from "../src/mail/ids";
import {
  CONFIRM_TTL_SECONDS,
  CONFIRM_VERSION,
  mailMoveChangeHashOf,
  mintConfirmation,
} from "../src/confirm";
import { ImapConnectError } from "../src/errors";
import { createLeasedMail } from "../src/agent/lease";
import { createSessionGate, resolveRoleFolder } from "../src/mail/service";
import type { FolderListing, FolderSummary } from "../src/mail/service";
import { decodeModifiedUtf7, resolveFolderRole } from "../src/mail/imap-parser";
import { connectImap } from "../src/mail/socket";
import { moveMessagesOver } from "../src/mail/triage";
import type { MoveEntry, MoveOutcome } from "../src/mail/triage";
import { registerMailTools } from "../src/mcp/tools/mail";
import {
  GREETING,
  INBOX_UIDVALIDITY,
  MEASURED_EMPTY_SEARCH_COMPLETION,
  MEASURED_ESEARCH_GONE_LINE,
  MEASURED_ESEARCH_PRESENT_LINE,
  MEASURED_POST_AUTH_CAPABILITY,
  POST_AUTH_CAPABILITY,
  PRE_AUTH_CAPABILITY,
  capabilityResponse,
  emptySearchReply,
  esearchCountReply,
  examineResponse,
  logoutExchange,
  selectResponse,
  taggedOk,
  wire,
} from "./fixtures/icloud-bytes";
import { createFakeDuplex, createStallingDuplex } from "./fixtures/fake-duplex";
import type { FakeDuplex } from "./fixtures/fake-duplex";
import { ownerPrincipal } from "./fixtures/bound-secrets";

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

describe.each([false, true])("mail moves (mailOnly=%s)", (mailOnly) => {

type ToolAnswer = { content: { type: "text"; text: string }[]; isError?: boolean };
type Callback = (args: Record<string, unknown>) => Promise<ToolAnswer>;

/** The callbacks the mail tools register, on one gate, as one request would. */
function tools(): { move: Callback; commit: Callback } {
  const callbacks = new Map<string, Callback>();
  const server = {
    registerTool(name: string, _options: unknown, handler: Callback) {
      callbacks.set(name, handler);
    },
  };
  registerMailTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), ownerPrincipal(), mailOnly);
  expect(callbacks.get("mail_move"), "mail_move is not registered").toBeDefined();
  expect(callbacks.get("mail_commit"), "mail_commit is not registered").toBeDefined();
  return { move: callbacks.get("mail_move")!, commit: callbacks.get("mail_commit")! };
}

/** The fixed text a credential-carrying line is reduced to. */
const REDACTED = "[redacted]";

/** Every written line, with the login line redacted. */
function wireOf(duplex: FakeDuplex): string[] {
  return duplex.writtenLines().map((line) => {
    const tokens = line.split(" ");
    if ((tokens[1] ?? "").toUpperCase() === "LOGIN") {
      return `${tokens[0]} ${tokens[1]} ${REDACTED}`;
    }
    return line;
  });
}

/**
 * The post-login capability line these moves run under: the one iCloud really
 * sent. It advertises UIDPLUS and CONDSTORE, which a move needs, and ESEARCH,
 * which the re-read's count form needs (21-08).
 */
const MOVE_CAPABILITY = MEASURED_POST_AUTH_CAPABILITY;

/** The four turns every conversation opens with. The next tag is `a4`. */
function authPrefix(capability = MOVE_CAPABILITY): Uint8Array[] {
  return [
    GREETING,
    capabilityResponse("a1", PRE_AUTH_CAPABILITY),
    taggedOk("a2", "LOGIN completed"),
    capabilityResponse("a3", capability),
  ];
}

/** The lines every session writes before its mailbox open. */
const SIGN_IN = ["a1 CAPABILITY", `a2 LOGIN ${REDACTED}`, "a3 CAPABILITY"];

// ---------------------------------------------------------------------------
// Local fixture builders. Used by this file only.
// ---------------------------------------------------------------------------

const ENCODER = new TextEncoder();

/** The destination folder's wire name. */
const RECEIPTS = "Receipts";

/**
 * The destination's UIDVALIDITY, deliberately DIFFERENT from the source's.
 *
 * RFC 4315 §3 puts the destination's validity first in COPYUID. A fixture where
 * the two were equal would pass whichever field a parser read (PITFALLS #35).
 */
const RECEIPTS_UIDVALIDITY = 1_726_000_001;

/** The internal date every fixture message carries, and its seconds. */
const INTERNAL_DATE = "13-Aug-2026 09:14:02 -0700";

/** A folder listing with INBOX and Receipts, then its completion. */
function listingReply(tag: string): Uint8Array {
  return wire(
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* STATUS "INBOX" (MESSAGES 172 UNSEEN 3)',
    `* LIST (\\HasNoChildren) "/" "${RECEIPTS}"`,
    `* STATUS "${RECEIPTS}" (MESSAGES 10 UNSEEN 0)`,
    `${tag} OK LIST completed`,
  );
}

/** One message as the fixtures describe it. */
interface Fixture {
  uid: number;
  size: number;
  modSeq: string;
  subject: string;
}

/** The fingerprint items of one message, as a FETCH reply's list. */
function fingerprintItems(message: Fixture): string {
  return (
    `UID ${message.uid} FLAGS (\\Seen) RFC822.SIZE ${message.size} ` +
    `INTERNALDATE "${INTERNAL_DATE}" MODSEQ (${message.modSeq})`
  );
}

/** The preview's fetch reply: fingerprint items plus a header literal each. */
function previewFetchReply(tag: string, messages: Fixture[]): Uint8Array {
  const parts: Uint8Array[] = [];
  messages.forEach((message, index) => {
    const header = ENCODER.encode(
      `Subject: ${message.subject}\r\nFrom: Shop <shop@example.com>\r\n` +
        "Date: Thu, 13 Aug 2026 09:14:02 -0700\r\n\r\n",
    );
    parts.push(
      ENCODER.encode(
        `* ${index + 1} FETCH (${fingerprintItems(message)} ` +
          `BODY[HEADER.FIELDS (SUBJECT FROM DATE)] {${header.byteLength}}\r\n`,
      ),
      header,
      ENCODER.encode(")\r\n"),
    );
  });
  parts.push(ENCODER.encode(`${tag} OK FETCH completed\r\n`));
  return concat(parts);
}

/** The commit's fingerprint re-read reply. */
function fingerprintReply(tag: string, messages: Fixture[]): Uint8Array {
  return wire(
    ...messages.map((message, index) => `* ${index + 1} FETCH (${fingerprintItems(message)})`),
    `${tag} OK FETCH completed`,
  );
}

/** A copy's completion carrying COPYUID: destination validity FIRST. */
function copyReply(tag: string, sourceUid: number, newUid: number): Uint8Array {
  return wire(
    `${tag} OK [COPYUID ${RECEIPTS_UIDVALIDITY} ${sourceUid} ${newUid}] COPY completed`,
  );
}

/** The removal mark's echo, then its completion. */
function markEcho(tag: string, uid: number, modSeq: string): Uint8Array {
  return wire(
    `* 1 FETCH (UID ${uid} MODSEQ (${modSeq}) FLAGS (\\Seen \\Deleted))`,
    `${tag} OK STORE completed`,
  );
}


function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

/** A message id in INBOX. */
function idOf(uid: number): string {
  return encodeMessageId({ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY, uid });
}

const RECEIPTS_ID = encodeFolderId({ mailbox: RECEIPTS });

/** The preview's conversation for `messages`. Its logout is tag `a7`. */
function previewServer(messages: Fixture[]): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    listingReply("a5"),
    previewFetchReply("a6", messages),
    logoutExchange("a7"),
  ]);
}

/** The preview's whole recorded line array for `uids`. */
function previewLines(uids: number[]): string[] {
  return [
    ...SIGN_IN,
    'a4 EXAMINE "INBOX"',
    'a5 LIST "" "*" RETURN (STATUS (MESSAGES UNSEEN))',
    `a6 UID FETCH ${uids.join(",")} (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ ` +
      "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])",
    "a7 LOGOUT",
  ];
}

/** Parse a text block of an answer. */
function body(answer: ToolAnswer, index = 0): Record<string, unknown> {
  return JSON.parse(answer.content[index]!.text) as Record<string, unknown>;
}

beforeEach(() => {
  vi.mocked(connectImap).mockReset();
});

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

describe("move one message to a named folder, previewed and committed", () => {
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "Receipt" };

  it("previews on the read path, then moves, and reports moved from the re-read", async () => {
    const { move, commit } = tools();
    const preview = previewServer([MESSAGE]);
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      fingerprintReply("a5", [MESSAGE]),
      copyReply("a6", MESSAGE.uid, 88),
      markEcho("a7", MESSAGE.uid, "743"),
      wire("* 1 EXPUNGE", "a8 OK EXPUNGE completed"),
      esearchCountReply("a9", 0),
      logoutExchange("a10"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(MESSAGE.uid)];
    const previewed = await move({ ids, destination: RECEIPTS_ID });

    expect(previewed.isError).toBeUndefined();
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    const trusted = body(previewed);
    expect(typeof trusted.confirmToken).toBe("string");
    expect(trusted.change).toEqual({ op: "move", ids, destination: RECEIPTS_ID });
    expect(trusted.confirmationLine).toBe(
      "Moving 1 message from 'INBOX' to 'Receipts'. It can be moved back.",
    );
    expect(trusted.count).toBe(1);
    // The stranger-authored half sits behind the fence, not in the trusted block.
    expect(previewed.content[0]!.text).not.toContain("Receipt for");
    expect(previewed.content[1]!.text).toContain('"subject":"Receipt"');

    const answer = await commit({
      confirmToken: trusted.confirmToken,
      change: trusted.change,
    });

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(committed)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 UID FETCH 4242 (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)",
      'a6 UID COPY 4242 "Receipts"',
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID EXPUNGE 4242",
      "a9 UID SEARCH RETURN (COUNT) UID 4242",
      "a10 LOGOUT",
    ]);

    const result = body(answer) as {
      confirmationLine: string;
      results: { id: string; outcome: string; reason: string; newId: string; destination: string }[];
    };
    expect(result.confirmationLine).toBe(
      "Moved 1 message from 'INBOX' to 'Receipts'. It can be moved back.",
    );
    expect(result.results).toHaveLength(1);
    expect(result.results[0]).toMatchObject({
      id: ids[0],
      outcome: "moved",
      reason: "verified-gone",
      destination: RECEIPTS_ID,
    });
    // The new id carries the DESTINATION's validity from COPYUID, never the
    // source's (PITFALLS #35).
    expect(decodeMessageId(result.results[0]!.newId)).toEqual({
      mailbox: RECEIPTS,
      uidValidity: RECEIPTS_UIDVALIDITY,
      uid: 88,
    });
    expect(RECEIPTS_UIDVALIDITY).not.toBe(INBOX_UIDVALIDITY);
  });

  it("refuses to spend the same confirmation twice", async () => {
    const { move, commit } = tools();
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewServer([MESSAGE]) as never)
      .mockReturnValueOnce(
        createFakeDuplex([
          ...authPrefix(),
          selectResponse("a4", "[READ-WRITE]"),
          fingerprintReply("a5", [MESSAGE]),
          copyReply("a6", MESSAGE.uid, 88),
          markEcho("a7", MESSAGE.uid, "743"),
          wire("a8 OK EXPUNGE completed"),
          esearchCountReply("a9", 0),
          logoutExchange("a10"),
        ]) as never,
      );

    const trusted = body(await move({ ids: [idOf(MESSAGE.uid)], destination: RECEIPTS_ID }));
    await commit({ confirmToken: trusted.confirmToken, change: trusted.change });
    const again = await commit({ confirmToken: trusted.confirmToken, change: trusted.change });

    expect(again.isError).toBe(true);
    expect(body(again).category).toBe("confirmation_invalid");
    // The second commit opened nothing.
    expect(connectImap).toHaveBeenCalledTimes(2);
  });
});

describe("move two messages in one session", () => {
  const FIRST: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "One" };
  const SECOND: Fixture = { uid: 4250, size: 2_048, modSeq: "760", subject: "Two" };

  it("fetches both fingerprints at once, then each message's four lines in the caller's order", async () => {
    const { move, commit } = tools();
    const preview = previewServer([FIRST, SECOND]);
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      fingerprintReply("a5", [FIRST, SECOND]),
      copyReply("a6", FIRST.uid, 88),
      markEcho("a7", FIRST.uid, "761"),
      wire("a8 OK EXPUNGE completed"),
      esearchCountReply("a9", 0),
      copyReply("a10", SECOND.uid, 89),
      markEcho("a11", SECOND.uid, "762"),
      wire("a12 OK EXPUNGE completed"),
      esearchCountReply("a13", 0),
      logoutExchange("a14"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(FIRST.uid), idOf(SECOND.uid)];
    const trusted = body(await move({ ids, destination: RECEIPTS_ID }));

    expect(wireOf(preview)).toEqual(previewLines([FIRST.uid, SECOND.uid]));
    expect(trusted.confirmationLine).toBe(
      "Moving 2 messages from 'INBOX' to 'Receipts'. They can be moved back.",
    );

    const answer = body(
      await commit({ confirmToken: trusted.confirmToken, change: trusted.change }),
    ) as { confirmationLine: string; results: { id: string; outcome: string; newId: string }[] };

    expect(wireOf(committed)).toEqual([
      ...SIGN_IN,
      'a4 SELECT "INBOX"',
      "a5 UID FETCH 4242,4250 (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)",
      'a6 UID COPY 4242 "Receipts"',
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID EXPUNGE 4242",
      "a9 UID SEARCH RETURN (COUNT) UID 4242",
      'a10 UID COPY 4250 "Receipts"',
      "a11 UID STORE 4250 (UNCHANGEDSINCE 760) +FLAGS (\\Deleted)",
      "a12 UID EXPUNGE 4250",
      "a13 UID SEARCH RETURN (COUNT) UID 4250",
      "a14 LOGOUT",
    ]);
    expect(answer.confirmationLine).toBe(
      "Moved 2 messages from 'INBOX' to 'Receipts'. They can be moved back.",
    );
    expect(answer.results.map((one) => [one.id, one.outcome])).toEqual([
      [ids[0], "moved"],
      [ids[1], "moved"],
    ]);
    expect(decodeMessageId(answer.results[1]!.newId).uid).toBe(89);
  });
});

describe("a MODSEQ past 2^53", () => {
  // RFC 7162 permits 63 bits. This value and its neighbour are the same JS
  // number, so a MODSEQ that went through one would arrive on the wire wrong.
  const BIG = "4611686018427387905";
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: BIG, subject: "Big" };

  it("reaches the removal-mark line byte for byte", async () => {
    const { move, commit } = tools();
    const committed = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]"),
      fingerprintReply("a5", [MESSAGE]),
      copyReply("a6", MESSAGE.uid, 88),
      markEcho("a7", MESSAGE.uid, "4611686018427387906"),
      wire("a8 OK EXPUNGE completed"),
      esearchCountReply("a9", 0),
      logoutExchange("a10"),
    ]);
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewServer([MESSAGE]) as never)
      .mockReturnValueOnce(committed as never);

    const trusted = body(await move({ ids: [idOf(MESSAGE.uid)], destination: RECEIPTS_ID }));
    await commit({ confirmToken: trusted.confirmToken, change: trusted.change });

    expect(wireOf(committed)).toContain(
      `a7 UID STORE 4242 (UNCHANGEDSINCE ${BIG}) +FLAGS (\\Deleted)`,
    );
    expect(String(Number(BIG))).not.toBe(BIG);
  });
});

describe("the verdict comes from the re-read, not from an OK (TRIA-06)", () => {
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "Still" };

  it("reports copied_not_removed when the removal answers OK and the search still lists the UID", async () => {
    const { move, commit } = tools();
    vi.mocked(connectImap)
      .mockReturnValueOnce(previewServer([MESSAGE]) as never)
      .mockReturnValueOnce(
        createFakeDuplex([
          ...authPrefix(),
          selectResponse("a4", "[READ-WRITE]"),
          fingerprintReply("a5", [MESSAGE]),
          copyReply("a6", MESSAGE.uid, 88),
          markEcho("a7", MESSAGE.uid, "743"),
          wire("a8 OK EXPUNGE completed"),
          esearchCountReply("a9", 1),
          logoutExchange("a10"),
        ]) as never,
      );

    const trusted = body(await move({ ids: [idOf(MESSAGE.uid)], destination: RECEIPTS_ID }));
    const answer = body(
      await commit({ confirmToken: trusted.confirmToken, change: trusted.change }),
    ) as { confirmationLine: string; results: { outcome: string; reason: string; newId: string }[] };

    expect(answer.results[0]).toMatchObject({
      outcome: "copied_not_removed",
      reason: "still-in-source",
    });
    // The copy was proven, so the answer still says where it went.
    expect(decodeMessageId(answer.results[0]!.newId).uidValidity).toBe(RECEIPTS_UIDVALIDITY);
    expect(answer.confirmationLine).toBe(
      "Moved 0 of 1 message from 'INBOX' to 'Receipts'; 1 copied but not removed. " +
        "It can be moved back.",
    );
  });
});

// ---------------------------------------------------------------------------
// Every way a move can end (21-02 Task 1)
//
// These drive the verb directly over a fake duplex, so each case can script a
// reply the tool path never would. Every case asserts the WHOLE recorded line
// array and the outcome together: an outcome alone cannot tell a removal that
// was skipped from one that was sent and ignored.
// ---------------------------------------------------------------------------

/** Short bounds, so no ordinary case here costs wall time. */
const VERB_BOUNDS = {
  readTimeoutMs: 40,
  drainTimeoutMs: 20,
  closeTimeoutMs: 20,
  callDeadlineMs: 5_000,
};

/** `INTERNAL_DATE` as whole seconds since the epoch, as a preview seals it. */
const INTERNAL_SECONDS = Date.UTC(2026, 7, 13, 16, 14, 2) / 1000;

const INBOX_SOURCE = { mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY };

const ONE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "One" };
const TWO: Fixture = { uid: 4250, size: 2_048, modSeq: "760", subject: "Two" };
const THREE: Fixture = { uid: 4260, size: 512, modSeq: "771", subject: "Three" };

/** The entry a preview of `message` would have sealed. */
function entryOf(message: Fixture): MoveEntry {
  return {
    uid: message.uid,
    size: message.size,
    internalDate: INTERNAL_SECONDS,
    modSeq: message.modSeq,
  };
}

/** Run the verb over `duplex` and hand back its answer. */
async function runMove(
  duplex: FakeDuplex,
  messages: Fixture[],
  options: Record<string, number> = VERB_BOUNDS,
): Promise<MoveOutcome> {
  return moveMessagesOver(
    duplex,
    await ownerPrincipal(),
    createSessionGate(),
    INBOX_SOURCE,
    messages.map(entryOf),
    RECEIPTS,
    options,
  );
}

/** A read-write open with the default permanent flags. */
function writableOpen(tag = "a4"): Uint8Array {
  return selectResponse(tag, "[READ-WRITE]");
}

/** The lines of one message's full four-step move, from tag `a<n>`. */
function fullMoveLines(n: number, message: Fixture): string[] {
  return [
    `a${n} UID COPY ${message.uid} "${RECEIPTS}"`,
    `a${n + 1} UID STORE ${message.uid} (UNCHANGEDSINCE ${message.modSeq}) +FLAGS (\\Deleted)`,
    `a${n + 2} UID EXPUNGE ${message.uid}`,
    `a${n + 3} UID SEARCH RETURN (COUNT) UID ${message.uid}`,
  ];
}

/** The replies of one message's clean move, from tag `a<n>`. */
function fullMoveReplies(n: number, message: Fixture, newUid: number): Uint8Array[] {
  return [
    copyReply(`a${n}`, message.uid, newUid),
    markEcho(`a${n + 1}`, message.uid, "9001"),
    wire(`a${n + 2} OK EXPUNGE completed`),
    esearchCountReply(`a${n + 3}`, 0),
  ];
}

/** The commit's opening lines for `messages`: the open, then the whole-list check. */
function openAndCheckLines(messages: Fixture[]): string[] {
  return [
    ...SIGN_IN,
    'a4 SELECT "INBOX"',
    `a5 UID FETCH ${messages.map((m) => m.uid).join(",")} ` +
      "(UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)",
  ];
}

/**
 * The command word of a recorded line, past its tag and any `UID` prefix, with
 * the first argument: `"STORE 4242"`, `"COPY 4242"`, `"LOGOUT "`.
 */
function commandOf(line: string): { word: string; uid: string } {
  const tokens = line.split(" ");
  const rest = (tokens[1] ?? "").toUpperCase() === "UID" ? tokens.slice(2) : tokens.slice(1);
  const word = (rest[0] ?? "").toUpperCase();
  // SEARCH names its UID last, after the `UID` search key.
  const uid = word === "SEARCH" ? (rest[rest.length - 1] ?? "") : (rest[1] ?? "");
  return { word, uid };
}

/** Assert that no recorded line sends `word` for `uid` (any UID when omitted). */
function expectNoLine(lines: string[], word: string, uid?: number): void {
  const hits = lines.filter((line) => {
    const command = commandOf(line);
    return command.word === word && (uid === undefined || command.uid === String(uid));
  });
  expect(hits, `a ${word}${uid === undefined ? "" : ` for ${uid}`} was sent`).toEqual([]);
}

/** The three commands that change mail, after the copy. */
const CHANGING = ["COPY", "STORE", "EXPUNGE"] as const;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A duplex whose every chunk waits `delayMs` before it is handed over.
 *
 * Models a slow server: each reply takes a while, so a list's time runs out
 * part-way through. Built over `createFakeDuplex` so the recording is the same.
 */
function slowDuplex(script: Uint8Array[], delayMs: number): FakeDuplex {
  const fake = createFakeDuplex(script);
  const inner = fake.readable.getReader();
  const readable = new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        await sleep(delayMs);
        const { value, done } = await inner.read();
        if (done) controller.close();
        else controller.enqueue(value);
      },
    },
    { highWaterMark: 0 },
  );
  return { ...fake, readable };
}

describe("every way a move can end", () => {
  it("copy answered NO: not_copied, copy-refused, nothing more for it, and the next message still moves", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE, TWO]),
      wire("a6 NO [OVERQUOTA] COPY failed"),
      ...fullMoveReplies(7, TWO, 89),
      logoutExchange("a11"),
    ]);

    const outcome = await runMove(duplex, [ONE, TWO]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE, TWO]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      ...fullMoveLines(7, TWO),
      "a11 LOGOUT",
    ]);
    for (const word of ["STORE", "EXPUNGE", "SEARCH"]) expectNoLine(lines, word, ONE.uid);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "not_copied", reason: "copy-refused", newUid: null, destinationUidValidity: null },
        { uid: 4250, outcome: "moved", reason: "verified-gone", newUid: 89, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it.each([
    ["no COPYUID at all", "a6 OK COPY completed"],
    ["a COPYUID naming a different source UID", `a6 OK [COPYUID ${RECEIPTS_UIDVALIDITY} 4243 88] COPY completed`],
    ["a COPYUID with two destination UIDs", `a6 OK [COPYUID ${RECEIPTS_UIDVALIDITY} 4242,4243 88,89] COPY completed`],
  ])("copy OK with %s: copied_not_removed, copy-unproven, and nothing more for it", async (_label, reply) => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      wire(reply),
      logoutExchange("a7"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      "a7 LOGOUT",
    ]);
    for (const word of ["STORE", "EXPUNGE", "SEARCH"]) expectNoLine(lines, word, ONE.uid);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "copied_not_removed", reason: "copy-unproven", newUid: null, destinationUidValidity: null },
      ],
    });
  });

  it.each([
    ["OK", "a7 OK [MODIFIED 4242] Conditional STORE failed"],
    ["NO", "a7 NO [MODIFIED 4242] Conditional STORE failed"],
  ])("removal mark answered %s [MODIFIED]: no removal, the search runs, changed-since-preview", async (_label, reply) => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      wire(reply),
      esearchCountReply("a8", 1),
      logoutExchange("a9"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID SEARCH RETURN (COUNT) UID 4242",
      "a9 LOGOUT",
    ]);
    expectNoLine(lines, "EXPUNGE");
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "copied_not_removed", reason: "changed-since-preview", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it("removal mark answered NO with no code: copied_not_removed, mark-refused, no removal", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      wire("a7 NO STORE failed"),
      esearchCountReply("a8", 1),
      logoutExchange("a9"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID SEARCH RETURN (COUNT) UID 4242",
      "a9 LOGOUT",
    ]);
    expectNoLine(lines, "EXPUNGE");
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "copied_not_removed", reason: "mark-refused", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it("removal answered NO and the search still lists the UID: copied_not_removed, removal-refused", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      markEcho("a7", ONE.uid, "743"),
      wire("a8 NO EXPUNGE failed"),
      esearchCountReply("a9", 1),
      logoutExchange("a10"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([
      ...openAndCheckLines([ONE]),
      ...fullMoveLines(6, ONE),
      "a10 LOGOUT",
    ]);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "copied_not_removed", reason: "removal-refused", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it("removal mark refused but the search no longer lists the UID: moved, verified-gone", async () => {
    // Someone else removed the original in the meantime. The copy is proven in
    // the destination and the source no longer holds it, which is a move.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      wire("a7 NO STORE failed"),
      esearchCountReply("a8", 0),
      logoutExchange("a9"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID SEARCH RETURN (COUNT) UID 4242",
      "a9 LOGOUT",
    ]);
    expectNoLine(lines, "EXPUNGE");
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "moved", reason: "verified-gone", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it.each([
    ["NO", "a9 NO SEARCH failed"],
    ["BAD", "a9 BAD Invalid search"],
  ])("search answered %s: unknown, verify-refused, with the proven copy", async (_label, reply) => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      markEcho("a7", ONE.uid, "743"),
      wire("a8 OK EXPUNGE completed"),
      wire(reply),
      logoutExchange("a10"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([
      ...openAndCheckLines([ONE]),
      ...fullMoveLines(6, ONE),
      "a10 LOGOUT",
    ]);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "unknown", reason: "verify-refused", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  const STALE: [string, (message: Fixture) => string][] = [
    ["its MODSEQ", (m) => `* 1 FETCH (UID ${m.uid} FLAGS (\\Seen) RFC822.SIZE ${m.size} INTERNALDATE "${INTERNAL_DATE}" MODSEQ (999))`],
    ["its size", (m) => `* 1 FETCH (UID ${m.uid} FLAGS (\\Seen) RFC822.SIZE ${m.size + 1} INTERNALDATE "${INTERNAL_DATE}" MODSEQ (${m.modSeq}))`],
    ["its internal date", (m) => `* 1 FETCH (UID ${m.uid} FLAGS (\\Seen) RFC822.SIZE ${m.size} INTERNALDATE "13-Aug-2026 09:14:03 -0700" MODSEQ (${m.modSeq}))`],
    ["no reply for it at all", () => "* 1 FETCH (UID 1 FLAGS (\\Seen))"],
  ];

  it.each(STALE)("whole-list check where one message differs in %s: changed-since-preview naming it, and no copy anywhere", async (_label, staleLine) => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      wire(
        `* 2 FETCH (${fingerprintItems(ONE)})`,
        staleLine(TWO),
        `* 3 FETCH (${fingerprintItems(THREE)})`,
        "a5 OK FETCH completed",
      ),
      logoutExchange("a6"),
    ]);

    const outcome = await runMove(duplex, [ONE, TWO, THREE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([...openAndCheckLines([ONE, TWO, THREE]), "a6 LOGOUT"]);
    for (const word of CHANGING) expectNoLine(lines, word);
    expect(outcome).toEqual({
      applied: false,
      refusal: "changed-since-preview",
      changedUids: [TWO.uid],
    });
  });

  it("an open that completes read-only: mailbox-read-only, nothing after the open", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-ONLY]"),
      logoutExchange("a5"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([...SIGN_IN, 'a4 SELECT "INBOX"', "a5 LOGOUT"]);
    expect(outcome).toEqual({ applied: false, refusal: "mailbox-read-only" });
  });

  it("a permanent-flags list with the seen flag but not the removal mark: removal-not-kept, nothing after the open", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 172, INBOX_UIDVALIDITY, "\\Answered \\Seen \\*"),
      logoutExchange("a5"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([...SIGN_IN, 'a4 SELECT "INBOX"', "a5 LOGOUT"]);
    expect(outcome).toEqual({ applied: false, refusal: "removal-not-kept" });
  });

  it("a permanent-flags list with the removal mark but not the seen flag: goes on and moves (D-08)", async () => {
    // Before 21-04 the orchestrator refused any open without the seen flag.
    // A move needs only the removal mark, so it now goes on.
    const duplex = createFakeDuplex([
      ...authPrefix(),
      selectResponse("a4", "[READ-WRITE]", 172, INBOX_UIDVALIDITY, "\\Deleted"),
      fingerprintReply("a5", [ONE]),
      ...fullMoveReplies(6, ONE, 88),
      logoutExchange("a10"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([
      ...openAndCheckLines([ONE]),
      ...fullMoveLines(6, ONE),
      "a10 LOGOUT",
    ]);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "moved", reason: "verified-gone", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it.each([
    ["UIDPLUS", MOVE_CAPABILITY.replace(" UIDPLUS", "")],
    ["CONDSTORE", MOVE_CAPABILITY.replace(" CONDSTORE", "")],
  ])("a post-login capability without %s: commands-unavailable, nothing after the open", async (missing, capability) => {
    expect(capability.split(" ")).not.toContain(missing);
    const duplex = createFakeDuplex([
      GREETING,
      capabilityResponse("a1", PRE_AUTH_CAPABILITY),
      taggedOk("a2", "LOGIN completed"),
      capabilityResponse("a3", capability),
      writableOpen(),
      logoutExchange("a5"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([...SIGN_IN, 'a4 SELECT "INBOX"', "a5 LOGOUT"]);
    expect(outcome).toEqual({ applied: false, refusal: "commands-unavailable" });
  });

  it("a connection lost right after the first copy: that one unknown, the rest not attempted, and results rather than an error", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE, TWO, THREE]),
      // The script ends here, so the copy's reply never comes.
    ]);

    const outcome = await runMove(duplex, [ONE, TWO, THREE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE, TWO, THREE]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      "a7 LOGOUT",
    ]);
    expectNoLine(lines, "COPY", TWO.uid);
    expectNoLine(lines, "COPY", THREE.uid);
    expectNoLine(lines, "STORE");
    expectNoLine(lines, "EXPUNGE");
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "unknown", reason: "connection-lost", newUid: null, destinationUidValidity: null },
        { uid: 4250, outcome: "not_copied", reason: "not-attempted", newUid: null, destinationUidValidity: null },
        { uid: 4260, outcome: "not_copied", reason: "not-attempted", newUid: null, destinationUidValidity: null },
      ],
    });
  });

  it("a connection lost during the whole-list check: a connection failure, and no copy", async () => {
    const duplex = createFakeDuplex([
      ...authPrefix(),
      writableOpen(),
      // The script ends before the fingerprint reply.
    ]);

    await expect(runMove(duplex, [ONE, TWO])).rejects.toBeInstanceOf(ImapConnectError);

    const lines = wireOf(duplex);
    expect(lines).toEqual([...openAndCheckLines([ONE, TWO]), "a6 LOGOUT"]);
    for (const word of CHANGING) expectNoLine(lines, word);
  });

  it("the call deadline firing while the second copy waits: first moved, second unknown, third not copied, and nothing changing after it", async () => {
    const duplex = createStallingDuplex([
      ...authPrefix(),
      writableOpen(),
      fingerprintReply("a5", [ONE, TWO, THREE]),
      ...fullMoveReplies(6, ONE, 88),
      // The second copy's reply never comes, and the stream never ends.
    ]);

    const outcome = await runMove(duplex, [ONE, TWO, THREE], {
      readTimeoutMs: 400,
      drainTimeoutMs: 20,
      closeTimeoutMs: 20,
      callDeadlineMs: 120,
    });

    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "moved", reason: "verified-gone", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
        { uid: 4250, outcome: "unknown", reason: "connection-lost", newUid: null, destinationUidValidity: null },
        { uid: 4260, outcome: "not_copied", reason: "not-attempted", newUid: null, destinationUidValidity: null },
      ],
    });

    // Give any late continuation of the abandoned step time to act.
    await sleep(500);
    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE, TWO, THREE]),
      ...fullMoveLines(6, ONE),
      `a10 UID COPY 4250 "${RECEIPTS}"`,
      "a11 LOGOUT",
    ]);
    for (const uid of [TWO.uid, THREE.uid]) {
      expectNoLine(lines, "STORE", uid);
      expectNoLine(lines, "EXPUNGE", uid);
    }
    expectNoLine(lines, "COPY", THREE.uid);
  });

  it("replies slow enough that half the call deadline passes during the first message: the rest not attempted, with no line", async () => {
    const duplex = slowDuplex(
      [
        ...authPrefix(),
        writableOpen(),
        fingerprintReply("a5", [ONE, TWO, THREE]),
        ...fullMoveReplies(6, ONE, 88),
        logoutExchange("a10"),
      ],
      80,
    );

    const outcome = await runMove(duplex, [ONE, TWO, THREE], {
      readTimeoutMs: 1_000,
      drainTimeoutMs: 20,
      closeTimeoutMs: 20,
      // Half is 320ms. The check and the first message take about 400.
      callDeadlineMs: 640,
    });

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE, TWO, THREE]),
      ...fullMoveLines(6, ONE),
      "a10 LOGOUT",
    ]);
    for (const uid of [TWO.uid, THREE.uid]) {
      for (const word of [...CHANGING, "SEARCH"]) expectNoLine(lines, word, uid);
    }
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "moved", reason: "verified-gone", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
        { uid: 4250, outcome: "not_copied", reason: "not-attempted", newUid: null, destinationUidValidity: null },
        { uid: 4260, outcome: "not_copied", reason: "not-attempted", newUid: null, destinationUidValidity: null },
      ],
    });
  });
});


// ---------------------------------------------------------------------------
// The re-read on iCloud's real replies (21-08)
//
// Live on 2026-09-27, every move that worked reported unknown. iCloud sends no
// untagged search line when a plain search matches nothing, so the old re-read
// never saw an answer (21-UAT.md, "Probe, 2026-09-27"). The re-read now asks
// for a count, which iCloud always answers. Every reply below is iCloud's
// measured shape, retagged to this conversation.
// ---------------------------------------------------------------------------

describe("the re-read asks for a count, and only a count for this command is an answer", () => {
  /** Script one clean copy, mark and removal of ONE, then `reread` as the re-read's reply. */
  function oneMoveWith(reread: Uint8Array, capability = MOVE_CAPABILITY): FakeDuplex {
    return createFakeDuplex([
      ...authPrefix(capability),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      markEcho("a7", ONE.uid, "743"),
      wire("a8 OK EXPUNGE completed"),
      reread,
      logoutExchange("a10"),
    ]);
  }

  const SENT = [
    `a6 UID COPY 4242 "${RECEIPTS}"`,
    "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
    "a8 UID EXPUNGE 4242",
    "a9 UID SEARCH RETURN (COUNT) UID 4242",
    "a10 LOGOUT",
  ];

  it("the measured lines are the ones the probe recorded", () => {
    expect(MEASURED_ESEARCH_GONE_LINE).toBe('* ESEARCH (TAG "a6") UID COUNT 0');
    expect(MEASURED_ESEARCH_PRESENT_LINE).toBe('* ESEARCH (TAG "a7") UID COUNT 1');
    expect(MEASURED_EMPTY_SEARCH_COMPLETION).toBe("a3 OK SEARCH completed");
  });

  it("COUNT 0: moved, verified-gone", async () => {
    const duplex = oneMoveWith(
      wire(MEASURED_ESEARCH_GONE_LINE.replace('"a6"', '"a9"'), "a9 OK SEARCH completed"),
    );

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([...openAndCheckLines([ONE]), ...SENT]);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "moved", reason: "verified-gone", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it("COUNT 1: copied_not_removed, still-in-source", async () => {
    const duplex = oneMoveWith(
      wire(MEASURED_ESEARCH_PRESENT_LINE.replace('"a7"', '"a9"'), "a9 OK SEARCH completed"),
    );

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([...openAndCheckLines([ONE]), ...SENT]);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "copied_not_removed", reason: "still-in-source", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it.each<[string, Uint8Array]>([
    // iCloud's real answer to a plain search that matched nothing. It must not
    // read as "gone": it is also exactly what a server that never looked sends.
    ["iCloud's empty plain-search shape: OK and no untagged line", emptySearchReply("a9")],
    ["a count line for another command's tag", wire(MEASURED_ESEARCH_GONE_LINE, "a9 OK SEARCH completed")],
    ["an empty plain search line instead of a count", wire("* SEARCH", "a9 OK SEARCH completed")],
    ["a count line with no number", wire('* ESEARCH (TAG "a9") UID COUNT', "a9 OK SEARCH completed")],
    ["two count lines for this tag that disagree", wire('* ESEARCH (TAG "a9") UID COUNT 0', '* ESEARCH (TAG "a9") UID COUNT 1', "a9 OK SEARCH completed")],
  ])("%s: unknown, verify-unanswered, never moved", async (_label, reread) => {
    const duplex = oneMoveWith(reread);

    const outcome = await runMove(duplex, [ONE]);

    expect(wireOf(duplex)).toEqual([...openAndCheckLines([ONE]), ...SENT]);
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "unknown", reason: "verify-unanswered", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });

  it("a server that does not advertise ESEARCH: the move still runs, no re-read is sent, and the answer is unknown, verify-unanswered", async () => {
    // The count form is needed only for the verdict. The copy, the mark and the
    // removal need UIDPLUS and CONDSTORE and nothing else, so they still run.
    const withoutEsearch = MOVE_CAPABILITY.split(" ")
      .filter((atom) => atom !== "ESEARCH")
      .join(" ");
    expect(withoutEsearch.split(" ")).not.toContain("ESEARCH");
    const duplex = createFakeDuplex([
      ...authPrefix(withoutEsearch),
      writableOpen(),
      fingerprintReply("a5", [ONE]),
      copyReply("a6", ONE.uid, 88),
      markEcho("a7", ONE.uid, "743"),
      wire("a8 OK EXPUNGE completed"),
      logoutExchange("a9"),
    ]);

    const outcome = await runMove(duplex, [ONE]);

    const lines = wireOf(duplex);
    expect(lines).toEqual([
      ...openAndCheckLines([ONE]),
      `a6 UID COPY 4242 "${RECEIPTS}"`,
      "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
      "a8 UID EXPUNGE 4242",
      "a9 LOGOUT",
    ]);
    expectNoLine(lines, "SEARCH");
    expect(outcome).toEqual({
      applied: true,
      results: [
        { uid: 4242, outcome: "unknown", reason: "verify-unanswered", newUid: 88, destinationUidValidity: RECEIPTS_UIDVALIDITY },
      ],
    });
  });
});

// ---------------------------------------------------------------------------
// The move tools refuse by name (21-02 Task 2)
//
// Through the registered callbacks, with `connectImap` counted. A refusal that
// can be decided from the input alone must not cost a connection, and a commit
// that does not match what was previewed must not reach one.
// ---------------------------------------------------------------------------

/** The four whole-mailbox wire lines a stale-free preview listing carries. */
function listingWith(tag: string, receiptsAttributes = "\\HasNoChildren"): Uint8Array {
  return wire(
    '* LIST (\\HasNoChildren) "/" "INBOX"',
    '* STATUS "INBOX" (MESSAGES 172 UNSEEN 3)',
    `* LIST (${receiptsAttributes}) "/" "${RECEIPTS}"`,
    `* STATUS "${RECEIPTS}" (MESSAGES 10 UNSEEN 0)`,
    `${tag} OK LIST completed`,
  );
}

/** A preview conversation whose listing and fetch reply the case chooses. */
function previewServerWith(listing: Uint8Array, fetched: Uint8Array): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    listing,
    fetched,
    logoutExchange("a7"),
  ]);
}

/** Assert a named refusal: plain JSON, no token, never `isError`. */
function expectRefusal(answer: ToolAnswer, refusal: string): Record<string, unknown> {
  expect(answer.isError, "a refusal is not an error").toBeUndefined();
  const parsed = body(answer);
  expect(parsed.refusal).toBe(refusal);
  expect(typeof parsed.reason).toBe("string");
  expect(parsed).not.toHaveProperty("confirmToken");
  return parsed;
}

/** Assert a tool error of `category`. */
function expectCategory(answer: ToolAnswer, category: string): void {
  expect(answer.isError).toBe(true);
  expect(body(answer).category).toBe(category);
}

describe("the move tools refuse by name", () => {
  describe("before any socket", () => {
    it("26 ids: too-many, naming the cap", async () => {
      const { move } = tools();
      const ids = Array.from({ length: 26 }, (_unused, index) => idOf(4000 + index));

      const parsed = expectRefusal(await move({ ids, destination: RECEIPTS_ID }), "too-many");

      expect(parsed.cap).toBe(25);
      expect(parsed.reason).toContain("25");
      expect(connectImap).not.toHaveBeenCalled();
    });

    it("the same id twice: duplicate-ids", async () => {
      const { move } = tools();

      const parsed = expectRefusal(
        await move({ ids: [idOf(4242), idOf(4250), idOf(4242)], destination: RECEIPTS_ID }),
        "duplicate-ids",
      );

      expect(parsed.ids).toEqual([idOf(4242)]);
      expect(connectImap).not.toHaveBeenCalled();
    });

    it.each([
      [
        "two folders",
        encodeMessageId({ mailbox: RECEIPTS, uidValidity: INBOX_UIDVALIDITY, uid: 7 }),
      ],
      [
        "one folder under two validities",
        encodeMessageId({ mailbox: "INBOX", uidValidity: INBOX_UIDVALIDITY + 1, uid: 7 }),
      ],
    ])("ids from %s: mixed-folders", async (_label, other) => {
      const { move } = tools();

      expectRefusal(
        await move({ ids: [idOf(4242), other], destination: RECEIPTS_ID }),
        "mixed-folders",
      );
      expect(connectImap).not.toHaveBeenCalled();
    });

    it.each([
      ["an undecodable id", { ids: [idOf(4242), "not-an-id"], destination: RECEIPTS_ID }],
      ["an undecodable destination", { ids: [idOf(4242)], destination: "not-a-folder" }],
    ])("%s: not_found", async (_label, args) => {
      const { move } = tools();

      expectCategory(await move(args), "not_found");
      expect(connectImap).not.toHaveBeenCalled();
    });
  });

  describe("after the one read session", () => {
    const ONE_P: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "One" };
    const TWO_P: Fixture = { uid: 4250, size: 2_048, modSeq: "760", subject: "Two" };

    async function refusedPreview(
      duplex: FakeDuplex,
      ids: string[],
      destination: string,
      refusal: string,
    ): Promise<Record<string, unknown>> {
      const { move } = tools();
      vi.mocked(connectImap).mockReturnValueOnce(duplex as never);
      const parsed = expectRefusal(await move({ ids, destination }), refusal);
      expect(connectImap).toHaveBeenCalledTimes(1);
      const lines = wireOf(duplex);
      // Read path only: the open is the read-only one, and nothing changes mail.
      expectNoLine(lines, "SELECT");
      for (const word of CHANGING) expectNoLine(lines, word);
      return parsed;
    }

    it("a UID the fetch does not answer: messages-not-found naming that id", async () => {
      const duplex = previewServerWith(listingWith("a5"), previewFetchReply("a6", [ONE_P]));

      const parsed = await refusedPreview(
        duplex,
        [idOf(ONE_P.uid), idOf(TWO_P.uid)],
        RECEIPTS_ID,
        "messages-not-found",
      );

      expect(parsed.ids).toEqual([idOf(TWO_P.uid)]);
      expect(wireOf(duplex)).toEqual(previewLines([ONE_P.uid, TWO_P.uid]));
    });

    it("a message already carrying the removal mark: already-marked-for-removal naming it", async () => {
      const duplex = previewServerWith(
        listingWith("a5"),
        wire(
          `* 1 FETCH (${fingerprintItems(ONE_P)})`,
          `* 2 FETCH (${fingerprintItems(TWO_P).replace("FLAGS (\\Seen)", "FLAGS (\\Seen \\Deleted)")})`,
          "a6 OK FETCH completed",
        ),
      );

      const parsed = await refusedPreview(
        duplex,
        [idOf(ONE_P.uid), idOf(TWO_P.uid)],
        RECEIPTS_ID,
        "already-marked-for-removal",
      );

      expect(parsed.ids).toEqual([idOf(TWO_P.uid)]);
    });

    it("the fetch answered BAD: no-change-numbers", async () => {
      const duplex = previewServerWith(listingWith("a5"), wire("a6 BAD MODSEQ not supported"));

      const parsed = await refusedPreview(
        duplex,
        [idOf(ONE_P.uid)],
        RECEIPTS_ID,
        "no-change-numbers",
      );

      expect(parsed.ids).toEqual([idOf(ONE_P.uid)]);
    });

    it("a destination no listed folder has: destination-not-found", async () => {
      await refusedPreview(
        previewServerWith(listingWith("a5"), previewFetchReply("a6", [ONE_P])),
        [idOf(ONE_P.uid)],
        encodeFolderId({ mailbox: "Archive" }),
        "destination-not-found",
      );
    });

    it("the source folder as the destination: destination-is-source", async () => {
      await refusedPreview(
        previewServerWith(listingWith("a5"), previewFetchReply("a6", [ONE_P])),
        [idOf(ONE_P.uid)],
        encodeFolderId({ mailbox: "INBOX" }),
        "destination-is-source",
      );
    });

    it("a destination listed as unselectable: destination-not-selectable", async () => {
      await refusedPreview(
        previewServerWith(
          listingWith("a5", "\\Noselect \\HasChildren"),
          previewFetchReply("a6", [ONE_P]),
        ),
        [idOf(ONE_P.uid)],
        RECEIPTS_ID,
        "destination-not-selectable",
      );
    });
  });

  describe("the commit gate", () => {
    const FIRST: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "One" };
    const SECOND: Fixture = { uid: 4250, size: 2_048, modSeq: "760", subject: "Two" };

    /** Preview FIRST and SECOND, and hand back the token and change. */
    async function previewed(move: Callback): Promise<{
      confirmToken: string;
      change: { op: string; ids: string[]; destination: string };
    }> {
      vi.mocked(connectImap).mockReturnValueOnce(previewServer([FIRST, SECOND]) as never);
      const trusted = body(
        await move({ ids: [idOf(FIRST.uid), idOf(SECOND.uid)], destination: RECEIPTS_ID }),
      );
      expect(typeof trusted.confirmToken).toBe("string");
      return trusted as never;
    }

    it.each([
      ["the destination swapped", (c: { ids: string[]; destination: string }) => ({ op: "move", ids: c.ids, destination: encodeFolderId({ mailbox: "Archive" }) })],
      ["the ids reordered", (c: { ids: string[]; destination: string }) => ({ op: "move", ids: [...c.ids].reverse(), destination: c.destination })],
      ["one id dropped", (c: { ids: string[]; destination: string }) => ({ op: "move", ids: c.ids.slice(0, 1), destination: c.destination })],
      ["an op that is not move", (c: { ids: string[]; destination: string }) => ({ op: "delete", ids: c.ids, destination: c.destination })],
    ])("a commit with %s: confirmation_invalid, and no socket", async (_label, alter) => {
      const { move, commit } = tools();
      const { confirmToken, change } = await previewed(move);
      expect(connectImap).toHaveBeenCalledTimes(1);

      const answer = await commit({ confirmToken, change: alter(change) });

      expectCategory(answer, "confirmation_invalid");
      expect(connectImap).toHaveBeenCalledTimes(1);
    });

    it("the same token committed twice: the second is confirmation_invalid, and the commit opened one socket", async () => {
      const { move, commit } = tools();
      const { confirmToken, change } = await previewed(move);
      vi.mocked(connectImap).mockReturnValueOnce(
        createFakeDuplex([
          ...authPrefix(),
          selectResponse("a4", "[READ-WRITE]"),
          fingerprintReply("a5", [FIRST, SECOND]),
          ...fullMoveReplies(6, FIRST, 88),
          ...fullMoveReplies(10, SECOND, 89),
          logoutExchange("a14"),
        ]) as never,
      );

      const first = await commit({ confirmToken, change });
      const again = await commit({ confirmToken, change });

      expect(first.isError).toBeUndefined();
      expectCategory(again, "confirmation_invalid");
      // One for the preview, one for the first commit, none for the second.
      expect(connectImap).toHaveBeenCalledTimes(2);
    });

    it("a mail token whose kind is not move: confirmation_invalid, and no socket", async () => {
      const { commit } = tools();
      const actor = await ownerPrincipal();
      const change = {
        op: "move" as const,
        ids: [idOf(FIRST.uid)],
        destination: RECEIPTS_ID,
      };
      // Everything a real move token carries, with the one field wrong.
      const token = await mintConfirmation(
        {
          v: CONFIRM_VERSION,
          t: "mail",
          k: "delete",
          j: crypto.randomUUID(),
          m: encodeFolderId({ mailbox: "INBOX" }),
          uv: INBOX_UIDVALIDITY,
          q: RECEIPTS_ID,
          qr: null,
          l: [{ i: FIRST.uid, z: FIRST.size, d: INTERNAL_SECONDS, n: FIRST.modSeq }],
          h: await mailMoveChangeHashOf(change),
          x: Math.floor(Date.now() / 1000) + CONFIRM_TTL_SECONDS,
          u: actor.userId,
        },
        env.CONFIRM_SECRET,
      );

      expectCategory(await commit({ confirmToken: token, change }), "confirmation_invalid");
      expect(connectImap).not.toHaveBeenCalled();
    });

    it("a commit that finds a message changed: changed-since-preview with the caller's ids, not an error", async () => {
      const { move, commit } = tools();
      const { confirmToken, change } = await previewed(move);
      const committed = createFakeDuplex([
        ...authPrefix(),
        selectResponse("a4", "[READ-WRITE]"),
        fingerprintReply("a5", [FIRST, { ...SECOND, modSeq: "999" }]),
        logoutExchange("a6"),
      ]);
      vi.mocked(connectImap).mockReturnValueOnce(committed as never);

      const answer = await commit({ confirmToken, change });

      expect(answer.isError).toBeUndefined();
      expect(body(answer)).toEqual({
        refusal: "changed-since-preview",
        reason:
          "These messages changed after the preview, so nothing was moved. Preview the move again.",
        changedIds: [idOf(SECOND.uid)],
      });
      const lines = wireOf(committed);
      expect(lines).toEqual([...openAndCheckLines([FIRST, SECOND]), "a6 LOGOUT"]);
      for (const word of CHANGING) expectNoLine(lines, word);
    });
  });
});

// ---------------------------------------------------------------------------
// Archive and Trash: the same move, with a destination the server finds itself
// ---------------------------------------------------------------------------

/** Every registered mail callback, by name, on one gate. */
function allTools(): Map<string, Callback> {
  const callbacks = new Map<string, Callback>();
  const server = {
    registerTool(name: string, _options: unknown, handler: Callback) {
      callbacks.set(name, handler);
    },
  };
  registerMailTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), ownerPrincipal(), mailOnly);
  for (const name of ["mail_archive", "mail_trash", "mail_commit"]) {
    expect(callbacks.get(name), `${name} is not registered`).toBeDefined();
  }
  return callbacks;
}

/**
 * A folder listing with INBOX and the given folders, then its completion. Each
 * entry is `[wireName, attributes]`; the attributes are written verbatim.
 */
function listingOf(tag: string, folders: [string, string][], delimiter = "/"): Uint8Array {
  return wire(
    `* LIST (\\HasNoChildren) "${delimiter}" "INBOX"`,
    '* STATUS "INBOX" (MESSAGES 172 UNSEEN 3)',
    ...folders.flatMap(([name, attributes]) => [
      `* LIST (${attributes}) "${delimiter}" "${name}"`,
      `* STATUS "${name}" (MESSAGES 10 UNSEEN 0)`,
    ]),
    `${tag} OK LIST completed`,
  );
}

/** A preview conversation over a chosen listing. Its logout is tag `a7`. */
function rolePreviewServer(
  folders: [string, string][],
  messages: Fixture[],
  sourceMailbox = "INBOX",
): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    examineResponse("a4"),
    listingOf("a5", folders),
    previewFetchReply("a6", messages),
    logoutExchange("a7"),
  ]);
}

/** A commit conversation that moves one message cleanly. */
function oneMoveServer(message: Fixture): FakeDuplex {
  return createFakeDuplex([
    ...authPrefix(),
    selectResponse("a4", "[READ-WRITE]"),
    fingerprintReply("a5", [message]),
    copyReply("a6", message.uid, 88),
    markEcho("a7", message.uid, "743"),
    wire("* 1 EXPUNGE", "a8 OK EXPUNGE completed"),
    esearchCountReply("a9", 0),
    logoutExchange("a10"),
  ]);
}

/** The commit's whole recorded line array for one message copied to `mailbox`. */
function oneMoveLines(mailbox: string): string[] {
  return [
    ...SIGN_IN,
    'a4 SELECT "INBOX"',
    "a5 UID FETCH 4242 (UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ)",
    `a6 UID COPY 4242 "${mailbox}"`,
    "a7 UID STORE 4242 (UNCHANGEDSINCE 742) +FLAGS (\\Deleted)",
    "a8 UID EXPUNGE 4242",
    "a9 UID SEARCH RETURN (COUNT) UID 4242",
    "a10 LOGOUT",
  ];
}

describe("archive and Trash, resolved from the account, previewed and committed", () => {
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "Receipt" };

  it("archives into the folder the listing names Archive, and says so in both tenses", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer([["Archive", "\\HasNoChildren"]], [MESSAGE]);
    const committed = oneMoveServer(MESSAGE);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(MESSAGE.uid)];
    const previewed = await callbacks.get("mail_archive")!({ ids });

    expect(previewed.isError).toBeUndefined();
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    const trusted = body(previewed);
    const archiveId = encodeFolderId({ mailbox: "Archive" });
    expect(trusted.change).toEqual({ op: "move", ids, destination: archiveId });
    expect(trusted.destination).toEqual({ id: archiveId, role: "archive" });
    expect(trusted.confirmationLine).toBe(
      "Moving 1 message from 'INBOX' to the archive folder 'Archive'. It can be moved back.",
    );

    const answer = await callbacks.get("mail_commit")!({
      confirmToken: trusted.confirmToken,
      change: trusted.change,
    });

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(committed)).toEqual(oneMoveLines("Archive"));
    const result = body(answer) as { confirmationLine: string; results: { outcome: string }[] };
    expect(result.confirmationLine).toBe(
      "Moved 1 message from 'INBOX' to the archive folder 'Archive'. It can be moved back.",
    );
    expect(result.results[0]!.outcome).toBe("moved");
  });

  it("sends to Trash by the name Deleted Messages, and never says deleted", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer([["Deleted Messages", "\\HasNoChildren"]], [MESSAGE]);
    const committed = oneMoveServer(MESSAGE);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(MESSAGE.uid)];
    const previewed = await callbacks.get("mail_trash")!({ ids });

    expect(previewed.isError).toBeUndefined();
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    const trusted = body(previewed);
    const trashId = encodeFolderId({ mailbox: "Deleted Messages" });
    expect(trusted.change).toEqual({ op: "move", ids, destination: trashId });
    expect(trusted.destination).toEqual({ id: trashId, role: "trash" });
    expect(trusted.confirmationLine).toBe(
      "Moving 1 message from 'INBOX' to Trash. It can be moved back out of Trash until " +
        "Trash is emptied.",
    );

    const answer = await callbacks.get("mail_commit")!({
      confirmToken: trusted.confirmToken,
      change: trusted.change,
    });

    expect(connectImap).toHaveBeenCalledTimes(2);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(committed)).toEqual(oneMoveLines("Deleted Messages"));
    const result = body(answer) as { confirmationLine: string; results: { outcome: string }[] };
    expect(result.confirmationLine).toBe(
      "Moved 1 message from 'INBOX' to Trash. It can be moved back out of Trash until " +
        "Trash is emptied.",
    );
    expect(result.results[0]!.outcome).toBe("moved");
    expect(String(trusted.confirmationLine)).not.toMatch(/delet/i);
    expect(result.confirmationLine).not.toMatch(/delet/i);
  });
});

// ---------------------------------------------------------------------------
// Every way the archive or Trash folder can fail to resolve
// ---------------------------------------------------------------------------

/**
 * One folder as a listing would report it, with its role resolved by the SAME
 * function the listing uses, so a row here cannot claim a role the real ladder
 * would not give.
 */
function folderOf(wireName: string, attributes: string[] = [], delimiter = "/"): FolderSummary {
  const displayName = decodeModifiedUtf7(wireName);
  const { role, source } = resolveFolderRole(attributes, displayName, delimiter);
  return {
    id: encodeFolderId({ mailbox: wireName }),
    wireName,
    displayName,
    attributes,
    role,
    roleSource: source,
    totalCount: null,
    unreadCount: null,
  };
}

function listingFrom(folders: FolderSummary[]): FolderListing {
  return { folders: [folderOf("INBOX"), ...folders], delimiter: "/", countsSource: "list-status" };
}

describe("resolveRoleFolder: the attribute first, then the name, and a tie refuses", () => {
  it.each<{
    name: string;
    role: "archive" | "trash";
    folders: FolderSummary[];
    expected: { folder: string } | { refusal: "none" | "ambiguous" };
  }>([
    {
      name: "one special-use archive wins over a top-level folder named Archive",
      role: "archive",
      folders: [folderOf("Archive"), folderOf("Kept", ["\\Archive"])],
      expected: { folder: "Kept" },
    },
    {
      name: "two special-use archives are ambiguous",
      role: "archive",
      folders: [folderOf("Kept", ["\\Archive"]), folderOf("Old", ["\\Archive"])],
      expected: { refusal: "ambiguous" },
    },
    {
      name: "no special-use and one name match wins",
      role: "archive",
      folders: [folderOf("Receipts"), folderOf("Archive")],
      expected: { folder: "Archive" },
    },
    {
      name: "Archive/2024 alone is none: the ladder is top-level only",
      role: "archive",
      folders: [folderOf("Archive/2024")],
      expected: { refusal: "none" },
    },
    {
      name: "two name matches, Archive and archive, are ambiguous",
      role: "archive",
      folders: [folderOf("Archive"), folderOf("archive")],
      expected: { refusal: "ambiguous" },
    },
    {
      name: "a \\Trash special-use folder wins over Deleted Messages by name",
      role: "trash",
      folders: [folderOf("Deleted Messages"), folderOf("Bin", ["\\Trash"])],
      expected: { folder: "Bin" },
    },
    {
      name: "Deleted Messages by name alone wins",
      role: "trash",
      folders: [folderOf("Deleted Messages")],
      expected: { folder: "Deleted Messages" },
    },
    {
      name: "a trash folder does not answer for the archive",
      role: "archive",
      folders: [folderOf("Deleted Messages", ["\\Trash"])],
      expected: { refusal: "none" },
    },
    {
      name: "none is none",
      role: "trash",
      folders: [folderOf("Receipts")],
      expected: { refusal: "none" },
    },
  ])("$name", ({ role, folders, expected }) => {
    const resolved = resolveRoleFolder(listingFrom(folders), role);
    if ("folder" in expected) {
      expect("folder" in resolved && resolved.folder.wireName).toBe(expected.folder);
    } else {
      expect(resolved).toEqual(expected);
    }
  });
});

/** The reason and confirmationLine of every answer, for the /delet/i check. */
function serverWords(answer: ToolAnswer): string[] {
  const parsed = body(answer);
  return [parsed.reason, parsed.confirmationLine].filter(
    (value): value is string => typeof value === "string",
  );
}

describe("archive and Trash refuse rather than guess, and Trash never says deleted", () => {
  const MESSAGE: Fixture = { uid: 4242, size: 18_431, modSeq: "742", subject: "Receipt" };
  /** Every trash answer this block produces, checked at the end of each case. */
  const trashAnswers: ToolAnswer[] = [];

  beforeEach(() => {
    trashAnswers.length = 0;
  });

  it("mail_archive with no archive folder: no-archive-folder, one read session, nothing written", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer([[RECEIPTS, "\\HasNoChildren"]], [MESSAGE]);
    vi.mocked(connectImap).mockReturnValueOnce(preview as never);

    const answer = await callbacks.get("mail_archive")!({ ids: [idOf(MESSAGE.uid)] });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    expectNoLine(wireOf(preview), "SELECT");
    const parsed = body(answer);
    expect(parsed.refusal).toBe("no-archive-folder");
    expect(parsed.confirmToken).toBeUndefined();
    expect(String(parsed.reason)).toContain("mail_move");
    expect(String(parsed.reason)).toContain("no archive folder");
  });

  it("mail_trash with no Trash folder: no-trash-folder, the same shape", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer([[RECEIPTS, "\\HasNoChildren"]], [MESSAGE]);
    vi.mocked(connectImap).mockReturnValueOnce(preview as never);

    const answer = await callbacks.get("mail_trash")!({ ids: [idOf(MESSAGE.uid)] });
    trashAnswers.push(answer);

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(answer.isError).toBeUndefined();
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    expectNoLine(wireOf(preview), "SELECT");
    const parsed = body(answer);
    expect(parsed.refusal).toBe("no-trash-folder");
    expect(parsed.confirmToken).toBeUndefined();
    expect(String(parsed.reason)).toContain("mail_move");
    for (const words of trashAnswers.flatMap(serverWords)) expect(words).not.toMatch(/delet/i);
  });

  it("mail_archive with two tied archive folders: ambiguous-role-folder, and neither is picked", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer(
      [
        ["Kept", "\\HasNoChildren \\Archive"],
        ["Old", "\\HasNoChildren \\Archive"],
      ],
      [MESSAGE],
    );
    vi.mocked(connectImap).mockReturnValueOnce(preview as never);

    const answer = await callbacks.get("mail_archive")!({ ids: [idOf(MESSAGE.uid)] });

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(wireOf(preview)).toEqual(previewLines([MESSAGE.uid]));
    const parsed = body(answer);
    expect(parsed.refusal).toBe("ambiguous-role-folder");
    expect(parsed.confirmToken).toBeUndefined();
    expect(String(parsed.reason)).toContain("archive folder");
    expect(String(parsed.reason)).toContain("mail_move");
  });

  it("mail_trash on messages already in Trash: already-in-destination", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer([["Deleted Messages", "\\HasNoChildren"]], [MESSAGE]);
    vi.mocked(connectImap).mockReturnValueOnce(preview as never);
    const id = encodeMessageId({
      mailbox: "Deleted Messages",
      uidValidity: INBOX_UIDVALIDITY,
      uid: MESSAGE.uid,
    });

    const answer = await callbacks.get("mail_trash")!({ ids: [id] });
    trashAnswers.push(answer);

    expect(connectImap).toHaveBeenCalledTimes(1);
    expect(wireOf(preview)[3]).toBe('a4 EXAMINE "Deleted Messages"');
    const parsed = body(answer);
    expect(parsed.refusal).toBe("already-in-destination");
    expect(parsed.confirmToken).toBeUndefined();
    for (const words of trashAnswers.flatMap(serverWords)) expect(words).not.toMatch(/delet/i);
  });

  it("a Trash marked by attribute on a folder named otherwise is where the copy goes", async () => {
    const callbacks = allTools();
    const preview = rolePreviewServer(
      [
        ["Deleted Messages", "\\HasNoChildren"],
        ["Bin", "\\HasNoChildren \\Trash"],
      ],
      [MESSAGE],
    );
    const committed = oneMoveServer(MESSAGE);
    vi.mocked(connectImap)
      .mockReturnValueOnce(preview as never)
      .mockReturnValueOnce(committed as never);

    const ids = [idOf(MESSAGE.uid)];
    const previewed = await callbacks.get("mail_trash")!({ ids });
    trashAnswers.push(previewed);
    const trusted = body(previewed);
    expect(trusted.destination).toEqual({
      id: encodeFolderId({ mailbox: "Bin" }),
      role: "trash",
    });

    const answer = await callbacks.get("mail_commit")!({
      confirmToken: trusted.confirmToken,
      change: trusted.change,
    });
    trashAnswers.push(answer);

    expect(wireOf(committed)).toEqual(oneMoveLines("Bin"));
    expect(body(answer).confirmationLine).toBe(
      "Moved 1 message from 'INBOX' to Trash. It can be moved back out of Trash until " +
        "Trash is emptied.",
    );
    for (const words of trashAnswers.flatMap(serverWords)) expect(words).not.toMatch(/delet/i);
  });

  it("a trash commit refused for a change, and one partly done, still never say deleted", async () => {
    const callbacks = allTools();
    const folders: [string, string][] = [["Deleted Messages", "\\HasNoChildren"]];

    // Refused: the message changed after the preview.
    vi.mocked(connectImap).mockReturnValueOnce(rolePreviewServer(folders, [MESSAGE]) as never);
    const first = await callbacks.get("mail_trash")!({ ids: [idOf(MESSAGE.uid)] });
    trashAnswers.push(first);
    vi.mocked(connectImap).mockReturnValueOnce(
      createFakeDuplex([
        ...authPrefix(),
        selectResponse("a4", "[READ-WRITE]"),
        fingerprintReply("a5", [{ ...MESSAGE, modSeq: "999" }]),
        logoutExchange("a6"),
      ]) as never,
    );
    const refused = await callbacks.get("mail_commit")!({
      confirmToken: body(first).confirmToken,
      change: body(first).change,
    });
    trashAnswers.push(refused);
    expect(body(refused).refusal).toBe("changed-since-preview");

    // Partly done: the copy is refused, so the message stays where it was.
    vi.mocked(connectImap).mockReturnValueOnce(rolePreviewServer(folders, [MESSAGE]) as never);
    const second = await callbacks.get("mail_trash")!({ ids: [idOf(MESSAGE.uid)] });
    trashAnswers.push(second);
    vi.mocked(connectImap).mockReturnValueOnce(
      createFakeDuplex([
        ...authPrefix(),
        selectResponse("a4", "[READ-WRITE]"),
        fingerprintReply("a5", [MESSAGE]),
        wire("a6 NO [OVERQUOTA] COPY failed"),
        logoutExchange("a7"),
      ]) as never,
    );
    const partial = await callbacks.get("mail_commit")!({
      confirmToken: body(second).confirmToken,
      change: body(second).change,
    });
    trashAnswers.push(partial);
    expect(body(partial).confirmationLine).toBe(
      "Moved 0 of 1 message from 'INBOX' to Trash; 1 not copied. It can be moved back out " +
        "of Trash until Trash is emptied.",
    );

    expect(trashAnswers).toHaveLength(4);
    const words = trashAnswers.flatMap(serverWords);
    expect(words.length).toBeGreaterThanOrEqual(4);
    for (const line of words) expect(line).not.toMatch(/delet/i);
  });
});

});
