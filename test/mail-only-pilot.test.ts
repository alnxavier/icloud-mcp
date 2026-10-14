import { McpServer, InMemoryTransport } from "@modelcontextprotocol/server";
import type { JSONRPCMessage } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createServerFactory } from "../src/mcp/server";
import { registerMailTools } from "../src/mcp/tools/mail";
import { createLeasedMail } from "../src/agent/lease";
import { createSessionGate } from "../src/mail/service";
import { ImapAuthError } from "../src/errors";
import { autonomyConfigured, signInNotices, isAllowedRedirectOrigin } from "../src/auth/login-handler";
import { MAIL_ONLY_NOTICE, renderForm } from "../src/auth/login-page";
import { ownerPrincipal } from "./fixtures/bound-secrets";

afterEach(() => { vi.restoreAllMocks(); });
const MAIL_TOOLS = ["mail_get_message", "mail_list_folders", "mail_list_messages", "mail_find", "mail_list_unread", "mail_compose_new", "mail_compose_reply", "mail_mark_read", "mail_move", "mail_archive", "mail_trash", "mail_commit"];

function registered() {
  const tools = new Map<string, { inputSchema?: z.ZodType }>();
  const server = { registerTool(name: string, options: { inputSchema?: z.ZodType }) { tools.set(name, options); } };
  registerMailTools(server as unknown as McpServer, createLeasedMail(createSessionGate()), ownerPrincipal(), true);
  return tools;
}

describe("mail-only deployment", () => {
  it("exposes exactly fourteen authorized tools through the actual MCP protocol", async () => {
    const extra = vi.fn();
    const server = await createServerFactory(ownerPrincipal(), [extra], async () => null, true)({ era: "modern" });
    const [client, transport] = InMemoryTransport.createLinkedPair();
    const messages: Record<string, unknown>[] = [];
    client.onmessage = message => { messages.push(message as unknown as Record<string, unknown>); };
    await client.start();
    await server.connect(transport);
    const requests: JSONRPCMessage[] = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2026-07-28", capabilities: {}, clientInfo: { name: "mail-only-test", version: "1" } } },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "mail_flag", arguments: {} } },
    ];
    for (const request of requests) await client.send(request);
    await new Promise(resolve => setTimeout(resolve, 0));
    await server.close();
    const result = messages.find(m => m.id === 2)?.result as { tools: { name: string }[] };
    expect(result.tools.map(t => t.name).sort()).toEqual([...MAIL_TOOLS, "account_whoami", "mail_imap_diagnose"].sort());
    const refused = messages.find(m => m.id === 3);
    expect(Boolean(refused?.error) || Boolean((refused?.result as { isError?: boolean })?.isError)).toBe(true);
    expect(extra).not.toHaveBeenCalled();
  });

  it("refuses attachments, another destination folder, and oversized draft bodies", () => {
    const tools = registered();
    expect([...tools.keys()]).toEqual(MAIL_TOOLS);
    for (const name of ["mail_compose_new", "mail_compose_reply"]) {
      const schema = tools.get(name)!.inputSchema!;
      const base = name === "mail_compose_new" ? { to: ["a@example.invalid"], subject: "hello", text: "draft" } : { parentId: "opaque", text: "draft" };
      expect(schema.safeParse(base).success).toBe(true);
      expect(schema.safeParse({ ...base, attachmentIds: ["opaque"] }).success).toBe(false);
      expect(schema.safeParse({ ...base, folderId: "another-folder" }).success).toBe(false);
      expect(schema.safeParse({ ...base, text: "a".repeat(16001) }).success).toBe(false);
    }
  });

  it("admits read/unread and previewed moves but refuses other commit operations", () => {
    const tools = registered();
    const mark = tools.get("mail_mark_read")!.inputSchema!;
    for (const read of [true, false]) expect(mark.safeParse({ id: "opaque", read }).success).toBe(true);
    expect(mark.safeParse({ id: "opaque", read: "true" }).success).toBe(false);
    for (const name of ["mail_move", "mail_archive", "mail_trash"]) {
      const schema = tools.get(name)!.inputSchema!;
      expect(schema.safeParse({ ids: [], destination: "folder" }).success).toBe(false);
      expect(schema.safeParse({ ids: ["opaque"], destination: "folder" }).success).toBe(true);
    }
    const commit = tools.get("mail_commit")!.inputSchema!;
    expect(commit.safeParse({ confirmToken: "sealed", change: { op: "move", ids: ["opaque"], destination: "folder" } }).success).toBe(true);
    expect(commit.safeParse({ confirmToken: "sealed", change: { op: "draft-delete", id: "opaque", subject: null } }).success).toBe(false);
    expect(commit.safeParse({ change: { op: "move", ids: ["opaque"], destination: "folder" } }).success).toBe(false);
  });

  it("keeps every mail handler behind authentication before acquiring a connection", async () => {
    const rejected = Promise.reject(new ImapAuthError()); rejected.catch(() => {});
    const lease = { withConnectionLease: vi.fn() };
    const callbacks: Array<(args: Record<string, unknown>) => Promise<{ isError?: boolean }>> = [];
    const recorder = { registerTool(_name: string, _options: unknown, callback: typeof callbacks[number]) { callbacks.push(callback); } };
    registerMailTools(recorder as unknown as McpServer, lease, rejected, true);
    for (const callback of callbacks) expect((await callback({})).isError).toBe(true);
    expect(lease.withConnectionLease).not.toHaveBeenCalled();
  });

  it("disables autonomy even when upstream autonomy secrets are configured", async () => {
    const mailEnv = { ...env, MAIL_ONLY_MODE: "true" };
    expect(autonomyConfigured(mailEnv)).toBe(false);
    expect(signInNotices(mailEnv)).toEqual([MAIL_ONLY_NOTICE]);
    const page = await renderForm("", null, { name: "ChatGPT", redirectUri: "https://chatgpt.com/connector_platform_oauth_redirect" }, signInNotices(mailEnv)).text();
    expect(page).not.toContain("can read your iCloud mail, calendar and contacts");
    expect(page).not.toContain('name="autonomy_notice"');
    expect(page).toContain("save drafts");
  });

  it("allows the real ChatGPT origin and refuses lookalikes or insecure variants", () => {
    expect(isAllowedRedirectOrigin("https://chatgpt.com")).toBe(true);
    for (const origin of ["https://chatgpt.com.evil.example", "http://chatgpt.com", "https://chatgpt.com:8443", "https://evil.example"]) expect(isAllowedRedirectOrigin(origin)).toBe(false);
  });
});
