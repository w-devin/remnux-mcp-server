/**
 * IdaConnector — MCP client that proxies tool calls to an ida-mcp-rs server.
 *
 * Two connection modes:
 *   1. Stdio (default when --ida-bin is set): spawns ida-mcp-rs as a child
 *      process and communicates over stdin/stdout. The child is automatically
 *      started on first tool call and killed on disconnect.
 *   2. HTTP (when --ida-endpoint is set): connects to an already-running
 *      ida-mcp-rs instance via Streamable HTTP.
 *
 * The connection is self-healing: if the underlying transport dies mid-session
 * (SSE drop, HTTP reset, child exit), onclose nulls the cached Client so the
 * next call rebuilds it, and callTool/listTools retry once on the definitive
 * "Connection closed" / "Not connected" signals. Timeouts are NOT retried, to
 * avoid double-firing long-running operations like open_idb auto_analyse.
 *
 * All connection-lifecycle events (connect, transport death, reconnect,
 * disconnect, per-call timing, child stderr) are logged to stderr with an
 * `[IDA]` prefix + ISO timestamp. This is the diagnostic surface for the
 * frequent-disconnect problem — grep stderr for `[IDA` to see the timeline.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createRequire } from "node:module";

export interface IdaConnectorConfig {
  /** Path to ida-mcp-rs binary (stdio mode — spawns child process) */
  bin?: string;
  /** Extra args passed to the ida-mcp-rs binary */
  binArgs?: string[];
  /** ida-mcp-rs HTTP endpoint (HTTP mode — connects to running instance) */
  endpoint?: string;
  /** Optional bearer token for ida-mcp-rs HTTP auth (HTTP mode only) */
  token?: string;
  /** Per-tool-call timeout in ms (default: 600_000) */
  timeout?: number;
  /** Tool name filter — only expose these tool names (exact match). Empty = expose all. */
  includeTools?: Set<string>;
  /** Tool name exclusion set */
  excludeTools?: Set<string>;
  /** Verbose mode: dump full request args + response content of every
   *  listTools/callTool exchange with ida-mcp-rs to stderr. Off by default —
   *  lifecycle logs (connect/onclose/reconnect/disconnect) always emit. */
  debug?: boolean;
  /** Rebuild the upstream connection once after an unexpected close. A
   *  stateful analysis registry disables this because a replacement worker has
   *  no previously opened IDB. */
  reconnectOnClose?: boolean;
  /** Called after an unexpected upstream close. Used by the analysis registry
   *  to release the now-invalid analysis_id. */
  onUnexpectedClose?: () => void;
}

export interface IdaToolMeta {
  name: string;
  description?: string;
  inputSchema: {
    type: "object";
    properties?: Record<string, unknown>;
    required?: string[];
    [k: string]: unknown;
  };
}

export class IdaConnector {
  private client: Client | null = null;
  private transport: StreamableHTTPClientTransport | StdioClientTransport | null = null;
  private connecting: Promise<void> | null = null;
  /** Marks the cached Client as dead; onclose sets this to "dead". */
  private clientAlive = false;
  /** True while disconnect() is closing the client intentionally — lets
   *  onclose distinguish a clean shutdown from an unexpected transport death. */
  private closing = false;
  /** Monotonic counter for each connect attempt — correlates rebuilds in logs. */
  private connectAttempt = 0;
  private readonly mode: "stdio" | "http";
  private readonly config: IdaConnectorConfig & { timeout: number };

  constructor(config: IdaConnectorConfig) {
    if (!config.bin && !config.endpoint) {
      throw new Error("IdaConnector requires either 'bin' (stdio) or 'endpoint' (HTTP)");
    }
    this.mode = config.bin ? "stdio" : "http";
    this.config = {
      ...config,
      endpoint: config.endpoint?.replace(/\/+$/, ""),
      timeout: config.timeout ?? 600_000,
      debug: config.debug ?? false,
    };
    if (this.config.debug) {
      log("debug mode enabled — full request args and response content will be dumped to stderr");
    }
  }

  /**
   * Establish connection to ida-mcp-rs. Safe to call multiple times —
   * concurrent calls share a single in-flight handshake, and a client that
   * died (transport closed) is transparently rebuilt on the next call.
   */
  async connect(): Promise<void> {
    if (this.client && this.clientAlive) return;
    if (this.connecting) {
      await this.connecting;
      // A concurrent caller may have failed mid-handshake; recurse so the
      // next call gets a fresh attempt rather than returning a dead client.
      if (this.client && this.clientAlive) return;
    }

    this.connecting = (async () => {
      const attempt = ++this.connectAttempt;
      const isRebuild = this.connectAttempt > 1;
      const target = this.mode === "stdio" ? this.config.bin! : this.config.endpoint!;
      log(`connect #${attempt} ${isRebuild ? "(rebuild after transport death) " : ""}mode=${this.mode} target=${target}`);

      const _require = createRequire(import.meta.url);
      let version: string;
      if (typeof globalThis.__PACKAGE_VERSION__ === "string") {
        version = globalThis.__PACKAGE_VERSION__;
      } else {
        version = (_require("../../package.json") as { version: string }).version;
      }

      // Tear down any previous (dead) transport before building a new one.
      // We do NOT call client.close() here: it's already closed (that's why
      // we're rebuilding), and on a live-but-zombie stdio child close() would
      // kill a process ida-mcp-rs might still be reattaching to. Just drop refs.
      this.client = null;
      this.transport = null;
      this.clientAlive = false;
      this.closing = false;

      if (this.mode === "stdio") {
        this.transport = new StdioClientTransport({
          command: this.config.bin!,
          args: this.config.binArgs,
          stderr: "pipe",
        });
        // The SDK creates the PassThrough immediately (before start()), so
        // attaching here cannot lose early child output. ida-mcp-rs / IDA
        // library load failures and panics land here — often the direct cause
        // of a disconnect. Forward line-buffered to our logger.
        // StdioClientTransport.stderr is typed as `Stream | null` by the SDK,
        // but at runtime it is the PassThrough it created in the constructor.
        // Treat it as a Node readable for line-buffered forwarding.
        const stderrStream = (this.transport as StdioClientTransport).stderr as
          | NodeJS.ReadableStream
          | null;
        if (stderrStream) {
          attachChildStderr(stderrStream);
        } else {
          log("note: stdio child stderr stream is null (unexpected — child diagnostics will be lost)");
        }
      } else {
        const url = new URL(this.config.endpoint!);
        const transportOpts: ConstructorParameters<typeof StreamableHTTPClientTransport>[1] = {};
        if (this.config.token) {
          transportOpts.requestInit = {
            headers: { Authorization: `Bearer ${this.config.token}` },
          };
        }
        this.transport = new StreamableHTTPClientTransport(url, transportOpts);
      }

      const client = new Client(
        { name: "remnux-mcp-server", version },
        { capabilities: {} },
      );

      // SDK fires onclose for ANY reason the transport dies (network reset,
      // SSE drop, stdio child exit, explicit close()). When it does, the
      // Client is permanently unusable: Protocol._onclose() aborts all
      // in-flight requests and clears its transport. Mark dead so the next
      // call rebuilds it from scratch instead of returning a zombie.
      client.onclose = () => {
        const wasAlive = this.clientAlive;
        this.clientAlive = false;
        if (this.closing) {
          log(`onclose: client closed by disconnect() (clean shutdown)`);
        } else {
          // This is THE disconnect signal — an unexpected transport death.
          // Stateful callers can release their analysis handle here rather
          // than reconnecting to a fresh worker with no IDB loaded.
          log(`onclose: transport died unexpectedly (wasAlive=${wasAlive}); client marked dead`);
          this.config.onUnexpectedClose?.();
        }
      };

      try {
        await client.connect(this.transport);
      } catch (err) {
        log(`connect #${attempt} FAILED: ${describeError(err)}`);
        throw err;
      }
      this.client = client;
      this.clientAlive = true;
      if (this.mode === "stdio") {
        const pid = (this.transport as StdioClientTransport).pid;
        log(`connect #${attempt} ok: stdio child pid=${pid ?? "?"}`);
      } else {
        log(`connect #${attempt} ok: HTTP connected to ${this.config.endpoint}`);
      }
    })();

    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  /**
   * List tools exposed by ida-mcp-rs, filtered by include/exclude sets.
   * Retries once after a dead-connection signal (Connection closed / Not
   * connected) by forcing a reconnect.
   */
  async listTools(): Promise<IdaToolMeta[]> {
    try {
      return await this.listToolsOnce();
    } catch (err) {
      if (!isDeadConnection(err)) throw err;
      log(`listTools hit dead connection (${describeError(err)}), forcing reconnect and retrying once`);
      await this.connect();
      return this.listToolsOnce();
    }
  }

  private async listToolsOnce(): Promise<IdaToolMeta[]> {
    await this.connect();
    const startedAt = Date.now();
    if (this.config.debug) log("listTools -> ida-mcp-rs");
    const { tools } = await this.client!.listTools();
    log(`listTools ok: ${tools.length} tools in ${Date.now() - startedAt}ms`);
    if (this.config.debug) {
      debugLog(`listTools response: ${tools.length} tools`, tools.map((t) => t.name));
    }

    return tools
      .filter((t) => {
        if (this.config.includeTools?.size && !this.config.includeTools.has(t.name)) return false;
        if (this.config.excludeTools?.has(t.name)) return false;
        return true;
      })
      .map((t) => ({
        name: t.name,
        description: t.description ?? undefined,
        inputSchema: t.inputSchema as IdaToolMeta["inputSchema"],
      }));
  }

  /**
   * Call a tool on ida-mcp-rs and return the raw MCP result.
   * Retries once after a dead-connection signal (Connection closed / Not
   * connected) by forcing a reconnect. Timeouts are NOT retried — an
   * open_idb auto_analyse that timed out may still be running server-side,
   * and retrying would double-fire it.
   */
  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ content: Array<{ type: string; text?: string; [k: string]: unknown }>; isError?: boolean }> {
    try {
      return await this.callToolOnce(name, args);
    } catch (err) {
      if (!isDeadConnection(err) || this.config.reconnectOnClose === false) throw err;
      log(`callTool '${name}' hit dead connection (${describeError(err)}), forcing reconnect and retrying once`);
      await this.connect();
      return this.callToolOnce(name, args);
    }
  }

  private async callToolOnce(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ content: Array<{ type: string; text?: string; [k: string]: unknown }>; isError?: boolean }> {
    await this.connect();

    const startedAt = Date.now();
    const argKeys = Object.keys(args);
    // A start line with no matching completion line means the call is still
    // in-flight or hung — critical for correlating a hang with a disconnect.
    log(`callTool '${name}' -> ida-mcp-rs (arg keys: ${argKeys.length ? argKeys.join(", ") : "none"})`);
    if (this.config.debug) debugLog(`callTool '${name}' request args`, args);
    const result = await this.client!.callTool(
      { name, arguments: args },
      undefined,
      { timeout: this.config.timeout },
    );
    log(`callTool '${name}' <- ida-mcp-rs done in ${Date.now() - startedAt}ms (isError=${result.isError ?? false})`);
    if (this.config.debug) {
      // result is the SDK's CallToolResult union; normalise to the shape
      // dumpCallToolResponse expects. content may be absent in legacy form.
      dumpCallToolResponse(name, result as {
        content?: Array<{ type: string; text?: string; [k: string]: unknown }>;
        isError?: boolean;
      });
    }

    // The SDK returns either the new format ({ content, isError }) or the
    // legacy compatibility format ({ toolResult }). Normalise to new format.
    if ("content" in result) {
      return result as { content: Array<{ type: string; text?: string; [k: string]: unknown }>; isError?: boolean };
    }
    // Legacy path — wrap toolResult as text content
    return {
      content: [{ type: "text", text: JSON.stringify((result as { toolResult: unknown }).toolResult) }],
    };
  }

  /**
   * Gracefully close the connection. In stdio mode, kills the child process.
   */
  async disconnect(): Promise<void> {
    this.clientAlive = false;
    this.closing = true;
    const client = this.client;
    const transport = this.transport;
    this.client = null;
    this.transport = null;

    // Client.close() only tears down the local HTTP transport. Explicitly send
    // DELETE when an upstream Streamable HTTP session exists so ida-mcp-rs can
    // promptly reclaim its worker/session resources. The SDK treats 405 as a
    // valid response for a server that deliberately has no DELETE support.
    if (transport instanceof StreamableHTTPClientTransport) {
      try {
        await transport.terminateSession();
      } catch (err) {
        log(`disconnect: terminateSession() threw (${describeError(err)}) — best-effort, continuing`);
      }
    }

    try {
      if (client) {
        await client.close();
      } else if (transport) {
        await transport.close();
      }
    } catch (err) {
      log(`disconnect: transport close threw (${describeError(err)}) — best-effort, continuing`);
      // Best-effort — ida-mcp-rs may already be gone
    }
    log(`disconnected (mode=${this.mode})`);
  }
}

/**
 * Does this error mean the underlying transport is dead (and thus a reconnect
 * is both safe and necessary)? We match on the MCP SDK's definitive signals:
 * JSON-RPC error -32000 "Connection closed", and the protocol's pre-send
 * "Not connected" guard. Timeouts (-32001 RequestTimeout) and tool-level
 * errors are deliberately excluded — they are not connection failures.
 */
function isDeadConnection(err: unknown): boolean {
  if (err == null) return false;
  const message = err instanceof Error ? err.message : String(err);
  if (/\bConnection closed\b/.test(message)) return true;
  if (/^Not connected$/.test(message)) return true;
  // McpError stringifies as "{name}: {message}"; catch "Connection closed"
  // even when the code/type prefix is present.
  if (/Connection closed/.test(message)) return true;
  return false;
}

// ── Logging helpers ──────────────────────────────────────────────────────────
// All diagnostic output goes to stderr (console.error) — stdout is reserved
// for the MCP protocol. The `[IDA]` prefix + ISO timestamp makes the
// disconnect timeline greppable: `rg '\[IDA' <stderr-log>`.

function ts(): string {
  return new Date().toISOString();
}

function log(message: string): void {
  console.error(`[IDA ${ts()}] ${message}`);
}

/** Reduce any thrown value to a single diagnostic line (message + code/name). */
function describeError(err: unknown): string {
  if (err == null) return String(err);
  if (err instanceof Error) {
    // McpError carries a numeric `code`; surface it when present.
    const code = (err as { code?: number }).code;
    return code !== undefined ? `[${code}] ${err.message}` : err.message;
  }
  return String(err);
}

/** Max chars of a dumped string/text field before truncation. IDA
 *  decompilation output can be tens of KB; printing it whole would drown the
 *  log. Keep a generous preview and report the total length. */
const DEBUG_TEXT_BUDGET = 2000;

/** Debug-mode helper: dump an arbitrary value as pretty JSON, truncating
 *  long strings to keep the log readable. Used for request args and tool
 *  lists. */
function debugLog(label: string, value: unknown): void {
  const json = safeStringify(value);
  const body = json.length > DEBUG_TEXT_BUDGET
    ? `${json.slice(0, DEBUG_TEXT_BUDGET)} …(${json.length} chars total, truncated)`
    : json;
  log(`[debug] ${label}: ${body}`);
}

/** Dump a callTool response: how many content items, each item's type and a
 *  truncated text preview. Surfaces what ida-mcp-rs actually returned — the
 *  most useful detail when a tool call misbehaves or returns an error. */
function dumpCallToolResponse(
  name: string,
  result: { content?: Array<{ type: string; text?: string; [k: string]: unknown }>; isError?: boolean },
): void {
  const content = result.content;
  if (!content || content.length === 0) {
    log(`[debug] callTool '${name}' response: no content items (isError=${result.isError ?? false})`);
    return;
  }
  log(`[debug] callTool '${name}' response: ${content.length} content item(s) (isError=${result.isError ?? false})`);
  for (let i = 0; i < content.length; i++) {
    const item = content[i];
    const text = typeof item.text === "string" ? item.text : JSON.stringify(item);
    const preview = text.length > DEBUG_TEXT_BUDGET
      ? `${text.slice(0, DEBUG_TEXT_BUDGET)} …(${text.length} chars total, truncated)`
      : text;
    log(`[debug]   [${i}] type=${item.type} text=${preview}`);
  }
}

/** JSON.stringify that never throws on circular input (falls back to a
 *  shallow snapshot). Safe to pass arbitrary tool args here. */
function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    try {
      return JSON.stringify(shallowSnapshot(value), null, 2);
    } catch {
      return String(value);
    }
  }
}

/** Shallow, non-recursive snapshot of an object's own enumerable props — used
 *  only as a fallback when JSON.stringify hits a cycle. */
function shallowSnapshot(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>)) {
    const v = (value as Record<string, unknown>)[key];
    out[key] = typeof v === "object" && v !== null ? "[object]" : v;
  }
  return out;
}

/**
 * Line-buffer a child process stderr stream and forward each line to our
 * logger with a `[child stderr]` sub-prefix. Without this the PassThrough
 * created by StdioClientTransport (stderr: "pipe") is never drained, so
 * ida-mcp-rs / IDA library diagnostics — the most common root cause of a
 * stdio-mode disconnect — are silently lost.
 */
function attachChildStderr(stream: NodeJS.ReadableStream): void {
  let buf = "";
  stream.on("data", (chunk: Buffer) => {
    buf += chunk.toString();
    let newlineIdx: number;
    while ((newlineIdx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, newlineIdx).replace(/\r$/, "");
      buf = buf.slice(newlineIdx + 1);
      if (line.trim()) {
        log(`[child stderr] ${line}`);
      }
    }
  });
  stream.on("end", () => {
    if (buf.trim()) {
      log(`[child stderr] ${buf}`);
    }
  });
  stream.on("error", (err: Error) => {
    log(`[child stderr] stream error: ${describeError(err)}`);
  });
}
