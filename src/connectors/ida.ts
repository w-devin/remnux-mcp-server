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
    };
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

      if (this.mode === "stdio") {
        this.transport = new StdioClientTransport({
          command: this.config.bin!,
          args: this.config.binArgs,
          stderr: "pipe",
        });
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
        this.clientAlive = false;
      };

      await client.connect(this.transport);
      this.client = client;
      this.clientAlive = true;
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
      await this.connect();
      return this.listToolsOnce();
    }
  }

  private async listToolsOnce(): Promise<IdaToolMeta[]> {
    await this.connect();
    const { tools } = await this.client!.listTools();

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
      if (!isDeadConnection(err)) throw err;
      await this.connect();
      return this.callToolOnce(name, args);
    }
  }

  private async callToolOnce(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ content: Array<{ type: string; text?: string; [k: string]: unknown }>; isError?: boolean }> {
    await this.connect();

    const result = await this.client!.callTool(
      { name, arguments: args },
      undefined,
      { timeout: this.config.timeout },
    );

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
    const client = this.client;
    this.client = null;
    this.transport = null;
    try {
      if (client) {
        await client.close();
      }
    } catch {
      // Best-effort — ida-mcp-rs may already be gone
    }
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
