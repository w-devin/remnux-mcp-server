/**
 * IdaConnector — MCP client that proxies tool calls to an ida-mcp-rs server.
 *
 * Two connection modes:
 *   1. Stdio (default when --ida-bin is set): spawns ida-mcp-rs as a child
 *      process and communicates over stdin/stdout. The child is automatically
 *      started on first tool call and killed on disconnect.
 *   2. HTTP (when --ida-endpoint is set): connects to an already-running
 *      ida-mcp-rs instance via Streamable HTTP.
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
  /** Per-tool-call timeout in ms (default: 300_000) */
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
      timeout: config.timeout ?? 300_000,
    };
  }

  /**
   * Establish connection to ida-mcp-rs. Safe to call multiple times —
   * concurrent calls share a single in-flight handshake.
   */
  async connect(): Promise<void> {
    if (this.client) return;
    if (this.connecting) {
      await this.connecting;
      return;
    }

    this.connecting = (async () => {
      const _require = createRequire(import.meta.url);
      let version: string;
      if (typeof globalThis.__PACKAGE_VERSION__ === "string") {
        version = globalThis.__PACKAGE_VERSION__;
      } else {
        version = (_require("../../package.json") as { version: string }).version;
      }

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

      this.client = new Client(
        { name: "remnux-mcp-server", version },
        { capabilities: {} },
      );

      await this.client.connect(this.transport);
    })();

    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  /**
   * List tools exposed by ida-mcp-rs, filtered by include/exclude sets.
   */
  async listTools(): Promise<IdaToolMeta[]> {
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
   */
  async callTool(
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
    try {
      if (this.client) {
        await this.client.close();
      }
    } catch {
      // Best-effort — ida-mcp-rs may already be gone
    }
    this.client = null;
    this.transport = null;
  }
}
