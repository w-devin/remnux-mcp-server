import { describe, it, expect, afterEach } from "vitest";
import type { Server } from "node:http";
import { createHttpApp } from "../index.js";

const TEST_TOKEN = "test-token-123";

const MCP_HEADERS = {
  "Content-Type": "application/json",
  "Accept": "application/json, text/event-stream",
};

async function parseResponse(res: Response) {
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream")) {
    const text = await res.text();
    const dataLines = text.split("\n").filter((line) => line.startsWith("data: "));
    const results = dataLines.map((line) => JSON.parse(line.slice(6)));
    return results.length === 1 ? results[0] : results;
  }
  return res.json();
}

function makeConfig(token?: string) {
  return {
    mode: "local" as const,
    samplesDir: "/tmp/samples",
    outputDir: "/tmp/output",
    timeout: 30,
    noSandbox: true,
    ...(token ? { httpToken: token } : {}),
  };
}

function initRequest(id = 1) {
  return {
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0.0" },
    },
  };
}

describe("HTTP Transport", () => {
  let server: Server | undefined;
  let closeApp: (() => Promise<void>) | undefined;
  let port = 0;

  async function start(options: { token?: string } = {}) {
    const http = await createHttpApp(makeConfig(options.token));
    closeApp = http.close;
    await new Promise<void>((resolve) => {
      server = http.app.listen(0, "127.0.0.1", () => {
        const address = server!.address();
        port = typeof address === "object" && address ? address.port : 0;
        resolve();
      });
    });
  }

  function url() {
    return `http://127.0.0.1:${port}/mcp`;
  }

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server!.close((error) => error ? reject(error) : resolve());
      });
      server = undefined;
    }
    await closeApp?.();
    closeApp = undefined;
  });

  it("rejects an unauthenticated request when a token is configured", async () => {
    await start({ token: TEST_TOKEN });

    const res = await fetch(url(), {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(401);
  });

  it("accepts a valid bearer token", async () => {
    await start({ token: TEST_TOKEN });

    const res = await fetch(url(), {
      method: "POST",
      headers: { ...MCP_HEADERS, Authorization: `Bearer ${TEST_TOKEN}` },
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(200);
    const body = await parseResponse(res) as { result: { serverInfo: { name: string } } };
    expect(body.result.serverInfo.name).toBe("remnux-mcp-server");
  });

  it("works without a token on loopback development binds", async () => {
    await start();

    const res = await fetch(url(), {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify(initRequest()),
    });

    expect(res.status).toBe(200);
  });

  it("does not issue sessions and ignores stale Mcp-Session-Id headers", async () => {
    await start();

    const init = await fetch(url(), {
      method: "POST",
      headers: MCP_HEADERS,
      body: JSON.stringify(initRequest()),
    });
    expect(init.status).toBe(200);
    expect(init.headers.get("mcp-session-id")).toBeNull();

    const initialized = await fetch(url(), {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        "mcp-session-id": "stale-session-after-server-restart",
        "mcp-protocol-version": "2025-03-26",
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
    expect(initialized.status).toBe(202);

    const listTools = await fetch(url(), {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        "mcp-session-id": "stale-session-after-server-restart",
        "mcp-protocol-version": "2025-03-26",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
    });

    expect(listTools.status).toBe(200);
    const body = await parseResponse(listTools) as { result: { tools: Array<{ name: string }> } };
    expect(body.result.tools.map((tool) => tool.name)).toContain("analyze_file");
  });

  it("keeps REMnux tools available after repeated initialization/reconnect requests", async () => {
    await start();

    for (let id = 1; id <= 3; id++) {
      const init = await fetch(url(), {
        method: "POST",
        headers: { ...MCP_HEADERS, "mcp-session-id": `obsolete-${id}` },
        body: JSON.stringify(initRequest(id)),
      });
      expect(init.status).toBe(200);
      expect(init.headers.get("mcp-session-id")).toBeNull();
    }

    const report = await fetch(url(), {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        "mcp-session-id": "obsolete-after-reconnect",
        "mcp-protocol-version": "2025-03-26",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: { name: "get_report_template", arguments: {} },
      }),
    });

    expect(report.status).toBe(200);
    const body = await parseResponse(report) as { result: { content: Array<{ text: string }> } };
    expect(body.result.content[0].text).toContain("Malware Analysis Report");
  });

  it("returns 405 for GET because this server has no server-initiated SSE stream", async () => {
    await start();

    const res = await fetch(url(), {
      method: "GET",
      headers: { Accept: "text/event-stream" },
    });

    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
  });
});
