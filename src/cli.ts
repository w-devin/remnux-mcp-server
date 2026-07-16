#!/usr/bin/env node

import { startServer, type ServerConfig } from "./index.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// In a Bun-compiled binary, __PACKAGE_VERSION__ is injected at compile time via --define.
let version: string;
if (typeof globalThis.__PACKAGE_VERSION__ === "string") {
  version = globalThis.__PACKAGE_VERSION__;
} else {
  version = (require("../package.json") as { version: string }).version;
}

function parseIntOrExit(value: string, flag: string): number {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) {
    console.error(`Error: invalid number for ${flag}: ${value}`);
    process.exit(1);
  }
  return n;
}

function parseArgs(): ServerConfig {
  const args = process.argv.slice(2);
  const config: ServerConfig = {
    mode: "local",
    samplesDir: "/home/remnux/files/samples",
    outputDir: "/home/remnux/files/output",
    timeout: 300,
    noSandbox: true,
  };

  for (let i = 0; i < args.length; i++) {
    let arg = args[i];
    let value = args[i + 1];
    let usedEqualsSyntax = false;

    // Support --flag=value syntax: split on first '='
    if (arg.startsWith("--") && arg.includes("=")) {
      const eqIndex = arg.indexOf("=");
      value = arg.slice(eqIndex + 1);
      arg = arg.slice(0, eqIndex);
      usedEqualsSyntax = true;
    }

    // Helper: only skip next arg if value came from separate arg (not '=' syntax)
    const consumeValue = () => { if (!usedEqualsSyntax) i++; };

    switch (arg) {
      case "--mode":
        if (value === "docker" || value === "ssh" || value === "local") {
          config.mode = value;
        }
        consumeValue();
        break;
      case "--container":
        config.container = value;
        consumeValue();
        break;
      case "--container-user":
        config.containerUser = value;
        consumeValue();
        break;
      case "--host":
        config.host = value;
        consumeValue();
        break;
      case "--user":
        config.user = value;
        consumeValue();
        break;
      case "--port":
        config.port = parseIntOrExit(value, "--port");
        consumeValue();
        break;
      case "--password":
        config.password = value;
        consumeValue();
        break;
      case "--samples-dir":
        config.samplesDir = value;
        consumeValue();
        break;
      case "--output-dir":
        config.outputDir = value;
        consumeValue();
        break;
      case "--ingest-root":
        config.ingestRoot = value;
        consumeValue();
        break;
      case "--timeout":
        config.timeout = parseIntOrExit(value, "--timeout");
        consumeValue();
        break;
      case "--sandbox":
        config.noSandbox = false;
        break;
      case "--no-sandbox":
        // Backwards compatibility — already the default
        break;
      case "--transport":
        if (value === "stdio" || value === "http") {
          config.transport = value;
        }
        consumeValue();
        break;
      case "--http-port":
        config.httpPort = parseIntOrExit(value, "--http-port");
        consumeValue();
        break;
      case "--http-host":
        config.httpHost = value;
        consumeValue();
        break;
      case "--http-token":
        config.httpToken = value;
        consumeValue();
        break;
      case "--insecure-no-auth":
        config.allowInsecureNoAuth = true;
        break;
      case "--ida-endpoint":
        config.idaEndpoint = value;
        consumeValue();
        break;
      case "--ida-bin":
        config.idaBin = value;
        consumeValue();
        break;
      case "--ida-bin-args":
        // Comma-separated extra args for ida-mcp-rs binary
        config.idaBinArgs = value.split(",").map((s) => s.trim()).filter(Boolean);
        consumeValue();
        break;
      case "--ida-token":
        config.idaToken = value;
        consumeValue();
        break;
      case "--ida-timeout":
        config.idaTimeout = parseIntOrExit(value, "--ida-timeout");
        consumeValue();
        break;
      case "--ida-toolsets":
        config.idaToolsets = value;
        consumeValue();
        break;
      case "--ida-exclude-tools":
        config.idaExcludeTools = value;
        consumeValue();
        break;
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
      case "--version":
      case "-v":
        console.log(`@remnux/mcp-server v${version}`);
        process.exit(0);
      default:
        if (arg.startsWith("-")) {
          console.error(`Unknown flag: ${arg}`);
          process.exit(1);
        }
    }
  }

  // Read token from env var if not set via CLI
  if (!config.httpToken && process.env.MCP_TOKEN) {
    config.httpToken = process.env.MCP_TOKEN;
  }
  if (!config.idaToken && process.env.IDA_MCP_TOKEN) {
    config.idaToken = process.env.IDA_MCP_TOKEN;
  }

  return config;
}

function printHelp() {
  console.log(`
@remnux/mcp-server - MCP server for using the REMnux malware analysis toolkit via AI assistants

USAGE:
  npx @remnux/mcp-server [OPTIONS]

OPTIONS:
  --mode <mode>           Connection mode: local, docker, or ssh (default: local)
  --container <name>      Docker container name/ID (for docker mode)
  --container-user <user> User to run container commands as (docker mode, default: remnux)
  --host <host>           SSH host (for ssh mode)
  --user <user>           SSH user (default: remnux)
  --port <port>           SSH port (default: 22)
  --password <pass>       SSH password (uses SSH agent if omitted)
  --samples-dir <path>    Path to samples directory (default: /home/remnux/files/samples)
  --output-dir <path>     Path to output directory (default: /home/remnux/files/output)
  --timeout <seconds>     Default command timeout (default: 300)
  --sandbox               Enable path sandboxing (restrict files to samples/output dirs)
  --no-sandbox            No-op (sandbox is already off by default)
  --ingest-root <path>    With --sandbox, confine upload_from_host source reads to this
                          directory (defaults to samples dir; required in docker/ssh mode)
  --transport <mode>      Transport: stdio (default) or http
  --http-port <port>      HTTP port (default: 3000)
  --http-host <host>      HTTP bind address (default: 127.0.0.1)
  --http-token <token>    Bearer token for HTTP auth (also reads MCP_TOKEN env var)
  --insecure-no-auth      Allow a non-loopback HTTP bind with no token (NOT recommended).
                          The server otherwise refuses to start in that configuration

PROXY MODE (for Claude Desktop):
  When the REMNUX_URL environment variable is set, the server runs as a stdio-to-HTTP
  bridge (proxy mode) instead of a normal MCP server. This allows Claude Desktop —
  which only supports stdio MCP — to connect to a remote remnux-mcp-server.

  REMNUX_URL=<url>        Remote MCP endpoint (e.g. http://192.168.5.102:5555/mcp)
  REMNUX_TOKEN=<token>    Bearer token for authentication
  --ida-endpoint <url>    Connect to an ida-mcp-rs instance at this HTTP endpoint
                          (e.g. http://127.0.0.1:8765). When set, IDA Pro analysis
                          tools are automatically registered with the ida_ prefix
  --ida-bin <path>        Path to ida-mcp-rs binary. Spawns it as a child process
                          using stdio transport (auto-started on first tool call,
                          killed on server shutdown). Mutually exclusive with
                          --ida-endpoint; if both are set, --ida-bin takes precedence
  --ida-bin-args <args>   Comma-separated extra arguments for the ida-mcp-rs binary
                          (e.g. "--read-only,--log-level,debug")
  --ida-token <token>     Bearer token for ida-mcp-rs HTTP auth (also reads IDA_MCP_TOKEN env var)
  --ida-timeout <secs>    Per-IDA-tool-call timeout (default: 300)
  --ida-toolsets <sets>   Comma-separated IDA toolset categories to expose
                          (e.g. core,functions,disasm,xrefs). Omit to expose all
  --ida-exclude-tools <t> Comma-separated IDA tool names to exclude from exposure
  -h, --help              Show this help message
  -v, --version           Show version

EXAMPLES:
  # Local mode (default — run directly on REMnux)
  npx @remnux/mcp-server

  # Docker mode (REMnux in a container)
  npx @remnux/mcp-server --mode=docker --container=remnux

  # SSH mode (remote REMnux host)
  npx @remnux/mcp-server --mode=ssh --host=192.168.1.100 --user=remnux

  # HTTP transport (server inside REMnux)
  npx @remnux/mcp-server --transport=http --http-token=SECRET

  # Add to Claude Code (stdio)
  claude mcp add remnux -- npx @remnux/mcp-server

  # With IDA Pro integration (auto-spawn ida-mcp-rs via stdio)
  npx @remnux/mcp-server --ida-bin=/usr/local/bin/ida-mcp

  # With IDA Pro integration (connect to running ida-mcp-rs via HTTP)
  npx @remnux/mcp-server --ida-endpoint=http://127.0.0.1:8765

  # Expose only core + functions IDA tools
  npx @remnux/mcp-server --ida-bin=/usr/local/bin/ida-mcp --ida-toolsets=core,functions

  # Proxy mode for Claude Desktop (connects to remote remnux-mcp-server via HTTP)
  REMNUX_URL=http://192.168.5.102:5555/mcp REMNUX_TOKEN=secret npx @remnux/mcp-server

Built-in tool guidance: suggest_tools, get_tool_help, analyze_file
Optional docs MCP: https://docs.remnux.org/~gitbook/mcp
`);
}

// ── Proxy mode: bridge stdio ↔ HTTP when REMNUX_URL is set ───────────────────
// For Claude Desktop, which only supports stdio MCP servers.
// Launches a local stdio MCP server that proxies all tool calls to a
// remote remnux-mcp-server over Streamable HTTP.
if (process.env.REMNUX_URL) {
  const { startProxy } = await import("./proxy.js");
  startProxy({
    url: process.env.REMNUX_URL,
    token: process.env.REMNUX_TOKEN,
  }).catch((error) => {
    console.error("Failed to start proxy:", error);
    process.exit(1);
  });
} else {
  // Normal server mode
  startServer(parseArgs()).catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });
}
