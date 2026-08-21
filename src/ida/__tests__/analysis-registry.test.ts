import { describe, expect, it } from "vitest";
import {
  IdaAnalysisRegistry,
  type IdaAnalysisConnector,
  type IdaConnectorFactory,
} from "../analysis-registry.js";
import type { IdaConnectorConfig, IdaToolMeta } from "../../connectors/ida.js";

const CONNECTOR_CONFIG: IdaConnectorConfig = { bin: "/fake/ida-mcp" };
const TOOLS: IdaToolMeta[] = [{
  name: "decompile",
  description: "Decompile one function",
  inputSchema: { type: "object" },
}];

class FakeConnector implements IdaAnalysisConnector {
  readonly calls: Array<{ name: string; args: Record<string, unknown> }> = [];
  disconnected = false;

  constructor(
    private readonly config: IdaConnectorConfig,
    private readonly options: { openGate?: Promise<void>; openError?: boolean } = {},
  ) {}

  async listTools(): Promise<IdaToolMeta[]> {
    return TOOLS;
  }

  async callTool(name: string, args: Record<string, unknown>) {
    this.calls.push({ name, args });
    if (name === "open_idb" && this.options.openGate) await this.options.openGate;
    if (name === "open_idb" && this.options.openError) {
      return { content: [{ type: "text", text: "open failed" }], isError: true };
    }
    return { content: [{ type: "text", text: `${name} ok` }] };
  }

  async disconnect(): Promise<void> {
    this.disconnected = true;
  }

  unexpectedClose(): void {
    this.config.onUnexpectedClose?.();
  }
}

function connectorFactory(
  connectors: FakeConnector[],
  options: { openGate?: Promise<void>; openError?: boolean } = {},
): IdaConnectorFactory {
  return (config) => {
    const connector = new FakeConnector(config, options);
    connectors.push(connector);
    return connector;
  };
}

describe("IdaAnalysisRegistry", () => {
  it("does not create a connector until an IDA operation needs one", async () => {
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(
      CONNECTOR_CONFIG,
      2,
      connectorFactory(connectors),
    );

    expect(connectors).toHaveLength(0);
    expect(registry.cachedToolCount).toBeUndefined();
    expect(registry.activeCount).toBe(0);

    const tools = await registry.listTools();
    expect(tools).toEqual(TOOLS);
    expect(connectors).toHaveLength(1);
    expect(connectors[0].disconnected).toBe(true);
    expect(registry.cachedToolCount).toBe(1);
  });

  it("keeps separate IDA workers behind explicit analysis_id handles", async () => {
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(
      CONNECTOR_CONFIG,
      2,
      connectorFactory(connectors),
    );

    const first = await registry.callTool(undefined, "open_idb", { path: "/samples/first.exe" });
    const second = await registry.callTool(undefined, "open_idb", { path: "/samples/second.exe" });

    expect(first.created).toBe(true);
    expect(second.created).toBe(true);
    expect(first.analysisId).toBeTruthy();
    expect(second.analysisId).toBeTruthy();
    expect(first.analysisId).not.toBe(second.analysisId);

    await registry.callTool(first.analysisId, "decompile", { addr: "0x401000" });
    await registry.callTool(second.analysisId, "decompile", { addr: "0x402000" });

    expect(connectors).toHaveLength(2);
    expect(connectors[0].calls.map((call) => call.name)).toEqual(["open_idb", "decompile"]);
    expect(connectors[1].calls.map((call) => call.name)).toEqual(["open_idb", "decompile"]);
  });

  it("requires analysis_id for non-open calls when multiple analyses are active", async () => {
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(CONNECTOR_CONFIG, 2, connectorFactory(connectors));
    await registry.callTool(undefined, "open_idb", { path: "/samples/first.exe" });
    await registry.callTool(undefined, "open_idb", { path: "/samples/second.exe" });

    await expect(registry.callTool(undefined, "decompile", { addr: "0x401000" }))
      .rejects.toThrow("provide analysis_id");
  });

  it("counts in-progress opens against capacity and releases capacity on close_idb", async () => {
    let releaseOpen!: () => void;
    const openGate = new Promise<void>((resolve) => { releaseOpen = resolve; });
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(
      CONNECTOR_CONFIG,
      1,
      connectorFactory(connectors, { openGate }),
    );

    const opening = registry.callTool(undefined, "open_idb", { path: "/samples/first.exe" });
    await Promise.resolve();
    expect(registry.listOpenings()).toEqual([
      expect.objectContaining({ tool: "open_idb", sample: "/samples/first.exe" }),
    ]);
    await expect(registry.callTool(undefined, "open_idb", { path: "/samples/second.exe" }))
      .rejects.toThrow("capacity reached");

    releaseOpen();
    const first = await opening;
    await registry.callTool(first.analysisId, "close_idb", {});

    expect(registry.activeCount).toBe(0);
    expect(connectors[0].disconnected).toBe(true);

    const next = await registry.callTool(undefined, "open_idb", { path: "/samples/second.exe" });
    expect(next.created).toBe(true);
  });

  it("does not leak a connector when open_idb returns a tool error", async () => {
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(
      CONNECTOR_CONFIG,
      1,
      connectorFactory(connectors, { openError: true }),
    );

    const result = await registry.callTool(undefined, "open_idb", { path: "/samples/bad.exe" });

    expect(result.isError).toBe(true);
    expect(result.analysisId).toBeUndefined();
    expect(registry.activeCount).toBe(0);
    expect(connectors[0].disconnected).toBe(true);
  });

  it("releases an analysis whose upstream worker exits unexpectedly", async () => {
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(CONNECTOR_CONFIG, 1, connectorFactory(connectors));
    const opened = await registry.callTool(undefined, "open_idb", { path: "/samples/one.exe" });

    connectors[0].unexpectedClose();
    await Promise.resolve();

    expect(registry.activeCount).toBe(0);
    await expect(registry.callTool(opened.analysisId, "decompile", { addr: "0x401000" }))
      .rejects.toThrow("analysis context not found");
  });

  it("reports a blocked upstream call as busy without querying the worker", async () => {
    let releaseCall!: () => void;
    const callGate = new Promise<void>((resolve) => { releaseCall = resolve; });
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(
      CONNECTOR_CONFIG,
      1,
      (config) => {
        const connector = new FakeConnector(config);
        const original = connector.callTool.bind(connector);
        connector.callTool = async (name, args) => {
          if (name === "analyze_funcs") await callGate;
          return original(name, args);
        };
        connectors.push(connector);
        return connector;
      },
    );
    const opened = await registry.callTool(undefined, "open_idb", { path: "/samples/one.exe" });

    const running = registry.callTool(opened.analysisId, "analyze_funcs", { background: true });
    await Promise.resolve();

    const status = registry.inspect(opened.analysisId!);
    expect(status.state).toBe("busy");
    expect(status.current_operations).toEqual([
      expect.objectContaining({ tool: "analyze_funcs", status: "running" }),
    ]);
    expect(connectors[0].calls.map((call) => call.name)).toEqual(["open_idb"]);

    releaseCall();
    await running;
    const completed = registry.inspect(opened.analysisId!);
    expect(completed.state).toBe("idle");
    expect(completed.current_operations).toEqual([]);
    expect(completed.last_operation).toEqual(
      expect.objectContaining({ tool: "analyze_funcs", status: "succeeded" }),
    );
  });


  it("clears busy state and records a failed operation when an upstream call throws", async () => {
    const connectors: FakeConnector[] = [];
    const registry = new IdaAnalysisRegistry(
      CONNECTOR_CONFIG,
      1,
      (config) => {
        const connector = new FakeConnector(config);
        const original = connector.callTool.bind(connector);
        connector.callTool = async (name, args) => {
          if (name === "decompile") throw new Error("IDA analysis failed");
          return original(name, args);
        };
        connectors.push(connector);
        return connector;
      },
    );
    const opened = await registry.callTool(undefined, "open_idb", { path: "/samples/one.exe" });

    await expect(registry.callTool(opened.analysisId, "decompile", { addr: "0x401000" }))
      .rejects.toThrow("IDA analysis failed");

    const status = registry.inspect(opened.analysisId!);
    expect(status.state).toBe("idle");
    expect(status.current_operations).toEqual([]);
    expect(status.last_operation).toEqual(expect.objectContaining({
      tool: "decompile",
      status: "failed",
      error: "IDA analysis failed",
    }));
  });

});
