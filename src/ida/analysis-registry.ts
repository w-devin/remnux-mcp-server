import { randomUUID } from "node:crypto";
import { IdaConnector, type IdaConnectorConfig, type IdaToolMeta } from "../connectors/ida.js";
import { remnuxLog } from "../logging/remnux.js";

export interface IdaCallResult {
  analysisId?: string;
  created: boolean;
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
}

export interface IdaAnalysisSummary {
  analysis_id: string;
  opened_with: string;
  sample?: string;
  created_at: string;
  last_used_at: string;
}

export interface IdaAnalysisConnector {
  listTools(): Promise<IdaToolMeta[]>;
  callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ content: IdaCallResult["content"]; isError?: boolean }>;
  disconnect(): Promise<void>;
}

export type IdaConnectorFactory = (config: IdaConnectorConfig) => IdaAnalysisConnector;

interface IdaAnalysis {
  connector: IdaAnalysisConnector;
  openedWith: string;
  sample?: string;
  createdAt: number;
  lastUsedAt: number;
}

/**
 * Owns the stateful IDA connections independently of HTTP MCP transports.
 *
 * Every open_idb/open_dsc receives its own connector, which keeps one IDA
 * worker and its current database isolated from other analyses. The returned
 * analysis_id is therefore the only handle a caller needs to preserve across
 * otherwise stateless HTTP MCP requests.
 */
export class IdaAnalysisRegistry {
  private readonly analyses = new Map<string, IdaAnalysis>();
  private creating = 0;
  private toolCatalog: IdaToolMeta[] | null = null;

  constructor(
    private readonly connectorConfig: IdaConnectorConfig,
    private readonly maxConcurrentAnalyses: number,
    private readonly connectorFactory: IdaConnectorFactory = (config) => new IdaConnector(config),
  ) {
    if (!Number.isInteger(maxConcurrentAnalyses) || maxConcurrentAnalyses < 1) {
      throw new Error("IDA max concurrent analyses must be a positive integer");
    }
  }

  get activeCount(): number {
    return this.analyses.size;
  }

  get creatingCount(): number {
    return this.creating;
  }

  get capacity(): number {
    return this.maxConcurrentAnalyses;
  }

  get cachedToolCount(): number | undefined {
    return this.toolCatalog?.length;
  }

  listAnalyses(): IdaAnalysisSummary[] {
    return [...this.analyses.entries()].map(([analysisId, analysis]) =>
      this.toSummary(analysisId, analysis),
    );
  }

  inspect(analysisId: string): IdaAnalysisSummary {
    const analysis = this.analyses.get(analysisId);
    if (!analysis) throw new Error(this.notFoundMessage(analysisId));
    analysis.lastUsedAt = Date.now();
    return this.toSummary(analysisId, analysis);
  }

  /**
   * Lazily discovers the upstream tool catalog. A temporary connector is
   * always disconnected, so listing tools never leaves an ida-mcp-rs child
   * behind. Once discovered, the catalog is process-cached.
   */
  async listTools(analysisId?: string): Promise<IdaToolMeta[]> {
    if (analysisId) {
      const analysis = this.analyses.get(analysisId);
      if (!analysis) throw new Error(this.notFoundMessage(analysisId));
      analysis.lastUsedAt = Date.now();
      const tools = await analysis.connector.listTools();
      this.toolCatalog = tools;
      return tools;
    }

    if (this.toolCatalog) return this.toolCatalog;

    const existing = this.analyses.values().next().value as IdaAnalysis | undefined;
    if (existing) {
      existing.lastUsedAt = Date.now();
      const tools = await existing.connector.listTools();
      this.toolCatalog = tools;
      return tools;
    }

    const connector = this.connectorFactory(this.connectorConfig);
    try {
      const tools = await connector.listTools();
      this.toolCatalog = tools;
      return tools;
    } finally {
      await connector.disconnect();
    }
  }

  async callTool(
    requestedAnalysisId: string | undefined,
    name: string,
    args: Record<string, unknown>,
  ): Promise<IdaCallResult> {
    if (isOpenTool(name)) {
      if (!requestedAnalysisId) return this.createAnalysis(name, args);

      const analysisId = this.resolveAnalysisId(requestedAnalysisId);
      const analysis = this.analyses.get(analysisId)!;
      analysis.lastUsedAt = Date.now();
      const result = await this.callExistingAnalysis(analysisId, analysis, name, args);
      return { analysisId, created: false, ...result };
    }

    const analysisId = this.resolveAnalysisId(requestedAnalysisId);
    const analysis = this.analyses.get(analysisId)!;
    analysis.lastUsedAt = Date.now();

    if (name === "close_idb") {
      try {
        const result = await this.callExistingAnalysis(analysisId, analysis, name, args);
        return { analysisId, created: false, ...result };
      } finally {
        await this.release(analysisId);
      }
    }

    const result = await this.callExistingAnalysis(analysisId, analysis, name, args);
    return { analysisId, created: false, ...result };
  }

  async release(analysisId: string): Promise<boolean> {
    const analysis = this.analyses.get(analysisId);
    if (!analysis) return false;

    this.analyses.delete(analysisId);
    await analysis.connector.disconnect();
    remnuxLog(
      `IDA analysis released analysis=${analysisId} active=${this.analyses.size}/${this.maxConcurrentAnalyses}`,
    );
    return true;
  }

  async closeAll(): Promise<void> {
    const ids = [...this.analyses.keys()];
    await Promise.allSettled(ids.map((id) => this.release(id)));
  }

  private async createAnalysis(
    name: string,
    args: Record<string, unknown>,
  ): Promise<IdaCallResult> {
    if (this.analyses.size + this.creating >= this.maxConcurrentAnalyses) {
      throw new Error(
        `IDA analysis capacity reached (${this.analyses.size}/${this.maxConcurrentAnalyses} active; ` +
        `${this.creating} opening). Close an existing analysis or retry later.`,
      );
    }

    this.creating++;
    let analysisId: string | undefined;
    let closedUnexpectedly = false;
    const connector = this.connectorFactory({
      ...this.connectorConfig,
      // Reconnecting a dead connector would create a fresh IDA worker with no
      // previously opened IDB, so release the handle instead of pretending the
      // old analysis survived.
      reconnectOnClose: false,
      onUnexpectedClose: () => {
        closedUnexpectedly = true;
        if (analysisId) {
          void this.release(analysisId);
        }
      },
    });

    try {
      const result = await connector.callTool(name, args);
      if (result.isError) {
        await connector.disconnect();
        return { created: false, ...result };
      }
      if (closedUnexpectedly) {
        throw new Error("IDA analysis worker stopped while opening the database");
      }

      analysisId = randomUUID();
      const now = Date.now();
      this.analyses.set(analysisId, {
        connector,
        openedWith: name,
        sample: extractSample(args),
        createdAt: now,
        lastUsedAt: now,
      });
      remnuxLog(
        `IDA analysis created analysis=${analysisId} active=${this.analyses.size}/${this.maxConcurrentAnalyses}`,
      );
      return { analysisId, created: true, ...result };
    } catch (error) {
      await connector.disconnect();
      throw error;
    } finally {
      this.creating--;
    }
  }

  private async callExistingAnalysis(
    analysisId: string,
    analysis: IdaAnalysis,
    name: string,
    args: Record<string, unknown>,
  ): Promise<{ content: IdaCallResult["content"]; isError?: boolean }> {
    try {
      return await analysis.connector.callTool(name, args);
    } catch (error) {
      if (shouldReleaseAfterError(error)) {
        await this.release(analysisId);
      }
      throw error;
    }
  }

  private resolveAnalysisId(requestedAnalysisId?: string): string {
    if (requestedAnalysisId) {
      if (!this.analyses.has(requestedAnalysisId)) {
        throw new Error(this.notFoundMessage(requestedAnalysisId));
      }
      return requestedAnalysisId;
    }

    if (this.analyses.size === 1) {
      return this.analyses.keys().next().value as string;
    }
    if (this.analyses.size === 0) {
      throw new Error("No active IDA analysis. Call open_idb or open_dsc first.");
    }
    throw new Error(
      `Multiple IDA analyses are active (${this.analyses.size}); provide analysis_id to select one.`,
    );
  }

  private notFoundMessage(analysisId: string): string {
    return `IDA analysis context not found: ${analysisId}. Call open_idb again to create a new analysis context.`;
  }

  private toSummary(analysisId: string, analysis: IdaAnalysis): IdaAnalysisSummary {
    return {
      analysis_id: analysisId,
      opened_with: analysis.openedWith,
      ...(analysis.sample ? { sample: analysis.sample } : {}),
      created_at: new Date(analysis.createdAt).toISOString(),
      last_used_at: new Date(analysis.lastUsedAt).toISOString(),
    };
  }
}

function isOpenTool(name: string): boolean {
  return name === "open_idb" || name === "open_dsc";
}

function shouldReleaseAfterError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /connection closed|not connected|request timeout|timed out/i.test(message);
}

function extractSample(args: Record<string, unknown>): string | undefined {
  for (const key of ["path", "file", "idb", "idb_path", "input"]) {
    const value = args[key];
    if (typeof value === "string" && value) return value;
  }
  return undefined;
}
