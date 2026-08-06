import { randomUUID } from "node:crypto";

const DEBUG_TEXT_BUDGET = 2000;
const SENSITIVE_KEY = /(authorization|token|password|secret|api[_-]?key)/i;

export interface RemnuxLogOptions {
  debug: boolean;
  serverId: string;
}

export function remnuxLog(message: string): void {
  console.error(`[REMNUX ${new Date().toISOString()}] ${message}`);
}

/**
 * Logs every REMnux handler invocation to stderr without contaminating the
 * stdio MCP protocol. Debug mode adds redacted, bounded request/response
 * previews; regular mode remains useful for production timing diagnostics.
 */
export function withRemnuxToolLogging<TArgs extends unknown[], TResult>(
  name: string,
  options: RemnuxLogOptions,
  handler: (...args: TArgs) => Promise<TResult> | TResult,
): (...args: TArgs) => Promise<TResult> {
  return async (...args: TArgs): Promise<TResult> => {
    const requestId = randomUUID().slice(0, 8);
    const startedAt = Date.now();
    const toolArgs = args[0];
    const argKeys = isPlainObject(toolArgs) ? Object.keys(toolArgs) : [];
    const analysisId = getAnalysisId(toolArgs);
    const correlation = `request=${requestId} server=${options.serverId} analysis=${analysisId ?? "-"}`;

    remnuxLog(
      `tool '${name}' -> start ${correlation} ` +
      `(arg keys: ${argKeys.length ? argKeys.join(", ") : "none"})`,
    );
    if (options.debug) {
      debugLog(`tool '${name}' ${correlation} args`, toolArgs);
    }

    try {
      const result = await handler(...args);
      const summary = summarizeResult(result);
      remnuxLog(
        `tool '${name}' <- done ${correlation} ` +
        `elapsed_ms=${Date.now() - startedAt} ${summary}`,
      );
      if (options.debug) {
        debugLog(`tool '${name}' ${correlation} response`, result);
      }
      return result;
    } catch (error) {
      remnuxLog(
        `tool '${name}' !! failed ${correlation} ` +
        `elapsed_ms=${Date.now() - startedAt}: ${describeError(error)}`,
      );
      throw error;
    }
  };
}

function summarizeResult(result: unknown): string {
  if (!isPlainObject(result)) return `result_type=${typeof result}`;
  const isError = result.isError === true;
  const content = Array.isArray(result.content) ? result.content : [];
  return `isError=${isError} content_items=${content.length}`;
}

function getAnalysisId(value: unknown): string | undefined {
  if (!isPlainObject(value)) return undefined;
  const analysisId = value.analysis_id;
  return typeof analysisId === "string" && analysisId ? analysisId : undefined;
}

function debugLog(label: string, value: unknown): void {
  const json = safeStringify(redact(value));
  const body = json.length > DEBUG_TEXT_BUDGET
    ? `${json.slice(0, DEBUG_TEXT_BUDGET)} …(${json.length} chars total, truncated)`
    : json;
  remnuxLog(`[debug] ${label}: ${body}`);
}

function redact(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return "[circular]";
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redact(item, seen));
  }

  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    output[key] = SENSITIVE_KEY.test(key) ? "[REDACTED]" : redact(item, seen);
  }
  return output;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
