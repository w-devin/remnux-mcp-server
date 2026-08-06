import { afterEach, describe, expect, it, vi } from "vitest";
import { withRemnuxToolLogging } from "../remnux.js";

describe("withRemnuxToolLogging", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("logs an analysis correlation ID and redacts/truncates debug payloads", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const handler = withRemnuxToolLogging(
      "run_tool",
      { debug: true, serverId: "server-1" },
      async (_args: Record<string, unknown>) => ({
        content: [{ type: "text", text: "x".repeat(2_500) }],
        isError: false,
      }),
    );

    await handler({
      analysis_id: "ida-123",
      password: "do-not-log",
      nested: { authorization: "Bearer secret" },
    });

    const output = stderr.mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain("analysis=ida-123");
    expect(output).toContain("[REDACTED]");
    expect(output).not.toContain("do-not-log");
    expect(output).not.toContain("Bearer secret");
    expect(output).toContain("truncated");
    expect(output).toContain("elapsed_ms=");
  });
});
