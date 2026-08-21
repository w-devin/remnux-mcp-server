import { describe, expect, it, vi } from "vitest";
import { withProgressHeartbeat } from "../progress.js";

describe("withProgressHeartbeat", () => {
  it("sends client-visible heartbeats and stops when the operation completes", async () => {
    vi.useFakeTimers();
    try {
      let finish!: (value: string) => void;
      const operation = new Promise<string>((resolve) => { finish = resolve; });
      const sendNotification = vi.fn().mockResolvedValue(undefined);

      const running = withProgressHeartbeat(
        {
          _meta: { progressToken: "progress-1" },
          sendNotification,
        },
        { tool: "analyze_funcs", analysisId: "analysis-1" },
        () => operation,
        1_000,
      );

      await vi.advanceTimersByTimeAsync(2_100);
      expect(sendNotification).toHaveBeenCalledTimes(3);
      expect(sendNotification).toHaveBeenLastCalledWith({
        method: "notifications/progress",
        params: expect.objectContaining({
          progressToken: "progress-1",
          progress: 3,
          message: expect.stringContaining("analyze_funcs"),
        }),
      });

      finish("done");
      await expect(running).resolves.toBe("done");
      await vi.advanceTimersByTimeAsync(2_000);
      expect(sendNotification).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not send notifications when the caller omitted a progress token", async () => {
    const sendNotification = vi.fn().mockResolvedValue(undefined);
    const result = await withProgressHeartbeat(
      { sendNotification },
      { tool: "decompile" },
      async () => "done",
      1,
    );

    expect(result).toBe("done");
    expect(sendNotification).not.toHaveBeenCalled();
  });
});
