import { remnuxLog } from "../logging/remnux.js";

export const IDA_PROGRESS_HEARTBEAT_MS = 30_000;

interface ProgressExtra {
  _meta?: { progressToken?: string | number; [key: string]: unknown };
  sendNotification(notification: {
    method: "notifications/progress";
    params: {
      progressToken: string | number;
      progress: number;
      message?: string;
    };
  }): Promise<void>;
}

export async function withProgressHeartbeat<T>(
  extra: ProgressExtra,
  details: { tool: string; analysisId?: string },
  operation: () => Promise<T>,
  intervalMs = IDA_PROGRESS_HEARTBEAT_MS,
): Promise<T> {
  const progressToken = extra._meta?.progressToken;
  if (progressToken === undefined) return operation();

  const startedAt = Date.now();
  let progress = 0;
  let stopped = false;

  const send = async () => {
    if (stopped) return;
    progress += 1;
    const elapsedMs = Date.now() - startedAt;
    const analysis = details.analysisId ? ` analysis=${details.analysisId}` : "";
    try {
      await extra.sendNotification({
        method: "notifications/progress",
        params: {
          progressToken,
          progress,
          message: `IDA tool ${details.tool} is still running${analysis}; elapsed_ms=${elapsedMs}`,
        },
      });
    } catch (error) {
      remnuxLog(
        `IDA progress heartbeat failed tool=${details.tool} analysis=${details.analysisId ?? "-"}: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };

  await send();
  const timer = setInterval(() => { void send(); }, intervalMs);
  timer.unref?.();

  try {
    return await operation();
  } finally {
    stopped = true;
    clearInterval(timer);
  }
}
