export function replayRetryDelayMs(attempt: number): number {
  if (!Number.isInteger(attempt) || attempt < 1) {
    throw new Error("Replay attempt must be a positive integer");
  }
  return Math.min(60 * 60_000, 1_000 * 2 ** Math.min(attempt - 1, 12));
}
