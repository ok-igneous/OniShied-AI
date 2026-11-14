export function investigationRetryDelayMs(attempt: number): number {
  if (!Number.isInteger(attempt) || attempt < 1) {
    throw new Error("Investigation attempt must be a positive integer");
  }
  return Math.min(30 * 60_000, 2_000 * 2 ** Math.min(attempt - 1, 10));
}
