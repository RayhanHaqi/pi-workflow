/**
 * Package-internal wall-clock seam (V1-R2D-TIME).
 *
 * Production time source is exactly Date.now(); no caller, Goal, model, or
 * provider may supply a timestamp. The process keeps a realtime high-water
 * mark and fails closed if it ever observes realtime moving backwards relative
 * to its own previously observed value. Backward realtime correction that
 * happens while the process is down remains an accepted local-clock trust
 * limitation; no NTP/network/distributed-clock machinery exists here.
 *
 * Tests override time through installTestWallClock without sleeping.
 */

export class WallClockError extends Error {
  public constructor(
    public readonly code: "WALL_CLOCK_INVALID" | "WALL_CLOCK_REGRESSED",
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "WallClockError";
  }
}

let observedHighWaterMarkMs = -1;
let testSource: (() => number) | null = null;

/** The single production clock sample used by every durable timing decision. */
export function sampleWallClockMs(): number {
  const candidate = testSource === null ? Date.now() : testSource();
  if (typeof candidate !== "number" || !Number.isSafeInteger(candidate) || candidate < 0) {
    throw new WallClockError("WALL_CLOCK_INVALID", "observed realtime is not a nonnegative safe integer");
  }
  if (candidate < observedHighWaterMarkMs) {
    throw new WallClockError(
      "WALL_CLOCK_REGRESSED",
      `observed realtime moved backwards from ${observedHighWaterMarkMs} to ${candidate}`,
    );
  }
  observedHighWaterMarkMs = candidate;
  return candidate;
}

/** Test-only override. Passing null restores the exact production source. */
export function installTestWallClock(source: (() => number) | null): void {
  testSource = source;
  observedHighWaterMarkMs = -1;
}
