/**
 * Pro-User-Rate-Limit + Concurrency-Cap für den Live-Check (VEC-363).
 *
 * In-Memory, fail-closed, passend zur einzelnen API-Replik (vgl. server.ts /
 * @fastify/rate-limit-Begründung). Zwei unabhängige Schranken pro `userId`:
 *
 *   1. Sliding-Window-Rate-Limit: max. N Modul-Aufrufe pro Fenster.
 *   2. Concurrency-Cap: max. K gleichzeitig laufende Aufrufe.
 *
 * `acquire()` reserviert beide; der Aufrufer MUSS bei Erfolg im `finally`
 * `release()` rufen, sonst leakt der Concurrency-Slot.
 */

export interface LiveCheckLimits {
  windowMs: number;
  maxPerWindow: number;
  maxConcurrent: number;
}

export const DEFAULT_LIVE_CHECK_LIMITS: LiveCheckLimits = {
  windowMs: 60_000,
  maxPerWindow: 20, // 20 Modul-Aufrufe/User/Minute (~1 Voll-Scan der BEHALTEN-Module)
  maxConcurrent: 4,
};

export type AcquireResult =
  | { ok: true }
  | { ok: false; reason: 'rate_limited' | 'too_many_concurrent'; retryAfterSec: number };

export class LiveCheckLimiter {
  private readonly limits: LiveCheckLimits;
  private readonly windowHits = new Map<string, number[]>();
  private readonly active = new Map<string, number>();

  constructor(limits: LiveCheckLimits = DEFAULT_LIVE_CHECK_LIMITS) {
    this.limits = limits;
  }

  /** `now` injizierbar für deterministische Tests. */
  acquire(userId: string, now: number = Date.now()): AcquireResult {
    const cutoff = now - this.limits.windowMs;
    const hits = (this.windowHits.get(userId) ?? []).filter((t) => t > cutoff);

    if (hits.length >= this.limits.maxPerWindow) {
      this.windowHits.set(userId, hits);
      const oldest = hits[0];
      const retryAfterSec = Math.max(1, Math.ceil((oldest + this.limits.windowMs - now) / 1000));
      return { ok: false, reason: 'rate_limited', retryAfterSec };
    }

    const inFlight = this.active.get(userId) ?? 0;
    if (inFlight >= this.limits.maxConcurrent) {
      this.windowHits.set(userId, hits);
      return { ok: false, reason: 'too_many_concurrent', retryAfterSec: 2 };
    }

    hits.push(now);
    this.windowHits.set(userId, hits);
    this.active.set(userId, inFlight + 1);
    return { ok: true };
  }

  /** Gibt einen zuvor mit `acquire()` reservierten Concurrency-Slot frei. */
  release(userId: string): void {
    const inFlight = this.active.get(userId) ?? 0;
    if (inFlight <= 1) this.active.delete(userId);
    else this.active.set(userId, inFlight - 1);
  }
}
