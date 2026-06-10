/**
 * Live-Check (SofortScan) Abuse-Monitoring (VEC-368, §6 aus VEC-360).
 *
 * Reine Aggregations-Logik über `live_check_audit`-Zeilen — DB-frei und damit
 * unit-testbar. Verdichtet die forensische Spur zu einem Abuse-Bild pro Akteur
 * (User, ersatzweise Quell-IP) plus globalen Totals, das ein Admin-Endpoint
 * (read-only) ausliefert.
 *
 * Abuse-Signale, gewichtet:
 *   - `blocked`        SSRF-/Scope-Treffer → jemand probt interne Bereiche ab
 *                      (stärkstes Signal).
 *   - `rate_limited`   User hämmert die Fassade über das Limit hinaus.
 *   - `invalid`        gehäufte Müll-Eingaben (schwaches Signal, oft nur UX).
 *
 * Bewusst KEINE Persistenz/State: die Funktion ist deterministisch über ihre
 * Eingabe. Schwellwerte sind Parameter (Default unten), damit Tuning ohne
 * Code-Änderung über den Endpoint möglich ist.
 */

export type LiveCheckAuditStatus =
  | 'ok'
  | 'blocked'
  | 'rate_limited'
  | 'upstream_error'
  | 'invalid';

export interface LiveCheckAuditRow {
  userId: string | null;
  ip: string | null;
  status: LiveCheckAuditStatus;
}

export interface AbuseWeights {
  blocked: number;
  rateLimited: number;
  invalid: number;
}

export interface AbuseThresholds {
  /** Akteur wird geflaggt, wenn sein Score >= score. */
  score: number;
  /** … oder wenn er allein >= blocked SSRF-/Scope-Blocks ausgelöst hat. */
  blocked: number;
}

export const DEFAULT_ABUSE_WEIGHTS: AbuseWeights = {
  blocked: 5,
  rateLimited: 2,
  invalid: 1,
};

export const DEFAULT_ABUSE_THRESHOLDS: AbuseThresholds = {
  score: 15,
  blocked: 3,
};

export interface AbuseActor {
  /** Stabiler Akteurs-Schlüssel: `user:<id>` oder `ip:<addr>` als Fallback. */
  actor: string;
  userId: string | null;
  ip: string | null;
  total: number;
  ok: number;
  blocked: number;
  rateLimited: number;
  invalid: number;
  upstreamError: number;
  score: number;
  flagged: boolean;
}

export interface AbuseSummary {
  totals: {
    total: number;
    ok: number;
    blocked: number;
    rateLimited: number;
    invalid: number;
    upstreamError: number;
    distinctActors: number;
    flaggedActors: number;
  };
  /** Akteure absteigend nach Score (höchstes Abuse-Risiko zuerst). */
  actors: AbuseActor[];
}

function actorKey(row: LiveCheckAuditRow): string {
  if (row.userId) return `user:${row.userId}`;
  if (row.ip) return `ip:${row.ip}`;
  return 'anon:unknown';
}

/**
 * Verdichtet Audit-Zeilen zu einem Abuse-Bild. `topN` begrenzt die
 * zurückgegebene Akteurs-Liste (Score-Reihenfolge, geflaggte zuerst stabil).
 */
export function summarizeAbuse(
  rows: LiveCheckAuditRow[],
  opts: {
    weights?: AbuseWeights;
    thresholds?: AbuseThresholds;
    topN?: number;
  } = {},
): AbuseSummary {
  const weights = opts.weights ?? DEFAULT_ABUSE_WEIGHTS;
  const thresholds = opts.thresholds ?? DEFAULT_ABUSE_THRESHOLDS;
  const topN = opts.topN ?? 50;

  const byActor = new Map<string, AbuseActor>();
  const totals = {
    total: 0,
    ok: 0,
    blocked: 0,
    rateLimited: 0,
    invalid: 0,
    upstreamError: 0,
    distinctActors: 0,
    flaggedActors: 0,
  };

  for (const row of rows) {
    const key = actorKey(row);
    let a = byActor.get(key);
    if (!a) {
      a = {
        actor: key,
        userId: row.userId,
        ip: row.ip,
        total: 0,
        ok: 0,
        blocked: 0,
        rateLimited: 0,
        invalid: 0,
        upstreamError: 0,
        score: 0,
        flagged: false,
      };
      byActor.set(key, a);
    }
    a.total += 1;
    totals.total += 1;
    switch (row.status) {
      case 'ok':
        a.ok += 1;
        totals.ok += 1;
        break;
      case 'blocked':
        a.blocked += 1;
        totals.blocked += 1;
        break;
      case 'rate_limited':
        a.rateLimited += 1;
        totals.rateLimited += 1;
        break;
      case 'invalid':
        a.invalid += 1;
        totals.invalid += 1;
        break;
      case 'upstream_error':
        a.upstreamError += 1;
        totals.upstreamError += 1;
        break;
    }
  }

  const actors = [...byActor.values()];
  for (const a of actors) {
    a.score =
      a.blocked * weights.blocked +
      a.rateLimited * weights.rateLimited +
      a.invalid * weights.invalid;
    a.flagged = a.score >= thresholds.score || a.blocked >= thresholds.blocked;
  }

  totals.distinctActors = actors.length;
  totals.flaggedActors = actors.filter((a) => a.flagged).length;

  // Stable-Sort: Score desc, dann blocked desc, dann actor-Key asc (Tiebreaker).
  actors.sort(
    (x, y) =>
      y.score - x.score || y.blocked - x.blocked || x.actor.localeCompare(y.actor),
  );

  return { totals, actors: actors.slice(0, topN) };
}
