'use client';

/**
 * PolicyCoverage — zeigt, wieviel Prozent der Findings durch eine echte
 * Severity-Policy aufgeloest wurden vs. ueber SP-FALLBACK uebernommen.
 *
 * Datenquelle:
 *   - `policy_id_distinct` (Array von Policy-IDs)
 *   - `findings.length` (Total)
 *   - `policy_version` (Anzeige im Tooltip)
 *
 * Wert: hohe Coverage = Severities sind kalibriert + auditierbar.
 *       Niedrige Coverage = Mapper hat Luecken; Tool-Severity wurde uebernommen.
 */

interface Props {
  findings: Array<{ policy_id?: string }> | null | undefined;
  policyIdDistinct: string[] | null | undefined;
  policyVersion: string | null | undefined;
}

export default function PolicyCoverage({ findings, policyIdDistinct, policyVersion }: Props) {
  const totalFindings = findings?.length ?? 0;

  const fallbackCount = (findings ?? []).reduce(
    (acc, f) => acc + (f.policy_id === 'SP-FALLBACK' ? 1 : 0),
    0,
  );
  const policyHits = totalFindings - fallbackCount;
  const coveragePct = totalFindings > 0 ? Math.round((policyHits / totalFindings) * 100) : 0;

  const distinctPolicies = (policyIdDistinct ?? []).filter((p) => p && p !== 'SP-FALLBACK');

  // Farb-Skala fuer Coverage: 0-30% rot, 30-70% gelb, 70-100% gruen
  const barColor =
    coveragePct >= 70 ? 'bg-emerald-500'
    : coveragePct >= 30 ? 'bg-yellow-500'
    : 'bg-red-500';

  const labelColor =
    coveragePct >= 70 ? 'text-emerald-300'
    : coveragePct >= 30 ? 'text-yellow-300'
    : 'text-red-300';

  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-baseline justify-between mb-1">
          <span className="text-sm font-medium text-slate-300">Policy-Coverage</span>
          <span className={`text-xl font-bold tabular-nums ${labelColor}`}>{coveragePct}%</span>
        </div>
        <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
          <div
            className={`h-full ${barColor} transition-all duration-500`}
            style={{ width: `${coveragePct}%` }}
          />
        </div>
        <div className="mt-1 flex justify-between text-xs text-slate-500 tabular-nums">
          <span>{policyHits} via Policy</span>
          <span>{fallbackCount} Fallback</span>
        </div>
      </div>

      <div className="text-xs text-slate-400 space-y-1">
        <div>
          <span className="text-slate-500">Distinct policies:</span>{' '}
          <span className="text-slate-300 font-mono">{distinctPolicies.length}</span>
        </div>
        {policyVersion && (
          <div>
            <span className="text-slate-500">Policy version:</span>{' '}
            <span className="text-slate-300 font-mono">{policyVersion}</span>
          </div>
        )}
        {distinctPolicies.length > 0 && (
          <div className="pt-1 flex flex-wrap gap-1">
            {distinctPolicies.slice(0, 6).map((pid) => (
              <span
                key={pid}
                className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300"
              >
                {pid}
              </span>
            ))}
            {distinctPolicies.length > 6 && (
              <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
                +{distinctPolicies.length - 6}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
