'use client';

/**
 * KpiBar — kompakte KPI-Zeile als Ersatz fuer 2× p-5 Cards.
 *
 * Redesign Mai 2026: Severity-Donut + Policy-Coverage werden in eine
 * mehrspaltige KPI-Bar zusammengefuehrt. Detail-Anzeige per Klick auf Tile
 * (toggle expand).
 */

import { useState, type ReactElement } from 'react';

import SeverityDonut from './SeverityDonut';
import PolicyCoverage from './PolicyCoverage';
import type { Finding } from '@/lib/api';

interface Props {
  severityCounts: Record<string, number>;
  totalFindings: number;
  findings: Finding[];
  policyIdDistinct: string[] | null;
  policyVersion: string | null;
  hostsTotal: number;
  scannedHosts: number;
  skippedHosts: number;
  pkg: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH:     'bg-orange-500',
  MEDIUM:   'bg-amber-500',
  LOW:      'bg-yellow-500',
  INFO:     'bg-slate-500',
};

const SEVERITY_LABELS: Record<string, string> = {
  CRITICAL: 'Critical',
  HIGH:     'High',
  MEDIUM:   'Medium',
  LOW:      'Low',
  INFO:     'Info',
};

export function KpiBar({
  severityCounts, totalFindings, findings, policyIdDistinct, policyVersion,
  hostsTotal, scannedHosts, skippedHosts, pkg,
}: Props) {
  const [expanded, setExpanded] = useState<'sev' | 'policy' | null>(null);

  // Find dominant severity for status-Hint
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const dominantSev = sevOrder.find((s) => (severityCounts[s] ?? 0) > 0) || 'INFO';
  const dominantColor = SEVERITY_COLORS[dominantSev] || 'bg-slate-500';

  // Determinismus-Score
  const total = findings.length;
  const policyMatched = findings.filter((f) => f.policy_id && f.policy_id !== 'SP-FALLBACK').length;
  const coverage = total > 0 ? Math.round((policyMatched / total) * 100) : 0;

  return (
    <div className="space-y-2">
      {/* KPI-Tiles Row */}
      <div className="grid gap-2 grid-cols-2 lg:grid-cols-4">
        {/* Tile 1: Findings */}
        <button
          onClick={() => setExpanded(expanded === 'sev' ? null : 'sev')}
          className={`flex items-center gap-3 rounded-lg border bg-slate-900/60 p-3 text-left hover:border-slate-600 transition-colors ${
            expanded === 'sev' ? 'border-cyan-700' : 'border-slate-800'
          }`}
        >
          <div className={`w-2 self-stretch rounded ${dominantColor}`} aria-hidden />
          <div className="flex-1 min-w-0">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Findings</div>
            <div className="mt-0.5 flex items-baseline gap-2">
              <span className="text-2xl font-semibold text-slate-100 tabular-nums">{totalFindings}</span>
              <span className="text-xs text-slate-500">{SEVERITY_LABELS[dominantSev] ?? dominantSev}</span>
            </div>
            <div className="mt-1 flex items-center gap-0.5 text-[10px]">
              {sevOrder.map((s) => {
                const c = severityCounts[s] ?? 0;
                if (c === 0) return null;
                return (
                  <span key={s} className="flex items-center gap-0.5">
                    <span className={`inline-block h-1.5 w-1.5 rounded-full ${SEVERITY_COLORS[s]}`} />
                    <span className="text-slate-400 tabular-nums">{c}</span>
                  </span>
                );
              }).filter(Boolean).reduce((acc, el, i) => {
                if (i > 0) acc.push(<span key={`sep${i}`} className="text-slate-700">·</span>);
                acc.push(el as ReactElement);
                return acc;
              }, [] as ReactElement[])}
            </div>
          </div>
          <span className="text-slate-500 text-[10px]">{expanded === 'sev' ? '▴' : '▾'}</span>
        </button>

        {/* Tile 2: Determinismus */}
        <button
          onClick={() => setExpanded(expanded === 'policy' ? null : 'policy')}
          className={`flex items-center gap-3 rounded-lg border bg-slate-900/60 p-3 text-left hover:border-slate-600 transition-colors ${
            expanded === 'policy' ? 'border-cyan-700' : 'border-slate-800'
          }`}
        >
          <div className="w-2 self-stretch rounded bg-cyan-500" aria-hidden />
          <div className="flex-1 min-w-0">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Determinismus</div>
            <div className="mt-0.5 flex items-baseline gap-1.5">
              <span className="text-2xl font-semibold text-slate-100 tabular-nums">{coverage}%</span>
              <span className="text-xs text-slate-500">Policy-Coverage</span>
            </div>
            <div className="mt-1.5 h-1 w-full bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-500"
                style={{ width: `${coverage}%` }}
              />
            </div>
          </div>
          <span className="text-slate-500 text-[10px]">{expanded === 'policy' ? '▴' : '▾'}</span>
        </button>

        {/* Tile 3: Hosts */}
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <div className="w-2 self-stretch rounded bg-emerald-500" aria-hidden />
          <div className="flex-1 min-w-0">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Hosts</div>
            <div className="mt-0.5 text-2xl font-semibold text-slate-100 tabular-nums">{hostsTotal}</div>
            <div className="mt-0.5 text-[11px] text-slate-500">
              <span className="text-emerald-400">{scannedHosts} ✓</span>
              <span className="mx-1.5 text-slate-700">·</span>
              <span className="text-slate-400">{skippedHosts} ⊘</span>
            </div>
          </div>
        </div>

        {/* Tile 4: Paket */}
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <div className="w-2 self-stretch rounded bg-violet-500" aria-hidden />
          <div className="flex-1 min-w-0">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Paket</div>
            <div className="mt-0.5 text-base font-semibold text-slate-100 truncate">{pkg}</div>
            {policyVersion && (
              <div className="mt-0.5 text-[10px] font-mono text-slate-500 truncate" title={`Policy ${policyVersion}`}>
                Policy {policyVersion}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Expand-Detail (Severity-Donut oder Policy-Coverage) */}
      {expanded === 'sev' && (
        <div className="rounded-lg border border-cyan-900/40 bg-slate-900/60 p-4">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Severity-Verteilung im Detail</h3>
          <SeverityDonut counts={severityCounts} />
        </div>
      )}
      {expanded === 'policy' && (
        <div className="rounded-lg border border-cyan-900/40 bg-slate-900/60 p-4">
          <h3 className="text-sm font-medium text-slate-300 mb-3">Determinismus im Detail</h3>
          <PolicyCoverage
            findings={findings}
            policyIdDistinct={policyIdDistinct}
            policyVersion={policyVersion}
          />
        </div>
      )}
    </div>
  );
}
