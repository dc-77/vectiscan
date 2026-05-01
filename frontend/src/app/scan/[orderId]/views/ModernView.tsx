'use client';

/**
 * ModernView — strukturierte Bericht-Ansicht (Default seit Mai 2026).
 *
 * Layout (top → bottom):
 *   [HeaderBar]                       — Domain, Paket, Status, Aktionen
 *   [Pre-Check / Pending-Review]      — Status-Banner wenn nicht delivered
 *   [Live-Progress-Bar]               — wenn Scan laeuft
 *   [Metrics: Donut + PolicyCoverage] — Severity + Determinismus-Coverage
 *   [HostMap]                         — KI-Targeting pro Host
 *   [Findings]                        — FindingsViewer (mit Threat-Intel-Badges)
 *   [Recommendations]                 — RecommendationsViewer
 *   [Story-Timeline]                  — collapsible
 *   [Scan-Timeline (Phasen+Tools)]    — collapsible
 *   [Debug]                           — admin-only, collapsible
 */

import Link from 'next/link';
import { useMemo, useState } from 'react';
import FindingsViewer from '@/components/FindingsViewer';
import RecommendationsViewer from '@/components/RecommendationsViewer';
import HostMap from '@/components/scan/HostMap';
import PolicyCoverage from '@/components/scan/PolicyCoverage';
import ScanStoryTimeline from '@/components/scan/ScanStoryTimeline';
import SeverityDonut from '@/components/scan/SeverityDonut';
import ThreatIntelBadge from '@/components/scan/ThreatIntelBadge';
import ViewSwitcher from '@/components/scan/ViewSwitcher';
import {
  getReportDownloadUrl,
  type FindingsData,
  type OrderEvents,
  type OrderStatus,
} from '@/lib/api';
import { STATUS_LABELS } from '@/lib/utils';

interface Props {
  order: OrderStatus;
  findings: FindingsData | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  aiData: (OrderEvents & Record<string, any>) | null;
  admin: boolean;
  view: 'modern' | 'hacker';
  onViewChange: (v: 'modern' | 'hacker') => void;
  onApprove: () => void;
  onReject: () => void;
  onExclude: (findingId: string, reason: string) => void;
  onUnexclude: (findingId: string) => void;
}

const PKG_LABELS: Record<string, string> = {
  webcheck: 'WebCheck',
  perimeter: 'Perimeter',
  compliance: 'Compliance',
  supplychain: 'SupplyChain',
  insurance: 'Insurance',
  tlscompliance: 'TLS-Audit',
  basic: 'WebCheck',
  professional: 'Perimeter',
  nis2: 'Compliance',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export default function ModernView({
  order, findings, aiData, admin, view, onViewChange, onApprove, onReject,
  onExclude, onUnexclude,
}: Props) {
  const orderId = order.id ?? '';

  const [showStory, setShowStory] = useState(true);
  const [showCosts, setShowCosts] = useState(false);

  const isDone = order.status === 'report_complete' || order.status === 'delivered';
  const isFailed = order.status === 'failed' || order.status === 'cancelled' || order.status === 'rejected';
  const isPendingReview = order.status === 'pending_review';
  const isPrecheckRunning = order.status === 'precheck_running';
  const isPendingTargetReview = order.status === 'pending_target_review';

  const pkg = PKG_LABELS[order.package] ?? order.package;
  const statusLabel = STATUS_LABELS[order.status] ?? order.status;

  // Augment findings mit threat_intel-Badge (FindingsViewer erwartet kein
  // direktes Threat-Intel-Slot — wir rendern ein Wrapper-Element rundherum).
  // Da FindingsViewer ein vorhandenes Component ist, lassen wir es unveraendert
  // und rendern ueber ihm Statistik + unten zusaetzliche Threat-Intel-Liste.
  const threatIntelFindings = useMemo(() => {
    return (findings?.findings ?? []).filter((f) => f.threat_intel && typeof f.threat_intel === 'object');
  }, [findings]);

  const auditCounts = findings?.audit_severity_counts ?? findings?.severity_counts ?? null;
  const policyVersion = findings?.policy_version ?? null;
  const policyIdDistinct = findings?.policy_id_distinct ?? null;

  // KI-Daten aus events
  const aiStrategy = aiData?.aiStrategy ?? null;
  const aiConfigs = aiData?.aiConfigs ?? null;
  const toolOutputs = aiData?.toolOutputs ?? null;
  const discoveredHosts = aiData?.discoveredHosts ?? order.progress.discoveredHosts ?? null;
  // discoveredHosts kann Array oder Objekt mit .hosts sein
  const hostList = (() => {
    if (Array.isArray(discoveredHosts)) return discoveredHosts;
    if (discoveredHosts && typeof discoveredHosts === 'object') {
      const wrapped = (discoveredHosts as Record<string, unknown>).hosts;
      if (Array.isArray(wrapped)) return wrapped as Array<{ ip: string; fqdns?: string[] }>;
    }
    return [];
  })();

  const costs = aiData?.costs ?? null;

  return (
    <main className="flex-1 flex flex-col px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto w-full space-y-5">
        {/* ── HEADER ───────────────────────────── */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <Link href="/dashboard" className="text-slate-500 hover:text-slate-300 text-sm" aria-label="Zurück">
              ←
            </Link>
            <h1 className="text-xl font-semibold text-white truncate">{order.domain}</h1>
            <span className="text-xs uppercase tracking-wider text-slate-500">{pkg}</span>
            <span
              className={`text-xs px-2 py-0.5 rounded ${
                isDone ? 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30'
                : isFailed ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30'
                : 'bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30'
              }`}
            >
              {statusLabel}
            </span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <ViewSwitcher value={view} onChange={onViewChange} />
            {isDone && order.hasReport && (
              <a
                href={getReportDownloadUrl(orderId)}
                className="text-sm font-medium px-4 py-2 rounded-lg bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25 ring-1 ring-emerald-500/30 transition-colors"
              >
                PDF herunterladen
              </a>
            )}
          </div>
        </div>

        {/* Meta-Info */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
          {order.startedAt && <span>Gestartet: {formatDate(order.startedAt)}</span>}
          {order.finishedAt && <span>Fertig: {formatDate(order.finishedAt)}</span>}
          {order.progress.hostsTotal > 0 && (
            <span>
              {order.progress.hostsTotal} Host{order.progress.hostsTotal === 1 ? '' : 's'}
            </span>
          )}
          {policyVersion && (
            <span className="font-mono">Policy {policyVersion}</span>
          )}
        </div>

        {/* ── STATUS-BANNER ───────────────────── */}
        {isPrecheckRunning && (
          <div className="rounded-lg border border-cyan-800/50 bg-cyan-950/20 px-4 py-3 text-sm">
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-block h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="text-cyan-300 font-medium">Pre-Check läuft</span>
            </div>
            <p className="text-xs text-slate-400">
              Targets werden validiert, DNS aufgelöst und Live-Hosts ermittelt. Danach wartet der Auftrag auf Admin-Freigabe.
            </p>
          </div>
        )}
        {isPendingTargetReview && (
          <div className="rounded-lg border border-amber-800/50 bg-amber-950/20 px-4 py-3 text-sm flex items-center justify-between gap-3 flex-wrap">
            <div>
              <p className="text-amber-300 font-medium">Wartet auf Admin-Freigabe</p>
              <p className="text-xs text-slate-400 mt-1">
                Der Pre-Check ist abgeschlossen. Ein Admin muss die Targets freigeben, bevor der Scan startet.
              </p>
            </div>
            {admin && (
              <Link
                href={`/admin/review/${orderId}`}
                className="text-xs text-amber-300 hover:text-amber-200 font-medium px-3 py-1.5 bg-amber-400/10 rounded-lg transition-colors"
              >
                Review öffnen
              </Link>
            )}
          </div>
        )}
        {isPendingReview && admin && (
          <div className="rounded-lg border border-amber-800/50 bg-amber-950/20 px-4 py-3 text-sm flex items-center justify-between gap-3 flex-wrap">
            <span className="text-amber-300">
              Dieser Scan wartet auf deine Freigabe. Prüfe die Befunde und markiere ggf. False Positives, bevor du freigibst.
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={onApprove}
                className="text-xs text-green-300 hover:text-green-200 font-medium px-3 py-1.5 bg-green-500/15 ring-1 ring-green-500/30 rounded-lg transition-colors"
              >
                Freigeben
              </button>
              <button
                onClick={onReject}
                className="text-xs text-red-300 hover:text-red-200 font-medium px-3 py-1.5 bg-red-500/15 ring-1 ring-red-500/30 rounded-lg transition-colors"
              >
                Ablehnen
              </button>
            </div>
          </div>
        )}
        {order.error && (
          <div className="rounded-lg border border-red-800 bg-red-950/30 px-4 py-3 text-sm text-red-200">
            <span className="break-words whitespace-pre-wrap">{order.error}</span>
          </div>
        )}
        {order.status === 'report_generating' && (
          <div className="rounded-lg border border-cyan-800/50 bg-cyan-950/20 px-4 py-3 text-sm text-cyan-300">
            Report wird generiert…
          </div>
        )}

        {/* ── METRICS-ROW: Severity-Donut + Policy-Coverage ── */}
        {findings && (
          <div className="grid gap-4 md:grid-cols-2">
            <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-medium text-slate-300 mb-3">Severity-Verteilung</h2>
              <SeverityDonut counts={auditCounts} />
            </section>
            <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-medium text-slate-300 mb-3">Determinismus</h2>
              <PolicyCoverage
                findings={findings.findings ?? []}
                policyIdDistinct={policyIdDistinct}
                policyVersion={policyVersion}
              />
            </section>
          </div>
        )}

        {/* ── HOST-MAP ─────────────────────────── */}
        {(aiStrategy || hostList.length > 0) && (
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Host-Strategie</h2>
            <HostMap
              aiHosts={aiStrategy?.hosts ?? null}
              discoveredHosts={hostList}
              strategyNotes={aiStrategy?.strategy_notes ?? null}
            />
          </section>
        )}

        {/* ── FINDINGS ─────────────────────────── */}
        {findings && (
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-slate-300">
                Befunde {findings.findings ? `(${findings.findings.length})` : ''}
              </h2>
            </div>
            <FindingsViewer
              data={findings}
              excludedIds={findings.excluded_finding_ids ?? []}
              onExclude={onExclude}
              onUnexclude={onUnexclude}
            />
            {threatIntelFindings.length > 0 && (
              <div className="mt-4 border-t border-slate-800 pt-4">
                <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-2">
                  Threat-Intel zu CVE-Findings
                </h3>
                <ul className="space-y-2 text-xs">
                  {threatIntelFindings.map((f, idx) => (
                    <li
                      key={f.id ?? idx}
                      className="flex items-start gap-3 rounded border border-slate-800 bg-slate-950/40 p-2"
                    >
                      <span className="font-mono text-slate-400 shrink-0">{f.id ?? '—'}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-slate-200 truncate">{f.title}</div>
                        <div className="mt-1">
                          <ThreatIntelBadge threatIntel={f.threat_intel} />
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </section>
        )}

        {/* ── RECOMMENDATIONS ──────────────────── */}
        {findings && findings.recommendations && findings.recommendations.length > 0 && (
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-3">
              Empfehlungen ({findings.recommendations.length})
            </h2>
            <RecommendationsViewer recommendations={findings.recommendations} orderId={orderId} />
          </section>
        )}

        {/* ── STORY-TIMELINE (collapsible) ─────── */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <button
            type="button"
            onClick={() => setShowStory((v) => !v)}
            className="flex items-center justify-between w-full text-left"
          >
            <h2 className="text-sm font-medium text-slate-300">Scan-Story</h2>
            <span className="text-xs text-slate-500">{showStory ? '▲ einklappen' : '▼ ausklappen'}</span>
          </button>
          {showStory && (
            <div className="mt-4">
              <ScanStoryTimeline
                aiStrategy={aiStrategy}
                aiConfigs={aiConfigs}
                toolOutputs={toolOutputs}
                discoveredHosts={hostList}
              />
            </div>
          )}
        </section>

        {/* ── KI-COSTS (collapsible) ───────────── */}
        {costs && (
          <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <button
              type="button"
              onClick={() => setShowCosts((v) => !v)}
              className="flex items-center justify-between w-full text-left"
            >
              <h2 className="text-sm font-medium text-slate-300">
                KI-Kosten ·{' '}
                <span className="font-mono text-emerald-300">
                  ${(costs.total_usd ?? 0).toFixed(4)}
                </span>
              </h2>
              <span className="text-xs text-slate-500">{showCosts ? '▲ einklappen' : '▼ ausklappen'}</span>
            </button>
            {showCosts && Array.isArray(costs.breakdown) && (
              <table className="mt-3 w-full text-xs">
                <thead>
                  <tr className="text-left text-slate-500">
                    <th className="font-medium pb-2">Schritt</th>
                    <th className="font-medium pb-2">Modell</th>
                    <th className="font-medium pb-2 text-right">Tokens (in/out)</th>
                    <th className="font-medium pb-2 text-right">USD</th>
                  </tr>
                </thead>
                <tbody className="text-slate-300">
                  {(costs.breakdown as Array<Record<string, unknown>>).map((b, i) => (
                    <tr key={i} className="border-t border-slate-800">
                      <td className="py-1.5">{String(b.step ?? '—')}</td>
                      <td className="py-1.5 font-mono text-[11px] text-slate-400">{String(b.model ?? '—')}</td>
                      <td className="py-1.5 text-right font-mono tabular-nums">
                        {String(b.input_tokens ?? '—')} / {String(b.output_tokens ?? '—')}
                      </td>
                      <td className="py-1.5 text-right font-mono tabular-nums">
                        ${Number(b.cost_usd ?? 0).toFixed(4)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}
      </div>
    </main>
  );
}
