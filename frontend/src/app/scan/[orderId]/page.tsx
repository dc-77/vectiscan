'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import { getOrderStatus, getFindings, getScanResults, getReportDownloadUrl, getOrderEvents,
         excludeFinding, unexcludeFinding, regenerateReport, getReportVersions,
         OrderStatus, OrderEvents, FindingsData, ScanResult, ReportVersion } from '@/lib/api';
import FindingsViewer from '@/components/FindingsViewer';
import RecommendationsViewer from '@/components/RecommendationsViewer';

type Tab = 'findings' | 'recommendations' | 'debug';

// ─── Scan Timeline Component ─────────────────────────────

function formatDurationShort(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  return rs > 0 ? `${m}m ${rs}s` : `${m}m`;
}

const PHASE_COLORS: Record<number, string> = {
  0: '#3b82f6', // blue-500
  1: '#60a5fa', // blue-400
  2: '#93c5fd', // blue-300
  3: '#a78bfa', // violet-400 (Correlation & Enrichment)
};

function ScanTimeline({ results, startedAt, finishedAt }: {
  results: ScanResult[];
  startedAt: string | null;
  finishedAt: string | null;
}) {
  if (!results.length) return null;

  // Total duration
  const totalMs = startedAt && finishedAt
    ? new Date(finishedAt).getTime() - new Date(startedAt).getTime()
    : results.reduce((sum, r) => sum + (r.durationMs || 0), 0);

  // Phase durations
  const phaseDurations: Record<number, number> = {};
  for (const r of results) {
    if (r.durationMs > 0) {
      phaseDurations[r.phase] = (phaseDurations[r.phase] || 0) + r.durationMs;
    }
  }

  // Top tools by duration (exclude AI/internal tools with 0 duration)
  const toolDurations = results
    .filter(r => r.durationMs > 0 && !r.toolName.startsWith('ai_'))
    .sort((a, b) => b.durationMs - a.durationMs)
    .slice(0, 7);

  const maxToolMs = toolDurations[0]?.durationMs || 1;

  return (
    <div className="mb-6">
      <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3">Scan Timeline</h3>
      <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 space-y-4">
        {/* Total duration */}
        <div>
          <div className="flex justify-between text-xs mb-1">
            <span className="text-slate-400">Gesamtdauer</span>
            <span className="font-mono text-white">{formatDurationShort(totalMs)}</span>
          </div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 rounded-full" style={{ width: '100%' }} />
          </div>
        </div>

        {/* Phase breakdown */}
        <div className="space-y-1.5">
          {Object.entries(phaseDurations).sort(([a], [b]) => Number(a) - Number(b)).map(([phase, ms]) => {
            const pct = totalMs > 0 ? Math.round((ms / totalMs) * 100) : 0;
            const phaseNum = Number(phase);
            const label = phaseNum === 0 ? 'Phase 0 — DNS' : phaseNum === 1 ? 'Phase 1 — Tech' : phaseNum === 2 ? 'Phase 2 — Deep Scan' : 'Phase 3 — Korrelation';
            return (
              <div key={phase}>
                <div className="flex justify-between text-[10px] mb-0.5">
                  <span className="text-slate-500">{label}</span>
                  <span className="font-mono text-slate-400">{formatDurationShort(ms)} ({pct}%)</span>
                </div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all" style={{
                    width: `${pct}%`,
                    backgroundColor: PHASE_COLORS[phaseNum] || '#64748b',
                  }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Top tools */}
        {toolDurations.length > 0 && (
          <div>
            <div className="text-[10px] text-slate-500 mb-2">Top Tools nach Dauer</div>
            <div className="space-y-1">
              {toolDurations.map(r => {
                const pct = Math.round((r.durationMs / maxToolMs) * 100);
                const isTimeout = r.exitCode === -1;
                const isFailed = r.exitCode !== 0 && r.exitCode !== 1 && r.exitCode !== -1;
                return (
                  <div key={r.id} className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-slate-400 w-20 shrink-0 truncate">{r.toolName}</span>
                    <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{
                        width: `${pct}%`,
                        backgroundColor: isTimeout ? '#ef4444' : isFailed ? '#f59e0b' : '#3b82f6',
                      }} />
                    </div>
                    <span className={`text-[10px] font-mono w-14 text-right shrink-0 ${
                      isTimeout ? 'text-red-400' : 'text-slate-500'
                    }`}>
                      {(r.durationMs / 1000).toFixed(1)}s
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const PHASE_LABELS: Record<string, string> = {
  passive_intel: 'Passive Intel', dns_recon: 'DNS-Recon', scan_phase1: 'Phase 1', scan_phase2: 'Phase 2',
  scan_phase3: 'Phase 3 — Korrelation', scan_complete: 'Scan fertig', report_generating: 'Report...', report_complete: 'Fertig',
  failed: 'Fehlgeschlagen', cancelled: 'Abgebrochen',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export default function ScanDetailPage() {
  const router = useRouter();
  const params = useParams();
  const orderId = params.orderId as string;

  const [ready, setReady] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [order, setOrder] = useState<OrderStatus | null>(null);
  const [findings, setFindings] = useState<FindingsData | null>(null);
  const [scanResults, setScanResults] = useState<ScanResult[] | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [aiData, setAiData] = useState<(OrderEvents & Record<string, any>) | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('findings');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const [reportVersions, setReportVersions] = useState<ReportVersion[]>([]);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setAdmin(isAdmin());
    setReady(true);
  }, [router]);

  const loadData = useCallback(async () => {
    try {
      // Load order status
      const orderRes = await getOrderStatus(orderId);
      if (!orderRes.success || !orderRes.data) {
        setError(orderRes.error || 'Scan nicht gefunden');
        setLoading(false);
        return;
      }
      setOrder(orderRes.data);

      // Load findings if report is complete
      if (['report_complete', 'scan_complete', 'report_generating'].includes(orderRes.data.status)) {
        const findingsRes = await getFindings(orderId);
        if (findingsRes.success && findingsRes.data) {
          setFindings(findingsRes.data);
        }
      }

      // Load report versions when scan is done
      if (orderRes.data.status === 'report_complete' && orderRes.data.hasReport) {
        const versionsRes = await getReportVersions(orderId);
        if (versionsRes.success && versionsRes.data) {
          setReportVersions(versionsRes.data.versions);
        }
      }

      // Load scan results (for debug tab)
      const resultsRes = await getScanResults(orderId);
      if (resultsRes.success && resultsRes.data) {
        setScanResults(resultsRes.data.results);
      }

      // Load AI events
      const eventsRes = await getOrderEvents(orderId);
      if (eventsRes.success && eventsRes.data) {
        setAiData(eventsRes.data);
      }
    } catch {
      setError('Fehler beim Laden der Scan-Daten');
    } finally {
      setLoading(false);
    }
  }, [orderId]);

  useEffect(() => {
    if (ready) loadData();
  }, [ready, loadData]);

  // --- Finding exclusion handlers ---
  const handleExclude = useCallback(async (findingId: string, reason: string) => {
    const res = await excludeFinding(orderId, findingId, reason);
    if (res.success) {
      const findingsRes = await getFindings(orderId);
      if (findingsRes.success && findingsRes.data) setFindings(findingsRes.data);
    }
  }, [orderId]);

  const handleUnexclude = useCallback(async (findingId: string) => {
    const res = await unexcludeFinding(orderId, findingId);
    if (res.success) {
      const findingsRes = await getFindings(orderId);
      if (findingsRes.success && findingsRes.data) setFindings(findingsRes.data);
    }
  }, [orderId]);

  const handleRegenerate = useCallback(async () => {
    setRegenerating(true);
    const res = await regenerateReport(orderId);
    if (res.success) {
      // Refresh order status to pick up new report status
      const orderRes = await getOrderStatus(orderId);
      if (orderRes.success && orderRes.data) setOrder(orderRes.data);
      // Reload report versions
      const versionsRes = await getReportVersions(orderId);
      if (versionsRes.success && versionsRes.data) setReportVersions(versionsRes.data.versions);
    }
    setRegenerating(false);
  }, [orderId]);

  // Auto-switch to debug tab when scan failed and user is admin
  useEffect(() => {
    if (order && (order.status === 'failed' || order.status === 'cancelled') && admin) {
      setActiveTab('debug');
    }
  }, [order?.status, admin]);

  if (!ready) return null;

  if (loading) {
    return <main className="flex-1 flex items-center justify-center"><span className="text-slate-500">Lade Scan-Details...</span></main>;
  }

  if (error || !order) {
    return (
      <main className="flex-1 flex flex-col items-center justify-center px-4 gap-4">
        <p className="text-red-400">{error || 'Scan nicht gefunden'}</p>
        <Link href="/dashboard" className="text-blue-400 hover:text-blue-300 text-sm">Zurück zum Dashboard</Link>
      </main>
    );
  }

  const isDone = order.status === 'report_complete';
  const isFailed = order.status === 'failed' || order.status === 'cancelled';
  const showDebugDefault = isFailed && admin;
  const PKG_LABELS: Record<string, string> = {
    webcheck: 'WEBCHECK', perimeter: 'PERIMETER', compliance: 'COMPLIANCE',
    supplychain: 'SUPPLYCHAIN', insurance: 'INSURANCE', tlscompliance: 'TLS-AUDIT',
    basic: 'WEBCHECK', professional: 'PERIMETER', nis2: 'COMPLIANCE',
  };
  const pkg = PKG_LABELS[order.package] || order.package.toUpperCase();
  const statusLabel = PHASE_LABELS[order.status] || order.status;

  // Build IP → FQDNs lookup from discovered hosts
  const ipToFqdns: Record<string, string[]> = {};
  const rawHosts = aiData?.discoveredHosts || order.progress.discoveredHosts || [];
  // discoveredHosts may be an array or an object with .hosts key
  const hostList = Array.isArray(rawHosts) ? rawHosts
    : (rawHosts as Record<string, unknown>)?.hosts || [];
  const hostsArray = (Array.isArray(hostList) ? hostList : []) as Array<{ ip: string; fqdns?: string[] }>;
  for (const h of hostsArray) {
    if (h.ip && h.fqdns?.length) ipToFqdns[h.ip] = h.fqdns;
  }

  // Group scan results by phase + host for debug view
  const groupedResults: Record<string, ScanResult[]> = {};
  if (scanResults) {
    for (const r of scanResults) {
      let label = `Phase ${r.phase}`;
      if (r.hostIp) {
        const fqdns = ipToFqdns[r.hostIp];
        label += ` — ${r.hostIp}`;
        if (fqdns?.length) label += ` (${fqdns.join(', ')})`;
      }
      if (!groupedResults[label]) groupedResults[label] = [];
      groupedResults[label].push(r);
    }
  }

  return (
    <main className="flex-1 flex flex-col px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto w-full space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <Link href="/dashboard" className="text-slate-500 hover:text-slate-300 text-sm">&larr;</Link>
            <h1 className="text-lg font-semibold text-white truncate font-mono">{order.domain}</h1>
            <span className="text-[10px] font-mono uppercase text-slate-500">{pkg}</span>
            <span className={`text-xs px-2 py-0.5 rounded ${
              isDone ? 'bg-slate-700 text-slate-300'
              : isFailed ? 'bg-red-500/15 text-red-400'
              : 'bg-blue-500/20 text-blue-400'
            }`}>{statusLabel}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {isDone && order.hasReport && (
              <a href={getReportDownloadUrl(orderId)}
                className="text-sm text-blue-400 hover:text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 px-4 py-2 rounded-lg transition-colors">
                PDF herunterladen
              </a>
            )}
          </div>
        </div>

        {/* Report Versions */}
        {isDone && order.hasReport && reportVersions.length > 0 && (
          <div className="bg-[#1e293b] rounded-xl p-5 border border-slate-700">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              Reports ({reportVersions.length} {reportVersions.length === 1 ? 'Version' : 'Versionen'})
            </h3>
            <div className="space-y-2">
              {reportVersions.map((rv) => (
                <div key={rv.version} className={`flex items-center justify-between p-3 rounded-lg border ${
                  rv.isCurrent ? 'border-blue-500/30 bg-blue-900/10' : 'border-slate-700 bg-slate-800/50 opacity-70'
                }`}>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-slate-200">v{rv.version}</span>
                      {rv.isCurrent && (
                        <span className="px-1.5 py-0.5 bg-blue-600/30 text-blue-300 text-xs rounded">Aktuell</span>
                      )}
                      {rv.excludedCount > 0 && (
                        <span className="px-1.5 py-0.5 bg-yellow-600/20 text-yellow-300 text-xs rounded">
                          {rv.excludedCount} FP ausgeschlossen
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      {new Date(rv.createdAt).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      {' \u2014 '}{rv.findingsCount} Befunde
                      {rv.fileSizeBytes > 0 && ` \u2014 ${(rv.fileSizeBytes / 1024).toFixed(0)} KB`}
                    </div>
                  </div>
                  <a
                    href={getReportDownloadUrl(orderId, rv.version)}
                    className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs rounded-lg whitespace-nowrap"
                  >
                    PDF herunterladen
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Meta info */}
        <div className="flex items-center gap-3 text-xs text-slate-600 flex-wrap">
          {order.startedAt && <span>Gestartet: {formatDate(order.startedAt)}</span>}
          {order.finishedAt && <span>Fertig: {formatDate(order.finishedAt)}</span>}
          {order.progress.hostsTotal > 0 && <span>{order.progress.hostsTotal} Hosts</span>}
        </div>

        {/* Error message + retry button */}
        {order.error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            <div className="flex items-start justify-between gap-4">
              <span className="break-words whitespace-pre-wrap flex-1">{order.error}</span>
              {admin && isFailed && (
                <button
                  onClick={handleRegenerate}
                  disabled={regenerating}
                  className="flex-shrink-0 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white text-xs font-medium px-3 py-1.5 rounded transition-colors"
                >
                  {regenerating ? 'Wird generiert...' : 'Report erneut generieren'}
                </button>
              )}
            </div>
          </div>
        )}
        {order.status === 'report_generating' && (
          <div className="bg-blue-900/20 border border-blue-800/50 rounded-lg px-4 py-3 text-sm text-blue-300">
            Report wird generiert...
          </div>
        )}

        {/* Tabs */}
        <div className="flex border-b border-gray-800">
          {(isDone || findings) && (
            <>
              <button onClick={() => setActiveTab('findings')}
                className={`px-4 py-2.5 text-xs font-medium transition-colors ${
                  activeTab === 'findings' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-500 hover:text-slate-300'
                }`}>Befunde</button>
              <button onClick={() => setActiveTab('recommendations')}
                className={`px-4 py-2.5 text-xs font-medium transition-colors ${
                  activeTab === 'recommendations' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-500 hover:text-slate-300'
                }`}>Empfehlungen</button>
            </>
          )}
          {(admin || isFailed) && (
            <button onClick={() => setActiveTab('debug')}
              className={`px-4 py-2.5 text-xs font-medium transition-colors ${
                activeTab === 'debug' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-500 hover:text-slate-300'
              }`}>{isFailed ? 'Fehleranalyse' : 'Debug'}</button>
          )}
        </div>

        {/* Tab Content */}
        <div className="min-h-[300px]">
          {/* Findings Tab */}
          {activeTab === 'findings' && findings && (
            <div className="space-y-4">
              {regenerating && (
                <div className="bg-blue-900/20 border border-blue-800/50 rounded-lg px-4 py-3 text-sm text-blue-300">
                  Report wird neu generiert...
                </div>
              )}
              <FindingsViewer
                data={findings}
                excludedIds={findings.excluded_finding_ids || []}
                onExclude={admin ? handleExclude : undefined}
                onUnexclude={admin ? handleUnexclude : undefined}
                onRegenerateReport={admin ? handleRegenerate : undefined}
                lastReportExcludedFindings={reportVersions.length > 0 ? reportVersions[0].excludedFindings : []}
              />
            </div>
          )}
          {activeTab === 'findings' && !findings && (
            <div className="text-center py-12 text-slate-600 text-sm">
              {isDone ? 'Keine Befunddaten verfügbar.' : 'Befunde werden nach Abschluss des Scans angezeigt.'}
            </div>
          )}

          {/* Recommendations Tab */}
          {activeTab === 'recommendations' && findings && (
            <RecommendationsViewer recommendations={findings.recommendations} />
          )}
          {activeTab === 'recommendations' && !findings && (
            <div className="text-center py-12 text-slate-600 text-sm">Keine Empfehlungen verfügbar.</div>
          )}

          {/* Debug Tab (Admin or Failed scans) */}
          {activeTab === 'debug' && (admin || isFailed) && (
            <div className="space-y-6">
              {/* Timeline */}
              {scanResults && (
                <ScanTimeline results={scanResults} startedAt={order.startedAt} finishedAt={order.finishedAt} />
              )}

              {/* AI Costs (admin only) */}
              {admin && aiData?.costs && aiData.costs.total_usd > 0 && (
                <details className="border border-slate-700 rounded-lg">
                  <summary className="p-4 cursor-pointer text-sm font-semibold text-slate-300 hover:text-white">
                    AI-Kosten: ${aiData.costs.total_usd.toFixed(4)} USD
                  </summary>
                  <div className="p-4 border-t border-slate-700">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-slate-500 border-b border-slate-700">
                          <th className="text-left py-2">Schritt</th>
                          <th className="text-left py-2">Modell</th>
                          <th className="text-right py-2">Tokens</th>
                          <th className="text-right py-2">Kosten</th>
                        </tr>
                      </thead>
                      <tbody className="text-slate-300">
                        {aiData.costs.breakdown.map((c: { step: string; model: string; tokens: number; cost_usd: number }, i: number) => (
                          <tr key={i} className="border-t border-slate-800">
                            <td className="py-1.5">{c.step.replace(/_/g, ' ')}</td>
                            <td className="py-1.5 text-slate-400 font-mono text-[10px]">{c.model.split('-').slice(-2).join('-')}</td>
                            <td className="py-1.5 text-right font-mono">{c.tokens.toLocaleString()}</td>
                            <td className="py-1.5 text-right font-mono">${c.cost_usd.toFixed(4)}</td>
                          </tr>
                        ))}
                        <tr className="border-t border-slate-600 font-semibold">
                          <td className="py-2" colSpan={3}>Gesamt</td>
                          <td className="py-2 text-right font-mono">${aiData.costs.total_usd.toFixed(4)}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </details>
              )}

              {/* AI Decisions */}
              {aiData && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">KI-Entscheidungen</h3>
                  {aiData.aiStrategy && (
                    <details className="bg-[#1e293b] rounded-lg border border-gray-800 mb-2">
                      <summary className="px-4 py-2.5 text-sm font-mono text-blue-400 cursor-pointer hover:bg-[#253347]">
                        AI Host Strategy
                      </summary>
                      <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap"
                        style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                        {JSON.stringify(aiData.aiStrategy, null, 2)}
                      </pre>
                    </details>
                  )}
                  {aiData.aiConfigs && Object.keys(aiData.aiConfigs as Record<string, unknown>).length > 0 && (
                    <details className="bg-[#1e293b] rounded-lg border border-gray-800 mb-2">
                      <summary className="px-4 py-2.5 text-sm font-mono text-blue-400 cursor-pointer hover:bg-[#253347]">
                        AI Phase 2 Configs ({Object.keys(aiData.aiConfigs as Record<string, unknown>).length} hosts)
                      </summary>
                      <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap"
                        style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                        {JSON.stringify(aiData.aiConfigs, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              )}

              {/* Copy All Debug Data Button */}
              {scanResults && scanResults.length > 0 && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      const debugData = {
                        orderId,
                        domain: order.domain,
                        status: order.status,
                        package: order.package,
                        error: order.error,
                        startedAt: order.startedAt,
                        finishedAt: order.finishedAt,
                        progress: order.progress,
                        aiStrategy: aiData?.aiStrategy || null,
                        aiConfigs: aiData?.aiConfigs || null,
                        passiveIntel: order.passiveIntelSummary || null,
                        correlationData: order.correlationData || null,
                        businessImpactScore: order.businessImpactScore || null,
                        toolResults: scanResults.map(r => ({
                          tool: r.toolName,
                          phase: r.phase,
                          host: r.hostIp,
                          exitCode: r.exitCode,
                          durationMs: r.durationMs,
                          output: r.rawOutput,
                        })),
                      };
                      navigator.clipboard.writeText(JSON.stringify(debugData, null, 2)).then(() => {
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      });
                    }}
                    className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors ${
                      copied
                        ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                        : 'bg-slate-700 text-slate-300 hover:bg-slate-600 border border-slate-600'
                    }`}
                  >
                    {copied ? 'Kopiert!' : 'Debug-JSON kopieren'}
                  </button>
                  <span className="text-[10px] text-slate-600">{scanResults.length} Tool-Outputs</span>
                </div>
              )}

              {/* Passive Intelligence (Phase 0a) */}
              {order.passiveIntelSummary && Object.keys(order.passiveIntelSummary).length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Passive Intelligence</h3>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800">
                    <summary className="px-4 py-2.5 text-sm font-mono text-violet-400 cursor-pointer hover:bg-[#253347]">
                      Phase 0a — Shodan, AbuseIPDB, WHOIS, DNS-Security
                    </summary>
                    <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto"
                      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                      {JSON.stringify(order.passiveIntelSummary, null, 2)}
                    </pre>
                  </details>
                </div>
              )}

              {/* Phase 3 Correlation Data */}
              {order.correlationData && (order.correlationData as unknown[]).length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Korrelation &amp; Enrichment (Phase 3)</h3>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800 mb-2">
                    <summary className="px-4 py-2.5 text-sm font-mono text-violet-400 cursor-pointer hover:bg-[#253347]">
                      Korrelierte Findings ({(order.correlationData as unknown[]).length})
                      {order.businessImpactScore != null && (
                        <span className="ml-3 text-xs text-slate-500">Business-Impact: {order.businessImpactScore.toFixed(1)}/10</span>
                      )}
                    </summary>
                    <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto"
                      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                      {JSON.stringify(order.correlationData, null, 2)}
                    </pre>
                  </details>
                </div>
              )}

              {/* Claude Report Debug (admin only) */}
              {aiData?.claudeDebug && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Claude Report Debug</h3>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800 mb-2">
                    <summary className="px-4 py-2.5 text-sm font-mono text-amber-400 cursor-pointer hover:bg-[#253347]">
                      System Prompt ({aiData.claudeDebug.package})
                    </summary>
                    <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto"
                      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                      {aiData.claudeDebug.system_prompt}
                    </pre>
                  </details>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800 mb-2">
                    <summary className="px-4 py-2.5 text-sm font-mono text-amber-400 cursor-pointer hover:bg-[#253347]">
                      User Prompt
                    </summary>
                    <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto"
                      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                      {aiData.claudeDebug.user_prompt}
                    </pre>
                  </details>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800 mb-2">
                    <summary className="px-4 py-2.5 text-sm font-mono text-amber-400 cursor-pointer hover:bg-[#253347]">
                      Claude Raw Response {aiData.claudeDebug.error && <span className="text-red-400 ml-2">(Parse Error)</span>}
                    </summary>
                    <pre className="px-4 pb-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto"
                      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                      {aiData.claudeDebug.raw_response}
                    </pre>
                  </details>
                  {aiData.claudeDebug.error && (
                    <div className="bg-red-900/20 border border-red-800/50 rounded-lg px-4 py-2 text-xs font-mono text-red-300 mb-2">
                      {aiData.claudeDebug.error}
                    </div>
                  )}
                </div>
              )}

              {/* AI Communication Debug */}
              {aiData?.aiDebug && Object.keys(aiData.aiDebug).length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">AI-Kommunikation</h3>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800">
                    <summary className="px-4 py-2.5 text-sm font-mono text-cyan-400 cursor-pointer hover:bg-[#253347]">
                      AI-Kommunikation ({Object.keys(aiData.aiDebug).length} Aufrufe)
                    </summary>
                    <div className="px-4 pb-3 space-y-3 border-t border-gray-800">
                      {Object.entries(aiData.aiDebug).map(([key, data]: [string, any]) => {
                        // Per-host configs (ai_phase2_config has IPs as keys)
                        const isPerHost = key === 'ai_phase2_config' && typeof data === 'object' && !data.system_prompt;

                        if (isPerHost) {
                          return Object.entries(data).map(([ip, hostData]: [string, any]) => (
                            <details key={`${key}-${ip}`} className="border border-gray-700 rounded-lg">
                              <summary className="px-3 py-2 cursor-pointer text-xs font-mono text-slate-400 hover:text-slate-200">
                                {key} — {ip}
                              </summary>
                              <div className="px-3 pb-2 space-y-2 text-xs">
                                <div><span className="text-slate-500">System Prompt:</span>
                                  <pre className="mt-1 p-2 bg-[#0c1222] border border-gray-800 rounded text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto"
                                    style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{hostData.system_prompt}</pre>
                                </div>
                                <div><span className="text-slate-500">User Prompt:</span>
                                  <pre className="mt-1 p-2 bg-[#0c1222] border border-gray-800 rounded text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto"
                                    style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{hostData.user_prompt}</pre>
                                </div>
                                <div><span className="text-slate-500">Raw Response:</span>
                                  <pre className="mt-1 p-2 bg-[#0c1222] border border-gray-800 rounded text-green-400 whitespace-pre-wrap max-h-40 overflow-y-auto"
                                    style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{hostData.raw_response}</pre>
                                </div>
                              </div>
                            </details>
                          ));
                        }

                        return (
                          <details key={key} className="border border-gray-700 rounded-lg">
                            <summary className="px-3 py-2 cursor-pointer text-xs font-mono text-slate-400 hover:text-slate-200">
                              {key.replace(/_/g, ' ').replace(/ai /i, 'AI ')}
                            </summary>
                            <div className="px-3 pb-2 space-y-2 text-xs">
                              <div><span className="text-slate-500">System Prompt:</span>
                                <pre className="mt-1 p-2 bg-[#0c1222] border border-gray-800 rounded text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto"
                                  style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{data.system_prompt}</pre>
                              </div>
                              <div><span className="text-slate-500">User Prompt:</span>
                                <pre className="mt-1 p-2 bg-[#0c1222] border border-gray-800 rounded text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto"
                                  style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{data.user_prompt}</pre>
                              </div>
                              <div><span className="text-slate-500">Raw Response:</span>
                                <pre className="mt-1 p-2 bg-[#0c1222] border border-gray-800 rounded text-green-400 whitespace-pre-wrap max-h-40 overflow-y-auto"
                                  style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{data.raw_response}</pre>
                              </div>
                            </div>
                          </details>
                        );
                      })}
                    </div>
                  </details>
                </div>
              )}

              {/* False Positives */}
              {aiData?.falsePositives && aiData.falsePositives.count > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Aussortierte False Positives</h3>
                  <details className="bg-[#1e293b] rounded-lg border border-gray-800">
                    <summary className="px-4 py-2.5 text-sm font-mono text-yellow-400 cursor-pointer hover:bg-[#253347]">
                      False Positives ({aiData.falsePositives.count})
                    </summary>
                    <div className="px-4 pb-3 space-y-3 border-t border-gray-800">
                      {/* Summary by reason */}
                      <div className="flex flex-wrap gap-2 pt-3">
                        {Object.entries(aiData.falsePositives.by_reason).map(([reason, count]) => (
                          <span key={reason} className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">
                            {reason}: {count as number}
                          </span>
                        ))}
                      </div>
                      {/* Detail table */}
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs text-left">
                          <thead className="text-slate-500 border-b border-slate-700">
                            <tr>
                              <th className="py-2 pr-3">Tool</th>
                              <th className="py-2 pr-3">Titel</th>
                              <th className="py-2 pr-3">Severity</th>
                              <th className="py-2 pr-3">Host</th>
                              <th className="py-2">Grund</th>
                            </tr>
                          </thead>
                          <tbody className="text-slate-300">
                            {aiData.falsePositives.details.map((fp: any, i: number) => (
                              <tr key={i} className="border-b border-slate-800">
                                <td className="py-2 pr-3 text-slate-400">{fp.tool}</td>
                                <td className="py-2 pr-3">{fp.title}</td>
                                <td className="py-2 pr-3">
                                  <span className={`px-1.5 py-0.5 rounded text-xs ${
                                    fp.severity === 'high' || fp.severity === 'HIGH' ? 'bg-red-900/50 text-red-300' :
                                    fp.severity === 'medium' || fp.severity === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-300' :
                                    fp.severity === 'critical' || fp.severity === 'CRITICAL' ? 'bg-red-900/70 text-red-200' :
                                    'bg-slate-700 text-slate-300'
                                  }`}>{fp.severity}</span>
                                </td>
                                <td className="py-2 pr-3 font-mono text-slate-400">{fp.host}</td>
                                <td className="py-2 text-slate-500">{fp.reason}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </details>
                </div>
              )}

              {/* Tool Results */}
              {scanResults && scanResults.length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">Tool-Ergebnisse</h3>
                  <div className="divide-y divide-gray-800/50">
                    {Object.entries(groupedResults).map(([group, items]) => (
                      <div key={group}>
                        <div className="px-4 py-2 bg-[#1e293b]/50 text-xs font-medium text-slate-400 uppercase tracking-wider">{group}</div>
                        <div className="divide-y divide-gray-800/30">
                          {items.map((result) => {
                            const toolId = `${orderId}-${result.id}`;
                            const isOpen = expandedTool === toolId;
                            const exitOk = result.exitCode === 0 || result.exitCode === 1;
                            const sec = result.durationMs ? (result.durationMs / 1000).toFixed(1) : '?';

                            return (
                              <div key={result.id}>
                                <button onClick={() => setExpandedTool(isOpen ? null : toolId)}
                                  className="w-full px-4 py-2.5 flex items-center justify-between gap-3 hover:bg-[#1e293b]/30 transition-colors text-left">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span className={`w-2 h-2 rounded-full shrink-0 ${exitOk ? 'bg-green-500' : result.exitCode === -1 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                                    <span className="text-sm font-mono text-blue-400 truncate">{result.toolName}</span>
                                  </div>
                                  <div className="flex items-center gap-3 shrink-0 text-xs text-slate-500">
                                    <span>{sec}s</span>
                                    <span className={`font-mono ${exitOk ? 'text-green-600' : result.exitCode === -1 ? 'text-yellow-600' : 'text-red-600'}`}>
                                      {result.exitCode === -1 ? 'TIMEOUT' : `exit ${result.exitCode}`}
                                    </span>
                                    <span className="text-slate-700">{isOpen ? '\u25B2' : '\u25BC'}</span>
                                  </div>
                                </button>
                                {isOpen && result.rawOutput && (
                                  <div className="px-4 pb-3">
                                    <pre className="bg-[#0c1222] border border-gray-800 rounded-lg p-3 text-xs font-mono text-slate-400 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap break-all"
                                      style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>{result.rawOutput}</pre>
                                  </div>
                                )}
                                {isOpen && !result.rawOutput && (
                                  <div className="px-4 pb-3 text-xs text-slate-600 italic">Keine Rohausgabe.</div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(!scanResults || scanResults.length === 0) && (
                <div className="text-center py-12 text-slate-600 text-sm">Keine Rohdaten vorhanden.</div>
              )}
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
