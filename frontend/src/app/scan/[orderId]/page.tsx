'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import { getOrderStatus, getFindings, getScanResults, getReportDownloadUrl, getOrderEvents,
         OrderStatus, FindingsData, ScanResult } from '@/lib/api';
import FindingsViewer from '@/components/FindingsViewer';
import RecommendationsViewer from '@/components/RecommendationsViewer';

type Tab = 'findings' | 'recommendations' | 'debug';

const PHASE_LABELS: Record<string, string> = {
  dns_recon: 'DNS-Recon', scan_phase1: 'Phase 1', scan_phase2: 'Phase 2',
  scan_complete: 'Scan fertig', report_generating: 'Report...', report_complete: 'Fertig',
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
  const [aiData, setAiData] = useState<Record<string, any> | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('findings');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedTool, setExpandedTool] = useState<string | null>(null);

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
  const pkg = order.package === 'professional' ? 'PRO' : order.package.toUpperCase();
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

        {/* Meta info */}
        <div className="flex items-center gap-3 text-xs text-slate-600 flex-wrap">
          {order.startedAt && <span>Gestartet: {formatDate(order.startedAt)}</span>}
          {order.finishedAt && <span>Fertig: {formatDate(order.finishedAt)}</span>}
          {order.progress.hostsTotal > 0 && <span>{order.progress.hostsTotal} Hosts</span>}
        </div>

        {/* Error message */}
        {order.error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {order.error}
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
          {admin && (
            <button onClick={() => setActiveTab('debug')}
              className={`px-4 py-2.5 text-xs font-medium transition-colors ${
                activeTab === 'debug' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-500 hover:text-slate-300'
              }`}>Debug</button>
          )}
        </div>

        {/* Tab Content */}
        <div className="min-h-[300px]">
          {/* Findings Tab */}
          {activeTab === 'findings' && findings && (
            <FindingsViewer data={findings} />
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

          {/* Debug Tab (Admin only) */}
          {activeTab === 'debug' && admin && (
            <div className="space-y-6">
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
