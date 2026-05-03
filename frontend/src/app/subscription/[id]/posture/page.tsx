'use client';

import { useState, useEffect, useCallback, use } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  getSubscriptionPosture, getSubscriptionFindings, getPostureHistory,
  acceptFindingRisk, reopenFinding, generateStatusReport,
  SubscriptionPosture, ConsolidatedFinding, PostureHistoryPoint,
} from '@/lib/api';
import { isLoggedIn } from '@/lib/auth';

interface PageProps { params: Promise<{ id: string }> }

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-300 ring-red-500/40',
  HIGH:     'bg-orange-500/20 text-orange-300 ring-orange-500/40',
  MEDIUM:   'bg-amber-500/20 text-amber-300 ring-amber-500/40',
  LOW:      'bg-blue-500/20 text-blue-300 ring-blue-500/40',
  INFO:     'bg-slate-500/20 text-slate-300 ring-slate-500/40',
};
const STATUS_LABEL: Record<string, string> = {
  open: 'Offen', resolved: 'Behoben', regressed: 'Wieder offen', risk_accepted: 'Akzeptiert',
};
const STATUS_COLOR: Record<string, string> = {
  open: 'bg-red-500/15 text-red-300',
  resolved: 'bg-emerald-500/15 text-emerald-300',
  regressed: 'bg-orange-500/15 text-orange-300',
  risk_accepted: 'bg-slate-700 text-slate-300',
};

export default function SubscriptionPosturePage({ params }: PageProps) {
  const router = useRouter();
  const { id } = use(params);
  const [ready, setReady] = useState(false);
  const [posture, setPosture] = useState<SubscriptionPosture | null>(null);
  const [findings, setFindings] = useState<ConsolidatedFinding[]>([]);
  const [history, setHistory] = useState<PostureHistoryPoint[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('open');
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setReady(true);
  }, [router]);

  const load = useCallback(async () => {
    const [p, f, h] = await Promise.all([
      getSubscriptionPosture(id),
      getSubscriptionFindings(id, { status: statusFilter }),
      getPostureHistory(id, 30),
    ]);
    if (p.success && p.data) setPosture(p.data);
    if (f.success && f.data) setFindings(f.data.findings);
    if (h.success && h.data) setHistory(h.data.history);
  }, [id, statusFilter]);

  useEffect(() => { if (ready) load(); }, [ready, load]);

  const handleAcceptRisk = async (fid: string) => {
    const reason = prompt('Begruendung fuer Risk-Acceptance (mind. 5 Zeichen):');
    if (!reason || reason.trim().length < 5) return;
    const res = await acceptFindingRisk(id, fid, reason.trim());
    if (res.success) load();
    else alert(`Fehler: ${res.error}`);
  };

  const handleReopen = async (fid: string) => {
    if (!confirm('Risk-Acceptance widerrufen?')) return;
    const res = await reopenFinding(id, fid);
    if (res.success) load();
    else alert(`Fehler: ${res.error}`);
  };

  const handleGenerate = async () => {
    setGenerating(true);
    const res = await generateStatusReport(id);
    setGenerating(false);
    if (res.success) alert('Status-Report wird erstellt. Erscheint in 1-2 Min in der Liste.');
    else alert(`Fehler: ${res.error}`);
  };

  if (!ready || !posture) {
    return <main className="flex-1 px-4 py-6 md:px-8"><div className="max-w-6xl mx-auto text-slate-500">Lade…</div></main>;
  }

  const score = posture.postureScore != null ? Math.round(posture.postureScore) : null;
  const scoreColor = score == null ? 'text-slate-400'
    : score >= 80 ? 'text-emerald-300'
    : score >= 60 ? 'text-amber-300'
    : 'text-red-300';
  const trendIcon = {
    improving: '↗', degrading: '↘', stable: '→', unknown: '—',
  }[posture.trendDirection];
  const open = posture.severityCounts.open || {};

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <Link href="/dashboard" className="text-xs text-slate-500 hover:text-slate-300">← Dashboard</Link>

        {/* Score-Hero */}
        <div className="rounded-xl p-6 bg-[#1e293b] border border-slate-700 grid md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-xs text-slate-500 uppercase tracking-wider">Posture-Score</div>
            <div className={`text-6xl font-bold ${scoreColor} mt-2`}>{score ?? '–'}</div>
            <div className="text-sm text-slate-400 mt-1">von 100 · {trendIcon} {posture.trendDirection}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Offene Befunde</div>
            <div className="space-y-1 text-sm">
              {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const).map(s => (
                <div key={s} className="flex justify-between">
                  <span className={`${SEV_COLOR[s].split(' ').slice(1).join(' ')}`}>{s}</span>
                  <span className="text-slate-300 font-mono">{open[s] ?? 0}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Lifecycle</div>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between"><span className="text-emerald-300">Behoben (kumuliert)</span><span className="font-mono">{posture.severityCounts.resolved_total ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-orange-300">Wieder offen</span><span className="font-mono">{posture.severityCounts.regressed_total ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">Akzeptiert</span><span className="font-mono">{posture.severityCounts.accepted_total ?? 0}</span></div>
            </div>
            <button
              onClick={handleGenerate}
              disabled={generating}
              className="mt-4 w-full text-xs font-medium px-3 py-2 rounded-lg bg-cyan-500/20 text-cyan-200 hover:bg-cyan-500/30 disabled:opacity-50"
            >
              {generating ? 'Wird erstellt…' : 'Status-Report (PDF) jetzt erstellen'}
            </button>
          </div>
        </div>

        {/* Trend-Chart (SVG inline, simpel) */}
        {history.length >= 2 && (
          <div className="rounded-xl p-5 bg-[#1e293b] border border-slate-700">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Score-Verlauf (letzte {history.length} Aggregationen)</div>
            <TrendChart history={history} />
          </div>
        )}

        {/* Findings-Tabelle mit Status-Filter */}
        <div className="rounded-xl p-5 bg-[#1e293b] border border-slate-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200">Befunde ({findings.length})</h2>
            <div className="flex gap-1">
              {['open','resolved','regressed','risk_accepted'].map(s => (
                <button key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`text-xs px-2.5 py-1 rounded ${
                    statusFilter === s ? STATUS_COLOR[s] + ' ring-1 ring-current' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >{STATUS_LABEL[s]}</button>
              ))}
            </div>
          </div>
          {findings.length === 0 ? (
            <div className="text-sm text-slate-500 italic">Keine Befunde mit Status &laquo;{STATUS_LABEL[statusFilter]}&raquo;.</div>
          ) : (
            <div className="space-y-2">
              {findings.map(f => (
                <div key={f.id} className="border border-slate-700/50 rounded-lg p-3 bg-slate-900/30">
                  <div className="flex items-start gap-3 flex-wrap">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ring-1 ring-inset ${SEV_COLOR[f.severity]}`}>{f.severity}</span>
                    <span className="font-mono text-xs text-slate-400">{f.hostIp}</span>
                    {f.portOrPath && <span className="font-mono text-xs text-slate-500">{f.portOrPath}</span>}
                    <span className="text-sm text-white flex-1 min-w-0">{f.title}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1.5 flex gap-3 flex-wrap">
                    <span>Erstmals: {new Date(f.firstSeenAt).toLocaleDateString('de-DE')}</span>
                    <span>Zuletzt: {new Date(f.lastSeenAt).toLocaleDateString('de-DE')}</span>
                    {f.resolvedAt && <span className="text-emerald-400">Behoben: {new Date(f.resolvedAt).toLocaleDateString('de-DE')}</span>}
                    {f.cvssScore && <span>CVSS {f.cvssScore.toFixed(1)}</span>}
                  </div>
                  {f.riskAcceptedReason && (
                    <div className="text-xs text-slate-400 mt-2 italic">
                      Akzeptiert: {f.riskAcceptedReason}
                    </div>
                  )}
                  <div className="mt-2 flex gap-1.5">
                    {(f.status === 'open' || f.status === 'regressed') && (
                      <button onClick={() => handleAcceptRisk(f.id)}
                        className="text-[10px] font-medium px-2 py-1 rounded bg-slate-700 text-slate-300 hover:bg-slate-600">
                        Risiko akzeptieren
                      </button>
                    )}
                    {f.status === 'risk_accepted' && (
                      <button onClick={() => handleReopen(f.id)}
                        className="text-[10px] font-medium px-2 py-1 rounded bg-amber-500/20 text-amber-300 hover:bg-amber-500/30">
                        Erneut bewerten
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </main>
  );
}

function TrendChart({ history }: { history: PostureHistoryPoint[] }) {
  // Simple SVG-Linie ueber posture_score
  const pts = [...history].reverse(); // chronologisch
  const w = 800, h = 120, padX = 30, padY = 10;
  const xs = pts.map((_, i) => padX + (i / Math.max(1, pts.length - 1)) * (w - 2 * padX));
  const ys = pts.map(p => h - padY - (p.postureScore / 100) * (h - 2 * padY));
  const path = xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-32">
      {/* Y-Achse Marker */}
      {[0, 50, 100].map(v => {
        const y = h - padY - (v / 100) * (h - 2 * padY);
        return (
          <g key={v}>
            <line x1={padX} y1={y} x2={w - padX} y2={y} stroke="#334155" strokeWidth="0.5" strokeDasharray="2,3" />
            <text x={5} y={y + 3} fill="#64748b" fontSize="9">{v}</text>
          </g>
        );
      })}
      <path d={path} fill="none" stroke="#0EA5E9" strokeWidth="2" />
      {pts.map((p, i) => (
        <circle key={i} cx={xs[i]} cy={ys[i]} r="3" fill="#0EA5E9" />
      ))}
    </svg>
  );
}
