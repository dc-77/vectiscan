'use client';

/**
 * PerHostFindingsDrawer — Slide-in-Drawer mit allen Findings fuer einen Host.
 *
 * Migration 027 (Mai 2026): zeigt sowohl die selektierten Top-N-Findings
 * als auch die additional_findings (ueber dem Top-N-Cap) gefiltert auf
 * den uebergebenen Host.
 *
 * Datenquelle: GET /api/orders/:id/hosts/:host/findings
 */

import { useEffect, useState } from 'react';

import { getOrderHostFindings, type Finding, type PerHostFindings } from '@/lib/api';

interface Props {
  orderId: string;
  host: string;
  onClose: () => void;
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-900/60 text-red-200 border-red-700',
  HIGH:     'bg-orange-900/60 text-orange-200 border-orange-700',
  MEDIUM:   'bg-amber-900/60 text-amber-200 border-amber-700',
  LOW:      'bg-yellow-900/60 text-yellow-200 border-yellow-700',
  INFO:     'bg-slate-800/60 text-slate-300 border-slate-700',
};

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

export function PerHostFindingsDrawer({ orderId, host, onClose }: Props) {
  const [data, setData] = useState<PerHostFindings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getOrderHostFindings(orderId, host)
      .then((res) => {
        if (res.success && res.data) {
          setData(res.data);
        } else {
          setError(res.error || 'Unbekannter Fehler');
        }
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [orderId, host]);

  // ESC schliesst Drawer
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const sortedFindings = (findings: Finding[]): Finding[] =>
    [...findings].sort((a, b) => {
      const sa = SEVERITY_ORDER[a.severity?.toUpperCase()] ?? 99;
      const sb = SEVERITY_ORDER[b.severity?.toUpperCase()] ?? 99;
      if (sa !== sb) return sa - sb;
      return parseFloat(b.cvss_score || '0') - parseFloat(a.cvss_score || '0');
    });

  return (
    <div
      className="fixed inset-0 z-50 flex"
      role="dialog"
      aria-modal="true"
      aria-label={`Befunde fuer ${host}`}
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative ml-auto h-full w-full max-w-3xl overflow-y-auto border-l border-slate-700 bg-slate-950 shadow-2xl">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-800 bg-slate-950/95 px-6 py-4 backdrop-blur">
          <div>
            <h2 className="text-lg font-medium text-slate-100">
              Befunde fuer <span className="font-mono text-cyan-300">{host}</span>
            </h2>
            {data && (
              <p className="mt-1 text-xs text-slate-400">
                {data.total_count} Befunde insgesamt
                {data.additional_count > 0 && (
                  <> · davon <span className="text-slate-300">{data.additional_count}</span> ueber Top-N-Cap</>
                )}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 text-xl leading-none px-2"
            aria-label="Schliessen"
          >
            ×
          </button>
        </div>

        <div className="px-6 py-4">
          {loading && (
            <div className="text-sm text-slate-500">Befunde laden …</div>
          )}
          {error && (
            <div className="rounded border border-red-800 bg-red-950/50 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          )}
          {data && data.findings.length === 0 && (
            <div className="rounded border border-slate-800 bg-slate-900/40 px-4 py-3 text-sm text-slate-400">
              Keine Befunde fuer diesen Host.
            </div>
          )}
          {data && data.findings.length > 0 && (
            <div className="space-y-2">
              {sortedFindings(data.findings).map((f, idx) => {
                const sev = (f.severity || 'INFO').toUpperCase();
                const style = SEVERITY_STYLE[sev] || SEVERITY_STYLE.INFO;
                const isOpen = expanded === f.id;
                return (
                  <div
                    key={f.id || idx}
                    className="rounded border border-slate-800 bg-slate-900/40"
                  >
                    <button
                      onClick={() => setExpanded(isOpen ? null : f.id)}
                      className="flex w-full items-start gap-3 p-3 text-left hover:bg-slate-900/70 transition-colors"
                    >
                      <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-mono uppercase ${style}`}>
                        {sev}
                      </span>
                      <span className="font-mono text-xs text-slate-500 shrink-0">
                        {f.cvss_score || '—'}
                      </span>
                      <span className="flex-1 text-sm text-slate-200">
                        {f.title}
                      </span>
                      <span className="text-slate-500 text-xs">{isOpen ? '▾' : '▸'}</span>
                    </button>
                    {isOpen && (
                      <div className="border-t border-slate-800 px-3 py-3 text-xs text-slate-300 space-y-2">
                        {f.affected && (
                          <div><span className="text-slate-500">Betroffen:</span> <span className="font-mono">{f.affected}</span></div>
                        )}
                        {f.description && (
                          <div><span className="text-slate-500 block mb-1">Beschreibung:</span>{f.description}</div>
                        )}
                        {f.recommendation && (
                          <div><span className="text-slate-500 block mb-1">Empfehlung:</span>{f.recommendation}</div>
                        )}
                        {f.policy_id && (
                          <div className="text-[10px] font-mono text-slate-500">{f.policy_id}</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
