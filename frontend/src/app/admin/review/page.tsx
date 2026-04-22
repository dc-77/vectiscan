'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import { getReviewQueue, ReviewQueue } from '@/lib/api';

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function AdminReviewListPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [queue, setQueue] = useState<ReviewQueue | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn() || !isAdmin()) {
      router.replace('/dashboard');
      return;
    }
    setReady(true);
  }, [router]);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await getReviewQueue();
    if (res.success && res.data) {
      setQueue(res.data);
      setError(null);
    } else {
      setError(res.error || 'Review-Queue konnte nicht geladen werden.');
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (ready) load();
  }, [ready, load]);

  if (!ready) return null;

  const orders = queue?.orders || [];
  const subs = queue?.subscriptions || [];
  const total = orders.length + subs.length;

  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/admin" className="text-slate-500 hover:text-slate-300 text-sm">&larr;</Link>
            <h1 className="text-lg font-semibold text-white">Target-Review</h1>
            <span className="text-xs px-2 py-0.5 rounded bg-amber-400/10 text-amber-400">
              {total} offen
            </span>
          </div>
          <button
            onClick={load}
            className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5 bg-slate-800 rounded-lg transition-colors"
          >
            Aktualisieren
          </button>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {loading && (
          <div className="text-center py-12 text-slate-500 text-sm">Lade Review-Queue...</div>
        )}

        {!loading && total === 0 && (
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-8 text-center">
            <p className="text-sm text-slate-400">Keine offenen Reviews.</p>
          </div>
        )}

        {!loading && orders.length > 0 && (
          <div>
            <h2 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">
              Aufträge ({orders.length})
            </h2>
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-[#0f172a] text-xs text-slate-500 uppercase tracking-wider">
                  <tr>
                    <th className="text-left px-4 py-2.5 font-medium">Domain / Ziel</th>
                    <th className="text-left px-4 py-2.5 font-medium">Kunde</th>
                    <th className="text-left px-4 py-2.5 font-medium">Paket</th>
                    <th className="text-right px-4 py-2.5 font-medium">Targets</th>
                    <th className="text-right px-4 py-2.5 font-medium">Live-Hosts</th>
                    <th className="text-left px-4 py-2.5 font-medium">Eingang</th>
                    <th className="px-4 py-2.5"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {orders.map(o => (
                    <tr key={o.id} className="hover:bg-[#253347]/30 transition-colors">
                      <td className="px-4 py-3 font-mono text-slate-200 text-xs">{o.displayName}</td>
                      <td className="px-4 py-3">
                        <div className="text-xs text-slate-300">{o.customer.email}</div>
                        {o.customer.companyName && (
                          <div className="text-[10px] text-slate-500">{o.customer.companyName}</div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono uppercase text-slate-500 bg-gray-800 px-1.5 py-0.5 rounded">
                          {o.package}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-300">
                        {o.pendingTargets}{o.targetCount != null ? ` / ${o.targetCount}` : ''}
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-400">
                        {o.liveHostsCount ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDate(o.createdAt)}</td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          href={`/admin/review/${o.id}`}
                          className="text-xs text-blue-400 hover:text-blue-300 font-medium px-3 py-1.5 bg-blue-400/10 rounded-lg transition-colors whitespace-nowrap"
                        >
                          Review öffnen
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {!loading && subs.length > 0 && (
          <div>
            <h2 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">
              Abos ({subs.length})
            </h2>
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-[#0f172a] text-xs text-slate-500 uppercase tracking-wider">
                  <tr>
                    <th className="text-left px-4 py-2.5 font-medium">Abo</th>
                    <th className="text-left px-4 py-2.5 font-medium">Kunde</th>
                    <th className="text-left px-4 py-2.5 font-medium">Paket</th>
                    <th className="text-left px-4 py-2.5 font-medium">Intervall</th>
                    <th className="text-right px-4 py-2.5 font-medium">Targets</th>
                    <th className="text-left px-4 py-2.5 font-medium">Eingang</th>
                    <th className="px-4 py-2.5"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {subs.map(s => (
                    <tr key={s.id} className="hover:bg-[#253347]/30 transition-colors">
                      <td className="px-4 py-3 font-mono text-slate-400 text-[10px]">{s.id.slice(0, 8)}&hellip;</td>
                      <td className="px-4 py-3">
                        <div className="text-xs text-slate-300">{s.customer.email}</div>
                        {s.customer.companyName && (
                          <div className="text-[10px] text-slate-500">{s.customer.companyName}</div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono uppercase text-slate-500 bg-gray-800 px-1.5 py-0.5 rounded">
                          {s.package}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{s.scanInterval}</td>
                      <td className="px-4 py-3 text-right font-mono text-xs text-slate-300">
                        {s.pendingTargets}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDate(s.createdAt)}</td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          href={`/admin/review/subscription/${s.id}`}
                          className="text-xs text-blue-400 hover:text-blue-300 font-medium px-3 py-1.5 bg-blue-400/10 rounded-lg transition-colors whitespace-nowrap"
                        >
                          Review öffnen
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
