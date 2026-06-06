'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { useAdminGuard, AdminDenied } from '@/components/ds';

interface Subscription {
  id: string;
  customerEmail: string | null;
  package: string;
  status: string;
  scanInterval: string | null;
  createdAt: string | null;
  targetCount?: number;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';
const STATUS_BADGE: Record<string, string> = {
  active: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
  pending: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
  expired: 'bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/30',
  cancelled: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',
};

export default function AdminSubscriptionsPage() {
  const { ready, denied } = useAdminGuard();
  const [subs, setSubs] = useState<Subscription[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'active' | 'cancelled'>('all');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const token = typeof window !== 'undefined' ? window.localStorage.getItem('token') : null;
    try {
      const res = await fetch(`${API_URL}/api/subscriptions`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const data = await res.json();
      if (data.success && data.data) {
        setSubs(data.data.subscriptions || []);
      }
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => { if (ready) void load(); }, [ready, load]);

  async function cancelSub(id: string) {
    const reason = window.prompt('Grund für Beendigung (optional):', '') ?? '';
    if (!window.confirm(`Abo ${id.slice(0, 8)} wirklich beenden? Status wird auf "cancelled" gesetzt, Daten bleiben erhalten.`)) return;
    setBusy(id);
    setError(null);
    try {
      const token = window.localStorage.getItem('token');
      const res = await fetch(`${API_URL}/api/admin/subscriptions/${id}/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ reason }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error || 'Cancel fehlgeschlagen');
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function deleteSub(id: string, customerEmail: string | null) {
    const confirm1 = window.confirm(
      `Abo ${id.slice(0, 8)} (${customerEmail || '?'}) ENDGÜLTIG löschen?\n\n` +
      'ALLE zugehörigen Scans, Reports, Findings und Posture-Daten werden via CASCADE gelöscht. ' +
      'Nicht rückgängig zu machen.',
    );
    if (!confirm1) return;
    const confirm2 = window.prompt(`Tippe "DELETE" zur Bestätigung:`);
    if (confirm2 !== 'DELETE') return;
    setBusy(id);
    setError(null);
    try {
      const token = window.localStorage.getItem('token');
      const res = await fetch(`${API_URL}/api/admin/subscriptions/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error || 'Delete fehlgeschlagen');
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  if (denied) return <AdminDenied />;
  if (!ready) return null;

  const filtered = subs.filter(s =>
    filter === 'all' ? true : filter === 'active' ? s.status === 'active' : s.status === 'cancelled',
  );

  return (
    <main className="flex-1 px-4 py-8">
      <div className="mx-auto w-full max-w-6xl space-y-6">
        <header className="flex items-center justify-between">
          <h1 className="text-xl font-medium text-slate-200">Abo-Verwaltung (Admin)</h1>
          <Link href="/admin" className="text-sm text-cyan-400 hover:text-cyan-300">← Admin-Cockpit</Link>
        </header>

        <div className="flex gap-2">
          {(['all', 'active', 'cancelled'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded px-3 py-1.5 text-xs ${
                filter === f
                  ? 'bg-cyan-500/20 text-cyan-200 ring-1 ring-cyan-500/40'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              {f === 'all' ? 'Alle' : f === 'active' ? 'Aktiv' : 'Beendet'} ({subs.filter(s => f === 'all' || s.status === f).length})
            </button>
          ))}
        </div>

        {error && (
          <div className="rounded border border-red-800 bg-red-900/30 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950/60 text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2 text-left">ID</th>
                <th className="px-3 py-2 text-left">Kunde</th>
                <th className="px-3 py-2 text-left">Paket</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Intervall</th>
                <th className="px-3 py-2 text-left">Erstellt</th>
                <th className="px-3 py-2 text-right">Aktionen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filtered.map(s => (
                <tr key={s.id} className="hover:bg-slate-950/40">
                  <td className="px-3 py-2 font-mono text-xs text-slate-300">{s.id.slice(0, 8)}…</td>
                  <td className="px-3 py-2 text-slate-300">{s.customerEmail || '—'}</td>
                  <td className="px-3 py-2 text-slate-300">{s.package}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded px-2 py-0.5 text-xs ${STATUS_BADGE[s.status] || 'bg-slate-700 text-slate-300'}`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400">{s.scanInterval || '—'}</td>
                  <td className="px-3 py-2 text-xs text-slate-400">
                    {s.createdAt ? new Date(s.createdAt).toLocaleDateString('de-DE') : '—'}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex justify-end gap-2">
                      {s.status !== 'cancelled' && (
                        <button
                          disabled={busy === s.id}
                          onClick={() => cancelSub(s.id)}
                          className="rounded bg-amber-600/20 px-2 py-1 text-xs text-amber-200 ring-1 ring-amber-600/40 hover:bg-amber-600/30 disabled:opacity-50"
                          title="Status auf cancelled setzen, Daten bleiben"
                        >
                          Beenden
                        </button>
                      )}
                      <button
                        disabled={busy === s.id}
                        onClick={() => deleteSub(s.id, s.customerEmail)}
                        className="rounded bg-red-600/20 px-2 py-1 text-xs text-red-200 ring-1 ring-red-600/40 hover:bg-red-600/30 disabled:opacity-50"
                        title="ENDGÜLTIG löschen (inkl. Scans+Reports via CASCADE)"
                      >
                        Löschen
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-8 text-center text-slate-500">Keine Abos.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
