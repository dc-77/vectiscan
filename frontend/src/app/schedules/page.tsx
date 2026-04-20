'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn } from '@/lib/auth';
import { listSchedules, createSchedule, updateSchedule, deleteSchedule, ScanSchedule } from '@/lib/api';

const SCHEDULE_TYPES = [
  { value: 'weekly', label: 'Wöchentlich' },
  { value: 'monthly', label: 'Monatlich' },
  { value: 'quarterly', label: 'Quartalsweise' },
  { value: 'once', label: 'Einmalig' },
];

const PACKAGES = [
  { value: 'webcheck', label: 'WebCheck' },
  { value: 'perimeter', label: 'Perimeter-Scan' },
  { value: 'compliance', label: 'Compliance-Scan' },
  { value: 'supplychain', label: 'SupplyChain' },
  { value: 'insurance', label: 'Cyberversicherung' },
  { value: 'tlscompliance', label: 'TLS-Compliance' },
];

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function SchedulesPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  // Create form state
  const [domain, setDomain] = useState('');
  const [pkg, setPkg] = useState('perimeter');
  const [scheduleType, setScheduleType] = useState('monthly');
  const [scheduledAt, setScheduledAt] = useState('');
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setReady(true);
  }, [router]);

  const fetchSchedules = useCallback(async () => {
    try {
      const res = await listSchedules();
      if (res.success && res.data) {
        setSchedules(res.data.schedules);
        setError(null);
      } else {
        setError(res.error || 'Fehler beim Laden');
      }
    } catch {
      setError('API nicht erreichbar');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (ready) fetchSchedules();
  }, [ready, fetchSchedules]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);

    const trimmed = domain.trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');

    try {
      const res = await createSchedule({
        domain: trimmed,
        package: pkg,
        scheduleType,
        ...(scheduleType === 'once' && scheduledAt ? { scheduledAt: new Date(scheduledAt).toISOString() } : {}),
      });
      if (res.success) {
        setShowCreate(false);
        setDomain('');
        fetchSchedules();
      } else {
        setError(res.error || 'Fehler beim Erstellen');
      }
    } catch {
      setError('API nicht erreichbar');
    } finally {
      setCreating(false);
    }
  };

  const handleToggle = async (s: ScanSchedule) => {
    try {
      await updateSchedule(s.id, { enabled: !s.enabled });
      fetchSchedules();
    } catch {
      setError('Fehler beim Aktualisieren');
    }
  };

  const handleDelete = async (s: ScanSchedule) => {
    if (!confirm(`Schedule für ${s.domain} löschen?`)) return;
    try {
      await deleteSchedule(s.id);
      fetchSchedules();
    } catch {
      setError('Fehler beim Löschen');
    }
  };

  if (!ready) return null;

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold text-white">Geplante Scans</h1>
          <button onClick={() => setShowCreate(!showCreate)}
            className="text-sm font-medium px-4 py-2 rounded-lg transition-colors"
            style={showCreate
              ? { color: '#94A3B8', border: '1px solid rgba(148,163,184,0.2)' }
              : { backgroundColor: '#2DD4BF', color: '#0F172A' }
            }>
            {showCreate ? 'Abbrechen' : '+ Neuer Zeitplan'}
          </button>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}

        {/* Create Form */}
        {showCreate && (
          <form onSubmit={handleCreate} className="bg-[#1e293b] rounded-lg p-5 space-y-4 border border-gray-800">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-slate-500 mb-1">Domain</label>
                <input type="text" value={domain} onChange={e => setDomain(e.target.value)}
                  placeholder="beispiel.de" disabled={creating}
                  className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] disabled:opacity-50" />
                <p className="text-[10px] text-slate-600 mt-1">Domain muss vorher einmal verifiziert worden sein.</p>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Paket</label>
                <select value={pkg} onChange={e => setPkg(e.target.value)} disabled={creating}
                  className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#2DD4BF] disabled:opacity-50">
                  {PACKAGES.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Intervall</label>
                <select value={scheduleType} onChange={e => setScheduleType(e.target.value)} disabled={creating}
                  className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#2DD4BF] disabled:opacity-50">
                  {SCHEDULE_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
              {scheduleType === 'once' && (
                <div>
                  <label className="block text-xs text-slate-500 mb-1">Zeitpunkt</label>
                  <input type="datetime-local" value={scheduledAt} onChange={e => setScheduledAt(e.target.value)}
                    disabled={creating}
                    className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#2DD4BF] disabled:opacity-50" />
                </div>
              )}
            </div>
            <button type="submit" disabled={creating || !domain.trim()}
              className="bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] disabled:bg-gray-700 text-white text-sm font-medium px-5 py-2 rounded-lg transition-colors">
              {creating ? 'Erstellen...' : 'Zeitplan erstellen'}
            </button>
          </form>
        )}

        {/* Schedule List */}
        {loading && <div className="text-center py-12 text-slate-500">Lade Zeitpläne...</div>}

        {!loading && schedules.length === 0 && !showCreate && (
          <div className="text-center py-16 space-y-4">
            <div className="w-14 h-14 rounded-full mx-auto mb-3 flex items-center justify-center" style={{ backgroundColor: '#2DD4BF12', border: '2px solid #2DD4BF30' }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2DD4BF" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            </div>
            <p className="font-semibold" style={{ color: '#F8FAFC' }}>Noch keine geplanten Scans</p>
            <p className="text-sm max-w-sm mx-auto" style={{ color: '#94A3B8' }}>
              Mit Zeitplänen scannen Sie Ihre Domains automatisch in regelmäßigen Abständen — wöchentlich, monatlich oder quartalsweise.
            </p>
            <button onClick={() => setShowCreate(true)}
              className="px-5 py-2.5 rounded-lg text-sm font-medium transition-colors"
              style={{ backgroundColor: '#2DD4BF', color: '#0F172A' }}>
              Ersten Zeitplan erstellen
            </button>
          </div>
        )}

        {!loading && schedules.length > 0 && (
          <div className="space-y-3">
            {schedules.map(s => (
              <div key={s.id} className="bg-[#1e293b] rounded-lg border border-gray-800 p-4">
                <div className="flex items-center justify-between gap-3 mb-2">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${s.enabled ? 'bg-blue-500' : 'bg-slate-600'}`} />
                    <span className="font-mono text-blue-400 text-sm truncate">{s.domain}</span>
                    <span className="text-xs font-mono uppercase text-slate-500">{s.package.toUpperCase()}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-xs px-2 py-0.5 rounded ${s.enabled ? 'bg-blue-500/15 text-blue-400' : 'bg-slate-700 text-slate-500'}`}>
                      {s.scheduleLabel}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 text-xs text-slate-600 flex-wrap">
                    <span>Nächster Scan: <span className="text-slate-400">{s.enabled ? formatDate(s.nextScanAt) : 'Deaktiviert'}</span></span>
                    {s.lastScanAt && <span>Letzter: <span className="text-slate-400">{formatDate(s.lastScanAt)}</span></span>}
                    {s.lastOrderId && (
                      <Link href={`/dashboard`} className="text-blue-400 hover:text-blue-300">Letzte Order</Link>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button onClick={() => handleToggle(s)}
                      className={`text-xs px-3 py-1.5 rounded-lg transition-colors ${
                        s.enabled ? 'text-slate-400 hover:text-red-400 bg-slate-800/50' : 'text-slate-400 hover:text-blue-400 bg-slate-800/50'
                      }`}>
                      {s.enabled ? 'Deaktivieren' : 'Aktivieren'}
                    </button>
                    <button onClick={() => handleDelete(s)}
                      className="text-xs text-slate-400 hover:text-red-400 px-3 py-1.5 bg-slate-800/50 rounded-lg transition-colors">
                      Löschen
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
