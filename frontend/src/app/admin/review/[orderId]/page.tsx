'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import {
  getReviewDetail, releaseOrder, deleteAuthorization,
  ReviewDetail, ScanAuthorization,
} from '@/lib/api';
import { useOrderProgress } from '@/lib/websocket';
import TargetReviewCard from '@/components/TargetReviewCard';
import ScanAuthorizationUpload from '@/components/ScanAuthorizationUpload';

const DOC_TYPE_LABELS: Record<string, string> = {
  whois_screenshot: 'WHOIS-Screenshot',
  signed_authorization: 'Unterschriebene Scan-Freigabe',
  email_thread: 'E-Mail-Verlauf',
  scan_agreement: 'Scan-Vereinbarung',
  other: 'Sonstiges',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function AdminReviewOrderPage() {
  const router = useRouter();
  const params = useParams();
  const orderId = params.orderId as string;

  const [ready, setReady] = useState(false);
  const [detail, setDetail] = useState<ReviewDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [releasing, setReleasing] = useState(false);

  const { events, connected } = useOrderProgress(ready ? orderId : null);

  useEffect(() => {
    if (!isLoggedIn() || !isAdmin()) {
      router.replace('/dashboard');
      return;
    }
    setReady(true);
  }, [router]);

  const load = useCallback(async () => {
    const res = await getReviewDetail('order', orderId);
    if (res.success && res.data) {
      setDetail(res.data);
      setError(null);
    } else {
      setError(res.error || 'Review-Detail konnte nicht geladen werden.');
    }
    setLoading(false);
  }, [orderId]);

  useEffect(() => {
    if (ready) load();
  }, [ready, load]);

  // Auto-Reload bei relevanten WebSocket-Events
  const lastEvent = events[events.length - 1];
  useEffect(() => {
    if (!lastEvent) return;
    const relevant: string[] = [
      'target_approved', 'target_rejected',
      'precheck_target_complete', 'precheck_complete',
    ];
    if (relevant.includes(lastEvent.type as string)) {
      load();
    }
  }, [lastEvent, load]);

  const stats = useMemo(() => {
    if (!detail) return { total: 0, approved: 0, rejected: 0, removed: 0, pending: 0, liveHosts: 0 };
    const t = detail.targets;
    return {
      total: t.length,
      approved: t.filter(x => x.status === 'approved').length,
      rejected: t.filter(x => x.status === 'rejected').length,
      removed: t.filter(x => x.status === 'removed').length,
      pending: t.filter(x => !['approved', 'rejected', 'removed'].includes(x.status)).length,
      liveHosts: t.reduce((sum, x) => sum + x.hosts.filter(h => h.is_live).length, 0),
    };
  }, [detail]);

  const canRelease = stats.pending === 0 && stats.approved > 0;

  const handleRelease = async () => {
    if (!window.confirm(`Auftrag freigeben? ${stats.approved} Target${stats.approved === 1 ? '' : 's'} werden gescannt.`)) return;
    setReleasing(true);
    const res = await releaseOrder(orderId);
    setReleasing(false);
    if (res.success) {
      router.push('/admin/review');
    } else {
      setError(res.error || 'Release fehlgeschlagen');
    }
  };

  const handleDeleteAuth = async (auth: ScanAuthorization) => {
    if (!window.confirm(`Dokument "${auth.original_filename}" löschen?`)) return;
    const res = await deleteAuthorization(auth.id);
    if (res.success) load();
    else setError(res.error || 'Löschen fehlgeschlagen');
  };

  if (!ready) return null;

  if (loading) {
    return (
      <main className="flex-1 flex items-center justify-center">
        <span className="text-slate-500">Lade Review...</span>
      </main>
    );
  }

  if (error && !detail) {
    return (
      <main className="flex-1 flex flex-col items-center justify-center px-4 gap-4">
        <p className="text-red-400">{error}</p>
        <Link href="/admin/review" className="text-blue-400 hover:text-blue-300 text-sm">Zurück zur Übersicht</Link>
      </main>
    );
  }

  if (!detail) return null;

  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3 min-w-0">
            <Link href="/admin/review" className="text-slate-500 hover:text-slate-300 text-sm">&larr;</Link>
            <h1 className="text-lg font-semibold text-white">Target-Review</h1>
            <span className="text-xs text-slate-500 font-mono">Order {orderId.slice(0, 8)}&hellip;</span>
            <span className={`text-[10px] px-2 py-0.5 rounded ${connected ? 'bg-green-500/15 text-green-400' : 'bg-slate-500/15 text-slate-500'}`}>
              {connected ? 'Live' : 'Offline'}
            </span>
          </div>
          <Link href={`/scan/${orderId}`} className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5 bg-slate-800 rounded-lg transition-colors">
            Scan-Detail ansehen
          </Link>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-3">
            <p className="text-[10px] text-slate-500 uppercase">Targets</p>
            <p className="text-xl font-bold text-white mt-0.5">{stats.total}</p>
          </div>
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-3">
            <p className="text-[10px] text-slate-500 uppercase">Offen</p>
            <p className="text-xl font-bold text-amber-400 mt-0.5">{stats.pending}</p>
          </div>
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-3">
            <p className="text-[10px] text-slate-500 uppercase">Freigegeben</p>
            <p className="text-xl font-bold text-green-400 mt-0.5">{stats.approved}</p>
          </div>
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-3">
            <p className="text-[10px] text-slate-500 uppercase">Abgelehnt</p>
            <p className="text-xl font-bold text-red-400 mt-0.5">{stats.rejected}</p>
          </div>
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-3">
            <p className="text-[10px] text-slate-500 uppercase">Live-Hosts</p>
            <p className="text-xl font-bold text-cyan-400 mt-0.5">{stats.liveHosts}</p>
          </div>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {/* Authorizations */}
        <section className="space-y-3">
          <h2 className="text-sm font-medium text-slate-400">Scan-Autorisierungen ({detail.authorizations.length})</h2>
          <ScanAuthorizationUpload ownerType="order" ownerId={orderId} onUploadComplete={load} />
          {detail.authorizations.length > 0 && (
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 divide-y divide-gray-800">
              {detail.authorizations.map(a => (
                <div key={a.id} className="px-4 py-3 flex items-center justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm text-slate-200 truncate">{a.original_filename}</span>
                      <span className="text-[10px] uppercase bg-gray-800 text-slate-400 px-1.5 py-0.5 rounded">
                        {DOC_TYPE_LABELS[a.document_type] || a.document_type}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-slate-500 mt-0.5">
                      <span>{formatDate(a.created_at)}</span>
                      <span>{(a.file_size_bytes / 1024).toFixed(0)} KB</span>
                      {a.valid_until && <span>gültig bis {new Date(a.valid_until).toLocaleDateString('de-DE')}</span>}
                    </div>
                    {a.notes && <p className="text-xs text-slate-400 mt-1">{a.notes}</p>}
                  </div>
                  <button
                    onClick={() => handleDeleteAuth(a)}
                    className="text-xs text-red-400 hover:text-red-300 font-medium px-3 py-1.5 bg-red-400/10 rounded-lg transition-colors shrink-0"
                  >
                    Löschen
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Target Cards */}
        <section className="space-y-3">
          <h2 className="text-sm font-medium text-slate-400">Targets ({detail.targets.length})</h2>
          {detail.targets.length === 0 ? (
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-6 text-center text-sm text-slate-500">
              Keine Targets vorhanden.
            </div>
          ) : (
            <div className="space-y-3">
              {detail.targets.map(t => (
                <TargetReviewCard key={t.id} target={t} onChanged={load} />
              ))}
            </div>
          )}
        </section>

        {/* Footer — Release */}
        <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 flex items-center justify-between gap-3">
          <div className="text-xs text-slate-400">
            {canRelease ? (
              <>Alle Targets entschieden. <strong className="text-white">{stats.approved}</strong> Target{stats.approved === 1 ? '' : 's'} werden gescannt.</>
            ) : stats.approved === 0 ? (
              <>Mindestens ein Target muss freigegeben werden.</>
            ) : (
              <>{stats.pending} Target{stats.pending === 1 ? '' : 's'} noch offen.</>
            )}
          </div>
          <button
            onClick={handleRelease}
            disabled={!canRelease || releasing}
            className="text-sm font-medium px-4 py-2 rounded-lg transition-colors disabled:cursor-not-allowed"
            style={{
              color: canRelease ? '#2DD4BF' : '#64748B',
              backgroundColor: canRelease ? 'rgba(45,212,191,0.1)' : 'rgba(100,116,139,0.1)',
            }}
          >
            {releasing ? 'Wird freigegeben...' : 'Auftrag freigeben'}
          </button>
        </div>
      </div>
    </main>
  );
}
