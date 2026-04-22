'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import {
  getReviewDetail, deleteAuthorization,
  ReviewDetail, ScanAuthorization,
} from '@/lib/api';
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

export default function AdminReviewSubscriptionPage() {
  const router = useRouter();
  const params = useParams();
  const subId = params.subId as string;

  const [ready, setReady] = useState(false);
  const [detail, setDetail] = useState<ReviewDetail | null>(null);
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
    const res = await getReviewDetail('subscription', subId);
    if (res.success && res.data) {
      setDetail(res.data);
      setError(null);
    } else {
      setError(res.error || 'Review-Detail konnte nicht geladen werden.');
    }
    setLoading(false);
  }, [subId]);

  useEffect(() => {
    if (ready) load();
  }, [ready, load]);

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
            <h1 className="text-lg font-semibold text-white">Abo Target-Review</h1>
            <span className="text-xs text-slate-500 font-mono">Sub {subId.slice(0, 8)}&hellip;</span>
          </div>
        </div>

        {/* Info banner: no release for subscriptions */}
        <div className="bg-blue-900/20 border border-blue-800/50 rounded-lg px-4 py-3 text-sm text-blue-300">
          Bei Abos werden freigegebene Targets automatisch vom Scheduler abgeholt. Es gibt keinen manuellen Release.
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
          <ScanAuthorizationUpload ownerType="subscription" ownerId={subId} onUploadComplete={load} />
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
      </div>
    </main>
  );
}
