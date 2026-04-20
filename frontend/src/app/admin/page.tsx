'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';

import { listUsers, changeUserRole, deleteUser, getAdminStats, getAiCosts, getPendingReviews, approveOrder, rejectOrder, getPendingDomains, approveDomain, rejectDomain, AdminUser, AdminStats, AiCostsData, PendingReview, PendingDomain } from '@/lib/api';
import { isLoggedIn, isAdmin } from '@/lib/auth';


function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function AdminPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [aiCosts, setAiCosts] = useState<AiCostsData | null>(null);
  const [pendingReviews, setPendingReviews] = useState<PendingReview[]>([]);
  const [pendingDomains, setPendingDomains] = useState<PendingDomain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn() || !isAdmin()) {
      router.replace('/dashboard');
      return;
    }
    setReady(true);
  }, [router]);

  const fetchData = useCallback(async () => {
    try {
      const [usersRes, statsRes, costsRes, reviewsRes, domainsRes] = await Promise.all([
        listUsers(), getAdminStats(), getAiCosts(), getPendingReviews(), getPendingDomains(),
      ]);
      if (usersRes.success && usersRes.data) setUsers(usersRes.data.users);
      if (statsRes.success && statsRes.data) setStats(statsRes.data);
      if (costsRes.success && costsRes.data) setAiCosts(costsRes.data);
      if (reviewsRes.success && reviewsRes.data) setPendingReviews(reviewsRes.data.reviews);
      if (domainsRes.success && domainsRes.data) setPendingDomains(domainsRes.data.domains);
      setError(null);
    } catch {
      setError('Daten konnten nicht geladen werden.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (ready) fetchData();
  }, [ready, fetchData]);

  const handleRoleToggle = async (user: AdminUser) => {
    const newRole = user.role === 'admin' ? 'customer' : 'admin';
    if (!confirm(`Rolle von ${user.email} auf "${newRole}" ändern?`)) return;
    try {
      const res = await changeUserRole(user.id, newRole);
      if (res.success) {
        setUsers((prev) => prev.map((u) => u.id === user.id ? { ...u, role: newRole } : u));
      } else {
        setError(res.error || 'Fehler beim Ändern der Rolle');
      }
    } catch {
      setError('Fehler beim Ändern der Rolle');
    }
  };

  const handleApprove = async (review: PendingReview) => {
    if (!confirm(`Scan für ${review.domain} freigeben und Report generieren?`)) return;
    try {
      const res = await approveOrder(review.id);
      if (res.success) {
        setPendingReviews((prev) => prev.filter((r) => r.id !== review.id));
      } else {
        setError(res.error || 'Fehler beim Freigeben');
      }
    } catch {
      setError('Fehler beim Freigeben');
    }
  };

  const handleReject = async (review: PendingReview) => {
    const reason = prompt(`Begründung für die Ablehnung von ${review.domain}:`);
    if (reason === null) return;
    try {
      const res = await rejectOrder(review.id, reason);
      if (res.success) {
        setPendingReviews((prev) => prev.filter((r) => r.id !== review.id));
      } else {
        setError(res.error || 'Fehler beim Ablehnen');
      }
    } catch {
      setError('Fehler beim Ablehnen');
    }
  };

  const handleApproveDomain = async (d: PendingDomain) => {
    if (!confirm(`Domain ${d.domain} für Abo genehmigen?`)) return;
    try {
      const res = await approveDomain(d.id);
      if (res.success) {
        setPendingDomains((prev) => prev.filter((x) => x.id !== d.id));
      } else {
        setError(res.error || 'Fehler beim Genehmigen');
      }
    } catch {
      setError('Fehler beim Genehmigen');
    }
  };

  const handleRejectDomain = async (d: PendingDomain) => {
    if (!confirm(`Domain ${d.domain} ablehnen?`)) return;
    try {
      const res = await rejectDomain(d.id);
      if (res.success) {
        setPendingDomains((prev) => prev.filter((x) => x.id !== d.id));
      } else {
        setError(res.error || 'Fehler beim Ablehnen');
      }
    } catch {
      setError('Fehler beim Ablehnen');
    }
  };

  const handleDeleteUser = async (user: AdminUser) => {
    if (!confirm(`Benutzer ${user.email} endgültig löschen?`)) return;
    try {
      const res = await deleteUser(user.id);
      if (res.success) {
        setUsers((prev) => prev.filter((u) => u.id !== user.id));
      } else {
        setError(res.error || 'Fehler beim Löschen');
      }
    } catch {
      setError('Fehler beim Löschen');
    }
  };

  if (!ready) return null;

  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <h1 className="text-lg font-semibold text-white">Administration</h1>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider">Benutzer</p>
              <p className="text-2xl font-bold text-white mt-1">{stats.users.total}</p>
              <p className="text-xs text-gray-500">{stats.users.admins} Admin{stats.users.admins !== 1 ? 's' : ''}</p>
            </div>
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider">Aufträge gesamt</p>
              <p className="text-2xl font-bold text-white mt-1">{stats.orders.total}</p>
            </div>
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider">Heute</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">{stats.orders.today}</p>
            </div>
            <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider">Fertig</p>
              <p className="text-2xl font-bold text-green-400 mt-1">{stats.orders.byStatus?.report_complete ?? 0}</p>
            </div>
          </div>
        )}

        {/* Pending Reviews */}
        {pendingReviews.length > 0 && (
          <div className="bg-[#1e293b] rounded-lg border border-amber-800/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-amber-400">
                Ausstehende Reviews ({pendingReviews.length})
              </h2>
              <span className="text-xs text-amber-400/60 bg-amber-400/10 px-2 py-0.5 rounded">Aktion erforderlich</span>
            </div>
            <div className="space-y-2">
              {pendingReviews.map((review) => {
                const sevCounts = review.severityCounts;
                return (
                  <div key={review.id} className="bg-[#0f172a] rounded-lg border border-gray-800 p-3 flex items-center justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <a href={`/scan/${review.id}`} className="text-sm text-white font-medium hover:text-blue-400 transition-colors truncate">
                          {review.domain}
                        </a>
                        <span className="text-[10px] text-gray-500 uppercase bg-gray-800 px-1.5 py-0.5 rounded">{review.package}</span>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-xs text-gray-500">{review.customerEmail}</span>
                        {review.scanFinishedAt && (
                          <span className="text-xs text-gray-600">{formatDate(review.scanFinishedAt)}</span>
                        )}
                        {sevCounts && (
                          <div className="flex items-center gap-1.5">
                            {(sevCounts.CRITICAL || 0) > 0 && <span className="text-[10px] font-medium text-red-400 bg-red-400/10 px-1.5 py-0.5 rounded">{sevCounts.CRITICAL} CRIT</span>}
                            {(sevCounts.HIGH || 0) > 0 && <span className="text-[10px] font-medium text-orange-400 bg-orange-400/10 px-1.5 py-0.5 rounded">{sevCounts.HIGH} HIGH</span>}
                            {(sevCounts.MEDIUM || 0) > 0 && <span className="text-[10px] font-medium text-yellow-400 bg-yellow-400/10 px-1.5 py-0.5 rounded">{sevCounts.MEDIUM} MED</span>}
                            {(sevCounts.LOW || 0) > 0 && <span className="text-[10px] font-medium text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded">{sevCounts.LOW} LOW</span>}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <a href={`/scan/${review.id}`}
                        className="text-xs text-blue-400 hover:text-blue-300 font-medium px-3 py-1.5 bg-blue-400/10 rounded-lg transition-colors">
                        Prüfen
                      </a>
                      <button onClick={() => handleApprove(review)}
                        className="text-xs text-green-400 hover:text-green-300 font-medium px-3 py-1.5 bg-green-400/10 rounded-lg transition-colors">
                        Freigeben
                      </button>
                      <button onClick={() => handleReject(review)}
                        className="text-xs text-red-400 hover:text-red-300 font-medium px-3 py-1.5 bg-red-400/10 rounded-lg transition-colors">
                        Ablehnen
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Pending Domain Approvals */}
        {pendingDomains.length > 0 && (
          <div className="bg-[#1e293b] rounded-lg border border-cyan-800/50 p-4 space-y-3">
            <h2 className="text-sm font-medium text-cyan-400">
              Domain-Genehmigungen ({pendingDomains.length})
            </h2>
            <div className="space-y-2">
              {pendingDomains.map((d) => (
                <div key={d.id} className="bg-[#0f172a] rounded-lg border border-gray-800 p-3 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-white font-medium">{d.domain}</span>
                      <span className="text-[10px] text-gray-500 uppercase bg-gray-800 px-1.5 py-0.5 rounded">{d.package}</span>
                    </div>
                    <span className="text-xs text-gray-500">{d.customerEmail}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button onClick={() => handleApproveDomain(d)}
                      className="text-xs text-green-400 hover:text-green-300 font-medium px-3 py-1.5 bg-green-400/10 rounded-lg transition-colors">
                      Genehmigen
                    </button>
                    <button onClick={() => handleRejectDomain(d)}
                      className="text-xs text-red-400 hover:text-red-300 font-medium px-3 py-1.5 bg-red-400/10 rounded-lg transition-colors">
                      Ablehnen
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* AI Costs */}
        {aiCosts && aiCosts.total_cost_usd > 0 && (
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-gray-400">AI-Kosten <span className="text-[10px] text-gray-600 font-normal">(Anthropic API, in USD)</span></h2>
              <span className="text-lg font-bold text-white">${aiCosts.total_cost_usd.toFixed(2)}</span>
            </div>

            {/* Cost by Model */}
            {Object.keys(aiCosts.cost_by_model).length > 0 && (
              <div>
                <h3 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Nach Modell</h3>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-gray-500 border-b border-gray-700">
                      <th className="text-left py-1.5">Modell</th>
                      <th className="text-right py-1.5">Aufrufe</th>
                      <th className="text-right py-1.5">Gesamt</th>
                      <th className="text-right py-1.5">Durchschnitt</th>
                    </tr>
                  </thead>
                  <tbody className="text-gray-300">
                    {Object.entries(aiCosts.cost_by_model).map(([model, data]) => (
                      <tr key={model} className="border-t border-gray-800">
                        <td className="py-1.5 font-mono text-[10px]">{model}</td>
                        <td className="py-1.5 text-right">{data.count}</td>
                        <td className="py-1.5 text-right font-mono">${data.total_usd.toFixed(2)}</td>
                        <td className="py-1.5 text-right font-mono text-gray-500">${(data.total_usd / data.count).toFixed(4)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Cost by Package */}
            {Object.keys(aiCosts.cost_by_package).length > 0 && (
              <div>
                <h3 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Nach Paket</h3>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-gray-500 border-b border-gray-700">
                      <th className="text-left py-1.5">Paket</th>
                      <th className="text-right py-1.5">Aufrufe</th>
                      <th className="text-right py-1.5">Gesamt</th>
                      <th className="text-right py-1.5">Durchschnitt</th>
                    </tr>
                  </thead>
                  <tbody className="text-gray-300">
                    {Object.entries(aiCosts.cost_by_package).map(([pkg, data]) => (
                      <tr key={pkg} className="border-t border-gray-800">
                        <td className="py-1.5 uppercase">{pkg}</td>
                        <td className="py-1.5 text-right">{data.count}</td>
                        <td className="py-1.5 text-right font-mono">${data.total_usd.toFixed(2)}</td>
                        <td className="py-1.5 text-right font-mono text-gray-500">${(data.total_usd / data.count).toFixed(4)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Recent Reports */}
            {aiCosts.recent_reports.length > 0 && (
              <div>
                <h3 className="text-xs text-gray-500 uppercase tracking-wider mb-2">Letzte Reports</h3>
                <div className="space-y-1.5 max-h-64 overflow-y-auto" style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}>
                  {aiCosts.recent_reports.map((r, i) => (
                    <div key={i} className="flex items-center justify-between text-xs py-1.5 border-t border-gray-800">
                      <div className="min-w-0">
                        <span className="text-gray-300 font-mono truncate">{r.domain}</span>
                        <span className="ml-2 text-gray-600 uppercase text-[10px]">{r.package}</span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <span className="text-gray-500 text-[10px] font-mono">{r.model.split('-').slice(-2).join('-')}</span>
                        <span className="text-gray-300 font-mono">${r.cost_usd.toFixed(4)}</span>
                        <span className="text-gray-600 text-[10px]">{r.createdAt ? formatDate(r.createdAt) : ''}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {/* Users Table */}
        <div>
          <h2 className="text-sm font-medium text-gray-400 mb-3">Benutzer ({users.length})</h2>
          {loading ? (
            <div className="text-center py-12 text-gray-500">Lade...</div>
          ) : (
            <div className="space-y-2">
              {users.map((user) => (
                <div key={user.id} className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-white font-medium truncate">{user.email}</span>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                        user.role === 'admin'
                          ? 'bg-purple-500/20 text-purple-400'
                          : 'bg-blue-500/20 text-blue-400'
                      }`}>
                        {user.role}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-xs text-gray-500">{formatDate(user.createdAt)}</span>
                      <span className="text-xs text-gray-600">{user.orderCount} Aufträge</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={() => handleRoleToggle(user)}
                      className="text-xs text-yellow-400 hover:text-yellow-300 font-medium px-3 py-1.5 bg-yellow-400/10 rounded-lg transition-colors"
                    >
                      Rolle → {user.role === 'admin' ? 'Kunde' : 'Admin'}
                    </button>
                    <button
                      onClick={() => handleDeleteUser(user)}
                      className="text-xs text-red-400 hover:text-red-300 font-medium px-3 py-1.5 bg-red-400/10 rounded-lg transition-colors"
                    >
                      Löschen
                    </button>
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
