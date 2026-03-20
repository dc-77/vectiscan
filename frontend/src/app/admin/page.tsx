'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';

import { listUsers, changeUserRole, deleteUser, getAdminStats, getAiCosts, AdminUser, AdminStats, AiCostsData } from '@/lib/api';
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
      const [usersRes, statsRes, costsRes] = await Promise.all([listUsers(), getAdminStats(), getAiCosts()]);
      if (usersRes.success && usersRes.data) setUsers(usersRes.data.users);
      if (statsRes.success && statsRes.data) setStats(statsRes.data);
      if (costsRes.success && costsRes.data) setAiCosts(costsRes.data);
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

        {/* AI Costs */}
        {aiCosts && aiCosts.total_cost_usd > 0 && (
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-gray-400">AI-Kosten</h2>
              <span className="text-lg font-bold text-white">${aiCosts.total_cost_usd.toFixed(2)} USD</span>
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
                      {user.role === 'admin' ? 'Zu Customer' : 'Zu Admin'}
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
