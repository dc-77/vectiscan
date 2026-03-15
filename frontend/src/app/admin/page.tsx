'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listUsers, changeUserRole, deleteUser, getAdminStats, AdminUser, AdminStats } from '@/lib/api';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import VectiScanLogo from '@/components/VectiScanLogo';

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
      const [usersRes, statsRes] = await Promise.all([listUsers(), getAdminStats()]);
      if (usersRes.success && usersRes.data) setUsers(usersRes.data.users);
      if (statsRes.success && statsRes.data) setStats(statsRes.data);
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
    <main className="min-h-screen px-4 py-8 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="hidden sm:block"><VectiScanLogo /></div>
            <h1 className="text-lg sm:text-xl font-semibold text-white">Administration</h1>
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-purple-500/20 text-purple-400">Admin</span>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard" className="bg-[#1e293b] hover:bg-[#253347] text-gray-400 hover:text-white text-sm font-medium px-3 py-2 rounded-lg border border-gray-700 transition-colors">
              Dashboard
            </Link>
          </div>
        </div>

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
