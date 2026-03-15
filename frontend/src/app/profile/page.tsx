'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { changePassword } from '@/lib/api';
import { isLoggedIn, getUser, clearToken } from '@/lib/auth';
import VectiScanLogo from '@/components/VectiScanLogo';

export default function ProfilePage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('');

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
      return;
    }
    const user = getUser();
    if (user) {
      setEmail(user.email);
      setRole(user.role);
    }
    setReady(true);
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!currentPassword || !newPassword) {
      setError('Bitte alle Felder ausfüllen.');
      return;
    }

    if (newPassword.length < 8) {
      setError('Neues Passwort muss mindestens 8 Zeichen haben.');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('Passwörter stimmen nicht überein.');
      return;
    }

    setLoading(true);
    try {
      const res = await changePassword(currentPassword, newPassword);
      if (res.success) {
        setSuccess('Passwort erfolgreich geändert.');
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        setError(res.error || 'Unbekannter Fehler');
      }
    } catch {
      setError('API nicht erreichbar.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    clearToken();
    router.replace('/login');
  };

  if (!ready) return null;

  return (
    <main className="min-h-screen px-4 py-8 md:px-8">
      <div className="max-w-lg mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <VectiScanLogo />
            <h1 className="text-lg font-semibold text-white">Profil</h1>
          </div>
          <Link href="/dashboard" className="bg-[#1e293b] hover:bg-[#253347] text-gray-400 hover:text-white text-sm font-medium px-3 py-2 rounded-lg border border-gray-700 transition-colors">
            Dashboard
          </Link>
        </div>

        {/* Account Info */}
        <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-5 space-y-3">
          <h2 className="text-sm font-medium text-gray-400">Account</h2>
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">E-Mail</span>
            <span className="text-sm text-white">{email}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-500">Rolle</span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded ${
              role === 'admin' ? 'bg-purple-500/20 text-purple-400' : 'bg-blue-500/20 text-blue-400'
            }`}>
              {role}
            </span>
          </div>
        </div>

        {/* Password Change */}
        <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-5 space-y-4">
          <h2 className="text-sm font-medium text-gray-400">Passwort ändern</h2>
          <form onSubmit={handleSubmit} className="space-y-3">
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Aktuelles Passwort"
              disabled={loading}
              className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50 text-sm"
            />
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Neues Passwort"
              disabled={loading}
              className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50 text-sm"
            />
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Neues Passwort wiederholen"
              disabled={loading}
              className="w-full bg-[#0f172a] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50 text-sm"
            />
            <button
              type="submit"
              disabled={loading || !currentPassword || !newPassword || !confirmPassword}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors text-sm"
            >
              {loading ? 'Bitte warten...' : 'Passwort ändern'}
            </button>
          </form>
        </div>

        {/* Messages */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}
        {success && (
          <div className="bg-green-900/30 border border-green-800 text-green-300 rounded-lg px-4 py-3 text-sm">{success}</div>
        )}

        {/* Logout */}
        <button
          onClick={handleLogout}
          className="w-full bg-[#1e293b] hover:bg-[#253347] text-red-400 hover:text-red-300 text-sm font-medium px-6 py-3 rounded-lg border border-gray-700 transition-colors"
        >
          Abmelden
        </button>
      </div>
    </main>
  );
}
