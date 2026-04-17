'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { login, register } from '@/lib/api';
import { setToken } from '@/lib/auth';
import VectiScanLogo from '@/components/VectiScanLogo';

type Tab = 'login' | 'register';

export default function LoginPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email.trim() || !password.trim()) {
      setError('Bitte alle Felder ausfüllen.');
      return;
    }

    if (tab === 'register' && password !== passwordConfirm) {
      setError('Passwörter stimmen nicht überein.');
      return;
    }

    if (tab === 'register' && password.length < 8) {
      setError('Passwort muss mindestens 8 Zeichen haben.');
      return;
    }

    setLoading(true);
    try {
      const res = tab === 'login' ? await login(email, password) : await register(email, password);

      if (res.success && res.data) {
        setToken(res.data.token);
        router.push('/');
      } else {
        setError(res.error || 'Unbekannter Fehler');
      }
    } catch {
      setError('API nicht erreichbar.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex-1 flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center space-y-3">
          <VectiScanLogo className="mb-2" />
          <p className="text-gray-400">
            {tab === 'login' ? 'Anmelden' : 'Konto erstellen'}
          </p>
        </div>

        {/* Tabs */}
        <div className="flex rounded-lg overflow-hidden border border-gray-700">
          <button
            onClick={() => { setTab('login'); setError(null); }}
            className={`flex-1 py-2 text-sm font-medium transition-colors ${
              tab === 'login'
                ? 'bg-[#2DD4BF] text-[#0F172A]'
                : 'bg-[#1e293b] text-gray-400 hover:text-white'
            }`}
          >
            Login
          </button>
          <button
            onClick={() => { setTab('register'); setError(null); }}
            className={`flex-1 py-2 text-sm font-medium transition-colors ${
              tab === 'register'
                ? 'bg-[#2DD4BF] text-[#0F172A]'
                : 'bg-[#1e293b] text-gray-400 hover:text-white'
            }`}
          >
            Registrieren
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="E-Mail-Adresse"
            autoFocus
            disabled={loading}
            className="w-full bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] disabled:opacity-50"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Passwort"
            disabled={loading}
            className="w-full bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] disabled:opacity-50"
          />
          {tab === 'register' && (
            <input
              type="password"
              value={passwordConfirm}
              onChange={(e) => setPasswordConfirm(e.target.value)}
              placeholder="Passwort wiederholen"
              disabled={loading}
              className="w-full bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] disabled:opacity-50"
            />
          )}
          <button
            type="submit"
            disabled={loading || !email.trim() || !password.trim()}
            className="w-full bg-[#2DD4BF] hover:bg-[#14B8A6] disabled:bg-gray-700 disabled:cursor-not-allowed text-[#0F172A] font-medium px-6 py-3 rounded-lg transition-colors"
          >
            {loading
              ? 'Bitte warten...'
              : tab === 'login'
                ? 'Anmelden'
                : 'Konto erstellen'}
          </button>
        </form>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm text-center">
            {error}
          </div>
        )}

        {tab === 'login' && (
          <Link
            href="/forgot-password"
            className="block text-center text-sm text-gray-400 hover:text-white transition-colors"
          >
            Passwort vergessen?
          </Link>
        )}
      </div>
    </main>
  );
}
