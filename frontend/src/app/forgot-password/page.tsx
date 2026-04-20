'use client';

import { useState } from 'react';
import Link from 'next/link';
import { forgotPassword } from '@/lib/api';


export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email.trim()) {
      setError('Bitte E-Mail-Adresse eingeben.');
      return;
    }

    setLoading(true);
    try {
      const res = await forgotPassword(email);
      if (res.success) {
        setSent(true);
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
    <main className="flex-1 flex flex-col items-center justify-center px-4 py-12" style={{ backgroundColor: '#0F172A' }}>
      <div className="w-full max-w-sm rounded-2xl p-8 space-y-6" style={{ backgroundColor: '#1E293B' }}>
        <p className="text-center font-semibold" style={{ color: '#F8FAFC' }}>Passwort zurücksetzen</p>

        {sent ? (
          <div className="space-y-4">
            <div className="bg-green-900/30 border border-green-800 text-green-300 rounded-lg px-4 py-3 text-sm text-center">
              Falls ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link gesendet.
            </div>
            <Link
              href="/login"
              className="block text-center text-sm text-[#2DD4BF] hover:text-[#5EEAD4] transition-colors"
            >
              Zurück zum Login
            </Link>
          </div>
        ) : (
          <>
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
              <button
                type="submit"
                disabled={loading || !email.trim()}
                className="w-full bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors"
              >
                {loading ? 'Bitte warten...' : 'Reset-Link senden'}
              </button>
            </form>

            {error && (
              <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm text-center">
                {error}
              </div>
            )}

            <Link
              href="/login"
              className="block text-center text-sm text-gray-400 hover:text-white transition-colors"
            >
              Zurück zum Login
            </Link>
          </>
        )}
      </div>
    </main>
  );
}
