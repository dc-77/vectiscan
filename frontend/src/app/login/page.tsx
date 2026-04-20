'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { login, register } from '@/lib/api';
import { setToken } from '@/lib/auth';
import { VectiScanShield } from '@/components/VectiScanLogo';

type Tab = 'login' | 'register';

const inputClass = `w-full bg-transparent border rounded-lg px-4 py-3 text-[#F8FAFC] placeholder-[#64748B]
  focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] transition-colors text-sm`;

export default function LoginPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password.trim()) { setError('Bitte alle Felder ausfüllen.'); return; }
    if (tab === 'register' && password !== passwordConfirm) { setError('Passwörter stimmen nicht überein.'); return; }
    if (tab === 'register' && password.length < 8) { setError('Passwort muss mindestens 8 Zeichen haben.'); return; }

    setLoading(true);
    try {
      const res = tab === 'login' ? await login(email, password) : await register(email, password, companyName || undefined);
      if (res.success && res.data) { setToken(res.data.token); router.push('/dashboard'); }
      else { setError(res.error || 'Unbekannter Fehler'); }
    } catch { setError('API nicht erreichbar.'); }
    finally { setLoading(false); }
  };

  return (
    <main className="flex-1 flex flex-col items-center justify-center px-4" style={{ backgroundColor: '#0F172A' }}>
      <div className="w-full max-w-sm">
        <div className="rounded-2xl p-10 space-y-6" style={{ backgroundColor: '#1E293B' }}>
          {/* Logo */}
          <div className="flex flex-col items-center gap-3 mb-2">
            <VectiScanShield size={64} variant="teal" />
            <span className="text-lg font-bold tracking-tight" style={{ letterSpacing: '-0.5px' }}>
              <span style={{ color: '#F8FAFC' }}>vecti</span>
              <span style={{ color: '#2DD4BF' }}>scan</span>
            </span>
          </div>

          {/* Tabs */}
          <div className="flex rounded-lg overflow-hidden" style={{ border: '1px solid rgba(148,163,184,0.15)' }}>
            <button onClick={() => { setTab('login'); setError(null); }}
              className="flex-1 py-2.5 text-sm font-medium transition-colors"
              style={tab === 'login' ? { backgroundColor: '#2DD4BF', color: '#0F172A' } : { color: '#94A3B8' }}>
              Anmelden
            </button>
            <button onClick={() => { setTab('register'); setError(null); }}
              className="flex-1 py-2.5 text-sm font-medium transition-colors"
              style={tab === 'register' ? { backgroundColor: '#2DD4BF', color: '#0F172A' } : { color: '#94A3B8' }}>
              Registrieren
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {tab === 'register' && (
              <input type="text" value={companyName} onChange={e => setCompanyName(e.target.value)}
                placeholder="Firmenname (optional)" disabled={loading}
                className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
            )}
            <input type="email" value={email} onChange={e => setEmail(e.target.value)}
              placeholder="E-Mail-Adresse" autoFocus disabled={loading}
              className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
            <div>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                placeholder="Passwort (min. 8 Zeichen)" disabled={loading}
                className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
              {tab === 'register' && password.length > 0 && (
                <div className="flex gap-1 mt-2">
                  {[1,2,3,4].map(i => {
                    const strength = password.length >= 12 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^a-zA-Z0-9]/.test(password) ? 4
                      : password.length >= 10 && /[A-Z]/.test(password) && /[0-9]/.test(password) ? 3
                      : password.length >= 8 ? 2 : 1;
                    const colors = ['#EF4444', '#F59E0B', '#3B82F6', '#22C55E'];
                    return <div key={i} className="flex-1 h-1 rounded-full" style={{ backgroundColor: i <= strength ? colors[strength-1] : '#1E293B' }} />;
                  })}
                </div>
              )}
            </div>
            {tab === 'register' && (
              <>
                <input type="password" value={passwordConfirm} onChange={e => setPasswordConfirm(e.target.value)}
                  placeholder="Passwort wiederholen" disabled={loading}
                  className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
                <label className="flex items-start gap-2 text-xs" style={{ color: '#64748B' }}>
                  <input type="checkbox" required className="mt-0.5 accent-[#2DD4BF]" />
                  <span>Ich akzeptiere die <a href="/datenschutz" className="underline" style={{ color: '#2DD4BF' }}>Datenschutzerklärung</a> und stimme der Verarbeitung meiner Daten zu.</span>
                </label>
              </>
            )}
            <button type="submit" disabled={loading || !email.trim() || !password.trim()}
              className="w-full py-3 rounded-lg text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed hover:shadow-[0_0_16px_#2DD4BF30]"
              style={{ backgroundColor: '#2DD4BF', color: '#0F172A' }}>
              {loading ? 'Bitte warten...' : tab === 'login' ? 'Anmelden' : 'Konto erstellen'}
            </button>
          </form>

          {error && (
            <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm text-center">{error}</div>
          )}

          {tab === 'login' && (
            <div className="text-center space-y-2">
              <Link href="/forgot-password" className="block text-sm transition-colors hover:underline" style={{ color: '#2DD4BF' }}>
                Passwort vergessen?
              </Link>
              <p className="text-xs" style={{ color: '#64748B' }}>
                Noch kein Konto?{' '}
                <button onClick={() => setTab('register')} className="hover:underline" style={{ color: '#2DD4BF' }}>Registrieren</button>
              </p>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
