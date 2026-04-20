'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

import { changePassword, getVerifiedDomains, VerifiedDomain } from '@/lib/api';
import { isLoggedIn, getUser } from '@/lib/auth';

const inputClass = `w-full bg-transparent border rounded-lg px-4 py-3 text-white placeholder-gray-500
  focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] disabled:opacity-50 text-sm`;

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
  const [verifiedDomains, setVerifiedDomains] = useState<VerifiedDomain[]>([]);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    const user = getUser();
    if (user) { setEmail(user.email); setRole(user.role); }
    setReady(true);
    getVerifiedDomains().then(res => {
      if (res.success && res.data) setVerifiedDomains(res.data.domains);
    }).catch(() => {});
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null); setSuccess(null);
    if (!currentPassword || !newPassword) { setError('Bitte alle Felder ausfüllen.'); return; }
    if (newPassword.length < 8) { setError('Neues Passwort muss mindestens 8 Zeichen haben.'); return; }
    if (newPassword !== confirmPassword) { setError('Passwörter stimmen nicht überein.'); return; }

    setLoading(true);
    try {
      const res = await changePassword(currentPassword, newPassword);
      if (res.success) {
        setSuccess('Passwort erfolgreich geändert.');
        setCurrentPassword(''); setNewPassword(''); setConfirmPassword('');
      } else { setError(res.error || 'Unbekannter Fehler'); }
    } catch { setError('API nicht erreichbar.'); }
    finally { setLoading(false); }
  };

  if (!ready) return null;

  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-lg mx-auto space-y-5">
        <h1 className="text-lg font-semibold" style={{ color: '#F8FAFC' }}>Profil</h1>

        {/* Account Info */}
        <div className="rounded-2xl p-5 space-y-3" style={{ backgroundColor: '#1E293B' }}>
          <h2 className="text-xs font-medium uppercase tracking-wider" style={{ color: '#64748B' }}>Account</h2>
          <div className="flex items-center justify-between">
            <span className="text-sm" style={{ color: '#94A3B8' }}>E-Mail</span>
            <span className="text-sm" style={{ color: '#F8FAFC' }}>{email}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm" style={{ color: '#94A3B8' }}>Rolle</span>
            <span className="text-xs font-medium px-2 py-0.5 rounded"
              style={{ backgroundColor: role === 'admin' ? 'rgba(168,85,247,0.2)' : 'rgba(45,212,191,0.2)', color: role === 'admin' ? '#A855F7' : '#2DD4BF' }}>
              {role === 'admin' ? 'Administrator' : 'Kunde'}
            </span>
          </div>
        </div>

        {/* Verified Domains */}
        <div className="rounded-2xl p-5 space-y-3" style={{ backgroundColor: '#1E293B' }}>
          <h2 className="text-xs font-medium uppercase tracking-wider" style={{ color: '#64748B' }}>Verifizierte Domains</h2>
          {verifiedDomains.length === 0 ? (
            <p className="text-sm" style={{ color: '#64748B' }}>Keine verifizierten Domains vorhanden.</p>
          ) : (
            <div className="space-y-2">
              {verifiedDomains.map((d) => {
                const methodLabels: Record<string, string> = { dns_txt: 'DNS-TXT', file: 'Datei', meta_tag: 'Meta-Tag', manual: 'Manuell' };
                const expiresDate = new Date(d.expires_at);
                const daysLeft = Math.ceil((expiresDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
                const isExpiringSoon = daysLeft <= 14;
                return (
                  <div key={d.domain} className="flex items-center justify-between py-2 border-b last:border-0" style={{ borderColor: 'rgba(30,58,95,0.2)' }}>
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: '#22C55E' }} />
                      <span className="text-sm truncate" style={{ color: '#F8FAFC' }}>{d.domain}</span>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0 ml-3">
                      <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(45,212,191,0.15)', color: '#2DD4BF' }}>
                        {methodLabels[d.verification_method] || d.verification_method}
                      </span>
                      <span className="text-xs" style={{ color: isExpiringSoon ? '#F59E0B' : '#64748B' }}
                        title="Domains werden nach 90 Tagen automatisch re-verifiziert. Bei einer Verlängerung wird ein neuer Scan ausgelöst.">
                        {daysLeft > 0 ? `noch ${daysLeft} Tage gültig` : 'Abgelaufen'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Password Change */}
        <div className="rounded-2xl p-5 space-y-4" style={{ backgroundColor: '#1E293B' }}>
          <h2 className="text-xs font-medium uppercase tracking-wider" style={{ color: '#64748B' }}>Passwort ändern</h2>
          <form onSubmit={handleSubmit} className="space-y-3">
            <input type="password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)}
              placeholder="Aktuelles Passwort" disabled={loading}
              className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
            <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)}
              placeholder="Neues Passwort (min. 8 Zeichen)" disabled={loading}
              className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
            <input type="password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)}
              placeholder="Neues Passwort wiederholen" disabled={loading}
              className={inputClass} style={{ borderColor: 'rgba(148,163,184,0.2)' }} />
            <button type="submit"
              disabled={loading || !currentPassword || !newPassword || !confirmPassword}
              className="w-full disabled:bg-gray-700 disabled:cursor-not-allowed font-medium px-6 py-3 rounded-lg transition-colors text-sm"
              style={{ backgroundColor: '#2DD4BF', color: '#0F172A' }}>
              {loading ? 'Bitte warten...' : 'Passwort ändern'}
            </button>
          </form>
        </div>

        {/* Messages */}
        {error && <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>}
        {success && <div className="bg-green-900/30 border border-green-800 text-green-300 rounded-lg px-4 py-3 text-sm">{success}</div>}

        {/* P5: Abmelden-Button entfernt (ist schon in Nav) */}
      </div>
    </main>
  );
}
