'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { createOrder } from '@/lib/api';
import { isLoggedIn } from '@/lib/auth';
import { VectiScanShield } from '@/components/VectiScanLogo';

export default function WelcomePage() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [domain, setDomain] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (typeof window !== 'undefined' && !isLoggedIn()) {
    router.replace('/login');
    return null;
  }

  const handleScan = async () => {
    if (!domain.trim()) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await createOrder([{ raw_input: domain.trim(), exclusions: [] }], 'webcheck');
      if (res.success && res.data) {
        router.push(`/scan/${res.data.id}`);
      } else {
        setError(res.error || 'Fehler beim Starten');
      }
    } catch {
      setError('Verbindung fehlgeschlagen.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="flex-1 flex items-center justify-center px-6 py-16">
      <div className="max-w-lg w-full text-center space-y-8">

        {step === 1 && (
          <>
            <VectiScanShield size={80} variant="teal" className="mx-auto opacity-60" />
            <h1 className="text-2xl sm:text-3xl font-semibold" style={{ color: '#F8FAFC' }}>
              Willkommen bei VectiScan
            </h1>
            <p className="text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
              In wenigen Minuten wissen Sie, wie angreifbar Ihre IT-Infrastruktur von außen ist.
              Wir scannen Ihre Domain und erstellen einen professionellen Sicherheitsreport.
            </p>
            <div className="flex flex-col items-center gap-4 pt-4">
              <div className="grid grid-cols-1 gap-3 text-left w-full max-w-xs">
                <div className="flex items-center gap-3 text-sm" style={{ color: '#CBD5E1' }}>
                  <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style={{ backgroundColor: '#2DD4BF20', color: '#2DD4BF' }}>1</span>
                  Domain eingeben
                </div>
                <div className="flex items-center gap-3 text-sm" style={{ color: '#CBD5E1' }}>
                  <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style={{ backgroundColor: '#2DD4BF20', color: '#2DD4BF' }}>2</span>
                  Automatischer Schnell-Scan (~15 Min)
                </div>
                <div className="flex items-center gap-3 text-sm" style={{ color: '#CBD5E1' }}>
                  <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style={{ backgroundColor: '#2DD4BF20', color: '#2DD4BF' }}>3</span>
                  Ergebnis mit Handlungsempfehlungen
                </div>
              </div>
              <button onClick={() => setStep(2)}
                className="px-8 py-3.5 rounded-lg text-sm font-semibold transition-all cta-glow mt-4"
                style={{ backgroundColor: '#2DD4BF', color: '#0F172A' }}>
                Jetzt starten
              </button>
            </div>
          </>
        )}

        {step === 2 && (
          <>
            <h2 className="text-xl sm:text-2xl font-semibold" style={{ color: '#F8FAFC' }}>
              Welche Domain möchten Sie scannen?
            </h2>
            <p className="text-sm" style={{ color: '#94A3B8' }}>
              Geben Sie Ihre Unternehmens-Domain ein. Der Schnell-Scan dauert ca. 15 Minuten.
            </p>
            <div className="space-y-4 pt-4 max-w-sm mx-auto">
              <input
                type="text"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                placeholder="meinefirma.de"
                autoFocus
                disabled={submitting}
                className="w-full bg-transparent rounded-lg px-4 py-3 text-center text-lg font-mono focus:outline-none focus:ring-2 focus:ring-[#2DD4BF] disabled:opacity-50"
                style={{ color: '#F8FAFC', border: '1px solid rgba(148,163,184,0.2)' }}
                onKeyDown={e => { if (e.key === 'Enter' && domain.trim()) handleScan(); }}
              />
              {error && (
                <p className="text-sm" style={{ color: '#EF4444' }}>{error}</p>
              )}
              <button onClick={handleScan}
                disabled={submitting || !domain.trim()}
                className="w-full px-8 py-3.5 rounded-lg text-sm font-semibold transition-all disabled:opacity-40 cta-glow"
                style={{ backgroundColor: '#2DD4BF', color: '#0F172A' }}>
                {submitting ? 'Wird gestartet...' : 'Schnell-Scan starten'}
              </button>
              <button onClick={() => setStep(1)}
                className="text-xs transition-colors" style={{ color: '#64748B' }}>
                Zurück
              </button>
            </div>
          </>
        )}
      </div>
    </main>
  );
}
