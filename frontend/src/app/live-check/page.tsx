'use client';

// ── SofortScan: Ziel-Eingabe (Screen 2) ─────────────────────────
// Route: /live-check (post-login, AppShell)
// VEC-366 — UX nach VEC-365 §2

import { useState, useCallback, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn } from '@/lib/auth';

function ZapIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

function InfoIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="M12 11v5" /><path d="M12 8h.01" />
    </svg>
  );
}

function isValidTarget(input: string): boolean {
  const v = input.trim().toLowerCase();
  if (!v) return false;
  // Einfache FQDN/IPv4-Prüfung (Backend entscheidet final)
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(v);
  const fqdn = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(v);
  return ipv4 || fqdn;
}

export default function LiveCheckPage() {
  const [target, setTarget] = useState('');
  const [touched, setTouched] = useState(false);
  const router = useRouter();

  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
    }
  }, [router]);

  const valid = isValidTarget(target);
  const showError = touched && target.trim().length > 0 && !valid;

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!valid) return;
    const t = target.trim().toLowerCase();
    router.push(`/live-check/results?target=${encodeURIComponent(t)}`);
  }, [target, valid, router]);

  return (
    <div className="max-w-lg mx-auto px-4 pt-10 pb-16">
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-100">Sofort-Check</h1>
        <p className="text-sm text-slate-400 mt-2">
          Domain oder IP eingeben. Ergebnisse erscheinen in Echtzeit.
        </p>
      </div>

      <form onSubmit={handleSubmit} noValidate>
        {/* Target input */}
        <div className="mb-4">
          <label htmlFor="target-input" className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase tracking-wide">
            Ziel
          </label>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input
                id="target-input"
                type="text"
                value={target}
                onChange={e => { setTarget(e.target.value); setTouched(false); }}
                onBlur={() => setTouched(true)}
                placeholder="example.com oder 203.0.113.1"
                autoComplete="off"
                spellCheck={false}
                aria-describedby={showError ? 'target-error' : 'target-hint'}
                aria-invalid={showError ? 'true' : undefined}
                className="w-full px-3.5 py-2.5 rounded-lg text-sm font-mono text-slate-100 placeholder-slate-500 border outline-none transition-colors min-h-[44px]"
                style={{
                  background: 'var(--slate-light)',
                  borderColor: showError ? 'var(--tone-danger)' : valid && touched ? 'var(--tone-active)' : 'var(--border-muted)',
                }}
              />
            </div>
            {target && (
              <button
                type="button"
                onClick={() => { setTarget(''); setTouched(false); }}
                className="px-3 rounded-lg border text-slate-400 hover:text-slate-200 transition-colors min-h-[44px] min-w-[44px]"
                style={{ borderColor: 'var(--border-muted)', background: 'var(--slate-light)' }}
                aria-label="Eingabe löschen"
              >
                ×
              </button>
            )}
          </div>

          {showError && (
            <p id="target-error" role="alert" className="mt-1.5 text-xs text-red-400">
              Ungültig — FQDN (example.com) oder IPv4-Adresse erwartet
            </p>
          )}
          {!showError && (
            <p id="target-hint" className="mt-1.5 text-xs text-slate-500">
              Scan-Berechtigung bei Registrierung bestätigt ·{' '}
              <Link href="/profile" className="underline underline-offset-2 hover:text-slate-300">Details</Link>
            </p>
          )}
        </div>

        {/* CTA */}
        <button
          type="submit"
          disabled={!valid && touched}
          className="w-full flex items-center justify-center gap-2 py-3 rounded-lg text-sm font-semibold transition-opacity min-h-[48px]"
          style={{
            background: 'var(--tone-active)',
            color: 'var(--slate)',
            opacity: (!valid && touched) ? 0.5 : 1,
          }}
        >
          <ZapIcon />
          Sofort-Check starten
        </button>
      </form>

      {/* Upsell Hinweis */}
      <div className="mt-5 flex items-center gap-2 text-xs text-slate-500">
        <InfoIcon />
        <span>
          Für 3–15 Hosts mit PDF-Report:{' '}
          <Link href="/subscribe" className="text-teal-400 hover:text-teal-300 underline underline-offset-2">
            Pakete ansehen →
          </Link>
        </span>
      </div>

      {/* Disclaimer */}
      <p className="mt-4 text-xs text-slate-600">
        Der Sofort-Check ist eine automatische Momentaufnahme öffentlich erreichbarer Dienste.
        Kein Ersatz für einen vollständigen Penetrationstest.
      </p>
    </div>
  );
}
