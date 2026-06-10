'use client';

import Link from 'next/link';
import { PACKAGE_CATALOG } from '@/lib/catalog.generated';

// ── DS-Komponente: CTAStaircase (VEC-366) ────────────────────────
// Dreistufige Upsell-Treppe am Ende des SofortScan-Results.
// Preis aus catalog.generated (SSoT), nie hardcoded.
// Goal-Gradient + Anchoring: Fester Block, kein Pop-up.

interface CTAStaircaseProps {
  domain?: string;
}

function DocIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" /><path d="M9 15h6" /><path d="M9 11h4" />
    </svg>
  );
}
function SearchIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export default function CTAStaircase({ domain }: CTAStaircaseProps) {
  const webcheck = PACKAGE_CATALOG.find(p => p.key === 'webcheck')!;
  const perimeter = PACKAGE_CATALOG.find(p => p.key === 'perimeter')!;

  const webcheckParams = new URLSearchParams({
    ...(domain ? { domain } : {}),
  }).toString();

  return (
    <section className="mt-10 rounded-xl border border-slate-700 bg-slate-800/60 overflow-hidden">
      <div className="px-6 pt-6 pb-4 border-b border-slate-700">
        <h2 className="text-base font-semibold text-slate-100">Was kommt als Nächstes?</h2>
        <p className="text-sm text-slate-400 mt-1">
          Der Sofort-Check ist eine Momentaufnahme. Für einen vollständigen Bericht mit Maßnahmenplan:
        </p>
      </div>

      <div className="divide-y divide-slate-700">
        {/* Stufe 1 — Gratis-Report */}
        <div className="flex items-start gap-4 p-6">
          <span className="shrink-0 mt-0.5 text-teal-400">
            <DocIcon />
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-slate-100">
              Vollständiger Bericht
              <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold"
                style={{ background: 'rgba(45,212,191,0.14)', color: 'var(--tone-active)', border: '1px solid rgba(45,212,191,0.28)' }}>
                Kostenlos
              </span>
            </p>
            <p className="text-sm text-slate-400 mt-1">
              Alle Findings priorisiert — als E-Mail-Report. Schnell, ohne Scan-Job.
            </p>
          </div>
          <Link
            href={`/webcheck${webcheckParams ? `?${webcheckParams}` : ''}`}
            className="shrink-0 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold transition-colors min-h-[40px]"
            style={{ background: 'var(--tone-active)', color: 'var(--slate)' }}
          >
            Gratis-Report →
          </Link>
        </div>

        {/* Stufe 2 — WebCheck-Paket */}
        <div className="flex items-start gap-4 p-6">
          <span className="shrink-0 mt-0.5 text-sky-400">
            <SearchIcon />
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-slate-100">{webcheck.marketingName}-Scan</p>
            <p className="text-sm text-slate-400 mt-1">
              PDF-Report, Mail-Security-Modul, bis zu {webcheck.maxHosts} Hosts ·{' '}
              {webcheck.durationShort}
            </p>
          </div>
          <Link
            href="/subscribe?package=webcheck"
            className="shrink-0 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold border transition-colors min-h-[40px]"
            style={{ color: 'var(--text)', borderColor: 'var(--border-muted)' }}
          >
            Starten →
          </Link>
        </div>

        {/* Stufe 3 — Perimeter / Demo */}
        <div className="flex items-start gap-4 p-6">
          <span className="shrink-0 mt-0.5 text-violet-400">
            <ShieldIcon />
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-slate-100">{perimeter.marketingName} & Compliance</p>
            <p className="text-sm text-slate-400 mt-1">
              Bis zu {perimeter.maxHosts} Hosts, BSIG §30, Audit-Trail ·{' '}
              {perimeter.priceEur ? `ab €${perimeter.priceEur.toLocaleString('de-DE')}/J` : 'Auf Anfrage'}
            </p>
          </div>
          <Link
            href="/demo"
            className="shrink-0 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold border transition-colors min-h-[40px]"
            style={{ color: 'var(--text-muted)', borderColor: 'var(--border-muted)' }}
          >
            Demo anfragen
          </Link>
        </div>
      </div>
    </section>
  );
}
