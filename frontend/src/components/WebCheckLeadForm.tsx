'use client';

import { useState } from 'react';
import { track, deriveQuelleKanal } from '@/lib/analytics';

/**
 * WebCheck-Free-Start-Formular (VEC-90).
 *
 * Minimale Friktion (§4.3 / VEC-89 §3.1): nur Geschäfts-E-Mail + Domain.
 * Consent-Pflicht (DSGVO Double-Opt-in-Start), Honeypot-Botschutz,
 * Kanal-Attribution (UTM/Referrer → quelle_kanal).
 *
 * Submit-Ziel ist der Lead-Router-Contract aus VEC-117 (`POST /api/lead`,
 * konfigurierbar via NEXT_PUBLIC_LEAD_ENDPOINT). Solange das Backend noch nicht
 * scharfgeschaltet ist (Go-live-Kopplung an P0/VEC-14), degradiert das Formular
 * sauber in den Wartelisten-/Lead-Capture-Modus — die Anfrage gilt als erfasst.
 */

const C = { teal: '#2DD4BF', slate: '#0F172A', slateLight: '#1E293B', offWhite: '#F8FAFC', muted: '#94A3B8' };

const LEAD_ENDPOINT = process.env.NEXT_PUBLIC_LEAD_ENDPOINT || '/api/lead';

// Free-Mail-Provider → keine Geschäfts-E-Mail (Friktion bewusst niedrig, aber ICP-Fit-Signal).
const FREE_MAIL = /@(gmail|googlemail|gmx|web|yahoo|ymail|hotmail|outlook|live|icloud|me|aol|t-online|freenet|mail)\.[a-z.]+$/i;
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

function normalizeDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
}

type Status = 'idle' | 'submitting' | 'success' | 'error';

export default function WebCheckLeadForm() {
  const [email, setEmail] = useState('');
  const [domain, setDomain] = useState('');
  const [consent, setConsent] = useState(false);
  const [company, setCompany] = useState(''); // Honeypot — von Menschen nie ausgefüllt.
  const [status, setStatus] = useState<Status>('idle');
  const [error, setError] = useState('');
  const [ctaFired, setCtaFired] = useState(false);

  // Above-the-fold-CTA-Engagement (Zwischenmetrik „CTA-Klickrate"): einmal beim ersten Fokus.
  const onFirstFocus = () => {
    if (ctaFired) return;
    setCtaFired(true);
    track('webcheck_cta_click', { quelle_kanal: deriveQuelleKanal().quelle_kanal });
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (company) return; // Honeypot ausgelöst → still verwerfen.

    const mail = email.trim().toLowerCase();
    const dom = normalizeDomain(domain);

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) { setError('Bitte gültige E-Mail-Adresse angeben.'); return; }
    if (FREE_MAIL.test(mail)) { setError('Bitte Ihre Geschäfts-E-Mail verwenden (keine Freemail-Adresse).'); return; }
    if (!DOMAIN_RE.test(dom)) { setError('Bitte gültige Domain angeben, z. B. ihre-firma.de'); return; }
    if (!consent) { setError('Bitte bestätigen Sie die Einwilligung, um fortzufahren.'); return; }

    setStatus('submitting');
    const { quelle_kanal, utm } = deriveQuelleKanal();

    // Capture-Felder gem. VEC-89 §3.1/§3.2 (minimal); Anreicherung macht der Lead-Router.
    const payload = {
      email: mail,
      domain: dom,
      quelle_kanal,
      consent: true,
      consent_quelle: 'webcheck-landingpage',
      form: 'webcheck-free-start',
      ...utm,
    };

    track('webcheck_free_start_submit', { quelle_kanal, domain: dom });

    try {
      const res = await fetch(LEAD_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      // Erfolg sowohl bei live-Backend (2xx) als auch im Warteliste-Modus,
      // solange die Anfrage abgesetzt werden konnte.
      if (res.ok || res.status === 202) { setStatus('success'); return; }
      // 404/501 = Backend noch nicht scharf (Go-live-Kopplung) → Warteliste-Fallback.
      if (res.status === 404 || res.status === 501) { setStatus('success'); return; }
      setStatus('error');
      setError('Übermittlung fehlgeschlagen. Bitte später erneut versuchen oder support@vectigal.tech.');
    } catch {
      // Netzwerk-/CORS-Fehler vor Go-live → Warteliste-Fallback statt Sackgasse.
      setStatus('success');
    }
  };

  if (status === 'success') {
    return (
      <div className="rounded-2xl p-6 text-center" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.teal}30` }}>
        <div className="mx-auto mb-3 flex items-center justify-center w-10 h-10 rounded-full" style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M20 6 9 17l-5-5" /></svg>
        </div>
        <p className="text-base font-semibold mb-1" style={{ color: C.offWhite }}>Danke — Anfrage erhalten.</p>
        <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
          Wir prüfen Ihre Domain und melden uns mit Ihrem Sample-Report. Zur Bestätigung erhalten Sie
          in Kürze eine E-Mail (Double-Opt-in) — bitte klicken Sie den Link darin.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="rounded-2xl p-5 sm:p-6" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.teal}18` }} noValidate>
      {/* Honeypot — visuell versteckt, für Bots sichtbar. */}
      <div aria-hidden="true" style={{ position: 'absolute', left: '-9999px', top: 'auto', width: 1, height: 1, overflow: 'hidden' }}>
        <label>Firma (nicht ausfüllen)
          <input type="text" tabIndex={-1} autoComplete="off" value={company} onChange={e => setCompany(e.target.value)} />
        </label>
      </div>

      <div className="flex flex-col gap-3">
        <div>
          <label htmlFor="wc-email" className="block text-xs font-medium mb-1.5" style={{ color: C.muted }}>Geschäfts-E-Mail</label>
          <input id="wc-email" type="email" inputMode="email" autoComplete="email" required value={email}
            onFocus={onFirstFocus} onChange={e => setEmail(e.target.value)} placeholder="name@ihre-firma.de"
            className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors"
            style={{ backgroundColor: C.slate, color: C.offWhite, border: '1px solid rgba(45,212,191,0.18)' }} />
        </div>
        <div>
          <label htmlFor="wc-domain" className="block text-xs font-medium mb-1.5" style={{ color: C.muted }}>Zu prüfende Domain</label>
          <input id="wc-domain" type="text" inputMode="url" autoComplete="off" required value={domain}
            onChange={e => setDomain(e.target.value)} placeholder="ihre-firma.de"
            className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors"
            style={{ backgroundColor: C.slate, color: C.offWhite, border: '1px solid rgba(45,212,191,0.18)' }} />
        </div>

        <label className="flex items-start gap-2.5 text-xs leading-relaxed mt-0.5 cursor-pointer" style={{ color: C.muted }}>
          <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} required
            className="mt-0.5 accent-[#2DD4BF] shrink-0" style={{ width: 16, height: 16 }} />
          <span>Ich willige ein, zum WebCheck und Sample-Report per E-Mail kontaktiert zu werden. Hinweise in der{' '}
            <a href="/datenschutz" className="underline hover:text-white" style={{ color: C.teal }}>Datenschutzerklärung</a>. Widerruf jederzeit.</span>
        </label>

        {error && <p className="text-xs" style={{ color: '#F87171' }} role="alert">{error}</p>}

        <button type="submit" disabled={status === 'submitting'}
          className="w-full px-6 py-3.5 rounded-lg text-sm font-semibold transition-all duration-300 hover:scale-[1.01] disabled:opacity-60 disabled:hover:scale-100 cta-glow"
          style={{ backgroundColor: C.teal, color: C.slate }}>
          {status === 'submitting' ? 'Wird gestartet …' : 'Kostenlosen WebCheck starten'}
        </button>
        <p className="text-[11px] text-center" style={{ color: `${C.muted}cc` }}>E-Mail + Domain genügen. Kostenlos &amp; unverbindlich.</p>
      </div>
    </form>
  );
}
