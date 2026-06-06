'use client';

import { useState, useEffect } from 'react';
// VEC-289: Paket-Interesse-Optionen aus dem kanonischen Katalog (deckungsgleich
// mit der Backend-Validierung in api/src/routes/leads.ts).
import { PACKAGE_CATALOG } from '@/lib/catalog.generated';

/**
 * Demo-/Beratungs-Anfrage (Lead-Capture, VEC-36).
 *
 * Conversion-Linse: ein klares Versprechen, niedrige Friktion (nur E-Mail +
 * Einwilligung sind Pflicht), Trust-Signale sichtbar. Sendet an POST /api/leads;
 * der Lead wird serverseitig persistiert und an den Vertrieb geroutet.
 */

const C = {
  slate: '#0F172A',
  slateLight: '#1E293B',
  teal: '#2DD4BF',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
  border: 'rgba(45,212,191,0.2)',
};

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

const PACKAGES = [
  { value: '', label: 'Paket-Interesse (optional)' },
  ...PACKAGE_CATALOG.map((p) => ({ value: p.key, label: p.marketingName })),
  { value: 'unsure', label: 'Noch unsicher — bitte beraten' },
];

const inputStyle: React.CSSProperties = {
  background: C.slate,
  border: `1px solid ${C.border}`,
  color: C.offWhite,
};

export default function DemoRequestForm() {
  const [form, setForm] = useState({
    name: '',
    email: '',
    company: '',
    phone: '',
    targetDomain: '',
    packageInterest: '',
    message: '',
    // Honeypot (VEC-110): bleibt für echte Nutzer leer; Bots füllen es aus.
    website: '',
  });
  const [consent, setConsent] = useState(false);
  const [status, setStatus] = useState<'idle' | 'submitting' | 'success' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [utm, setUtm] = useState<{ source?: string; medium?: string; campaign?: string }>({});

  useEffect(() => {
    try {
      const p = new URLSearchParams(window.location.search);
      setUtm({
        source: p.get('utm_source') || undefined,
        medium: p.get('utm_medium') || undefined,
        campaign: p.get('utm_campaign') || undefined,
      });
    } catch {
      // ignore
    }
  }, []);

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!form.email.trim()) {
      setError('Bitte geben Sie eine E-Mail-Adresse an.');
      return;
    }
    if (!consent) {
      setError('Bitte stimmen Sie der Kontaktaufnahme zu.');
      return;
    }

    setStatus('submitting');
    try {
      const res = await fetch(`${API_URL}/api/leads`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...form,
          consent,
          referrer: typeof document !== 'undefined' ? document.referrer || undefined : undefined,
          utmSource: utm.source,
          utmMedium: utm.medium,
          utmCampaign: utm.campaign,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        setStatus('success');
      } else {
        setStatus('error');
        setError(
          data.error === 'invalid_email'
            ? 'Die E-Mail-Adresse ist ungültig.'
            : 'Anfrage konnte nicht gesendet werden. Bitte versuchen Sie es erneut.',
        );
      }
    } catch {
      setStatus('error');
      setError('Verbindung fehlgeschlagen. Bitte versuchen Sie es erneut.');
    }
  };

  if (status === 'success') {
    return (
      <div
        className="rounded-xl p-8 text-center"
        style={{ background: C.slateLight, border: `1px solid ${C.border}` }}
        role="status"
        aria-live="polite"
      >
        <div className="text-3xl mb-3">✅</div>
        <h3 className="text-lg font-semibold mb-2" style={{ color: C.offWhite }}>
          Vielen Dank — Ihre Anfrage ist eingegangen.
        </h3>
        <p className="text-sm" style={{ color: C.mutedLight }}>
          Unser Team meldet sich in der Regel innerhalb eines Werktags bei Ihnen,
          um einen Termin für Ihre persönliche Demo abzustimmen.
        </p>
      </div>
    );
  }

  return (
    <form
      onSubmit={submit}
      className="rounded-xl p-6 sm:p-8 flex flex-col gap-4"
      style={{ background: C.slateLight, border: `1px solid ${C.border}` }}
    >
      {/* Honeypot (VEC-110): off-screen, aria-hidden, nicht fokussierbar.
          Echte Nutzer sehen es nie; Bots füllen es aus -> serverseitig verworfen. */}
      <input
        type="text"
        name="website"
        value={form.website}
        onChange={set('website')}
        tabIndex={-1}
        autoComplete="off"
        aria-hidden="true"
        style={{ position: 'absolute', left: '-9999px', width: 1, height: 1, opacity: 0 }}
      />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <input
          type="text"
          placeholder="Name"
          value={form.name}
          onChange={set('name')}
          className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF]"
          style={inputStyle}
        />
        <input
          type="text"
          placeholder="Unternehmen"
          value={form.company}
          onChange={set('company')}
          className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF]"
          style={inputStyle}
        />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <input
          type="email"
          required
          placeholder="E-Mail (geschäftlich) *"
          value={form.email}
          onChange={set('email')}
          className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF]"
          style={inputStyle}
        />
        <input
          type="tel"
          placeholder="Telefon (optional)"
          value={form.phone}
          onChange={set('phone')}
          className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF]"
          style={inputStyle}
        />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <input
          type="text"
          placeholder="Ihre Domain (z. B. ihre-firma.de)"
          value={form.targetDomain}
          onChange={set('targetDomain')}
          className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF]"
          style={inputStyle}
        />
        <select
          value={form.packageInterest}
          onChange={set('packageInterest')}
          className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF]"
          style={inputStyle}
        >
          {PACKAGES.map((p) => (
            <option key={p.value} value={p.value} style={{ background: C.slate }}>
              {p.label}
            </option>
          ))}
        </select>
      </div>
      <textarea
        placeholder="Was ist Ihr Compliance-Anlass? (z. B. NIS2, ISO-27001-Audit, Cyber-Versicherung) — optional"
        value={form.message}
        onChange={set('message')}
        rows={3}
        className="rounded-lg px-4 py-3 text-sm outline-none focus:border-[#2DD4BF] resize-y"
        style={inputStyle}
      />

      <label className="flex items-start gap-3 text-xs leading-relaxed" style={{ color: C.muted }}>
        <input
          type="checkbox"
          checked={consent}
          onChange={(e) => setConsent(e.target.checked)}
          className="mt-0.5 shrink-0"
          style={{ accentColor: C.teal }}
        />
        <span>
          Ich willige ein, dass Vectigal meine Angaben zur Bearbeitung meiner Anfrage und zur
          Kontaktaufnahme verarbeitet. Die Einwilligung kann ich jederzeit widerrufen. Details in der{' '}
          <a href="/datenschutz" className="underline" style={{ color: C.teal }}>
            Datenschutzerklärung
          </a>
          . *
        </span>
      </label>

      {error && (
        <p className="text-xs" style={{ color: '#F87171' }} role="alert">
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={status === 'submitting'}
        className="rounded-lg px-6 py-3.5 text-sm font-semibold transition-all duration-300 hover:scale-[1.01] disabled:opacity-60 disabled:hover:scale-100"
        style={{ background: C.teal, color: C.slate }}
      >
        {status === 'submitting' ? 'Wird gesendet …' : 'Demo anfragen'}
      </button>

      <p className="text-[11px] text-center" style={{ color: C.muted }}>
        🔒 Ihre Daten werden DSGVO-konform verarbeitet und in Deutschland gespeichert
        (Auftragsverarbeiter laut{' '}
        <a href="/datenschutz" className="underline" style={{ color: C.teal }}>
          Datenschutzerklärung
        </a>
        ). Kein Spam, kein Weiterverkauf.
      </p>
    </form>
  );
}
