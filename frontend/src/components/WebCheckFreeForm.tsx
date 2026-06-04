'use client';

import { useState } from 'react';
import { track, deriveQuelleKanal } from '@/lib/analytics';

/**
 * WebCheck-Free-Funnel-Formular (VEC-170 / AC1+AC2).
 *
 * Bindet den echten, öffentlichen Backend-Flow (VEC-91 / PA-11):
 *   1. POST /api/webcheck/start  — E-Mail + Domain (+ optional Marketing-Consent)
 *      → liefert leadId + Verifikations-Anleitung (DNS-TXT / Datei / Meta-Tag).
 *   2. POST /api/webcheck/verify — Domain-Kontrolle prüfen; bei Erfolg startet der
 *      Free-Scan, der Report wird per Mail (download_token, PA-4) zugestellt.
 *
 * DSGVO (Greta-Spec VEC-168 §4/§5.1): **Kopplungsverbot** — der Report (V1) ist NICHT
 * an die Marketing-Einwilligung (V2) gekoppelt. Die Marketing-Checkbox ist freiwillig
 * und unangekreuzt; der Scan/Report kommt unabhängig davon. `consent_text_version`
 * wird mitgeschrieben (Nachweis der eingewilligten Fassung).
 *
 * Copy: Greta (CMO), Capture-Spec v1.0 (VEC-168 §5.1/§5.5).
 * Claim-Disziplin (AC6): keine Sicherheits-/Compliance-Claims hier — die trägt die
 * Seiten-Shell (VEC-90, Sven-Sign-off v2.1). Security-/QA-Abnahme des öffentlichen
 * Flows: Sven (VEC-169) vor Go-live.
 */

const C = { teal: '#2DD4BF', slate: '#0F172A', slateLight: '#1E293B', offWhite: '#F8FAFC', muted: '#94A3B8' };

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

/** Version des Consent-Checkbox-Textes (Greta §5.1). Bei Textänderung hochzählen. */
const CONSENT_TEXT_VERSION = 'v1.0';

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

function normalizeDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
}

interface VerifyMethod {
  type: 'dns_txt' | 'file' | 'meta_tag';
  record?: string;
  path?: string;
  value: string;
}
interface Verification {
  token: string;
  methods: VerifyMethod[];
}

type Phase =
  | 'form' // Schritt 1: E-Mail + Domain
  | 'submitting'
  | 'verify' // Schritt 2: Domain-Nachweis + Prüfung
  | 'verifying'
  | 'scan_started' // Erfolg: Scan läuft, Report kommt per Mail
  | 'already_requested' // Für diese Domain läuft bereits ein Free-Scan
  | 'rate_limited'; // AC4 / AC3

export default function WebCheckFreeForm() {
  const [email, setEmail] = useState('');
  const [domain, setDomain] = useState('');
  const [marketingConsent, setMarketingConsent] = useState(false); // freiwillig, default false (Kopplungsverbot)
  const [company, setCompany] = useState(''); // Honeypot — von Menschen nie ausgefüllt.

  const [phase, setPhase] = useState<Phase>('form');
  const [error, setError] = useState('');
  const [notVerifiedYet, setNotVerifiedYet] = useState(false);
  const [leadId, setLeadId] = useState('');
  const [verification, setVerification] = useState<Verification | null>(null);
  const [verifiedDomain, setVerifiedDomain] = useState('');
  const [ctaFired, setCtaFired] = useState(false);

  // Above-the-fold-CTA-Engagement (Zwischenmetrik „CTA-Klickrate"): einmal beim ersten Fokus.
  const onFirstFocus = () => {
    if (ctaFired) return;
    setCtaFired(true);
    track('webcheck_cta_click', { quelle_kanal: deriveQuelleKanal().quelle_kanal });
  };

  // --- Schritt 1: start ---
  const submitStart = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (company) return; // Honeypot ausgelöst → still verwerfen.

    const mail = email.trim().toLowerCase();
    const dom = normalizeDomain(domain);

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) { setError('Bitte gültige E-Mail-Adresse angeben.'); return; }
    if (!DOMAIN_RE.test(dom)) { setError('Bitte gültige Domain angeben, z. B. ihre-firma.de'); return; }

    setPhase('submitting');
    const { quelle_kanal, utm } = deriveQuelleKanal();
    track('webcheck_free_start_submit', { quelle_kanal, domain: dom });

    const payload = {
      email: mail,
      domain: dom,
      // V2-Marketing (entkoppelt): nur gesetzt, wenn freiwillig angekreuzt.
      marketing_consent: marketingConsent,
      consent_text_version: CONSENT_TEXT_VERSION,
      // Capture/Attribution (AC7) — serverseitig persistiert.
      source: 'webcheck-free-form',
      channel: quelle_kanal,
      referrer: typeof document !== 'undefined' ? document.referrer : '',
      landing_path: typeof window !== 'undefined' ? window.location.pathname : '',
      ...utm,
    };

    try {
      const res = await fetch(`${API_URL}/api/webcheck/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const json = await res.json().catch(() => null);

      if (res.status === 429) { setVerifiedDomain(dom); setPhase('rate_limited'); return; }
      if (res.status === 400) {
        const code = json?.error;
        setError(code === 'invalid_email' ? 'Bitte gültige E-Mail-Adresse angeben.' : 'Bitte gültige Domain angeben, z. B. ihre-firma.de');
        setPhase('form');
        return;
      }
      if (res.ok && json?.success && json?.data?.verification) {
        setLeadId(json.data.leadId);
        setVerification(json.data.verification as Verification);
        setVerifiedDomain(json.data.domain || dom);
        setPhase('verify');
        return;
      }
      setError('Start fehlgeschlagen. Bitte später erneut versuchen oder support@vectigal.tech.');
      setPhase('form');
    } catch {
      setError('Verbindung fehlgeschlagen. Bitte später erneut versuchen oder support@vectigal.tech.');
      setPhase('form');
    }
  };

  // --- Schritt 2: verify + Scan-Start ---
  const submitVerify = async () => {
    if (!leadId) return;
    setError('');
    setNotVerifiedYet(false);
    setPhase('verifying');
    try {
      const res = await fetch(`${API_URL}/api/webcheck/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ leadId }),
      });
      const json = await res.json().catch(() => null);

      if (res.status === 429 || json?.error === 'free_scan_already_used') { setPhase('rate_limited'); return; }

      const data = json?.data;
      if (json?.success && data?.verified && (data.scanStarted || data.alreadyRequested)) {
        setPhase(data.alreadyRequested ? 'already_requested' : 'scan_started');
        return;
      }
      if (json?.success && data && data.verified === false) {
        // AC2: Domain noch nicht nachgewiesen → Anleitung erneut zeigen.
        setNotVerifiedYet(true);
        setPhase('verify');
        return;
      }
      setError('Prüfung fehlgeschlagen. Bitte erneut versuchen oder support@vectigal.tech.');
      setPhase('verify');
    } catch {
      setError('Verbindung fehlgeschlagen. Bitte erneut versuchen.');
      setPhase('verify');
    }
  };

  // ---------- Ergebnis-/Edge-Zustände ----------
  if (phase === 'scan_started' || phase === 'already_requested') {
    return (
      <Panel>
        <CheckIcon />
        <p className="text-base font-semibold mb-1" style={{ color: C.offWhite }}>
          {phase === 'scan_started' ? 'Domain bestätigt — Ihr WebCheck läuft.' : 'Für diese Domain läuft bereits ein WebCheck.'}
        </p>
        <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
          Ihren kostenlosen WebCheck-Report für <strong style={{ color: C.offWhite }}>{verifiedDomain}</strong> erhalten Sie
          nach Abschluss per E-Mail (Link 30 Tage gültig). Sie können dieses Fenster schließen.
        </p>
        {marketingConsent && (
          <p className="text-xs leading-relaxed mt-3" style={{ color: C.muted }}>
            Zur Bestätigung Ihrer Marketing-Einwilligung erhalten Sie zusätzlich eine separate Bestätigungs-Mail
            (Double-Opt-in) — bitte klicken Sie den Link darin.
          </p>
        )}
      </Panel>
    );
  }

  if (phase === 'rate_limited') {
    return (
      <Panel>
        <p className="text-base font-semibold mb-1" style={{ color: C.offWhite }}>Aktueller WebCheck liegt bereits vor.</p>
        <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
          Für <strong style={{ color: C.offWhite }}>{verifiedDomain || 'diese Domain'}</strong> liegt bereits ein aktueller
          WebCheck vor. Den vollständigen Scan inkl. Handlungsempfehlungen erhalten Sie über eine{' '}
          <a href="/pricing" className="underline hover:text-white" style={{ color: C.teal }}>Demo-Anfrage</a>.
        </p>
      </Panel>
    );
  }

  // ---------- Schritt 2: Verifizierung ----------
  if (phase === 'verify' || phase === 'verifying') {
    const dnsM = verification?.methods.find(m => m.type === 'dns_txt');
    const fileM = verification?.methods.find(m => m.type === 'file');
    const metaM = verification?.methods.find(m => m.type === 'meta_tag');
    return (
      <div className="rounded-2xl p-5 sm:p-6" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.teal}18` }}>
        <p className="text-sm font-semibold mb-1" style={{ color: C.offWhite }}>Domain-Kontrolle nachweisen</p>
        <p className="text-xs leading-relaxed mb-4" style={{ color: C.muted }}>
          Wir scannen nur Domains, deren Kontrolle Sie nachweisen. Hinterlegen Sie für{' '}
          <strong style={{ color: C.offWhite }}>{verifiedDomain}</strong> <em>eine</em> der folgenden Markierungen und
          klicken Sie dann auf „Verifizierung prüfen".
        </p>

        {notVerifiedYet && (
          <p className="text-xs mb-3 rounded-lg px-3 py-2" role="alert"
            style={{ color: '#FCD34D', backgroundColor: 'rgba(252,211,77,0.08)', border: '1px solid rgba(252,211,77,0.25)' }}>
            Wir konnten die Kontrolle über {verifiedDomain} noch nicht bestätigen. Bitte hinterlegen Sie die Markierung
            (DNS kann einige Minuten dauern) und versuchen Sie es erneut.
          </p>
        )}

        <div className="flex flex-col gap-3 mb-4">
          {dnsM && (
            <VerifyMethodCard label="DNS-TXT-Eintrag (empfohlen)">
              <CodeRow caption="Name / Host:" value={dnsM.record ?? ''} />
              <CodeRow caption="Wert:" value={dnsM.value} />
            </VerifyMethodCard>
          )}
          {fileM && (
            <VerifyMethodCard label="Datei auf Ihrem Webserver">
              <CodeRow caption="Pfad:" value={fileM.path ?? ''} />
              <CodeRow caption="Inhalt:" value={fileM.value} />
            </VerifyMethodCard>
          )}
          {metaM && (
            <VerifyMethodCard label="Meta-Tag im <head> Ihrer Startseite">
              <CodeRow value={metaM.value} />
            </VerifyMethodCard>
          )}
        </div>

        {error && <p className="text-xs mb-3" style={{ color: '#F87171' }} role="alert">{error}</p>}

        <button type="button" onClick={submitVerify} disabled={phase === 'verifying'}
          className="w-full px-6 py-3.5 rounded-lg text-sm font-semibold transition-all duration-300 hover:scale-[1.01] disabled:opacity-60 disabled:hover:scale-100 cta-glow"
          style={{ backgroundColor: C.teal, color: C.slate }}>
          {phase === 'verifying' ? 'Wird geprüft …' : 'Verifizierung prüfen & Scan starten'}
        </button>
        <p className="text-xs text-center mt-2" style={{ color: C.muted }}>
          Ihren Report erhalten Sie nach Abschluss per E-Mail an {email || 'Ihre Adresse'}.
        </p>
      </div>
    );
  }

  // ---------- Schritt 1: Start-Formular ----------
  return (
    <form onSubmit={submitStart} className="rounded-2xl p-5 sm:p-6" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.teal}18` }} noValidate>
      {/* Honeypot — visuell versteckt, für Bots sichtbar. */}
      <div aria-hidden="true" style={{ position: 'absolute', left: '-9999px', top: 'auto', width: 1, height: 1, overflow: 'hidden' }}>
        <label>Firma (nicht ausfüllen)
          <input type="text" tabIndex={-1} autoComplete="off" value={company} onChange={e => setCompany(e.target.value)} />
        </label>
      </div>

      <div className="flex flex-col gap-3">
        <div>
          <label htmlFor="wc-email" className="block text-xs font-medium mb-1.5" style={{ color: C.muted }}>E-Mail-Adresse</label>
          <input id="wc-email" type="email" inputMode="email" autoComplete="email" required value={email}
            onFocus={onFirstFocus} onChange={e => setEmail(e.target.value)} placeholder="name@ihre-firma.de"
            className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors"
            style={{ backgroundColor: C.slate, color: C.offWhite, border: '1px solid rgba(45,212,191,0.18)' }} />
        </div>
        <div>
          <label htmlFor="wc-domain" className="block text-xs font-medium mb-1.5" style={{ color: C.muted }}>Ihre Domain</label>
          <input id="wc-domain" type="text" inputMode="url" autoComplete="off" required value={domain}
            onChange={e => setDomain(e.target.value)} placeholder="ihre-firma.de"
            className="w-full px-3.5 py-3 rounded-lg text-sm outline-none transition-colors"
            style={{ backgroundColor: C.slate, color: C.offWhite, border: '1px solid rgba(45,212,191,0.18)' }} />
        </div>

        {/* Marketing-Consent — FREIWILLIG, unangekreuzt (Kopplungsverbot, Greta §5.1). */}
        <label className="flex items-start gap-2.5 text-xs leading-relaxed mt-0.5 cursor-pointer" style={{ color: C.muted }}>
          <input type="checkbox" checked={marketingConsent} onChange={e => setMarketingConsent(e.target.checked)}
            className="mt-0.5 accent-[#2DD4BF] shrink-0" style={{ width: 16, height: 16 }} />
          <span>Ja, ich möchte von Vectigal gelegentlich praxisnahe Hinweise zu IT-Sicherheit &amp; Compliance
            (z.&nbsp;B. NIS2, DSGVO, ISO&nbsp;27001) sowie Produkt-Infos per E-Mail erhalten. Die Einwilligung kann ich
            jederzeit mit Wirkung für die Zukunft widerrufen.</span>
        </label>

        {error && <p className="text-xs" style={{ color: '#F87171' }} role="alert">{error}</p>}

        <button type="submit" disabled={phase === 'submitting'}
          className="w-full px-6 py-3.5 rounded-lg text-sm font-semibold transition-all duration-300 hover:scale-[1.01] disabled:opacity-60 disabled:hover:scale-100 cta-glow"
          style={{ backgroundColor: C.teal, color: C.slate }}>
          {phase === 'submitting' ? 'Wird gestartet …' : 'Kostenlosen WebCheck starten'}
        </button>

        <p className="text-xs text-center leading-relaxed" style={{ color: C.muted }}>
          Kostenlos · 1 Scan pro verifizierter Domain · Wir scannen nur Domains, deren Kontrolle Sie nachweisen.
        </p>

        {/* Datenschutz-Pflichthinweis (Greta §5.1) — Report unabhängig von der Einwilligung. */}
        <p className="text-xs leading-relaxed mt-1" style={{ color: C.muted }}>
          Ihren Report erhalten Sie unabhängig von dieser Einwilligung. Wir verarbeiten Ihre Angaben zur Durchführung des
          angeforderten WebChecks. Details in unserer{' '}
          <a href="/datenschutz" className="underline hover:text-white" style={{ color: C.teal }}>Datenschutzerklärung</a>.
          Verantwortlich: Vectigal · datenschutz@vectigal.tech.
        </p>
      </div>
    </form>
  );
}

/* ── kleine Präsentations-Helfer ─────────────────────────── */

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-2xl p-6 text-center" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.teal}30` }}>
      {children}
    </div>
  );
}

function CheckIcon() {
  return (
    <div className="mx-auto mb-3 flex items-center justify-center w-10 h-10 rounded-full" style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M20 6 9 17l-5-5" /></svg>
    </div>
  );
}

function VerifyMethodCard({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg p-3" style={{ backgroundColor: C.slate, border: '1px solid rgba(45,212,191,0.12)' }}>
      <p className="text-xs font-semibold mb-2" style={{ color: C.offWhite }}>{label}</p>
      <div className="flex flex-col gap-2.5">{children}</div>
    </div>
  );
}

/**
 * Verify-Code-Block mit optionalem Feld-Label (AC3 — Recognition over Recall)
 * und Copy-to-Clipboard-Button (AC2). Ziel ≥36px hoch (Fitts); „Kopiert"-Feedback
 * erscheint sofort beim Klick (<100ms) und klingt nach ~1,2 s ab.
 */
function CodeRow({ caption, value }: { caption?: string; value: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Fallback für ältere/abgesicherte Kontexte ohne Clipboard-API.
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch { /* still nichts — Nutzer kann manuell markieren */ }
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div>
      {caption && (
        <p className="text-xs font-medium mb-1" style={{ color: C.muted }}>{caption}</p>
      )}
      <div className="flex items-stretch gap-1.5">
        <code className="flex-1 min-w-0 text-xs break-all rounded px-2 py-2 font-mono"
          style={{ backgroundColor: '#0b1220', color: C.teal, border: '1px solid rgba(45,212,191,0.10)' }}>
          {value}
        </code>
        <button type="button" onClick={copy}
          aria-label={copied ? 'In Zwischenablage kopiert' : 'In Zwischenablage kopieren'}
          className="shrink-0 min-w-[5rem] px-3 rounded text-xs font-semibold transition-colors"
          style={{
            backgroundColor: copied ? `${C.teal}26` : `${C.teal}14`,
            color: C.teal,
            border: `1px solid ${C.teal}33`,
          }}>
          {copied ? '✓ Kopiert' : 'Kopieren'}
        </button>
      </div>
    </div>
  );
}
