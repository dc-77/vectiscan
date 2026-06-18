'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

import { createSubscription, TargetEntry } from '@/lib/api';
import { getTier, formatEur } from '@/lib/pricing';
import { isLoggedIn, getUser } from '@/lib/auth';
import TargetInput from '@/components/TargetInput';
// VEC-289: Paket-Identitaet/Name/Untertitel/Farbe aus dem kanonischen Katalog (SSoT).
import { getPackage, type PackageKey } from '@/lib/catalog.generated';

const MAX_TARGETS = 10;

// Kuratierte Verkaufs-Bullets je Paket (Copy-Domaene, T7/Belfort). Welche Pakete
// der Wizard anbietet bzw. Name/Untertitel/Preis kommen aus dem Katalog.
const CURATED_FEATURES: Record<string, string[]> = {
  webcheck: [
    'SSL/TLS, HTTP-Header, CMS-Erkennung',
    'E-Mail-Security (SPF/DKIM/DMARC)',
    'Basis-Port-Scan (Top 100)',
    'Ampelbewertung — sofort einsatzbereit',
  ],
  perimeter: [
    'Vollständige Angriffsoberflächen-Analyse',
    'Port-Scanning, Web-Schwachstellen, DNS, E-Mail-Security',
    'PTES-konformer Report mit Executive Summary',
    'Priorisierter Maßnahmenplan mit Zeitrahmen',
  ],
  compliance: [
    'Alles aus dem Perimeter-Scan',
    '§30 BSIG-Mapping (NIS2)',
    'BSI-Grundschutz-Referenzen',
    'Audit-Trail für Behörden und Prüfer',
  ],
  supplychain: [
    'Alles aus dem Perimeter-Scan',
    'ISO 27001 Annex A Mapping',
    'Lieferanten-Nachweis-Dokument',
    'Auftraggeber-Kapitel im Report',
  ],
  insurance: [
    'Alles aus dem Perimeter-Scan',
    '10-Punkte Versicherungs-Fragebogen',
    'Risk-Score und Ransomware-Indikator',
    'Nachweis für Cyberversicherungsantrag',
  ],
};

// VEC-431 (Design Rev 3, VEC-423): WebCheck (free) ist kein Abo-Produkt und
// erscheint nicht mehr im Subscription-Wizard — 4 Pakete statt 5.
const WIZARD_PACKAGE_KEYS: PackageKey[] = ['perimeter', 'compliance', 'supplychain', 'insurance'];

const PACKAGES = WIZARD_PACKAGE_KEYS.map((key) => {
  const def = getPackage(key)!;
  return {
    id: def.key,
    name: def.marketingName,
    subtitle: def.subtitle,
    recommended: def.sellability === 'self_service',
    // Preis im Stripe-Kontext sichtbar: self_service = Betrag, sales_assisted = null.
    priceEur: def.priceEur,
    color: def.accentColor,
    badge: def.badge,
    badgeColor: def.badgeColor,
    features: CURATED_FEATURES[def.key] ?? def.reportFocus,
  };
});

const INTERVALS = [
  { id: 'weekly', label: 'Wöchentlich', desc: 'Scan jede Woche' },
  { id: 'monthly', label: 'Monatlich', desc: 'Scan jeden Monat' },
  { id: 'quarterly', label: 'Quartalsweise', desc: 'Scan alle 3 Monate' },
] as const;

const STEPS = ['Paket', 'Ziele', 'E-Mail', 'Intervall', 'Zusammenfassung'];

export default function SubscribePage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [userEmail, setUserEmail] = useState('');

  const [step, setStep] = useState(1);
  const [selectedPackage, setSelectedPackage] = useState<string>('perimeter');
  const [targets, setTargets] = useState<TargetEntry[]>([{ raw_input: '', exclusions: [] }]);
  const [reportEmails, setReportEmails] = useState<string[]>(['']);
  const [scanInterval, setScanInterval] = useState<string>('monthly');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    const user = getUser();
    const email = user?.email || '';
    setUserEmail(email);
    setReportEmails([email]);
    setReady(true);
  }, [router]);

  const cleanedTargets: TargetEntry[] = targets
    .map(t => ({ raw_input: t.raw_input.trim(), exclusions: t.exclusions }))
    .filter(t => t.raw_input !== '');
  const validEmails = reportEmails.filter(e => e.includes('@'));

  const canAdvance = () => {
    switch (step) {
      case 1: return !!selectedPackage;
      case 2: return cleanedTargets.length > 0 && cleanedTargets.length <= MAX_TARGETS;
      case 3: return validEmails.length > 0;
      case 4: return !!scanInterval;
      default: return true;
    }
  };

  const handleSubmit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const res = await createSubscription({
        package: selectedPackage,
        targets: cleanedTargets,
        scanInterval,
        reportEmails: validEmails,
      });
      if (res.success) {
        // Self-Service-Kauf (VEC-223): Backend legt das Abo als 'pending' an und
        // liefert eine Stripe-Checkout-URL. Das Abo wird erst nach bestaetigter
        // Zahlung (checkout.session.completed-Webhook) aktiv. Zur sicheren
        // Stripe-Zahlung weiterleiten, statt nur eine Erfolgsmeldung zu zeigen.
        if (res.data?.checkoutUrl) {
          window.location.href = res.data.checkoutUrl;
          return;
        }
        setSuccess(res.data?.id || 'ok');
      } else {
        setError(res.error || 'Unbekannter Fehler');
      }
    } catch {
      setError('Verbindung zum Server fehlgeschlagen.');
    } finally {
      setSubmitting(false);
    }
  };

  if (!ready) return null;

  if (success) {
    return (
      <main className="flex-1 px-4 py-8 md:px-8">
        <div className="max-w-lg mx-auto text-center space-y-6">
          <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto">
            <svg className="w-8 h-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          </div>
          <h1 className="text-xl font-semibold text-white">Abo erfolgreich erstellt</h1>
          <p className="text-sm text-gray-400">
            Ihre Domains werden jetzt von einem Administrator geprüft und freigegeben.
            Nach der Freigabe startet der erste Scan automatisch.
          </p>
          <Link href="/dashboard"
            className="inline-block bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] text-white font-medium px-6 py-3 rounded-lg transition-colors text-sm">
            Zum Dashboard
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-2xl mx-auto space-y-6">
        <h1 className="text-lg font-semibold text-white">Neues Abo erstellen</h1>

        {/* Step Indicator */}
        <div className="flex items-center gap-1">
          {STEPS.map((label, i) => {
            const stepNum = i + 1;
            const isActive = stepNum === step;
            const isDone = stepNum < step;
            return (
              <div key={label} className="flex items-center gap-1 flex-1">
                <div className={`flex items-center gap-1.5 ${isActive ? 'text-[#2DD4BF]' : isDone ? 'text-green-400' : 'text-slate-600'}`}>
                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium border ${
                    isActive ? 'border-[#2DD4BF] bg-[#2DD4BF]/10' : isDone ? 'border-green-400 bg-green-400/10' : 'border-slate-700'
                  }`}>
                    {isDone ? '\u2713' : stepNum}
                  </span>
                  <span className="text-xs hidden sm:inline">{label}</span>
                </div>
                {i < STEPS.length - 1 && <div className={`flex-1 h-px ${isDone ? 'bg-green-400/30' : 'bg-slate-700'}`} />}
              </div>
            );
          })}
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}

        {/* Step 1: Package Selection — VEC-431 (Design Rev 3): 4 Pakete (kein
            WebCheck), DS-Tokens analog PackageSelector.tsx, Preis sichtbar. */}
        {step === 1 && (
          <div className="space-y-3">
            <p className="text-sm text-[var(--text-muted)]">Wählen Sie Ihr Scan-Paket:</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {PACKAGES.map((pkg) => {
                const isSelected = selectedPackage === pkg.id;
                const borderColor = isSelected
                  ? pkg.color
                  : pkg.recommended ? `${pkg.color}30` : 'var(--border-muted)';
                const priceLabel = pkg.priceEur != null
                  ? `ab ${formatEur(pkg.priceEur)} / Jahr`
                  : 'Auf Anfrage';
                return (
                  <button key={pkg.id} onClick={() => setSelectedPackage(pkg.id)}
                    data-testid={`subscribe-package-${pkg.id}`}
                    className="relative text-left p-5 pt-6 rounded-xl transition-all duration-200 bg-[var(--surface)] hover:bg-[var(--surface-2)] outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--teal)] focus-visible:outline-offset-2"
                    style={{
                      borderWidth: '2px',
                      borderStyle: 'solid',
                      borderColor,
                      boxShadow: isSelected ? `0 0 28px ${pkg.color}24` : 'none',
                    }}>
                    {pkg.badge && (
                      <span
                        className={`absolute -top-2.5 left-4 font-bold px-3 py-0.5 rounded-full ${
                          pkg.recommended ? 'text-sm px-4' : 'text-xs'
                        }`}
                        style={{ backgroundColor: pkg.badgeColor || pkg.color, color: 'var(--slate)' }}>
                        {pkg.recommended ? `★ ${pkg.badge}` : pkg.badge}
                      </span>
                    )}
                    <div className="flex items-baseline justify-between gap-2 mb-1">
                      <span className="text-sm font-semibold text-[var(--text)]">{pkg.name}</span>
                      <span className="text-xs font-medium shrink-0" style={{ color: pkg.color }}>
                        {priceLabel}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--text-dim)] mb-3">{pkg.subtitle}</p>
                    <ul className="space-y-1.5">
                      {pkg.features.map((f) => (
                        <li key={f} className="text-xs text-[var(--text-muted)] flex items-start gap-1.5">
                          <span className="mt-0.5 w-1 h-1 rounded-full flex-shrink-0" style={{ backgroundColor: pkg.color }} />
                          {f}
                        </li>
                      ))}
                    </ul>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 2: Target Input */}
        {step === 2 && (
          <div className="space-y-3">
            <TargetInput
              value={targets}
              onChange={setTargets}
              disabled={submitting}
            />
            <p className="text-xs text-gray-600">
              Ziele werden nach der Bestellung von einem Administrator geprüft.
            </p>
          </div>
        )}

        {/* Step 3: Report Emails */}
        {step === 3 && (
          <div className="space-y-3">
            <p className="text-sm text-gray-400">An welche E-Mail-Adressen sollen die Reports versandt werden?</p>
            <div className="space-y-2">
              {reportEmails.map((email, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => {
                      const next = [...reportEmails];
                      next[i] = e.target.value;
                      setReportEmails(next);
                    }}
                    placeholder="it-leitung@firma.de"
                    className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] text-sm"
                  />
                  {reportEmails.length > 1 && (
                    <button onClick={() => setReportEmails(reportEmails.filter((_, j) => j !== i))}
                      className="text-red-400 hover:text-red-300 px-2 transition-colors">x</button>
                  )}
                </div>
              ))}
            </div>
            {reportEmails.length < 10 && (
              <button onClick={() => setReportEmails([...reportEmails, ''])}
                className="text-xs text-[#2DD4BF] hover:text-[#5EEAD4] font-medium transition-colors">
                + Empfänger hinzufügen
              </button>
            )}
          </div>
        )}

        {/* Step 4: Scan Interval */}
        {step === 4 && (
          <div className="space-y-3">
            <p className="text-sm text-gray-400">Wie oft sollen Ihre Domains gescannt werden?</p>
            <div className="grid grid-cols-3 gap-3">
              {INTERVALS.map((iv) => {
                const isSelected = scanInterval === iv.id;
                return (
                  <button key={iv.id} onClick={() => setScanInterval(iv.id)}
                    className={`text-center p-4 rounded-lg border-2 transition-all ${
                      isSelected
                        ? 'border-[#2DD4BF] bg-[#2DD4BF]/10'
                        : 'border-gray-800 bg-[#1e293b] hover:bg-[#253347]'
                    }`}>
                    <p className="text-sm font-medium text-white">{iv.label}</p>
                    <p className="text-xs text-gray-500 mt-1">{iv.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 5: Summary */}
        {step === 5 && (
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-5 space-y-4">
            <h2 className="text-sm font-medium text-white">Zusammenfassung</h2>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Paket</span>
                <span className="text-white font-medium">{PACKAGES.find(p => p.id === selectedPackage)?.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Ziele ({cleanedTargets.length} Einträge)</span>
                <span className="text-white font-mono text-xs max-w-[200px] text-right truncate">
                  {cleanedTargets.map(t => t.raw_input).join(', ')}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Report-Empfänger</span>
                <span className="text-white text-xs">{validEmails.join(', ')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Scan-Intervall</span>
                <span className="text-white">{INTERVALS.find(i => i.id === scanInterval)?.label}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Laufzeit</span>
                <span className="text-white">12 Monate</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Re-Scans inklusive</span>
                <span className="text-white">3 pro Jahr</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Preis</span>
                <span className="text-white font-medium">
                  {(() => {
                    const tier = getTier(selectedPackage);
                    return tier?.purchasable && tier.priceEur != null
                      ? `${formatEur(tier.priceEur)} / Jahr`
                      : 'Auf Anfrage';
                  })()}
                </span>
              </div>
            </div>
            <div className="border-t border-gray-700 pt-3">
              <p className="text-xs text-gray-500">
                {getTier(selectedPackage)?.purchasable
                  ? 'Sie werden zur sicheren Stripe-Zahlung weitergeleitet. Das Abo wird erst nach bestätigter Zahlung aktiv. Anschließend prüft ein Administrator Ihre Domains zur Freigabe, danach startet der erste Scan automatisch.'
                  : 'Nach der Bestellung werden Ihre Domains von einem Administrator geprüft. Der Preis wird Ihnen individuell mitgeteilt. Nach Freigabe startet der erste Scan automatisch.'}
              </p>
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="flex justify-between items-center pt-2">
          {step > 1 ? (
            <button onClick={() => { setStep(step - 1); setError(null); }}
              className="text-sm text-gray-400 hover:text-gray-300 transition-colors">
              Zurück
            </button>
          ) : <div />}

          {step < 5 ? (
            <div className="flex items-center gap-3">
              {!canAdvance() && step === 2 && <span className="text-xs" style={{ color: '#F59E0B' }}>Mindestens ein gültiges Ziel eingeben</span>}
              {!canAdvance() && step === 3 && <span className="text-xs" style={{ color: '#F59E0B' }}>Mindestens eine E-Mail-Adresse eingeben</span>}
              {/* VEC-431: WebCheck-Sonderfall (/welcome-Redirect) entfernt — WebCheck
                  ist nicht mehr Teil des Abo-Wizards. */}
              <button onClick={() => { if (canAdvance()) setStep(step + 1); }}
                disabled={!canAdvance()}
                className="disabled:bg-gray-700 disabled:cursor-not-allowed font-medium px-6 py-2.5 rounded-lg transition-colors text-sm"
                style={{ backgroundColor: canAdvance() ? '#2DD4BF' : undefined, color: canAdvance() ? '#0F172A' : undefined }}>
                Weiter
              </button>
            </div>
          ) : (
            <button onClick={handleSubmit} disabled={submitting}
              className="bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] disabled:bg-gray-700 text-white font-medium px-6 py-2.5 rounded-lg transition-colors text-sm">
              {submitting ? 'Wird erstellt...' : 'Abo starten'}
            </button>
          )}
        </div>
      </div>
    </main>
  );
}
