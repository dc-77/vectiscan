'use client';

// VEC-312 (VEC-306 b, Konzept §5.2): Geführter Scan-Wizard /scan/new.
// Ziel → Paket → [Inline-Upgrade statt 403] → Bestätigen, mit
// StepIndicator. Single-column, max ~640px (Tesler: das System trägt
// die Komplexität). Pakete kommen AUSSCHLIESSLICH aus dem kanonischen
// Katalog (VEC-289, catalog.generated). DS-Primitive: StepIndicator,
// StateView. A11y: Fokus-Reihenfolge, ≥44px, Plain-Language-Fehler.
//
// Inline-Upgrade (Kern-Fix, koordiniert mit VEC-294): braucht das
// gewählte Paket eine Freischaltung und der Kunde hat keine →
// derselbe Wizard zeigt einen Freischalt-Schritt mit Klartext-Nutzen
// + CTA (Abo/Beratung) STATT einer Access-denied-Sackgasse. Nicht
// blockierend: der Einmal-Scan bleibt für jeden Kunden durchläufbar
// (DoD „frischer Customer"); echtes Hard-Gating bleibt VEC-294.

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { createOrder, listSubscriptions, Subscription, TargetEntry } from '@/lib/api';
import { isLoggedIn } from '@/lib/auth';
import { getPackage, type PackageKey } from '@/lib/catalog.generated';
import TargetInput from '@/components/TargetInput';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';
import StepIndicator, { WizardStep } from '@/components/ds/StepIndicator';
import StateView from '@/components/ds/StateView';

// Aktiv-Stati eines Abos (siehe subscriptions.status).
const ACTIVE_SUB = new Set(['active', 'trialing']);

// Heuristik „Verifikation nötig": mindestens ein FQDN-Ziel (Domain-
// Besitznachweis). Reine IP/CIDR-Ziele haben keinen DNS-Ownership-Pfad.
function looksLikeFqdn(raw: string): boolean {
  const v = raw.trim().toLowerCase();
  if (!v || v.includes('/')) return false;          // CIDR raus
  if (/^[0-9.]+$/.test(v)) return false;            // reine IPv4 raus
  return /[a-z]/.test(v) && v.includes('.');
}

function formatEur(value: number): string {
  return `${value.toLocaleString('de-DE')} €`;
}

function priceHint(pkg: ReturnType<typeof getPackage>): string {
  if (!pkg) return '';
  if (pkg.priceEur === 0) return 'kostenlos';
  if (pkg.priceEur === null) return 'Preis auf Anfrage';
  return `Abo ab ${formatEur(pkg.priceEur)} / Jahr`;
}

export default function ScanNewPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [stepId, setStepId] = useState<string>('target');
  const [targets, setTargets] = useState<TargetEntry[]>([{ raw_input: '', exclusions: [] }]);
  const [selectedPackage, setSelectedPackage] = useState<ScanPackage>('perimeter');
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // VEC-436: Stripe-Cancel-URL für Einzelscans führt zurück nach
  // /scan/new?checkout=cancelled. Wir zeigen einen klaren Hinweis statt
  // wortlos auf der Paketwahl zu landen.
  const [paymentCancelled, setPaymentCancelled] = useState(false);

  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('checkout') === 'cancelled') {
      setPaymentCancelled(true);
    }
  }, []);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setReady(true);
    // Abo-Status laden (nicht-blockierend; Fehler = „kein Abo bekannt").
    listSubscriptions()
      .then(res => { if (res.success && res.data) setSubscriptions(res.data.subscriptions); })
      .catch(() => { /* offline → behandeln wie „kein Abo" */ });
  }, [router]);

  const pkgDef = getPackage(selectedPackage);

  const hasActiveSub = useMemo(
    () => subscriptions.some(s => s.package === selectedPackage && ACTIVE_SUB.has((s.status || '').toLowerCase())),
    [subscriptions, selectedPackage],
  );

  // Upgrade-Schritt: Paket ist nicht „free" und kein passendes aktives Abo.
  const needsUpgrade = !!pkgDef && pkgDef.sellability !== 'free' && !hasActiveSub;

  // VEC-436: Self-Service-Einzelkauf. Die Präsenz von oneTimePriceEnvKey im
  // Katalog signalisiert „kostenpflichtiger Einzelkauf" (heute nur Perimeter)
  // — spiegelt das Backend (isOneTimePurchasable). Ohne aktives Abo muss der
  // Kunde diesen Einzelscan zuerst per Stripe-Checkout bezahlen; das Backend
  // legt die Order dann als 'awaiting_payment' an und liefert eine checkoutUrl.
  const oneTimePriceEur = pkgDef?.oneTimePriceEur;
  const mustPayOneTime = !!pkgDef?.oneTimePriceEnvKey && oneTimePriceEur != null && !hasActiveSub;
  const needsVerifyInfo = targets.some(t => looksLikeFqdn(t.raw_input));

  const steps: WizardStep[] = useMemo(() => {
    const s: WizardStep[] = [
      { id: 'target', label: 'Ziel' },
      { id: 'package', label: 'Paket' },
    ];
    if (needsUpgrade) s.push({ id: 'upgrade', label: 'Freischalten' });
    s.push({ id: 'confirm', label: 'Bestätigen' });
    return s;
  }, [needsUpgrade]);

  const currentIdx = Math.max(0, steps.findIndex(s => s.id === stepId));

  // stepId konsistent halten, falls ein Schritt wegfällt (z.B. Paketwechsel).
  useEffect(() => {
    if (!steps.some(s => s.id === stepId)) setStepId(steps[steps.length - 1].id);
  }, [steps, stepId]);

  const hasValidTarget = targets.some(t => t.raw_input.trim() !== '');

  const goNext = useCallback(() => {
    setError(null);
    const next = steps[Math.min(currentIdx + 1, steps.length - 1)];
    setStepId(next.id);
  }, [steps, currentIdx]);

  const goBack = useCallback(() => {
    setError(null);
    const prev = steps[Math.max(currentIdx - 1, 0)];
    setStepId(prev.id);
  }, [steps, currentIdx]);

  const handleSubmit = useCallback(async () => {
    setError(null);
    const cleaned: TargetEntry[] = targets
      .map(t => ({ raw_input: t.raw_input.trim(), exclusions: t.exclusions }))
      .filter(t => t.raw_input !== '');
    if (cleaned.length === 0) {
      setError('Bitte gib mindestens ein Ziel ein.');
      setStepId('target');
      return;
    }
    setSubmitting(true);
    try {
      const res = await createOrder(cleaned, selectedPackage);
      if (res.success && res.data) {
        // VEC-436: Einmalzahlungs-Pfad. Hat das Backend eine Stripe-Checkout-URL
        // zurückgegeben, ist die Order 'awaiting_payment' und der Scan startet
        // erst nach bestätigter Zahlung. Vollständiger Redirect auf Stripe
        // (window.location, kein router.push — externe Domain).
        if (res.data.checkoutUrl) {
          window.location.href = res.data.checkoutUrl;
          return; // submitting bleibt true bis der Browser navigiert
        }
        router.push(`/scan/${res.data.id}`);
      } else if (res.error === 'payment_not_configured' || res.error === 'price_not_configured') {
        // Stripe/Preis nicht konfiguriert → kein Gratis-Scan als Fallback.
        setError('Die Zahlungsabwicklung ist derzeit nicht verfügbar. Bitte versuche es später erneut oder wähle ein anderes Paket.');
        setStepId('package');
      } else if (res.error === 'checkout_creation_failed') {
        setError('Der Checkout konnte nicht gestartet werden. Bitte versuche es in einem Moment erneut.');
      } else if (res.error === 'target_validation_failed') {
        setError('Mindestens ein Ziel ist ungültig. Bitte prüfe deine Eingaben im ersten Schritt.');
        setStepId('target');
      } else if (res.forbidden) {
        // VEC-294: Server hat das Paket gesperrt (z.B. Abo zwischenzeitlich
        // abgelaufen). Kein rohes „Access denied" — zurück zum Paket-Schritt,
        // der dann den Inline-Freischalt-Schritt anbietet statt einer Sackgasse.
        setError(`${getPackage(selectedPackage)?.marketingName ?? 'Dieses Paket'} ist für dein Konto aktuell nicht freigeschaltet. Wähle die Freischaltung oder ein anderes Paket.`);
        setStepId('package');
      } else {
        setError(res.error || 'Der Scan konnte nicht gestartet werden. Bitte versuche es erneut.');
      }
    } catch {
      setError('Server nicht erreichbar. Bitte versuche es in einem Moment erneut.');
    } finally {
      setSubmitting(false);
    }
  }, [targets, selectedPackage, router]);

  if (!ready) return null;

  const btnPrimary = 'min-h-[44px] px-6 py-2.5 rounded-lg text-sm font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed';
  const btnSecondary = 'min-h-[44px] px-5 py-2.5 rounded-lg text-sm font-medium transition-all';

  return (
    <div className="w-full max-w-[640px] mx-auto px-4 py-8 space-y-7">
      <header className="text-center space-y-1.5">
        <h1 className="text-xl font-bold" style={{ color: 'var(--text)' }}>Neuer Scan</h1>
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          In wenigen Schritten zum Sicherheits-Scan.
        </p>
      </header>

      {paymentCancelled && (
        <div role="status" className="rounded-lg px-4 py-3 text-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tone-warn) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--tone-warn) 32%, transparent)', color: 'var(--text)' }}>
          <span className="font-medium">Zahlung abgebrochen.</span> Es wurde kein Scan gestartet — du kannst die Bestellung jederzeit erneut anstoßen.
        </div>
      )}

      <StepIndicator steps={steps} current={currentIdx} />

      {/* ── Schritt 1: Ziel ─────────────────────────────────── */}
      {stepId === 'target' && (
        <section aria-labelledby="step-target" className="space-y-5">
          <div className="space-y-1">
            <h2 id="step-target" className="text-base font-semibold" style={{ color: 'var(--text)' }}>Was soll geprüft werden?</h2>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              Domain, Subdomain, IP-Adresse oder ein Netzbereich (CIDR). Bis zu 10 Zeilen,
              höchstens 1 CIDR (mindestens /24), maximal 50 lebende Hosts.
            </p>
          </div>
          <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-subtle)' }}>
            <TargetInput value={targets} onChange={setTargets} disabled={submitting} />
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              onClick={goNext}
              disabled={!hasValidTarget}
              className={btnPrimary}
              style={{ backgroundColor: 'var(--tone-active)', color: 'var(--slate)' }}
            >
              Weiter zum Paket
            </button>
          </div>
        </section>
      )}

      {/* ── Schritt 2: Paket ────────────────────────────────── */}
      {stepId === 'package' && (
        <section aria-labelledby="step-package" className="space-y-5">
          <div className="space-y-1">
            <h2 id="step-package" className="text-base font-semibold" style={{ color: 'var(--text)' }}>Welches Paket passt?</h2>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              Umfang und Tiefe des Scans. Das empfohlene Paket ist markiert.
            </p>
          </div>
          <PackageSelector selected={selectedPackage} onSelect={setSelectedPackage} />
          <div className="flex justify-between gap-3">
            <button type="button" onClick={goBack} className={btnSecondary} style={{ color: 'var(--text)', border: '1px solid var(--border-subtle)' }}>
              Zurück
            </button>
            <button type="button" onClick={goNext} className={btnPrimary} style={{ backgroundColor: 'var(--tone-active)', color: 'var(--slate)' }}>
              {needsUpgrade ? 'Weiter zur Freischaltung' : 'Weiter zur Bestätigung'}
            </button>
          </div>
        </section>
      )}

      {/* ── Schritt (bedingt): Freischalten — Inline-Upgrade statt 403 ─ */}
      {stepId === 'upgrade' && pkgDef && (
        <section aria-labelledby="step-upgrade" className="space-y-5">
          <h2 id="step-upgrade" className="sr-only">Paket freischalten</h2>
          <StateView
            variant="info"
            title={mustPayOneTime ? `${pkgDef.marketingName} buchen` : `${pkgDef.marketingName} freischalten`}
            description={
              pkgDef.sellability === 'sales_assisted'
                ? 'Dieses Paket richten wir gemeinsam mit dir ein — inklusive Compliance-Nachweis und Beratung. Fordere ein unverbindliches Angebot an.'
                : mustPayOneTime
                  // VEC-436: klare Wahl Einmalkauf vs. Abo statt reinem Abo-Push.
                  ? `Du kannst diesen Scan einmalig für ${formatEur(oneTimePriceEur!)} buchen oder ein Abo abschließen — wiederkehrende Scans, Verlaufs-Vergleiche und Sicherheits-Posture über die Zeit.`
                  : 'Mit einem Abo erhältst du wiederkehrende Scans, Verlaufs-Vergleiche und Sicherheits-Posture über die Zeit. Du kannst aber auch einen einmaligen Scan starten.'
            }
            actions={
              pkgDef.sellability === 'sales_assisted'
                ? [{ label: 'Beratung anfragen', href: '/contact', variant: 'primary' }]
                : mustPayOneTime
                  ? [
                      { label: `Einmal bezahlen (${formatEur(oneTimePriceEur!)})`, onClick: goNext, variant: 'primary' },
                      {
                        label: pkgDef.priceEur != null ? `Abo abschließen (${formatEur(pkgDef.priceEur)} / Jahr)` : 'Abo abschließen',
                        href: '/subscribe',
                        variant: 'secondary',
                      },
                    ]
                  : [
                      { label: 'Abo einrichten', href: '/subscribe', variant: 'primary' },
                      { label: 'Als Einmal-Scan fortfahren', onClick: goNext, variant: 'secondary' },
                    ]
            }
          >
            <ul className="text-left text-sm mx-auto max-w-sm space-y-1.5 mt-1" style={{ color: 'var(--text-muted)' }}>
              {pkgDef.reportFocus.map((f, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span aria-hidden style={{ color: 'var(--tone-active)' }}>✓</span>
                  <span>{f}</span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-center" style={{ color: 'var(--text-dim)' }}>{priceHint(pkgDef)}</p>
          </StateView>
          <div className="flex justify-start">
            <button type="button" onClick={goBack} className={btnSecondary} style={{ color: 'var(--text)', border: '1px solid var(--border-subtle)' }}>
              Zurück zur Paketwahl
            </button>
          </div>
        </section>
      )}

      {/* ── Schritt: Bestätigen ─────────────────────────────── */}
      {stepId === 'confirm' && pkgDef && (
        <section aria-labelledby="step-confirm" className="space-y-5">
          <div className="space-y-1">
            <h2 id="step-confirm" className="text-base font-semibold" style={{ color: 'var(--text)' }}>Alles bereit?</h2>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Prüfe deine Auswahl und starte den Scan.</p>
          </div>

          <div className="rounded-xl p-5 space-y-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-subtle)' }}>
            <div>
              <div className="text-xs uppercase tracking-wide mb-1.5" style={{ color: 'var(--text-dim)' }}>Ziele</div>
              <ul className="space-y-1">
                {targets.filter(t => t.raw_input.trim() !== '').map((t, i) => (
                  <li key={i} className="text-sm font-mono" style={{ color: 'var(--text)' }}>{t.raw_input.trim()}</li>
                ))}
              </ul>
            </div>
            <div className="h-px" style={{ backgroundColor: 'var(--border-subtle)' }} />
            <div>
              <div className="text-xs uppercase tracking-wide mb-1.5" style={{ color: 'var(--text-dim)' }}>Paket</div>
              <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{pkgDef.marketingName}</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {pkgDef.durationLong} · bis zu {pkgDef.maxHosts} Hosts
              </div>
              {mustPayOneTime && (
                <div className="text-sm font-semibold mt-1.5" style={{ color: 'var(--text)' }}>
                  Einmalzahlung {formatEur(oneTimePriceEur!)}
                </div>
              )}
            </div>
          </div>

          {/* Nächste Schritte / Verifikation (§5.2: „nur falls nötig") */}
          <div className="rounded-xl p-4 text-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tone-info) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--tone-info) 24%, transparent)' }}>
            <div className="font-medium mb-1" style={{ color: 'var(--text)' }}>So geht es weiter</div>
            <ol className="list-decimal list-inside space-y-0.5" style={{ color: 'var(--text-muted)' }}>
              {mustPayOneTime && (
                <li>Du schließt die Zahlung sicher über Stripe ab (Einmalzahlung {formatEur(oneTimePriceEur!)}). Der Scan startet erst nach bestätigter Zahlung.</li>
              )}
              <li>Wir prüfen deine Ziele automatisch (Pre-Check).</li>
              <li>Unser Team gibt den Auftrag frei.</li>
              {needsVerifyInfo && (
                <li>Du weist den Domain-Besitz nach (DNS-Eintrag, Datei oder Meta-Tag) — du wirst dazu benachrichtigt und kannst es später erledigen.</li>
              )}
              <li>Der Scan startet automatisch ({pkgDef.durationLong}).</li>
            </ol>
          </div>

          {error && (
            <div role="alert" className="rounded-lg px-4 py-3 text-sm" style={{ backgroundColor: 'color-mix(in srgb, var(--tone-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--tone-danger) 32%, transparent)', color: 'var(--tone-danger)' }}>
              {error}
            </div>
          )}

          <div className="flex justify-between gap-3">
            <button type="button" onClick={goBack} disabled={submitting} className={btnSecondary} style={{ color: 'var(--text)', border: '1px solid var(--border-subtle)' }}>
              Zurück
            </button>
            <button type="button" onClick={handleSubmit} disabled={submitting} className={btnPrimary} style={{ backgroundColor: 'var(--tone-active)', color: 'var(--slate)' }}>
              {mustPayOneTime
                ? (submitting ? 'Weiterleitung zur Zahlung…' : 'Weiter zur Zahlung')
                : (submitting ? 'Scan startet…' : 'Scan starten')}
            </button>
          </div>
        </section>
      )}

      <p className="text-center text-xs" style={{ color: 'var(--text-dim)' }}>
        Lieber das alte Formular? <Link href="/scan" className="underline" style={{ color: 'var(--text-muted)' }}>Klassische Ansicht</Link>
      </p>
    </div>
  );
}
