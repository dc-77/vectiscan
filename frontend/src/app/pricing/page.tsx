import Link from 'next/link';
import { getTier, formatEur } from '@/lib/pricing';
import { PACKAGE_CATALOG, type PackageDef, type PackageKey } from '@/lib/catalog.generated';

const C = {
  slate: '#0F172A',
  slateLight: '#1E293B',
  teal: '#2DD4BF',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
  border: 'rgba(45,212,191,0.12)',
  borderSubtle: 'rgba(30,58,95,0.35)',
};

// Feature-Matrix fuer die Vergleichstabelle. Support pro Paket-Key statt
// positionsgebundener Tupel, damit die Tabelle sich sauber auf die im Katalog
// gelisteten Pakete (listed-Flag, SSoT) reduziert — egal welche das sind.
const FEATURES: { label: string; support: Record<PackageKey, boolean> }[] = [
  { label: 'E-Mail-Security (SPF/DKIM/DMARC)', support: { webcheck: true, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'SSL/TLS-Konfigurationsanalyse', support: { webcheck: true, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'HTTP-Security-Header-Prüfung', support: { webcheck: true, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'Port-Scanning & Service-Erkennung', support: { webcheck: false, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'Web-Schwachstellen (OWASP ZAP)', support: { webcheck: false, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'DNS-Enumeration & Subdomain-Analyse', support: { webcheck: false, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'KI-Korrelation & FP-Filter', support: { webcheck: false, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'Executive Summary + Maßnahmenplan', support: { webcheck: false, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'Threat Intel (NVD, EPSS, CISA KEV)', support: { webcheck: false, perimeter: true, compliance: true, supplychain: true, insurance: true } },
  { label: 'NIS2 / §30 BSIG-Mapping', support: { webcheck: false, perimeter: false, compliance: true, supplychain: false, insurance: false } },
  { label: 'BSI-Grundschutz-Referenzen', support: { webcheck: false, perimeter: false, compliance: true, supplychain: false, insurance: false } },
  { label: 'ISO 27001 Annex A', support: { webcheck: false, perimeter: false, compliance: false, supplychain: true, insurance: false } },
  { label: 'Lieferanten-Nachweis-Dokument', support: { webcheck: false, perimeter: false, compliance: false, supplychain: true, insurance: false } },
  { label: 'Versicherungs-Fragebogen (10 Pkt.)', support: { webcheck: false, perimeter: false, compliance: false, supplychain: false, insurance: true } },
  { label: 'Risk-Score & Ransomware-Indikator', support: { webcheck: false, perimeter: false, compliance: false, supplychain: false, insurance: true } },
];

function Check() {
  return <span style={{ color: C.teal }}>&#x2713;</span>;
}
function Dash() {
  return <span style={{ color: `${C.muted}40` }}>—</span>;
}

function ctaFor(pkg: PackageDef) {
  if (pkg.sellability === 'free') return { label: 'Kostenlosen WebCheck starten', href: '/welcome', primary: true };
  if (pkg.sellability === 'self_service') return { label: 'Jetzt kaufen', href: '/subscribe', primary: true };
  return { label: 'Angebot anfragen', href: '/contact', primary: false };
}

function priceFor(pkg: PackageDef): { main: string; note: string } {
  const tier = getTier(pkg.key);
  if (pkg.sellability === 'free') return { main: 'Kostenlos', note: 'ohne Kreditkarte · kein Abo' };
  if (pkg.sellability === 'self_service' && tier?.priceEur != null) {
    return { main: `${formatEur(tier.priceEur)} / Jahr`, note: tier.billingNote };
  }
  return { main: 'Auf Anfrage', note: tier?.billingNote ?? 'Jahresabo — individuelle Preisgestaltung' };
}

export default function PricingPage() {
  // Nur im Kunden-Frontend gelistete Pakete (listed-Flag, SSoT) anzeigen.
  // Ausgeblendete Pakete bleiben im Katalog erhalten und jederzeit reaktivierbar.
  const listedPackages = PACKAGE_CATALOG.filter(p => p.listed);
  const freeAndSelfService = listedPackages.filter(p => p.sellability !== 'sales_assisted');
  const salesAssisted = listedPackages.filter(p => p.sellability === 'sales_assisted');

  return (
    <main className="flex-1">
      {/* Hero */}
      <section className="py-20 md:py-24">
        <div className="max-w-5xl mx-auto px-6 text-center">
          <h1 className="text-3xl md:text-4xl font-semibold mb-4" style={{ color: C.offWhite }}>
            Pakete &amp; Preise
          </h1>
          <p className="text-base max-w-2xl mx-auto" style={{ color: C.muted }}>
            Vom automatisierten Perimeter-Scan bis zum Nachweis für Ihre Cyberversicherung.
          </p>
        </div>
      </section>

      {/* Package Cards */}
      <section id="pakete" className="pb-16">
        <div className="max-w-5xl mx-auto px-6 space-y-6">

          {/* Free + Self-service row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {freeAndSelfService.map(pkg => {
              const cta = ctaFor(pkg);
              const price = priceFor(pkg);
              const isSelfService = pkg.sellability === 'self_service';
              return (
                <div key={pkg.key} className="rounded-xl p-7 relative flex flex-col"
                  style={{
                    backgroundColor: C.slateLight,
                    border: isSelfService ? `2px solid ${pkg.accentColor}40` : `1px solid ${C.borderSubtle}`,
                  }}>
                  {pkg.badge && (
                    <span className="absolute -top-3 left-6 text-[10px] font-semibold px-3 py-1 rounded-full"
                      style={{ backgroundColor: `${pkg.accentColor}25`, color: pkg.accentColor }}>
                      {pkg.badge}
                    </span>
                  )}
                  <h2 className="text-xl font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>{pkg.marketingName}</h2>
                  <p className="text-sm mb-6" style={{ color: C.muted }}>{pkg.subtitle}</p>
                  <ul className="space-y-2.5 mb-8 flex-1">
                    {pkg.reportFocus.map(f => (
                      <li key={f} className="flex items-start gap-2 text-sm" style={{ color: C.mutedLight }}>
                        <span className="mt-0.5" style={{ color: pkg.accentColor }}>&#x2713;</span> {f}
                      </li>
                    ))}
                  </ul>
                  <div className="border-t pt-5" style={{ borderColor: C.borderSubtle }}>
                    <p className="mb-1">
                      <span className="text-3xl font-semibold" style={{ color: C.offWhite }}>{price.main}</span>
                    </p>
                    <p className="text-xs mb-4" style={{ color: C.muted }}>{price.note}</p>
                    <Link href={cta.href}
                      className="block w-full text-center px-5 py-3 rounded-lg text-sm font-medium transition-all"
                      style={cta.primary
                        ? { backgroundColor: pkg.accentColor, color: C.slate }
                        : { color: pkg.accentColor, border: `1px solid ${pkg.accentColor}40` }}>
                      {cta.label}
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Sales-assisted row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {salesAssisted.map(pkg => {
              const cta = ctaFor(pkg);
              const price = priceFor(pkg);
              return (
                <div key={pkg.key} className="rounded-xl p-7 flex flex-col"
                  style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
                  {pkg.badge && (
                    <span className="inline-block self-start mb-3 text-[10px] font-semibold px-2.5 py-0.5 rounded-full"
                      style={{ backgroundColor: `${pkg.accentColor}20`, color: pkg.accentColor }}>
                      {pkg.badge}
                    </span>
                  )}
                  <h2 className="text-lg font-semibold mb-1" style={{ color: C.offWhite }}>{pkg.marketingName}</h2>
                  <p className="text-sm mb-5" style={{ color: C.muted }}>{pkg.subtitle}</p>
                  <ul className="space-y-2 mb-6 flex-1">
                    {pkg.reportFocus.map(f => (
                      <li key={f} className="flex items-start gap-2 text-sm" style={{ color: C.mutedLight }}>
                        <span className="mt-0.5" style={{ color: pkg.accentColor }}>&#x2713;</span> {f}
                      </li>
                    ))}
                  </ul>
                  <div className="border-t pt-4" style={{ borderColor: C.borderSubtle }}>
                    <p className="text-xs mb-3" style={{ color: C.muted }}>{price.note}</p>
                    <Link href={cta.href}
                      className="block w-full text-center px-5 py-2.5 rounded-lg text-sm font-medium transition-colors"
                      style={{ color: pkg.accentColor, border: `1px solid ${pkg.accentColor}40` }}>
                      {cta.label}
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Feature Comparison Table */}
      <section className="py-16" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-xl font-semibold text-center mb-8" style={{ color: C.offWhite }}>
            Funktionsvergleich
          </h2>
          <div className="overflow-x-auto rounded-xl" style={{ border: `1px solid ${C.borderSubtle}` }}>
            <table className="w-full text-sm" style={{ minWidth: '680px' }}>
              <thead>
                <tr style={{ backgroundColor: C.slateLight }}>
                  <th className="text-left py-3 px-5 font-medium" style={{ color: C.muted }}>Funktion</th>
                  {listedPackages.map(pkg => (
                    <th key={pkg.key} className="text-center py-3 px-3 font-medium text-xs"
                      style={{ color: pkg.accentColor }}>
                      {pkg.marketingName}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {FEATURES.map(({ label, support }, i) => (
                  <tr key={label} style={{ backgroundColor: i % 2 === 0 ? C.slate : `${C.slateLight}60` }}>
                    <td className="py-2.5 px-5 text-xs" style={{ color: C.mutedLight }}>{label}</td>
                    {listedPackages.map(pkg => (
                      <td key={pkg.key} className="text-center py-2.5 px-3">
                        {support[pkg.key] ? <Check /> : <Dash />}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Abo Details */}
      <section className="py-16">
        <div className="max-w-3xl mx-auto px-6">
          <h2 className="text-xl font-semibold text-center mb-8" style={{ color: C.offWhite }}>
            In jedem Abo enthalten
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              { title: 'Bis zu 30 Scan-Ziele', text: 'Domains, IP-Adressen, CIDR-Subnetze oder einzelne Hosts — flexibel kombinierbar.' },
              { title: 'Flexible Intervalle', text: 'Wöchentlich, monatlich oder quartalsweise — Sie bestimmen den Rhythmus.' },
              { title: '3 Re-Scans / Jahr', text: 'Nach der Behebung von Schwachstellen können Sie Nachscans beauftragen.' },
              { title: 'Manuelle Prüfung', text: 'Jeder Report wird vor Zustellung von einem Security-Analysten geprüft.' },
              { title: 'PDF per E-Mail', text: 'Reports werden automatisch an alle definierten Empfänger versandt.' },
              { title: '12 Monate Laufzeit', text: 'Jahresabo mit automatischer Verlängerung. Kündigung jederzeit zum Laufzeitende.' },
            ].map(item => (
              <div key={item.title} className="p-4 rounded-lg" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
                <h3 className="text-sm font-semibold mb-1" style={{ color: C.offWhite }}>{item.title}</h3>
                <p className="text-xs" style={{ color: C.muted }}>{item.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-2xl mx-auto px-6 text-center">
          <h2 className="text-2xl font-semibold mb-4" style={{ color: C.offWhite }}>
            Individuelles Angebot anfordern
          </h2>
          <p className="text-sm mb-8" style={{ color: C.muted }}>
            Schreiben Sie uns mit Ihren Domains und Anforderungen — wir erstellen
            Ihnen ein maßgeschneidertes Angebot innerhalb von 24 Stunden.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href="/contact"
              className="px-7 py-3 rounded-lg text-sm font-medium transition-all"
              style={{ backgroundColor: C.teal, color: C.slate }}>
              Angebot anfragen
            </Link>
            <Link href="/subscribe"
              className="px-7 py-3 rounded-lg text-sm font-medium transition-colors"
              style={{ color: C.muted, border: `1px solid ${C.borderSubtle}` }}>
              Oder direkt Abo starten
            </Link>
          </div>
          <p className="text-xs mt-6" style={{ color: C.muted }}>
            Fragen zu einem Paket oder laufenden Abo?{' '}
            <Link href="/contact" className="hover:underline" style={{ color: C.teal }}>
              Support &amp; Kontakt
            </Link>{' '}
            — Erstantwort innerhalb von 1 Werktag.
          </p>
        </div>
      </section>
    </main>
  );
}
