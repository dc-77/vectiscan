import Link from 'next/link';

/* ── Brand Colors ────────────────────────────────────────── */
const C = {
  slate: '#0F172A',
  slateLight: '#1E293B',
  teal: '#2DD4BF',
  tealDark: '#14B8A6',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
  border: 'rgba(45,212,191,0.12)',
  borderSubtle: 'rgba(30,58,95,0.35)',
};

/* ── Shield SVG (Hero visual) ──────────────────────────── */
function ShieldGraphic() {
  return (
    <svg width="280" height="280" viewBox="0 0 280 280" fill="none" className="opacity-20">
      <path d="M140 20L30 65v75c0 70 48 118 110 130 62-12 110-60 110-130V65L140 20z"
        fill="none" stroke={C.teal} strokeWidth="1.5" />
      <path d="M140 50L55 85v55c0 55 38 93 85 102 47-9 85-47 85-102V85L140 50z"
        fill="none" stroke={C.teal} strokeWidth="0.75" opacity="0.4" />
      <line x1="80" y1="140" x2="200" y2="140" stroke={C.teal} strokeWidth="0.75" opacity="0.3" />
      <line x1="140" y1="80" x2="140" y2="200" stroke={C.teal} strokeWidth="0.75" opacity="0.3" />
      <circle cx="140" cy="140" r="4" fill={C.teal} opacity="0.5" />
      {/* Scan lines */}
      {[100, 120, 160, 180].map(y => (
        <line key={y} x1="90" y1={y} x2="190" y2={y} stroke={C.teal} strokeWidth="0.5" opacity="0.15" />
      ))}
    </svg>
  );
}

/* ── Pain Point Card ───────────────────────────────────── */
function PainCard({ icon, title, text }: { icon: string; title: string; text: string }) {
  return (
    <div className="p-6 rounded-xl" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
      <div className="text-2xl mb-3">{icon}</div>
      <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
      <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{text}</p>
    </div>
  );
}

/* ── Feature Card ──────────────────────────────────────── */
function FeatureCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="p-5 rounded-lg" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
      <div className="w-1.5 h-1.5 rounded-full mb-3" style={{ backgroundColor: C.teal }} />
      <h4 className="text-sm font-semibold mb-1.5" style={{ color: C.offWhite }}>{title}</h4>
      <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{text}</p>
    </div>
  );
}

/* ── Step Card ─────────────────────────────────────────── */
function StepCard({ num, title, text }: { num: number; title: string; text: string }) {
  return (
    <div className="flex-1 text-center p-5">
      <div className="w-10 h-10 rounded-full mx-auto mb-3 flex items-center justify-center text-sm font-semibold"
        style={{ backgroundColor: `${C.teal}15`, color: C.teal, border: `1px solid ${C.teal}30` }}>
        {num}
      </div>
      <h4 className="text-sm font-semibold mb-1" style={{ color: C.offWhite }}>{title}</h4>
      <p className="text-xs" style={{ color: C.muted }}>{text}</p>
    </div>
  );
}

/* ── Main Landing Page ─────────────────────────────────── */
export default function LandingPage() {
  return (
    <main className="flex-1">

      {/* ── Hero ──────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div className="max-w-5xl mx-auto px-6 py-24 md:py-32 flex flex-col items-center text-center">
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <ShieldGraphic />
          </div>
          <div className="relative z-10">
            <h1 className="text-3xl md:text-5xl font-semibold leading-tight tracking-tight mb-6"
              style={{ color: C.offWhite }}>
              Kennen Sie Ihre<br />
              <span style={{ color: C.teal }}>Angriffsoberflache</span>?
            </h1>
            <p className="text-base md:text-lg max-w-2xl mx-auto mb-10 leading-relaxed"
              style={{ color: C.muted }}>
              VectiScan analysiert Ihre gesamte IT-Infrastruktur automatisiert auf Schwachstellen.
              Regelmaessig, zuverlassig und nach anerkannten Standards — damit Sie wissen,
              wo Sie stehen, bevor es ein Angreifer tut.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing"
                className="px-7 py-3 rounded-lg text-sm font-medium transition-all"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/pricing#pakete"
                className="px-7 py-3 rounded-lg text-sm font-medium transition-colors"
                style={{ color: C.teal, border: `1px solid ${C.teal}40` }}>
                Pakete vergleichen
              </Link>
            </div>
          </div>
        </div>

        {/* Trust Bar */}
        <div className="border-t border-b py-4" style={{ borderColor: C.borderSubtle }}>
          <div className="max-w-4xl mx-auto flex flex-wrap items-center justify-center gap-x-8 gap-y-2 px-6">
            {['BSI-konform', 'PTES-Standard', 'CVSS v3.1', 'DSGVO-konform', 'Hosting in Deutschland'].map(t => (
              <span key={t} className="text-xs font-medium tracking-wide uppercase" style={{ color: C.muted }}>{t}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pain Section ──────────────────────────────── */}
      <section className="py-20 md:py-24">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>
            Wissen Sie, wie angreifbar Ihr Unternehmen ist?
          </h2>
          <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
            Die meisten Unternehmen kennen nur einen Bruchteil ihrer exponierten Systeme.
            Angreifer kennen sie alle.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <PainCard
              icon="&#x1F50D;"
              title="Unbekannte Angriffsoberflache"
              text="Vergessene Subdomains, Testserver, offene Ports — Ihre IT-Landschaft ist groesser als Sie denken. Jeder exponierte Dienst ist ein potenzielles Einfallstor."
            />
            <PainCard
              icon="&#x26A0;"
              title="Veraltete Software"
              text="End-of-Life Betriebssysteme, fehlende Patches, bekannte CVEs — Schwachstellen die seit Monaten oeffentlich dokumentiert sind und aktiv ausgenutzt werden."
            />
            <PainCard
              icon="&#x1F4CB;"
              title="Compliance-Druck"
              text="NIS2, BSI-Grundschutz, Cyberversicherungen — alle fordern regelmaessige Nachweise Ihrer IT-Sicherheit. Ohne belastbare Dokumentation wird es teuer."
            />
          </div>
        </div>
      </section>

      {/* ── Features Section ──────────────────────────── */}
      <section className="py-20 md:py-24" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>
            Automatisierte Security-Analyse.<br />Regelmaessig. Zuverlassig.
          </h2>
          <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
            VectiScan kombiniert etablierte Open-Source-Scanner mit KI-gestutzter
            Analyse zu einem vollautomatisierten Security-Assessment.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <FeatureCard
              title="Perimeter-Analyse"
              text="Port-Scanning, DNS-Enumeration, Web-Schwachstellen, SSL/TLS-Pruefung — ueber 15 spezialisierte Scanner analysieren Ihre gesamte Angriffsoberflache."
            />
            <FeatureCard
              title="KI-gestutzte Bewertung"
              text="Intelligente Korrelation uber Tool-Grenzen hinweg. False-Positive-Filterung und kontextbezogene Risikobewertung nach CVSS v3.1."
            />
            <FeatureCard
              title="Professionelle Reports"
              text="Executive Summary fur die Geschaeftsleitung, technische Details fur Ihr IT-Team, priorisierter Massnahmenplan mit konkreten Handlungsempfehlungen."
            />
            <FeatureCard
              title="Automatische Wiederholung"
              text="Woechentliche, monatliche oder quartalsweise Scans — Sie definieren den Rhythmus, wir liefern zuverlaessig aktuelle Ergebnisse."
            />
            <FeatureCard
              title="Compliance-Nachweise"
              text="Mappings auf NIS2 (§30 BSIG), BSI-Grundschutz, ISO 27001 und Cyberversicherungs-Anforderungen — direkt im Report."
            />
            <FeatureCard
              title="Qualitaetsgesichert"
              text="Jeder Report wird vor der Zustellung manuell geprueft. False Positives werden markiert, Befunde validiert — keine automatisierten Fehlalarme."
            />
          </div>
        </div>
      </section>

      {/* ── Packages Preview ──────────────────────────── */}
      <section className="py-20 md:py-24">
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>
            Zwei Pakete. Ein Ziel: Ihre Sicherheit.
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Perimeter */}
            <div className="rounded-xl p-6 relative" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.border}` }}>
              <span className="absolute -top-2.5 left-5 text-[10px] font-semibold px-2.5 py-0.5 rounded-full"
                style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>Empfohlen</span>
              <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>Perimeter-Scan</h3>
              <p className="text-xs mb-4" style={{ color: C.muted }}>Vollstaendige Sicherheitsanalyse Ihrer externen Angriffsoberflache</p>
              <ul className="space-y-2 mb-5">
                {['Port-Scanning & Service-Erkennung', 'Web-Schwachstellen-Analyse (OWASP)', 'DNS- & E-Mail-Security-Pruefung', 'PTES-konformer Report mit Massnahmenplan', 'NIS2/BSI-Compliance-Mapping'].map(f => (
                  <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}>
                    <span style={{ color: C.teal }} className="mt-0.5">&#x2713;</span> {f}
                  </li>
                ))}
              </ul>
              <p className="text-xs font-medium" style={{ color: C.muted }}>Preis auf Anfrage</p>
            </div>

            {/* Insurance */}
            <div className="rounded-xl p-6" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
              <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>Cyberversicherung</h3>
              <p className="text-xs mb-4" style={{ color: C.muted }}>Nachweis und Dokumentation fuer Ihren Versicherungsantrag</p>
              <ul className="space-y-2 mb-5">
                {['Alles aus dem Perimeter-Scan', '10-Punkte Versicherungs-Fragebogen', 'Risk-Score & Ransomware-Indikator', 'Versicherungskonformer Nachweis-Report', 'Direkt einreichbar bei Ihrem Versicherer'].map(f => (
                  <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}>
                    <span style={{ color: C.teal }} className="mt-0.5">&#x2713;</span> {f}
                  </li>
                ))}
              </ul>
              <p className="text-xs font-medium" style={{ color: C.muted }}>Preis auf Anfrage</p>
            </div>
          </div>
          <div className="text-center mt-8">
            <Link href="/pricing"
              className="text-sm font-medium transition-colors"
              style={{ color: C.teal }}>
              Alle Details und Preise vergleichen &#8594;
            </Link>
          </div>
        </div>
      </section>

      {/* ── How It Works ──────────────────────────────── */}
      <section className="py-20 md:py-24" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>
            So funktioniert&apos;s
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            <StepCard num={1} title="Ziele definieren" text="Domains, IPs oder Subnetze — bis zu 5 Ziele pro Abo" />
            <StepCard num={2} title="Automatisch scannen" text="Regelmaessige Scans im gewaehlten Intervall" />
            <StepCard num={3} title="Report erhalten" text="Gepruefter PDF-Report per E-Mail" />
            <StepCard num={4} title="Massnahmen umsetzen" text="Priorisierter Plan mit konkreten Schritten" />
          </div>
        </div>
      </section>

      {/* ── Trust Section ─────────────────────────────── */}
      <section className="py-16">
        <div className="max-w-4xl mx-auto px-6">
          <p className="text-xs text-center uppercase tracking-widest mb-6" style={{ color: C.muted }}>
            Standards &amp; Technologie
          </p>
          <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
            {['OWASP ZAP', 'Nmap', 'Nuclei', 'testssl.sh', 'Claude AI', 'PTES', 'CVSS v3.1', 'BSI TR-03116-4'].map(t => (
              <span key={t} className="text-xs font-mono" style={{ color: `${C.muted}90` }}>{t}</span>
            ))}
          </div>
          <p className="text-center mt-6 text-xs" style={{ color: C.muted }}>
            Made in Germany — Entwicklung und Hosting in Deutschland
          </p>
        </div>
      </section>

      {/* ── Final CTA ─────────────────────────────────── */}
      <section className="py-20 md:py-24">
        <div className="max-w-2xl mx-auto px-6 text-center">
          <h2 className="text-2xl md:text-3xl font-semibold mb-4" style={{ color: C.offWhite }}>
            Bereit fuer Ihren ersten Security-Scan?
          </h2>
          <p className="text-sm mb-8" style={{ color: C.muted }}>
            Lassen Sie sich ein individuelles Angebot erstellen — oder starten Sie direkt.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href="/pricing"
              className="px-7 py-3 rounded-lg text-sm font-medium transition-all"
              style={{ backgroundColor: C.teal, color: C.slate }}>
              Angebot anfordern
            </Link>
            <Link href="/subscribe"
              className="px-7 py-3 rounded-lg text-sm font-medium transition-colors"
              style={{ color: C.muted, border: `1px solid ${C.borderSubtle}` }}>
              Direkt Abo starten
            </Link>
          </div>
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────── */}
      <footer className="border-t py-8 px-6" style={{ borderColor: C.borderSubtle }}>
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold" style={{ color: C.muted }}>vectigal</span>
            <span className="text-xs" style={{ color: C.teal }}>.</span>
            <span className="text-xs font-semibold" style={{ color: C.teal }}>ai</span>
          </div>
          <div className="flex items-center gap-6">
            <a href="mailto:kontakt@vectigal.gmbh" className="text-xs transition-colors" style={{ color: C.muted }}>Kontakt</a>
            <a href="/impressum" className="text-xs transition-colors" style={{ color: C.muted }}>Impressum</a>
            <a href="/datenschutz" className="text-xs transition-colors" style={{ color: C.muted }}>Datenschutz</a>
          </div>
          <p className="text-xs" style={{ color: `${C.muted}60` }}>&copy; 2026 Vectigal GmbH</p>
        </div>
      </footer>
    </main>
  );
}
