import Link from 'next/link';

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

const FEATURES = [
  { name: 'Port-Scanning & Service-Erkennung', perimeter: true, insurance: true },
  { name: 'DNS-Enumeration & Subdomain-Analyse', perimeter: true, insurance: true },
  { name: 'Web-Schwachstellen-Scan (OWASP ZAP)', perimeter: true, insurance: true },
  { name: 'SSL/TLS-Konfigurationsanalyse', perimeter: true, insurance: true },
  { name: 'E-Mail-Security (SPF, DKIM, DMARC)', perimeter: true, insurance: true },
  { name: 'HTTP-Security-Header-Prüfung', perimeter: true, insurance: true },
  { name: 'KI-gestutzte Korrelation & FP-Filter', perimeter: true, insurance: true },
  { name: 'Executive Summary + Massnahmenplan', perimeter: true, insurance: true },
  { name: 'NIS2 / BSI-Compliance-Mapping', perimeter: true, insurance: true },
  { name: 'Threat Intelligence (NVD, EPSS, CISA KEV)', perimeter: true, insurance: true },
  { name: 'Versicherungs-Fragebogen (10 Punkte)', perimeter: false, insurance: true },
  { name: 'Risk-Score & Ransomware-Indikator', perimeter: false, insurance: true },
  { name: 'Versicherungskonformer Nachweis-Report', perimeter: false, insurance: true },
];

function Check() {
  return <span style={{ color: C.teal }}>&#x2713;</span>;
}
function Dash() {
  return <span style={{ color: `${C.muted}40` }}>—</span>;
}

export default function PricingPage() {
  return (
    <main className="flex-1">
      {/* Hero */}
      <section className="py-20 md:py-24">
        <div className="max-w-5xl mx-auto px-6 text-center">
          <h1 className="text-3xl md:text-4xl font-semibold mb-4" style={{ color: C.offWhite }}>
            Pakete &amp; Preise
          </h1>
          <p className="text-base max-w-2xl mx-auto" style={{ color: C.muted }}>
            Wählen Sie das passende Paket für Ihre Anforderungen.
            Bis zu 30 Domains pro Abo, automatische Scans, geprüfte Reports.
          </p>
        </div>
      </section>

      {/* Package Cards */}
      <section id="pakete" className="pb-16">
        <div className="max-w-4xl mx-auto px-6 grid grid-cols-1 md:grid-cols-2 gap-6">

          {/* Perimeter */}
          <div className="rounded-xl p-7 relative flex flex-col"
            style={{ backgroundColor: C.slateLight, border: `2px solid ${C.border}` }}>
            <span className="absolute -top-3 left-6 text-[10px] font-semibold px-3 py-1 rounded-full"
              style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>Empfohlen</span>
            <h2 className="text-xl font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>Perimeter-Scan</h2>
            <p className="text-sm mb-6" style={{ color: C.muted }}>
              Vollständige Sicherheitsanalyse Ihrer externen IT-Infrastruktur
            </p>
            <ul className="space-y-2.5 mb-8 flex-1">
              {['Bis zu 30 Domains / IPs / Subnetze', 'Wöchentliche, monatliche oder quartalsweise Scans',
                '3 Re-Scans pro Jahr inklusive', 'Manuelle Qualitätsprüfung jedes Reports',
                'PDF-Report per E-Mail an Ihr Team', 'NIS2 & BSI-Compliance-Mapping',
              ].map(f => (
                <li key={f} className="flex items-start gap-2 text-sm" style={{ color: C.mutedLight }}>
                  <span className="mt-0.5" style={{ color: C.teal }}>&#x2713;</span> {f}
                </li>
              ))}
            </ul>
            <div className="border-t pt-5" style={{ borderColor: C.borderSubtle }}>
              <p className="text-xs mb-4" style={{ color: C.muted }}>Jahresabo — Preis auf Anfrage</p>
              <Link href="mailto:kontakt@vectigal.gmbh?subject=Angebot%20Perimeter-Scan&body=Guten%20Tag%2C%0A%0Aich%20interessiere%20mich%20f%C3%BCr%20den%20VectiScan%20Perimeter-Scan.%0A%0AFirma%3A%20%0ADomains%3A%20%0A%0AMit%20freundlichen%20Gr%C3%BC%C3%9Fen"
                className="block w-full text-center px-5 py-3 rounded-lg text-sm font-medium transition-all"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
            </div>
          </div>

          {/* Insurance */}
          <div className="rounded-xl p-7 flex flex-col"
            style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
            <h2 className="text-xl font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>Cyberversicherung</h2>
            <p className="text-sm mb-6" style={{ color: C.muted }}>
              Nachweis-Report für Ihren Versicherungsantrag
            </p>
            <ul className="space-y-2.5 mb-8 flex-1">
              {['Alles aus dem Perimeter-Scan', '10-Punkte Versicherungs-Fragebogen',
                'Risk-Score & Ransomware-Indikator', 'Versicherungskonformer Nachweis',
                'Direkt einreichbar beim Versicherer', 'Regelmäßige Aktualisierung für Verlängerung',
              ].map(f => (
                <li key={f} className="flex items-start gap-2 text-sm" style={{ color: C.mutedLight }}>
                  <span className="mt-0.5" style={{ color: C.teal }}>&#x2713;</span> {f}
                </li>
              ))}
            </ul>
            <div className="border-t pt-5" style={{ borderColor: C.borderSubtle }}>
              <p className="text-xs mb-4" style={{ color: C.muted }}>Jahresabo — Preis auf Anfrage</p>
              <Link href="mailto:kontakt@vectigal.gmbh?subject=Angebot%20Cyberversicherung&body=Guten%20Tag%2C%0A%0Aich%20interessiere%20mich%20f%C3%BCr%20den%20VectiScan%20Cyberversicherungs-Report.%0A%0AFirma%3A%20%0ADomains%3A%20%0A%0AMit%20freundlichen%20Gr%C3%BC%C3%9Fen"
                className="block w-full text-center px-5 py-3 rounded-lg text-sm font-medium transition-colors"
                style={{ color: C.teal, border: `1px solid ${C.teal}40` }}>
                Angebot anfordern
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Comparison Table */}
      <section className="py-16" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-4xl mx-auto px-6">
          <h2 className="text-xl font-semibold text-center mb-8" style={{ color: C.offWhite }}>
            Funktionsvergleich
          </h2>
          <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${C.borderSubtle}` }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ backgroundColor: C.slateLight }}>
                  <th className="text-left py-3 px-5 font-medium" style={{ color: C.muted }}>Funktion</th>
                  <th className="text-center py-3 px-4 font-medium" style={{ color: C.teal }}>Perimeter</th>
                  <th className="text-center py-3 px-4 font-medium" style={{ color: C.teal }}>Versicherung</th>
                </tr>
              </thead>
              <tbody>
                {FEATURES.map((f, i) => (
                  <tr key={f.name} style={{ backgroundColor: i % 2 === 0 ? C.slate : `${C.slateLight}60` }}>
                    <td className="py-2.5 px-5 text-xs" style={{ color: C.mutedLight }}>{f.name}</td>
                    <td className="text-center py-2.5 px-4">{f.perimeter ? <Check /> : <Dash />}</td>
                    <td className="text-center py-2.5 px-4">{f.insurance ? <Check /> : <Dash />}</td>
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
              { title: 'PDF per E-Mail', text: 'Reports werden automatisch an alle definierten Empfaenger versandt.' },
              { title: '12 Monate Laufzeit', text: 'Jahresabo mit automatischer Verlaengerung. Kuendigung jederzeit zum Laufzeitende.' },
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
            <Link href="mailto:kontakt@vectigal.gmbh?subject=VectiScan%20Angebot&body=Guten%20Tag%2C%0A%0Aich%20interessiere%20mich%20f%C3%BCr%20VectiScan.%0A%0AFirma%3A%20%0ADomains%3A%20%0AGew%C3%BCnschtes%20Paket%3A%20%0A%0AMit%20freundlichen%20Gr%C3%BC%C3%9Fen"
              className="px-7 py-3 rounded-lg text-sm font-medium transition-all"
              style={{ backgroundColor: C.teal, color: C.slate }}>
              kontakt@vectigal.gmbh
            </Link>
            <Link href="/subscribe"
              className="px-7 py-3 rounded-lg text-sm font-medium transition-colors"
              style={{ color: C.muted, border: `1px solid ${C.borderSubtle}` }}>
              Oder direkt Abo starten
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
