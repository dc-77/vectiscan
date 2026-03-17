'use client';

export type ScanPackage = 'webcheck' | 'perimeter' | 'compliance' | 'supplychain' | 'insurance';

interface Feature {
  name: string;
  webcheck: boolean | string;
  perimeter: boolean | string;
  compliance: boolean | string;
  supplychain: boolean | string;
  insurance: boolean | string;
}

const FEATURES: Feature[] = [
  { name: 'Port-Scan',                        webcheck: 'Top 100', perimeter: 'Top 1000', compliance: 'Top 1000', supplychain: 'Top 1000', insurance: 'Top 1000' },
  { name: 'SSL/TLS-Analyse',                  webcheck: true,  perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Security-Header-Check',            webcheck: true,  perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'CMS-Fingerprinting',               webcheck: true,  perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Screenshot',                       webcheck: true,  perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Passive Intelligence (Shodan)',     webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'DNS-Reconnaissance (vollständig)', webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Vulnerability-Scan (Nuclei)',      webcheck: 'High/Crit', perimeter: 'Alle', compliance: 'Alle', supplychain: 'Alle', insurance: 'Alle' },
  { name: 'Web-Vulnerability-Scan (Nikto)',   webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Directory-/Fuzzing (ffuf)',        webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'XSS-Scanner (dalfox)',             webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Threat-Intelligence (EPSS/KEV)',   webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'Cross-Tool-Korrelation',           webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: 'CVSS v3.1 Scoring',               webcheck: false, perimeter: true,  compliance: true,  supplychain: true,  insurance: true },
  { name: '§30 BSIG Compliance-Mapping',      webcheck: false, perimeter: false, compliance: true,  supplychain: false, insurance: false },
  { name: 'ISO 27001 Mapping',                webcheck: false, perimeter: false, compliance: false, supplychain: true,  insurance: false },
  { name: 'Versicherungs-Fragebogen',         webcheck: false, perimeter: false, compliance: false, supplychain: false, insurance: true },
  { name: 'Max. Hosts',                       webcheck: '3',   perimeter: '15',  compliance: '15',  supplychain: '15',  insurance: '15' },
];

interface PackageInfo {
  key: ScanPackage;
  title: string;
  description: string;
  duration: string;
  badge?: string;
  badgeColor?: string;
  accentColor: string;
}

const PACKAGES: PackageInfo[] = [
  {
    key: 'webcheck',
    title: 'WebCheck',
    description: 'Website-Sicherheit, SSL/TLS, E-Mail-Schutz (SPF/DMARC/DKIM) und CMS-Check. Kompakter Report mit Ampelbewertung.',
    duration: '~15–20 Min',
    accentColor: '#38BDF8',
  },
  {
    key: 'perimeter',
    title: 'PerimeterScan',
    description: 'Vollständige Angriffsflächen-Analyse: Passive Intelligence, Deep Vulnerability Scan, Directory-Fuzzing und Threat-Intelligence-Enrichment.',
    duration: '~60–90 Min',
    badge: 'Empfohlen',
    badgeColor: '#38BDF8',
    accentColor: '#38BDF8',
  },
  {
    key: 'compliance',
    title: 'ComplianceScan',
    description: 'Perimeter-Scan mit §30 BSIG-Mapping, BSI-Grundschutz-Referenzen und NIS2-Compliance-Summary. Inkl. Audit-Trail.',
    duration: '~65–95 Min',
    badge: 'NIS2',
    badgeColor: '#EAB308',
    accentColor: '#EAB308',
  },
  {
    key: 'supplychain',
    title: 'SupplyChain',
    description: 'Perimeter-Scan mit ISO 27001 Annex A Mapping und Sicherheitsnachweis-Kapitel für NIS2-pflichtige Auftraggeber.',
    duration: '~65–95 Min',
    badge: 'ISO 27001',
    badgeColor: '#A78BFA',
    accentColor: '#A78BFA',
  },
  {
    key: 'insurance',
    title: 'InsuranceReport',
    description: 'Perimeter-Scan mit Versicherungs-Fragebogen (10 Prüfpunkte), Risk-Score und Ransomware-Indikator. Zeigt prämienrelevante Maßnahmen.',
    duration: '~65–95 Min',
    badge: 'Versicherung',
    badgeColor: '#34D399',
    accentColor: '#34D399',
  },
];

interface Props {
  selected: ScanPackage;
  onSelect: (pkg: ScanPackage) => void;
}

function FeatureIcon({ value }: { value: boolean | string }) {
  if (typeof value === 'string') {
    return <span className="text-white font-medium text-sm">{value}</span>;
  }
  if (value) {
    return <span className="text-[#22C55E]" aria-label="included">✓</span>;
  }
  return <span className="text-[#475569]" aria-label="not included">—</span>;
}

export default function PackageSelector({ selected, onSelect }: Props) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4" data-testid="package-selector">
      {PACKAGES.map((pkg) => {
        const isSelected = selected === pkg.key;
        const borderColor = isSelected ? pkg.accentColor : '#334155';

        return (
          <div
            key={pkg.key}
            data-testid={`package-${pkg.key}`}
            onClick={() => onSelect(pkg.key)}
            className="relative rounded-xl p-5 cursor-pointer transition-all duration-200 bg-[#1E293B] hover:bg-[#253347]"
            style={{
              borderWidth: '2px',
              borderStyle: 'solid',
              borderColor,
              boxShadow: isSelected ? `0 0 20px ${pkg.accentColor}20` : 'none',
            }}
          >
            {/* Badge */}
            {pkg.badge && (
              <span
                className="absolute -top-3 left-4 text-xs font-bold px-3 py-0.5 rounded-full"
                style={{
                  backgroundColor: pkg.badgeColor,
                  color: '#0F172A',
                }}
                data-testid={`badge-${pkg.key}`}
              >
                {pkg.badge}
              </span>
            )}

            {/* Header */}
            <div className="mb-3 mt-1">
              <h3 className="text-white font-semibold text-lg">{pkg.title}</h3>
              <p className="text-[#94A3B8] text-sm mt-1">{pkg.description}</p>
            </div>

            {/* Duration Badge */}
            <span className="inline-block text-xs font-medium px-2.5 py-1 rounded-full bg-[#334155] text-[#94A3B8] mb-4">
              {pkg.duration}
            </span>

            {/* Feature List */}
            <ul className="space-y-1.5 mb-4">
              {FEATURES.map((f) => (
                <li key={f.name} className="flex items-center justify-between text-sm">
                  <span className="text-[#94A3B8] truncate mr-2">{f.name}</span>
                  <FeatureIcon value={f[pkg.key]} />
                </li>
              ))}
            </ul>

            {/* Select Button */}
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onSelect(pkg.key); }}
              className="w-full py-2 rounded-lg text-sm font-medium transition-colors"
              style={{
                backgroundColor: isSelected ? pkg.accentColor : 'transparent',
                color: isSelected ? '#0F172A' : pkg.accentColor,
                borderWidth: '1px',
                borderStyle: 'solid',
                borderColor: pkg.accentColor,
              }}
            >
              {isSelected ? 'Ausgewählt' : 'Scan starten'}
            </button>
          </div>
        );
      })}
    </div>
  );
}
