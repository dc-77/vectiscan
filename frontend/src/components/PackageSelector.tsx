'use client';

export type ScanPackage = 'basic' | 'professional' | 'nis2';

interface Feature {
  name: string;
  basic: boolean | string;
  professional: boolean | string;
  nis2: boolean | string;
}

const FEATURES: Feature[] = [
  { name: 'Port-Scan',                        basic: true,  professional: true,  nis2: true },
  { name: 'SSL/TLS-Analyse',                  basic: true,  professional: true,  nis2: true },
  { name: 'Security-Header-Check',            basic: true,  professional: true,  nis2: true },
  { name: 'CMS-/Framework-Erkennung',         basic: true,  professional: true,  nis2: true },
  { name: 'Screenshot',                       basic: true,  professional: true,  nis2: true },
  { name: 'DNS-Reconnaissance (vollständig)', basic: false, professional: true,  nis2: true },
  { name: 'Vulnerability-Scan (Nuclei)',      basic: false, professional: true,  nis2: true },
  { name: 'Web-Vulnerability-Scan (Nikto)',   basic: false, professional: true,  nis2: true },
  { name: 'Directory-Bruteforce',             basic: false, professional: true,  nis2: true },
  { name: 'CVSS v3.1 Scoring',               basic: false, professional: true,  nis2: true },
  { name: '§30 BSIG Compliance-Mapping',      basic: false, professional: false, nis2: true },
  { name: 'NIS2 Audit-Trail',                 basic: false, professional: false, nis2: true },
  { name: 'Lieferketten-Zusammenfassung',     basic: false, professional: false, nis2: true },
  { name: 'Max. Hosts',                       basic: '5',   professional: '10',  nis2: '10' },
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
    key: 'basic',
    title: 'Basic',
    description: 'Schneller Überblick über die wichtigsten Sicherheitsaspekte.',
    duration: '~10 Min',
    accentColor: '#38BDF8',
  },
  {
    key: 'professional',
    title: 'Professional',
    description: 'Vollständige Sicherheitsbewertung mit allen Scan-Tools.',
    duration: '~45 Min',
    badge: 'Empfohlen',
    badgeColor: '#38BDF8',
    accentColor: '#38BDF8',
  },
  {
    key: 'nis2',
    title: 'NIS2 Compliance',
    description: 'Pro-Scan mit §30 BSIG-Mapping und Audit-Trail.',
    duration: '~45 Min',
    badge: 'NIS2-konform',
    badgeColor: '#EAB308',
    accentColor: '#EAB308',
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
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4" data-testid="package-selector">
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
