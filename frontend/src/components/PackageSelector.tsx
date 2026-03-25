'use client';

export type ScanPackage = 'webcheck' | 'perimeter' | 'compliance' | 'supplychain' | 'insurance' | 'tlscompliance';

interface PackageInfo {
  key: ScanPackage;
  title: string;
  subtitle: string;
  reportFocus: string[];
  duration: string;
  hosts: string;
  tier: 'quick' | 'perimeter';
  badge?: string;
  badgeColor?: string;
  accentColor: string;
}

const PACKAGES: PackageInfo[] = [
  {
    key: 'webcheck',
    title: 'WebCheck',
    subtitle: 'SSL, Headers, CMS, E-Mail-Schutz — kompakter Report mit Ampel',
    reportFocus: ['Top-100-Port-Scan', 'Mail-Security (SPF/DMARC/DKIM)', 'Ampelbewertung'],
    duration: '~15–20 Min',
    hosts: '3',
    tier: 'quick',
    accentColor: '#38BDF8',
  },
  {
    key: 'tlscompliance',
    title: 'TLS-Compliance',
    subtitle: 'BSI TR-03116-4 Prüfung mit Compliance-Bescheinigung und Checklisten.',
    reportFocus: ['TLS-Versionen & Cipher', 'Zertifikats-Prüfung', 'Checkliste für interne Punkte'],
    duration: '~5–10 Min',
    hosts: '15',
    tier: 'quick',
    badge: 'BSI',
    badgeColor: '#16A34A',
    accentColor: '#16A34A',
  },
  {
    key: 'perimeter',
    title: 'PerimeterScan',
    subtitle: 'Vollständige Angriffsflächen-Analyse mit priorisiertem Maßnahmenplan.',
    reportFocus: ['PTES-konformer Report', 'Executive Summary', 'Priorisierte Maßnahmen'],
    duration: '~60–90 Min',
    hosts: '15',
    tier: 'perimeter',
    badge: 'Empfohlen',
    badgeColor: '#38BDF8',
    accentColor: '#38BDF8',
  },
  {
    key: 'compliance',
    title: 'ComplianceScan',
    subtitle: 'Perimeter-Scan mit NIS2-Compliance-Nachweis.',
    reportFocus: ['§30 BSIG-Mapping', 'BSI-Grundschutz-Refs', 'Audit-Trail'],
    duration: '~65–95 Min',
    hosts: '15',
    tier: 'perimeter',
    badge: 'NIS2',
    badgeColor: '#EAB308',
    accentColor: '#EAB308',
  },
  {
    key: 'supplychain',
    title: 'SupplyChain',
    subtitle: 'Sicherheitsnachweis für NIS2-pflichtige Auftraggeber.',
    reportFocus: ['ISO 27001 Annex A', 'Lieferanten-Nachweis', 'Auftraggeber-Kapitel'],
    duration: '~65–95 Min',
    hosts: '15',
    tier: 'perimeter',
    badge: 'ISO 27001',
    badgeColor: '#A78BFA',
    accentColor: '#A78BFA',
  },
  {
    key: 'insurance',
    title: 'InsuranceReport',
    subtitle: 'Nachweis für Cyberversicherung mit Risikobewertung.',
    reportFocus: ['10-Punkte Fragebogen', 'Risk-Score', 'Ransomware-Indikator'],
    duration: '~65–95 Min',
    hosts: '15',
    tier: 'perimeter',
    badge: 'Versicherung',
    badgeColor: '#34D399',
    accentColor: '#34D399',
  },
];

const SHARED_CAPABILITIES = [
  'Nmap Top-1000', 'Passive Intel', 'Nuclei', 'Nikto', 'ffuf',
  'XSS-Scanner', 'Threat-Intel', 'Korrelation', '15 Hosts',
];

interface Props {
  selected: ScanPackage;
  onSelect: (pkg: ScanPackage) => void;
}

function CheckCircle({ color }: { color: string }) {
  return (
    <span
      className="absolute top-3 right-3 w-5 h-5 rounded-full flex items-center justify-center"
      style={{ backgroundColor: color }}
    >
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <path d="M2.5 6L5 8.5L9.5 3.5" stroke="#0F172A" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

export default function PackageSelector({ selected, onSelect }: Props) {
  const quickPkgs = PACKAGES.filter(p => p.tier === 'quick');
  const perimeterPkgs = PACKAGES.filter(p => p.tier === 'perimeter');

  return (
    <div className="space-y-5" data-testid="package-selector">
      {/* ── Tier 1: Quick Scans ────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {quickPkgs.map((pkg) => {
          const isSelected = selected === pkg.key;
          const borderColor = isSelected ? pkg.accentColor : '#334155';
          return (
            <div
              key={pkg.key}
              data-testid={`package-${pkg.key}`}
              onClick={() => onSelect(pkg.key)}
              className="relative w-full rounded-xl p-4 cursor-pointer transition-all duration-200 bg-[#1E293B] hover:bg-[#253347]"
              style={{
                borderWidth: '2px',
                borderStyle: 'solid',
                borderColor,
                boxShadow: isSelected ? `0 0 20px ${pkg.accentColor}20` : 'none',
              }}
            >
              {isSelected && <CheckCircle color={pkg.accentColor} />}
              {pkg.badge && (
                <span
                  className="absolute -top-2.5 left-4 text-xs font-bold px-3 py-0.5 rounded-full"
                  style={{ backgroundColor: pkg.badgeColor || pkg.accentColor, color: '#0F172A' }}
                >
                  {pkg.badge}
                </span>
              )}
              <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-2xl shrink-0">&#9889;</span>
                  <div className="min-w-0">
                    <h3 className="text-white font-semibold text-base">{pkg.title}</h3>
                    <p className="text-[#94A3B8] text-sm mt-0.5">{pkg.subtitle}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 sm:ml-auto shrink-0">
                  <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-[#334155] text-[#94A3B8]">
                    {pkg.duration}
                  </span>
                  <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-[#334155] text-[#94A3B8]">
                    max {pkg.hosts} Hosts
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Divider ─────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="flex-1 h-px bg-[#1E3A5F]" />
        <span className="text-[10px] font-mono uppercase tracking-widest text-[#475569]">
          Full Perimeter Scan
        </span>
        <div className="flex-1 h-px bg-[#1E3A5F]" />
      </div>
      <p className="text-center text-xs text-[#64748B] -mt-3">
        Alle 4 Varianten scannen identisch — der Report-Typ macht den Unterschied.
      </p>

      {/* ── Shared Capabilities ─────────────────────────────── */}
      <div className="flex flex-wrap gap-1.5 justify-center">
        {SHARED_CAPABILITIES.map((cap) => (
          <span key={cap} className="text-[11px] text-[#64748B] bg-[#0F172A] px-2 py-0.5 rounded">
            {cap}
          </span>
        ))}
      </div>

      {/* ── Tier 2: Perimeter Variants (2×2 Grid) ──────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {perimeterPkgs.map((pkg) => {
          const isSelected = selected === pkg.key;
          const borderColor = isSelected ? pkg.accentColor : (pkg.key === 'perimeter' ? `${pkg.accentColor}30` : '#334155');

          return (
            <div
              key={pkg.key}
              data-testid={`package-${pkg.key}`}
              onClick={() => onSelect(pkg.key)}
              className="relative rounded-xl p-4 cursor-pointer transition-all duration-200 bg-[#1E293B] hover:bg-[#253347]"
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
                  className={`absolute -top-2.5 left-4 font-bold px-3 py-0.5 rounded-full ${
                    pkg.key === 'perimeter' ? 'text-sm px-4' : 'text-xs'
                  }`}
                  style={{ backgroundColor: pkg.badgeColor, color: '#0F172A' }}
                  data-testid={`badge-${pkg.key}`}
                >
                  {pkg.badge}
                </span>
              )}

              {/* Check circle */}
              {isSelected && <CheckCircle color={pkg.accentColor} />}

              {/* Content */}
              <div className="mt-2">
                <h3 className="text-white font-semibold text-base">{pkg.title}</h3>
                <p className="text-[#94A3B8] text-xs mt-1">{pkg.subtitle}</p>

                {/* Duration + Hosts */}
                <div className="flex items-center gap-2 mt-2.5">
                  <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-[#334155] text-[#94A3B8]">
                    {pkg.duration}
                  </span>
                  <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-[#334155] text-[#94A3B8]">
                    max {pkg.hosts} Hosts
                  </span>
                </div>

                {/* Report Focus Bullets */}
                <ul className="mt-3 space-y-1">
                  {pkg.reportFocus.map((item) => (
                    <li
                      key={item}
                      className="text-xs text-[#CBD5E1] pl-3"
                      style={{ borderLeft: `2px solid ${pkg.accentColor}40` }}
                    >
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
