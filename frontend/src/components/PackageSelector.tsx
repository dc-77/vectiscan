'use client';

// VEC-289: Pakete + Anzeige-Daten stammen aus dem kanonischen Katalog (SSoT).
// VEC-431: Redesign nach Sellability-Typen (Design-Spec Rev 3, VEC-423).
import { PACKAGE_CATALOG, type PackageKey, type Sellability } from '@/lib/catalog.generated';

export type ScanPackage = PackageKey;

interface PackageInfo {
  key: ScanPackage;
  title: string;
  subtitle: string;
  reportFocus: string[];
  duration: string;
  hosts: string;
  sellability: Sellability;
  tier: 'quick' | 'perimeter';
  badge?: string;
  badgeColor?: string;
  accentColor: string;
}

// Nur im Kunden-Frontend gelistete Pakete anbieten (listed-Flag, SSoT). Nicht
// gelistete Pakete bleiben im Katalog erhalten, tauchen aber im Wizard nicht auf.
const PACKAGES: PackageInfo[] = PACKAGE_CATALOG.filter((pkg) => pkg.listed).map((pkg) => ({
  key: pkg.key,
  title: pkg.marketingName,
  subtitle: pkg.subtitle,
  reportFocus: pkg.reportFocus,
  duration: pkg.durationShort,
  hosts: String(pkg.maxHosts),
  sellability: pkg.sellability,
  tier: pkg.tier,
  badge: pkg.badge ?? undefined,
  badgeColor: pkg.badgeColor ?? undefined,
  accentColor: pkg.accentColor,
}));

// Reine UI-Microcopy (kein Katalog-Datum) — an die Sellability gebunden.
const ICONS: Record<string, string> = { webcheck: '⚡', perimeter: '🎯', insurance: '🛡️' };
const FREE_VALUE_STATEMENT = '✦ Einmaliger Gratis-Check · Kein Abo nötig';
const ON_REQUEST = '📞 Auf Anfrage';

// '15 Hosts' entfernt — maxHosts wird pro Karte angezeigt (VEC-348 Bug-Fix).
const SHARED_CAPABILITIES = [
  'Port-Analyse', 'Passive Aufklärung', 'Schwachstellen-Scan', 'Webserver-Analyse', 'Verzeichnis-Scan',
  'Skript-Injection-Test', 'Bedrohungsanalyse', 'KI-Korrelation',
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
        <path d="M2.5 6L5 8.5L9.5 3.5" stroke="var(--slate)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-dim)] shrink-0">
        {children}
      </span>
      <div className="flex-1 h-px bg-[var(--border-subtle)]" />
    </div>
  );
}

function Badge({ pkg }: { pkg: PackageInfo }) {
  if (!pkg.badge) return null;
  // Empfohlen-Badge der self_service-Karte bekommt einen Stern (Design Rev 3).
  const text = pkg.sellability === 'self_service' ? `★ ${pkg.badge}` : pkg.badge;
  return (
    <span
      data-testid={`badge-${pkg.key}`}
      className={`absolute -top-2.5 left-4 font-bold px-3 py-0.5 rounded-full ${
        pkg.sellability === 'self_service' ? 'text-sm px-4' : 'text-xs'
      }`}
      style={{ backgroundColor: pkg.badgeColor || pkg.accentColor, color: 'var(--slate)' }}
    >
      {text}
    </span>
  );
}

interface CardProps {
  pkg: PackageInfo;
  selected: ScanPackage;
  onSelect: (pkg: ScanPackage) => void;
  className?: string;
  children: React.ReactNode;
}

// Gemeinsame Karten-Hülle: States, Border, Selected-Glow, Keyboard-Nav (WCAG 2.4.7).
function PackageCard({ pkg, selected, onSelect, className = '', children }: CardProps) {
  const isSelected = selected === pkg.key;
  const borderColor = isSelected
    ? pkg.accentColor
    : pkg.sellability === 'self_service'
      ? `${pkg.accentColor}30` // Empfohlen-Karte: dezent getönter Rand auch unselektiert
      : 'var(--border-muted)';
  const dimmed = pkg.sellability === 'sales_assisted' && !isSelected;

  return (
    <div
      data-testid={`package-${pkg.key}`}
      role="button"
      tabIndex={0}
      aria-pressed={isSelected}
      aria-label={pkg.title}
      onClick={() => onSelect(pkg.key)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(pkg.key); } }}
      className={`relative rounded-xl p-4 cursor-pointer transition-all duration-200 bg-[var(--surface)] hover:bg-[var(--surface-2)] outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--teal)] focus-visible:outline-offset-2 ${className}`}
      style={{
        borderWidth: '2px',
        borderStyle: 'solid',
        borderColor,
        boxShadow: isSelected ? `0 0 28px ${pkg.accentColor}24` : 'none',
        opacity: dimmed ? 0.88 : 1,
      }}
    >
      {isSelected && <CheckCircle color={pkg.accentColor} />}
      <Badge pkg={pkg} />
      {children}
    </div>
  );
}

function MetaPills({ pkg }: { pkg: PackageInfo }) {
  return (
    <div className="flex items-center gap-2 shrink-0">
      <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-[var(--surface-inset)] text-[var(--text-muted)]">
        {pkg.duration}
      </span>
      <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-[var(--surface-inset)] text-[var(--text-muted)]">
        max {pkg.hosts} Hosts
      </span>
    </div>
  );
}

export default function PackageSelector({ selected, onSelect }: Props) {
  const freePkg = PACKAGES.find(p => p.sellability === 'free');
  const selfServicePkgs = PACKAGES.filter(p => p.sellability === 'self_service');
  const salesPkgs = PACKAGES.filter(p => p.sellability === 'sales_assisted');
  // 2er-Grid für die ersten beiden Sales-Pakete, Rest (Cyberversicherung) full-width.
  const salesGrid = salesPkgs.slice(0, 2);
  const salesWide = salesPkgs.slice(2);

  return (
    <div className="space-y-5" data-testid="package-selector">
      {/* ── Abschnitt A: Schnell-Check (free) ───────────────── */}
      {freePkg && (
        <>
          <SectionLabel>Schnell-Check</SectionLabel>
          <PackageCard pkg={freePkg} selected={selected} onSelect={onSelect}>
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <span className="text-2xl shrink-0 w-11 h-11 rounded-lg bg-[var(--surface-inset)] flex items-center justify-center">
                  {ICONS[freePkg.key]}
                </span>
                <div className="min-w-0">
                  <h3 className="text-[var(--text)] font-semibold text-base">{freePkg.title}</h3>
                  <p className="text-[var(--text-muted)] text-sm mt-0.5">{freePkg.subtitle}</p>
                  <p className="text-xs font-medium mt-1.5" style={{ color: 'var(--tone-success)' }}>
                    {FREE_VALUE_STATEMENT}
                  </p>
                </div>
              </div>
              <div className="sm:ml-auto">
                <MetaPills pkg={freePkg} />
              </div>
            </div>
          </PackageCard>
        </>
      )}

      {/* ── Abschnitt B: Full-Scan Pakete ───────────────────── */}
      <SectionLabel>Full-Scan Pakete</SectionLabel>

      {/* Shared Capabilities — alle Full-Scan-Varianten enthalten */}
      <div className="rounded-lg bg-[var(--surface)] border border-[var(--border-subtle)] px-3 py-2.5">
        <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-dim)] mb-1.5">
          Alle Full-Scan-Varianten enthalten
        </p>
        <div className="flex flex-wrap gap-1.5">
          {SHARED_CAPABILITIES.map((cap) => (
            <span key={cap} className="text-[11px] text-[var(--text-dim)] bg-[var(--surface-inset)] px-2 py-0.5 rounded">
              {cap}
            </span>
          ))}
        </div>
      </div>

      {/* self_service (Perimeter) — volle Breite, Empfohlen, Features */}
      {selfServicePkgs.map((pkg) => (
        <PackageCard key={pkg.key} pkg={pkg} selected={selected} onSelect={onSelect} className="pt-5">
          <div className="flex flex-col sm:flex-row sm:items-center gap-2.5">
            <div className="flex items-center gap-3 min-w-0">
              <span className="text-2xl shrink-0">{ICONS[pkg.key]}</span>
              <div className="min-w-0">
                <h3 className="text-[var(--text)] font-semibold text-base">{pkg.title}</h3>
                <p className="text-[var(--text-muted)] text-xs mt-0.5">{pkg.subtitle}</p>
              </div>
            </div>
            <div className="sm:ml-auto">
              <MetaPills pkg={pkg} />
            </div>
          </div>
          <ul className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-1.5">
            {pkg.reportFocus.map((item) => (
              <li
                key={item}
                className="text-xs text-[var(--text-muted)] pl-3"
                style={{ borderLeft: `2px solid ${pkg.accentColor}40` }}
              >
                {item}
              </li>
            ))}
          </ul>
        </PackageCard>
      ))}

      {/* sales_assisted — gedämpft, „Auf Anfrage" */}
      {salesPkgs.length > 0 && (
        <SectionLabel>mit Compliance-Nachweis</SectionLabel>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {salesGrid.map((pkg) => (
          <PackageCard key={pkg.key} pkg={pkg} selected={selected} onSelect={onSelect} className="pt-5">
            <h3 className="text-[var(--text)] font-semibold text-base">{pkg.title}</h3>
            <p className="text-[var(--text-muted)] text-xs mt-1">{pkg.subtitle}</p>
            <p className="text-sm font-medium mt-2.5" style={{ color: pkg.accentColor }}>
              {ON_REQUEST}
            </p>
          </PackageCard>
        ))}
      </div>
      {salesWide.map((pkg) => (
        <PackageCard key={pkg.key} pkg={pkg} selected={selected} onSelect={onSelect} className="pt-5">
          <div className="flex flex-col sm:flex-row sm:items-center gap-2">
            <div className="flex items-center gap-3 min-w-0">
              <span className="text-2xl shrink-0">{ICONS[pkg.key]}</span>
              <div className="min-w-0">
                <h3 className="text-[var(--text)] font-semibold text-base">{pkg.title}</h3>
                <p className="text-[var(--text-muted)] text-xs mt-0.5">{pkg.subtitle}</p>
              </div>
            </div>
            <p className="text-sm font-medium sm:ml-auto shrink-0" style={{ color: pkg.accentColor }}>
              {ON_REQUEST}
            </p>
          </div>
        </PackageCard>
      ))}
    </div>
  );
}
