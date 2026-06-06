#!/usr/bin/env node
/**
 * VEC-289 — Codegen fuer den kanonischen Paket-Katalog.
 *
 * SSoT ist `catalog/packages.catalog.json`. Da `frontend/` und `api/` getrennte
 * Docker-Build-Kontexte sind (kein gemeinsames Laufzeit-Modul moeglich), wird die
 * Katalog-Wahrheit in je ein selbst-enthaltenes TS-Modul pro Service generiert:
 *   - api/src/lib/catalog.generated.ts
 *   - frontend/src/lib/catalog.generated.ts
 *
 * Beide Dateien sind inhaltlich identisch und werden eingecheckt. Ein Drift-Guard
 * (api/src/__tests__/catalog.parity.test.ts) ruft `renderCatalogModule()` und
 * vergleicht das Ergebnis mit den eingecheckten Dateien — divergiert etwas, faellt
 * der Test. So bleibt die JSON die EINZIGE Wahrheit.
 *
 * Nutzung:  node scripts/gen-catalog.js        (schreibt beide Dateien)
 *           node scripts/gen-catalog.js --check (faellt mit Exit 1 bei Drift)
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SSOT_PATH = path.join(ROOT, 'catalog', 'packages.catalog.json');
const TARGETS = [
  path.join(ROOT, 'api', 'src', 'lib', 'catalog.generated.ts'),
  path.join(ROOT, 'frontend', 'src', 'lib', 'catalog.generated.ts'),
];

/** Laedt + validiert die SSoT-JSON. */
function loadCatalog() {
  const raw = JSON.parse(fs.readFileSync(SSOT_PATH, 'utf8'));
  const packages = raw.packages;
  if (!Array.isArray(packages) || packages.length === 0) {
    throw new Error('packages.catalog.json: `packages` muss ein nicht-leeres Array sein');
  }
  const keys = packages.map((p) => p.key);
  if (new Set(keys).size !== keys.length) {
    throw new Error('packages.catalog.json: doppelte Paket-Keys');
  }
  return raw;
}

/** Erzeugt den Inhalt des generierten TS-Moduls (pure, deterministisch). */
function renderCatalogModule(catalog) {
  const keys = catalog.packages.map((p) => p.key);
  const keyUnion = keys.map((k) => `'${k}'`).join(' | ');
  const data = JSON.stringify(catalog.packages, null, 2);
  return `// ⚠️  GENERIERT — NICHT VON HAND BEARBEITEN.
// Quelle: catalog/packages.catalog.json  ·  Generator: scripts/gen-catalog.js
// Aenderungen an Paketen NUR in der JSON; danach \`node scripts/gen-catalog.js\`.
// Drift wird von api/src/__tests__/catalog.parity.test.ts erzwungen.

export type PackageKey = ${keyUnion};
export type Sellability = 'free' | 'self_service' | 'sales_assisted';

export interface PackageDef {
  /** Kanonischer Paket-Key — die einzige stabile Kennung (DB/Stripe/API/UI). */
  key: PackageKey;
  /** Anzeige-Name (Marketing). Nie woanders hartkodieren. */
  marketingName: string;
  /** Kurzbeschreibung fuer Karten/Selector. */
  subtitle: string;
  /** Verkaufsstufe: free = Lead-Magnet, self_service = Stripe-Checkout, sales_assisted = Angebot anfragen. */
  sellability: Sellability;
  /** Listenpreis EUR/Jahr fuer die Anzeige; null = "auf Anfrage", 0 = kostenlos. */
  priceEur: number | null;
  /** ENV-Key fuer Preis-Override im Frontend (NEXT_PUBLIC_…). */
  priceEnvKey: string;
  /** ENV-Key fuer die Stripe-Price-ID im Backend. */
  stripePriceEnvKey: string;
  /** Host-Limit fuer den Scan. */
  maxHosts: number;
  /** Top-N Findings im Report (selection.py). */
  topN: number;
  /** Gruppierung in der Scan-Maske. */
  tier: 'quick' | 'perimeter';
  /** Kurzes Dauer-Label ("~15–20 Min"). */
  durationShort: string;
  /** Langes Dauer-Label ("~15–20 Minuten"). */
  durationLong: string;
  /** Report-Schwerpunkte (Bullets). */
  reportFocus: string[];
  /** Compliance-Module (report-worker/reporter/compliance/*). */
  complianceModules: string[];
  /** Badge-Text fuer die Karte (oder null). */
  badge: string | null;
  /** Badge-Farbe (oder null). */
  badgeColor: string | null;
  /** Akzentfarbe der Karte. */
  accentColor: string;
}

export const CATALOG_POLICY_VERSION = '${catalog.policyVersion}';

export const PACKAGE_CATALOG: readonly PackageDef[] = ${data};

/** Kanonische Paket-Keys in Katalog-Reihenfolge. */
export const PACKAGE_KEYS: readonly PackageKey[] = [${keys.map((k) => `'${k}'`).join(', ')}];

const BY_KEY: Record<string, PackageDef> = Object.fromEntries(
  PACKAGE_CATALOG.map((p) => [p.key, p]),
);

/** Liefert die Paket-Definition oder undefined. */
export function getPackage(key: string): PackageDef | undefined {
  return BY_KEY[key];
}

/** Type-Guard: ist \`value\` ein gueltiger Paket-Key? */
export function isPackageKey(value: unknown): value is PackageKey {
  return typeof value === 'string' && value in BY_KEY;
}
`;
}

function main() {
  const checkOnly = process.argv.includes('--check');
  const catalog = loadCatalog();
  const content = renderCatalogModule(catalog);
  let drift = false;
  for (const target of TARGETS) {
    const existing = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
    if (existing === content) continue;
    if (checkOnly) {
      drift = true;
      console.error(`DRIFT: ${path.relative(ROOT, target)} weicht von der SSoT ab.`);
    } else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content);
      console.log(`geschrieben: ${path.relative(ROOT, target)}`);
    }
  }
  if (checkOnly && drift) {
    console.error('Fuehre `node scripts/gen-catalog.js` aus und committe die Aenderungen.');
    process.exit(1);
  }
  if (checkOnly) console.log('Katalog-Generate sind aktuell.');
}

module.exports = { loadCatalog, renderCatalogModule, SSOT_PATH, TARGETS, ROOT };

if (require.main === module) main();
