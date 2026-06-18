// ⚠️  GENERIERT — NICHT VON HAND BEARBEITEN.
// Quelle: catalog/packages.catalog.json  ·  Generator: scripts/gen-catalog.js
// Aenderungen an Paketen NUR in der JSON; danach `node scripts/gen-catalog.js`.
// Drift wird von api/src/__tests__/catalog.parity.test.ts erzwungen.

export type PackageKey = 'webcheck' | 'perimeter' | 'compliance' | 'supplychain' | 'insurance';
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
  /** ENV-Key fuer die Stripe-Price-ID im Backend (Jahres-Abo). */
  stripePriceEnvKey: string;
  /** Einmalpreis EUR fuer den Self-Service-Einzelscan-Kauf (VEC-436). Nur bei self_service-Einzelkauf-Paketen gesetzt. */
  oneTimePriceEur?: number;
  /** ENV-Key fuer die Stripe one-time Price-ID des Einzelscan-Kaufs (VEC-436). Praesenz signalisiert "kostenpflichtiger Einzelkauf". */
  oneTimePriceEnvKey?: string;
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

export const CATALOG_POLICY_VERSION = '2026-06-06.1';

export const PACKAGE_CATALOG: readonly PackageDef[] = [
  {
    "key": "webcheck",
    "marketingName": "WebCheck",
    "subtitle": "SSL, Headers, CMS, E-Mail-Schutz — kompakter Report mit Ampel",
    "sellability": "free",
    "priceEur": 0,
    "priceEnvKey": "NEXT_PUBLIC_PRICE_WEBCHECK_EUR",
    "stripePriceEnvKey": "STRIPE_PRICE_WEBCHECK",
    "maxHosts": 3,
    "topN": 8,
    "tier": "quick",
    "durationShort": "~15–20 Min",
    "durationLong": "~15–20 Minuten",
    "reportFocus": [
      "Top-100-Port-Scan",
      "Mail-Security (SPF/DMARC/DKIM)",
      "Ampelbewertung"
    ],
    "complianceModules": [],
    "badge": null,
    "badgeColor": null,
    "accentColor": "#38BDF8"
  },
  {
    "key": "perimeter",
    "marketingName": "Perimeter-Scan",
    "subtitle": "Vollständige Angriffsflächen-Analyse mit priorisiertem Maßnahmenplan.",
    "sellability": "self_service",
    "priceEur": 1490,
    "priceEnvKey": "NEXT_PUBLIC_PRICE_PERIMETER_EUR",
    "stripePriceEnvKey": "STRIPE_PRICE_PERIMETER",
    "oneTimePriceEur": 490,
    "oneTimePriceEnvKey": "STRIPE_PRICE_PERIMETER_ONETIME",
    "maxHosts": 15,
    "topN": 15,
    "tier": "perimeter",
    "durationShort": "~60–90 Min",
    "durationLong": "~60–90 Minuten",
    "reportFocus": [
      "PTES-konformer Report",
      "Executive Summary",
      "Priorisierte Maßnahmen"
    ],
    "complianceModules": [],
    "badge": "Empfohlen",
    "badgeColor": "#38BDF8",
    "accentColor": "#38BDF8"
  },
  {
    "key": "compliance",
    "marketingName": "Compliance-Scan",
    "subtitle": "Perimeter-Scan mit NIS2-Compliance-Nachweis.",
    "sellability": "sales_assisted",
    "priceEur": null,
    "priceEnvKey": "NEXT_PUBLIC_PRICE_COMPLIANCE_EUR",
    "stripePriceEnvKey": "STRIPE_PRICE_COMPLIANCE",
    "maxHosts": 15,
    "topN": 20,
    "tier": "perimeter",
    "durationShort": "~65–95 Min",
    "durationLong": "~65–95 Minuten",
    "reportFocus": [
      "§30 BSIG-Mapping",
      "BSI-Grundschutz-Refs",
      "Audit-Trail"
    ],
    "complianceModules": [
      "nis2_bsig",
      "bsi_grundschutz"
    ],
    "badge": "NIS2",
    "badgeColor": "#EAB308",
    "accentColor": "#EAB308"
  },
  {
    "key": "supplychain",
    "marketingName": "SupplyChain-Scan",
    "subtitle": "Sicherheitsnachweis für NIS2-pflichtige Auftraggeber.",
    "sellability": "sales_assisted",
    "priceEur": null,
    "priceEnvKey": "NEXT_PUBLIC_PRICE_SUPPLYCHAIN_EUR",
    "stripePriceEnvKey": "STRIPE_PRICE_SUPPLYCHAIN",
    "maxHosts": 15,
    "topN": 15,
    "tier": "perimeter",
    "durationShort": "~65–95 Min",
    "durationLong": "~65–95 Minuten",
    "reportFocus": [
      "ISO 27001 Annex A",
      "Lieferanten-Nachweis",
      "Auftraggeber-Kapitel"
    ],
    "complianceModules": [
      "iso27001"
    ],
    "badge": "ISO 27001",
    "badgeColor": "#A78BFA",
    "accentColor": "#A78BFA"
  },
  {
    "key": "insurance",
    "marketingName": "Cyberversicherung",
    "subtitle": "Nachweis für Cyberversicherung mit Risikobewertung.",
    "sellability": "sales_assisted",
    "priceEur": null,
    "priceEnvKey": "NEXT_PUBLIC_PRICE_INSURANCE_EUR",
    "stripePriceEnvKey": "STRIPE_PRICE_INSURANCE",
    "maxHosts": 15,
    "topN": 15,
    "tier": "perimeter",
    "durationShort": "~65–95 Min",
    "durationLong": "~65–95 Minuten",
    "reportFocus": [
      "10-Punkte Fragebogen",
      "Risk-Score",
      "Ransomware-Indikator"
    ],
    "complianceModules": [
      "insurance"
    ],
    "badge": "Versicherung",
    "badgeColor": "#34D399",
    "accentColor": "#34D399"
  }
];

/** Kanonische Paket-Keys in Katalog-Reihenfolge. */
export const PACKAGE_KEYS: readonly PackageKey[] = ['webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'];

const BY_KEY: Record<string, PackageDef> = Object.fromEntries(
  PACKAGE_CATALOG.map((p) => [p.key, p]),
);

/** Liefert die Paket-Definition oder undefined. */
export function getPackage(key: string): PackageDef | undefined {
  return BY_KEY[key];
}

/** Type-Guard: ist `value` ein gueltiger Paket-Key? */
export function isPackageKey(value: unknown): value is PackageKey {
  return typeof value === 'string' && value in BY_KEY;
}
