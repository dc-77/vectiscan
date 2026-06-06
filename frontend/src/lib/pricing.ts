// Anzeige-Preise + Sellability fuer Marketing-/Checkout-Oberflaechen
// (Pricing-Seite, Homepage-Karten, Subscribe-Wizard).
//
// VEC-289: Diese Datei leitet ALLES aus dem kanonischen Katalog
// (`@/lib/catalog.generated`, SSoT = catalog/packages.catalog.json) ab.
// Keine hartkodierten Paket-Namen oder -Preise mehr hier.
//
// WICHTIG: Der tatsaechliche Geldfluss laeuft NICHT ueber diese Zahlen, sondern
// ueber die serverseitig hinterlegte Stripe `price_id` (ENV `STRIPE_PRICE_<PAKET>`,
// siehe api/src/lib/stripe.ts::getPriceIdForPackage). Diese Datei steuert nur die
// dargestellte Preisangabe und ob ein Tier self-service kaufbar ist.
//
// Pro Tier per ENV `NEXT_PUBLIC_PRICE_<PAKET>_EUR` ueberschreibbar.

import { PACKAGE_CATALOG, type PackageDef } from '@/lib/catalog.generated';

export interface TierDisplay {
  /** Paket-Key, identisch mit dem Backend-Package-Namen (subscriptions/Stripe). */
  packageId: string;
  /** Anzeige-Preis in EUR/Jahr; `null` = "auf Anfrage" (nicht self-service kaufbar). */
  priceEur: number | null;
  /** Kleingedruckter Hinweis unter dem Preis. */
  billingNote: string;
  /** Ob der Tier per /subscribe self-service kaufbar ist (echter Stripe-Checkout). */
  purchasable: boolean;
}

function envPrice(key: string, fallback: number | null): number | null {
  const raw = process.env[key];
  const n = raw != null && raw !== '' ? Number(raw) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

function billingNoteFor(pkg: PackageDef): string {
  switch (pkg.sellability) {
    case 'free':
      return 'kostenlos & unverbindlich';
    case 'self_service':
      return 'netto zzgl. USt. · Jahresabo';
    case 'sales_assisted':
    default:
      return 'Jahresabo — individuelle Preisgestaltung';
  }
}

function toTier(pkg: PackageDef): TierDisplay {
  return {
    packageId: pkg.key,
    // Preis nur bei self-service-Tiers anzeigen; Sales-assisted/Free => kein Festpreis.
    priceEur:
      pkg.sellability === 'self_service'
        ? envPrice(pkg.priceEnvKey, pkg.priceEur)
        : null,
    billingNote: billingNoteFor(pkg),
    purchasable: pkg.sellability === 'self_service',
  };
}

/** Anzeige-Tiers fuer alle Pakete, key-indiziert — abgeleitet aus dem Katalog. */
export const TIERS: Record<string, TierDisplay> = Object.fromEntries(
  PACKAGE_CATALOG.map((pkg) => [pkg.key, toTier(pkg)]),
);

export function getTier(packageId: string): TierDisplay | undefined {
  return TIERS[packageId];
}

export function formatEur(amount: number): string {
  return new Intl.NumberFormat('de-DE', {
    style: 'currency',
    currency: 'EUR',
    maximumFractionDigits: 0,
  }).format(amount);
}
