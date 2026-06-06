// Single source of truth fuer die *Anzeige*-Preise auf der Marketing-/Checkout-
// Oberflaeche (Pricing-Seite + Subscribe-Zusammenfassung).
//
// WICHTIG: Der tatsaechliche Geldfluss laeuft NICHT ueber diese Zahlen, sondern
// ueber die serverseitig hinterlegte Stripe `price_id` (ENV `STRIPE_PRICE_<PAKET>`,
// siehe api/src/lib/stripe.ts::getPriceIdForPackage). Diese Datei steuert nur die
// dargestellte Preisangabe und ob ein Tier self-service kaufbar ist.
//
// Betraege = CEO-freigegebenes Launch-Pricing (VEC-53), netto/Jahr. Pro Tier per
// ENV `NEXT_PUBLIC_PRICE_<PAKET>_EUR` ueberschreibbar — kein verstreutes Hardcode.

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

function envPrice(key: string, fallback: number): number {
  const raw = process.env[key];
  const n = raw != null && raw !== '' ? Number(raw) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

// Launch-Tier (VEC-223): Perimeter ist der erste self-service kaufbare Tier.
// Weitere Tiers bleiben vorerst "auf Anfrage", bis sie freigegeben/verdrahtet sind.
export const TIERS: Record<string, TierDisplay> = {
  perimeter: {
    packageId: 'perimeter',
    priceEur: envPrice('NEXT_PUBLIC_PRICE_PERIMETER_EUR', 1490),
    billingNote: 'netto zzgl. USt. · Jahresabo',
    purchasable: true,
  },
  insurance: {
    packageId: 'insurance',
    priceEur: null,
    billingNote: 'Jahresabo — individuelle Preisgestaltung',
    purchasable: false,
  },
};

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
