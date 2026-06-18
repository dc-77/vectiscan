// VEC-436: Sperrt den Katalog-Vertrag, auf dem der /scan/new-Einzelkauf-Pfad
// aufsetzt. Die Präsenz von oneTimePriceEnvKey signalisiert dem Wizard (und
// dem Backend, isOneTimePurchasable) „kostenpflichtiger Einzelkauf"; der Preis
// (oneTimePriceEur) wird im Wizard und im Bestätigungsschritt angezeigt.

import { getPackage } from '@/lib/catalog.generated';

describe('VEC-436 Einzelscan-Checkout — Katalog-Vertrag', () => {
  it('Perimeter ist als Einzelkauf kaufbar mit 490 € Einmalpreis', () => {
    const pkg = getPackage('perimeter');
    expect(pkg).toBeDefined();
    expect(pkg!.oneTimePriceEur).toBe(490);
    // Präsenz des ENV-Keys = „muss bezahlt werden" (spiegelt Backend).
    expect(pkg!.oneTimePriceEnvKey).toBe('STRIPE_PRICE_PERIMETER_ONETIME');
  });

  it('WebCheck (gratis) hat keinen Einmalkauf-Pfad', () => {
    const pkg = getPackage('webcheck');
    expect(pkg).toBeDefined();
    expect(pkg!.oneTimePriceEur).toBeUndefined();
    expect(pkg!.oneTimePriceEnvKey).toBeUndefined();
  });

  it('Sales-assisted-Pakete sind nicht self-service einzeln kaufbar', () => {
    for (const key of ['compliance', 'supplychain', 'insurance'] as const) {
      const pkg = getPackage(key);
      expect(pkg).toBeDefined();
      expect(pkg!.sellability).toBe('sales_assisted');
      expect(pkg!.oneTimePriceEnvKey).toBeUndefined();
    }
  });
});
