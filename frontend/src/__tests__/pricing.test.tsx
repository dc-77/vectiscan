// VEC-223: Launch-Tier-Pricing-Config — Single Source of Truth fuer Anzeige-Preise.
// Lockt AC1 (Perimeter ist kaufbar mit konkretem Preis) + AC4 (Preis via Config/ENV,
// kein verstreutes Hardcode).

describe('pricing config (VEC-223 Launch-Tier)', () => {
  const ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ENV };
  });

  afterAll(() => {
    process.env = ENV;
  });

  it('Perimeter ist der kaufbare Launch-Tier mit konkretem Default-Preis (1.490 €)', () => {
    delete process.env.NEXT_PUBLIC_PRICE_PERIMETER_EUR;
    const { getTier } = require('@/lib/pricing');
    const tier = getTier('perimeter');
    expect(tier).toBeDefined();
    expect(tier.purchasable).toBe(true);
    expect(tier.priceEur).toBe(1490);
  });

  it('Preis ist per ENV ueberschreibbar (kein Hardcode-Lock-in)', () => {
    process.env.NEXT_PUBLIC_PRICE_PERIMETER_EUR = '1990';
    const { getTier } = require('@/lib/pricing');
    expect(getTier('perimeter').priceEur).toBe(1990);
  });

  it('ungueltiger ENV-Wert faellt sauber auf den Default zurueck', () => {
    process.env.NEXT_PUBLIC_PRICE_PERIMETER_EUR = 'abc';
    const { getTier } = require('@/lib/pricing');
    expect(getTier('perimeter').priceEur).toBe(1490);
  });

  it('Insurance bleibt vorerst "auf Anfrage" (nicht self-service kaufbar)', () => {
    const { getTier } = require('@/lib/pricing');
    const tier = getTier('insurance');
    expect(tier.purchasable).toBe(false);
    expect(tier.priceEur).toBeNull();
  });

  it('formatEur rendert deutsches EUR-Format ohne Nachkommastellen', () => {
    const { formatEur } = require('@/lib/pricing');
    // Intl nutzt geschuetztes Leerzeichen vor dem Symbol; nur Ziffern/Symbol pruefen.
    const out = formatEur(1490);
    expect(out).toMatch(/1\.490/);
    expect(out).toMatch(/€/);
    expect(out).not.toMatch(/,\d/);
  });
});
