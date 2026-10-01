import { DELIVERY_COLUMNS, deliveryNumber, reportFileName } from '../routes/orders';

// S7a Punkt 9 (spec/10 Teil 2 DB): Download-Name aus der Auslieferungsversion, dieselbe Zahl
// wie "Version n" auf dem Deckblatt; die Erzeugungsnummer steht nur in der Fusszeile.
// Vorher trug der Dateiname "v3" (Erzeugung), das Deckblatt "Version 1".

const BASIS = {
  target_url: 'dortmund-beach.com',
  package: 'perimeter',
  created_at: new Date('2026-09-26T08:40:00Z'),
};

describe('S7a: Dateiname aus der Auslieferungsversion', () => {
  it('nimmt bei einer freigegebenen Zeile delivery_version, nicht die Erzeugung', () => {
    const name = reportFileName({ ...BASIS, version: 3, delivery_version: 1, next_delivery_version: 1 });
    expect(name).toBe('vectiscan-dortmund-beach.com-perimeter-2026-09-26-0840-v1.pdf');
  });

  it('nimmt bei einem Entwurf die naechste Auslieferungsversion wie das Deckblatt', () => {
    expect(deliveryNumber({ version: 5, delivery_version: null, next_delivery_version: 2 })).toBe(2);
    expect(reportFileName({ ...BASIS, version: 5, delivery_version: null, next_delivery_version: 2 }))
      .toMatch(/-v2\.pdf$/);
  });

  it('faellt ohne Angaben auf Version 1 zurueck', () => {
    expect(deliveryNumber({})).toBe(1);
    expect(reportFileName({ ...BASIS })).toMatch(/-v1\.pdf$/);
  });

  it('zaehlt fuer den Entwurf nur Freigaben vor dieser Zeile', () => {
    expect(DELIVERY_COLUMNS).toContain('COALESCE(MAX(r2.delivery_version), 0) + 1');
    expect(DELIVERY_COLUMNS).toContain('r2.created_at < r.created_at');
  });
});
