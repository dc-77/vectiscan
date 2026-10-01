import { berlinDatum, fristHinweise, fristKlasse, type Schwellen } from '../lib/fristen';

// S7a Punkt 8 (E27): Fristregeln am Freigabetag, gleiche Einordnung wie
// report-worker/reporter/gate/fristen.py (tests/gate/test_v3_checks_s7a.py).

const SCHWELLEN: Schwellen = { sofort: 7, bald: 14, spaeter: 30, domain: 30 };

// Nutzlast wie der report-worker sie fuer heuel 2e56abe1 schreibt (Scan 23.09.2026).
const HEUEL = {
  fristen_scantag: '2026-09-23',
  fristen_schwellen: SCHWELLEN,
  fristen: [
    { art: 'tls', subjekt: 'online.heuel.com:443', gueltig_bis: '2026-10-25', tage_scantag: 31 },
    { art: 'service_cert', subjekt: '213.133.104.51:993', gueltig_bis: '2026-11-02', tage_scantag: 40 },
    { art: 'tls', subjekt: 'www.heuel.com:443', gueltig_bis: '2026-11-14', tage_scantag: 51 },
  ],
};

describe('S7a E27: Fristregeln am Freigabetag', () => {
  it('ordnet nach den Schwellen des Katalogs ein', () => {
    expect(fristKlasse('tls', 31, SCHWELLEN)).toBeNull();
    expect(fristKlasse('tls', 30, SCHWELLEN)).toBe('cert_expiring_later');
    expect(fristKlasse('tls', 14, SCHWELLEN)).toBe('cert_expiring');
    expect(fristKlasse('tls', 7, SCHWELLEN)).toBe('cert_expiring_sofort');
    expect(fristKlasse('tls', -1, SCHWELLEN)).toBe('cert_expired');
    expect(fristKlasse('service_cert', 5, SCHWELLEN)).toBeNull();
    expect(fristKlasse('service_cert', -1, SCHWELLEN)).toBe('service_cert_expired');
    expect(fristKlasse('domain', 30, SCHWELLEN)).toBe('domain_expiring');
  });

  it('meldet heuel online.heuel.com bei Freigabe am 27.09.', () => {
    const hinweise = fristHinweise(HEUEL, new Date('2026-09-27T10:00:00Z'));
    expect(hinweise).toEqual([{
      subjekt: 'online.heuel.com:443', gueltigBis: '2026-10-25', tageScantag: 31, tageFreigabe: 27,
      regelScantag: null, regelFreigabe: 'cert_expiring_later', freigabetag: '2026-09-27',
    }]);
  });

  it('meldet am Scantag nichts', () => {
    expect(fristHinweise(HEUEL, new Date('2026-09-23T12:00:00Z'))).toEqual([]);
  });

  it('rechnet den Freigabetag in Berliner Zeit', () => {
    // 23:30 UTC am 26.09. ist in Berlin schon der 27.09.
    expect(berlinDatum(new Date('2026-09-26T23:30:00Z'))).toBe('2026-09-27');
    expect(fristHinweise(HEUEL, new Date('2026-09-26T23:30:00Z'))[0]?.tageFreigabe).toBe(27);
  });

  it('meldet bei spaeter Freigabe auch den Ablauf eines Dienstzertifikats', () => {
    const hinweise = fristHinweise(HEUEL, new Date('2026-11-03T08:00:00Z'));
    expect(hinweise.map(h => [h.subjekt, h.regelFreigabe])).toEqual([
      ['online.heuel.com:443', 'cert_expired'],
      ['213.133.104.51:993', 'service_cert_expired'],
      ['www.heuel.com:443', 'cert_expiring'],
    ]);
  });

  it('ohne Fristen in der Nutzlast keine Hinweise', () => {
    expect(fristHinweise(null)).toEqual([]);
    expect(fristHinweise({ defects: [] })).toEqual([]);
    expect(fristHinweise({ ...HEUEL, fristen_schwellen: { sofort: 7 } })).toEqual([]);
  });
});
