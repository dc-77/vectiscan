/**
 * Feld-Praefixe fuer den Swarm (06.10.2026), siehe lib/buckets.ts und
 * lib/events.ts. Ohne die Variablen muss alles heissen wie auf docker02.
 */
describe('Feld-Praefixe', () => {
  const vorher = { ...process.env };

  afterEach(() => {
    process.env = { ...vorher };
    jest.resetModules();
  });

  it('ohne Variable bleiben Buckets und Kanal wie auf docker02', () => {
    delete process.env.MINIO_BUCKET_PREFIX;
    delete process.env.REDIS_EVENT_PREFIX;
    jest.isolateModules(() => {
      const buckets = require('../lib/buckets');
      const events = require('../lib/events');
      expect(buckets.REPORTS_BUCKET).toBe('scan-reports');
      expect(buckets.AUTH_BUCKET).toBe('scan-authorizations');
      expect(events.eventChannel('abc')).toBe('scan:events:abc');
    });
  });

  it('mit Feld-Praefix', () => {
    process.env.MINIO_BUCKET_PREFIX = 'vect-prod-';
    process.env.REDIS_EVENT_PREFIX = 'vect-prod:';
    jest.isolateModules(() => {
      const buckets = require('../lib/buckets');
      const events = require('../lib/events');
      expect(buckets.RAWDATA_BUCKET).toBe('vect-prod-scan-rawdata');
      expect(buckets.SCREENSHOTS_BUCKET).toBe('vect-prod-scan-screenshots');
      expect(buckets.DEBUG_BUCKET).toBe('vect-prod-scan-debug');
      expect(events.eventChannel('abc')).toBe('vect-prod:scan:events:abc');
      expect(events.EVENT_CHANNEL_PREFIX).toBe('vect-prod:');
    });
  });
});
