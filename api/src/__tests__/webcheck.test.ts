import fs from 'fs';
import path from 'path';
import {
  isValidEmail,
  normalizeEmail,
  normalizeDomain,
  decideRateLimited,
  decideVelocityAlert,
  recipientDomain,
  extractCapture,
  buildVerifyInstructions,
  WEBCHECK_PACKAGE,
  FREE_SCAN_WINDOW_HOURS,
  RATE_LIMITS,
  VELOCITY,
} from '../routes/webcheck.js';

describe('WebCheck-Free Lead-Magnet (VEC-91 / PA-11)', () => {
  describe('isValidEmail (AC1)', () => {
    it('accepts well-formed addresses', () => {
      expect(isValidEmail('alice@example.com')).toBe(true);
      expect(isValidEmail('a.b+tag@sub.example.co.uk')).toBe(true);
    });
    it('rejects malformed / non-string input', () => {
      expect(isValidEmail('not-an-email')).toBe(false);
      expect(isValidEmail('a@b')).toBe(false);
      expect(isValidEmail('a@b.')).toBe(false);
      expect(isValidEmail('')).toBe(false);
      expect(isValidEmail(undefined)).toBe(false);
      expect(isValidEmail(123)).toBe(false);
      expect(isValidEmail('x'.repeat(250) + '@example.com')).toBe(false);
    });
  });

  describe('normalization', () => {
    it('lowercases and trims email', () => {
      expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com');
    });
    it('lowercases, trims and strips trailing dot from domain', () => {
      expect(normalizeDomain('  Example.COM. ')).toBe('example.com');
    });
  });

  describe('decideRateLimited (AC4)', () => {
    it('does not throttle below all thresholds', () => {
      expect(decideRateLimited({ email: 0, domain: 0, ip: 0 })).toBe(false);
      expect(
        decideRateLimited({
          email: RATE_LIMITS.maxPerEmail - 1,
          domain: RATE_LIMITS.maxPerDomain - 1,
          ip: RATE_LIMITS.maxPerIp - 1,
        }),
      ).toBe(false);
    });
    it('throttles when the email threshold is reached', () => {
      expect(decideRateLimited({ email: RATE_LIMITS.maxPerEmail, domain: 0, ip: 0 })).toBe(true);
    });
    it('throttles when the domain threshold is reached', () => {
      expect(decideRateLimited({ email: 0, domain: RATE_LIMITS.maxPerDomain, ip: 0 })).toBe(true);
    });
    it('throttles when the IP threshold is reached', () => {
      expect(decideRateLimited({ email: 0, domain: 0, ip: RATE_LIMITS.maxPerIp })).toBe(true);
    });
  });

  describe('recipientDomain (VEC-173)', () => {
    it('extrahiert die Mail-Domain nach dem letzten @', () => {
      expect(recipientDomain('alice@example.com')).toBe('example.com');
      expect(recipientDomain('a.b+tag@sub.example.co.uk')).toBe('sub.example.co.uk');
    });
    it('liefert leeren String ohne @', () => {
      expect(recipientDomain('kein-at-zeichen')).toBe('');
    });
  });

  describe('decideVelocityAlert (VEC-173, F2)', () => {
    it('löst nicht aus unterhalb beider Schwellen', () => {
      const r = decideVelocityAlert({
        global: VELOCITY.maxGlobal - 1,
        recipientDomain: VELOCITY.maxPerRecipientDomain - 1,
      });
      expect(r.limited).toBe(false);
      expect(r.reasons).toEqual([]);
    });
    it('löst bei globalem Spike aus', () => {
      const r = decideVelocityAlert({ global: VELOCITY.maxGlobal, recipientDomain: 0 });
      expect(r.limited).toBe(true);
      expect(r.reasons).toContain('global');
    });
    it('löst bei Empfänger-Domain-Spike aus', () => {
      const r = decideVelocityAlert({
        global: 0,
        recipientDomain: VELOCITY.maxPerRecipientDomain,
      });
      expect(r.limited).toBe(true);
      expect(r.reasons).toContain('recipient_domain');
    });
    it('benennt beide Achsen, wenn beide Schwellen erreicht sind', () => {
      const r = decideVelocityAlert({
        global: VELOCITY.maxGlobal,
        recipientDomain: VELOCITY.maxPerRecipientDomain,
      });
      expect(r.reasons).toEqual(expect.arrayContaining(['global', 'recipient_domain']));
    });
  });

  describe('extractCapture (AC7)', () => {
    it('picks UTM / source / channel / icp fields and trims', () => {
      const out = extractCapture({
        utm_source: ' google ',
        utm_medium: 'cpc',
        utm_campaign: 'nis2',
        source: 'blog',
        channel: 'organic',
        icp_segment: 'mittelstand',
        ignored: 'nope',
      });
      expect(out.utm_source).toBe('google');
      expect(out.utm_medium).toBe('cpc');
      expect(out.source).toBe('blog');
      expect(out.icp_segment).toBe('mittelstand');
      // unknown keys are not surfaced as capture columns
      expect((out as Record<string, unknown>).ignored).toBeUndefined();
    });
    it('returns null for missing / empty / non-string values', () => {
      const out = extractCapture({ utm_source: '', utm_medium: 42 });
      expect(out.utm_source).toBeNull();
      expect(out.utm_medium).toBeNull();
      expect(out.utm_campaign).toBeNull();
    });
  });

  describe('buildVerifyInstructions (AC2)', () => {
    it('offers all three reusable verification methods with the token', () => {
      const inst = buildVerifyInstructions('example.com', 'vectiscan-verify-abc123');
      expect(inst.token).toBe('vectiscan-verify-abc123');
      const types = inst.methods.map((m) => m.type).sort();
      expect(types).toEqual(['dns_txt', 'file', 'meta_tag']);
      const dns = inst.methods.find((m) => m.type === 'dns_txt')!;
      expect(dns.record).toBe('_vectiscan-verify.example.com');
      expect(dns.value).toBe('vectiscan-verify-abc123');
    });
  });

  describe('limited scope constants (AC3)', () => {
    it('free scan is always the limited webcheck package', () => {
      expect(WEBCHECK_PACKAGE).toBe('webcheck');
    });
    it('one free scan per domain in a defined window', () => {
      expect(FREE_SCAN_WINDOW_HOURS).toBeGreaterThan(0);
    });
  });
});

describe('Migration 034 webcheck_leads schema (VEC-91)', () => {
  const migrationPath = path.join(__dirname, '..', 'migrations', '034_webcheck_leads.sql');

  it('migration file exists', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('creates the lead-capture table separate from product data', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS webcheck_leads');
  });

  it('has domain-verification columns (AC2)', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');
    expect(sql).toContain('verification_token');
    expect(sql).toContain('verified');
    expect(sql).toContain('verification_method');
  });

  it('has free-scan tracking columns (AC3)', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');
    expect(sql).toContain('order_id');
    expect(sql).toContain('scan_started_at');
  });

  it('has DSGVO double-opt-in consent columns (AC5)', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');
    expect(sql).toContain('consent_status');
    expect(sql).toContain('doi_token');
    expect(sql).toContain('doi_confirmed_at');
    expect(sql).toContain('legal_basis');
  });

  it('has lead-capture / UTM columns (AC7)', () => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');
    expect(sql).toContain('utm_source');
    expect(sql).toContain('utm_campaign');
    expect(sql).toContain('icp_segment');
  });
});
