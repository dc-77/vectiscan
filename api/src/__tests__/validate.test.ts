import { isValidDomain } from '../lib/validate';

describe('isValidDomain', () => {
  it('should accept valid domains', () => {
    expect(isValidDomain('example.com')).toBe(true);
    expect(isValidDomain('sub.example.com')).toBe(true);
    expect(isValidDomain('beispiel.de')).toBe(true);
    expect(isValidDomain('scanme.nmap.org')).toBe(true);
    expect(isValidDomain('my-site.co.uk')).toBe(true);
    expect(isValidDomain('a.bc')).toBe(true);
  });

  it('should reject domains with protocol', () => {
    expect(isValidDomain('http://example.com')).toBe(false);
    expect(isValidDomain('https://example.com')).toBe(false);
  });

  it('should reject domains with path', () => {
    expect(isValidDomain('example.com/path')).toBe(false);
    expect(isValidDomain('example.com/')).toBe(false);
  });

  it('should reject domains with port', () => {
    expect(isValidDomain('example.com:8080')).toBe(false);
  });

  it('should reject invalid inputs', () => {
    expect(isValidDomain('')).toBe(false);
    expect(isValidDomain(null)).toBe(false);
    expect(isValidDomain(undefined)).toBe(false);
    expect(isValidDomain(123)).toBe(false);
    expect(isValidDomain('just-a-word')).toBe(false);
    expect(isValidDomain('.example.com')).toBe(false);
    expect(isValidDomain('example.')).toBe(false);
    expect(isValidDomain('-example.com')).toBe(false);
  });
});
