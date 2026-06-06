import Fastify, { FastifyInstance } from 'fastify';
import { registerSecurityHeaders, CONTENT_SECURITY_POLICY } from '../lib/security-headers';

/**
 * VEC-166 Regressionstest (A05 Security Misconfiguration).
 *
 * Gegen den alten Zustand rot: Die API setzte den CSP-Header gar nicht in der
 * App-Schicht; live emittierte nur Traefik einen malformierten Header-Namen
 * (`contentsecuritypolicy` ohne Bindestriche), den Browser ignorieren.
 *
 * Grün-Bedingung: kanonischer, hyphenierter Header-Name `content-security-policy`
 * ist vorhanden — und es existiert KEIN malformierter `contentsecuritypolicy`-Key.
 */
describe('VEC-166: API Content-Security-Policy header', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = Fastify();
    registerSecurityHeaders(server);
    server.get('/__probe', async () => ({ ok: true }));
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  it('emittiert den kanonischen (hyphenierten) Content-Security-Policy-Header', async () => {
    const res = await server.inject({ method: 'GET', url: '/__probe' });
    // Fastify/Node normalisiert Header-Keys auf lowercase — kanonisch = mit Bindestrichen.
    expect(res.headers['content-security-policy']).toBe(CONTENT_SECURITY_POLICY);
  });

  it('setzt KEINEN malformierten Header-Namen ohne Bindestriche', async () => {
    const res = await server.inject({ method: 'GET', url: '/__probe' });
    expect(res.headers['contentsecuritypolicy']).toBeUndefined();
  });

  it('VEC-207: straffe Lockdown-Policy für reines JSON-Backend', async () => {
    const res = await server.inject({ method: 'GET', url: '/__probe' });
    const csp = String(res.headers['content-security-policy']);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it('VEC-207: kein irreführendes unsafe-inline / keine script-src-Direktive', async () => {
    const res = await server.inject({ method: 'GET', url: '/__probe' });
    const csp = String(res.headers['content-security-policy']);
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('script-src');
  });
});
