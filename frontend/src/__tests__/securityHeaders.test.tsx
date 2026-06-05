import { buildCsp, securityHeaders } from '../lib/securityHeaders';

/**
 * VEC-166 Regressionstest (A05 Security Misconfiguration), Frontend-Seite.
 *
 * Gegen den alten Zustand rot: next.config setzte keinen CSP-Header; live
 * emittierte nur Traefik den malformierten Namen `contentsecuritypolicy`.
 *
 * Grün-Bedingung: der von der App emittierte Header-Key ist exakt der
 * kanonische, hyphenierte Name `Content-Security-Policy` — und KEIN Key ohne
 * Bindestriche.
 */
describe('VEC-166: Frontend Content-Security-Policy header', () => {
  it('verwendet exakt den kanonischen, hyphenierten Header-Namen', () => {
    const headers = securityHeaders();
    const csp = headers.find((h) => h.key.toLowerCase().replace(/-/g, '') === 'contentsecuritypolicy');
    expect(csp).toBeDefined();
    expect(csp!.key).toBe('Content-Security-Policy');
  });

  it('emittiert KEINEN malformierten Header-Namen ohne Bindestriche', () => {
    const headers = securityHeaders();
    const malformed = headers.find((h) => h.key === 'ContentSecurityPolicy' || h.key === 'contentsecuritypolicy');
    expect(malformed).toBeUndefined();
  });

  it('leitet connect-src aus der API-URL ab (http→ws Variante inklusive)', () => {
    const csp = buildCsp('https://scan-api.vectigal.tech');
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain('https://scan-api.vectigal.tech');
    expect(csp).toContain('wss://scan-api.vectigal.tech');
  });

  it('fällt in Dev sinnvoll auf localhost zurück, ohne das Backend zu blocken', () => {
    const csp = buildCsp('http://localhost:4000');
    expect(csp).toContain('http://localhost:4000');
    expect(csp).toContain('ws://localhost:4000');
  });

  /**
   * VEC-166 (Sven QA): Das Lead-Formular (WebCheckLeadForm) macht einen
   * client-seitigen fetch auf NEXT_PUBLIC_LEAD_ENDPOINT (Prod: cross-origin
   * n8n-Webhook). Die DURCHGESETZTE CSP MUSS dieses Origin in connect-src
   * führen — sonst blockt der Browser den Lead-Submit (still, da der Catch
   * im Formular dennoch „success" meldet → Lead-Verlust). Gegen die
   * ursprüngliche Fassung (connect-src nur aus API_URL) rot.
   */
  it('nimmt das cross-origin Lead-Endpoint-Origin in connect-src auf', () => {
    const csp = buildCsp('https://scan-api.vectigal.tech', 'https://bergersysteme.app.n8n.cloud/webhook/lead');
    const connect = csp.split(';').find((d) => d.trim().startsWith('connect-src')) || '';
    // Origin (ohne Pfad) muss enthalten sein.
    expect(connect).toContain('https://bergersysteme.app.n8n.cloud');
    // Der Pfad darf NICHT in die Direktive lecken (CSP-Sources sind Origins).
    expect(connect).not.toContain('/webhook/lead');
  });

  it('nimmt ein relatives Lead-Endpoint NICHT als eigenes Origin auf (von self gedeckt)', () => {
    const csp = buildCsp('https://scan-api.vectigal.tech', '/api/lead');
    const connect = csp.split(';').find((d) => d.trim().startsWith('connect-src')) || '';
    expect(connect.trim()).toBe("connect-src 'self' https://scan-api.vectigal.tech wss://scan-api.vectigal.tech");
  });
});
