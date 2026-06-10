import { buildCsp } from '../lib/securityHeaders';

const NONCE = 'test-nonce-abc123';

/**
 * VEC-166 / VEC-186 Regressionstest (A05 Security Misconfiguration), Frontend.
 *
 * VEC-186 (Härtung): `script-src` trägt KEIN `'unsafe-inline'` mehr, sondern
 * ein pro Request gebundenes Nonce. `connect-src`-Ableitung (API + cross-origin
 * Lead-Endpoint) aus VEC-166 bleibt unverändert erhalten.
 */
describe('VEC-166/VEC-186: Frontend Content-Security-Policy', () => {
  const scriptSrcOf = (csp: string) =>
    csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('script-src'));

  it('bindet ein Nonce an script-src statt unsafe-inline', () => {
    const scriptSrc = scriptSrcOf(buildCsp(NONCE));
    expect(scriptSrc).toBeDefined();
    expect(scriptSrc).toContain(`'nonce-${NONCE}'`);
    // Härtung: kein unsafe-inline mehr in script-src.
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it('setzt restriktive Default-Direktiven', () => {
    const csp = buildCsp(NONCE);
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it('leitet connect-src aus der API-URL ab (http→ws Variante inklusive)', () => {
    const csp = buildCsp(NONCE, 'https://scan-api.vectigal.tech');
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain('https://scan-api.vectigal.tech');
    expect(csp).toContain('wss://scan-api.vectigal.tech');
  });

  it('fällt in Dev sinnvoll auf localhost zurück, ohne das Backend zu blocken', () => {
    const csp = buildCsp(NONCE, 'http://localhost:4000');
    expect(csp).toContain('http://localhost:4000');
    expect(csp).toContain('ws://localhost:4000');
  });

  /**
   * VEC-166 (Sven QA): Das Lead-Formular (WebCheckLeadForm) macht einen
   * client-seitigen fetch auf NEXT_PUBLIC_LEAD_ENDPOINT (Prod: cross-origin
   * n8n-Webhook). Die DURCHGESETZTE CSP MUSS dieses Origin in connect-src
   * führen — sonst blockt der Browser den Lead-Submit (still, da der Catch
   * im Formular dennoch „success" meldet → Lead-Verlust).
   */
  it('nimmt das cross-origin Lead-Endpoint-Origin in connect-src auf', () => {
    const csp = buildCsp(NONCE, 'https://scan-api.vectigal.tech', 'https://bergersysteme.app.n8n.cloud/webhook/lead');
    const connect = csp.split(';').find((d) => d.trim().startsWith('connect-src')) || '';
    // Origin (ohne Pfad) muss enthalten sein.
    expect(connect).toContain('https://bergersysteme.app.n8n.cloud');
    // Der Pfad darf NICHT in die Direktive lecken (CSP-Sources sind Origins).
    expect(connect).not.toContain('/webhook/lead');
  });

  it('nimmt ein relatives Lead-Endpoint NICHT als eigenes Origin auf (von self gedeckt)', () => {
    const csp = buildCsp(NONCE, 'https://scan-api.vectigal.tech', '/api/lead');
    const connect = csp.split(';').find((d) => d.trim().startsWith('connect-src')) || '';
    expect(connect.trim()).toBe("connect-src 'self' https://scan-api.vectigal.tech wss://scan-api.vectigal.tech");
  });

  /**
   * VEC-372 D1: Report-Screenshots werden als <img> direkt vom Backend-Origin
   * geladen (cross-origin, da Frontend/API auf getrennten Subdomains laufen).
   * Die DURCHGESETZTE CSP MUSS das API-Origin in img-src führen — sonst blockt
   * der Browser ALLE gowitness-Screenshots still.
   */
  it('nimmt das API-Origin in img-src auf (Report-Screenshots, VEC-372)', () => {
    const csp = buildCsp(NONCE, 'https://scan-api.vectigal.tech');
    const imgSrc = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('img-src')) || '';
    expect(imgSrc).toContain("'self'");
    expect(imgSrc).toContain('data:');
    expect(imgSrc).toContain('https://scan-api.vectigal.tech');
  });

  it('belässt style-src bewusst auf unsafe-inline (Tailwind/next-font)', () => {
    const csp = buildCsp(NONCE);
    const styleSrc = csp.split(';').map((d) => d.trim()).find((d) => d.startsWith('style-src'));
    expect(styleSrc).toContain("'unsafe-inline'");
  });
});
