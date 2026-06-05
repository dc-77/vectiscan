import { trackPageview } from '../lib/analytics';

/**
 * VEC-209 Regressionstest (OWASP API: Security Misconfiguration / CORS),
 * Frontend.
 *
 * Vuln-Klasse: der Analytics-Beacon nutzte `navigator.sendBeacon`, das
 * cross-origin ZWINGEND Cookies sendet (credentials mode 'include'). Das
 * Backend `scan-api` setzt bewusst KEIN `Access-Control-Allow-Credentials: true`
 * (`@fastify/cors` mit reflektierter `origin: true` — ein ACAC dort waere
 * selbst eine CORS-Fehlkonfiguration). Folge: der Browser verwirft die Antwort
 * -> stiller Analytics-Verlust in Prod.
 *
 * Fix (Daten-Minimierung / Least Privilege): Versand per `fetch` mit
 * `credentials: 'omit'` + `keepalive: true`, KEIN sendBeacon. Der Collect-
 * Endpunkt ist oeffentlich/cookielos (VEC-36), credentials sind unnoetig.
 *
 * Dieser Test schlaegt gegen den alten sendBeacon-Pfad fehl (kein fetch mit
 * credentials:'omit', stattdessen sendBeacon-Aufruf) und besteht gegen den Fix.
 */
describe('VEC-209: Analytics-Beacon ohne Cookies (CORS-Credentials)', () => {
  const ORIGINAL_FETCH = global.fetch;

  let fetchMock: jest.Mock;
  let sendBeaconMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn(() => Promise.resolve({ status: 204 } as Response));
    global.fetch = fetchMock as unknown as typeof fetch;

    sendBeaconMock = jest.fn(() => true);
    Object.defineProperty(window.navigator, 'sendBeacon', {
      configurable: true,
      writable: true,
      value: sendBeaconMock,
    });
  });

  afterEach(() => {
    global.fetch = ORIGINAL_FETCH;
    jest.restoreAllMocks();
  });

  it('sendet per fetch mit credentials:"omit" und ruft sendBeacon NICHT auf', () => {
    trackPageview('/login');

    // Kernregression: cross-origin Beacon darf KEINE Cookies tragen.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain('/api/analytics/collect');
    expect(init).toMatchObject({
      method: 'POST',
      credentials: 'omit',
      keepalive: true,
    });

    // sendBeacon ist die Vuln-Quelle (erzwingt credentials:'include') -> verboten.
    expect(sendBeaconMock).not.toHaveBeenCalled();
  });

  it('uebermittelt ausschliesslich anonyme Pageview-Felder (keine Cookies/PII im Body)', () => {
    trackPageview('/pricing');

    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    // Nur die anonyme Reichweiten-Taxonomie; kein Identifier/keine Auth.
    expect(body).toEqual(
      expect.objectContaining({ path: '/pricing', eventType: 'pageview' }),
    );
    // Allowlist: jedes gesendete Feld muss anonym sein. undefined-Felder
    // (referrer/utm in jsdom) werden von JSON.stringify ohnehin verworfen.
    const ALLOWED = new Set([
      'eventType', 'path', 'referrer', 'utmCampaign', 'utmMedium', 'utmSource',
    ]);
    for (const key of Object.keys(body)) {
      expect(ALLOWED.has(key)).toBe(true);
    }
  });
});
