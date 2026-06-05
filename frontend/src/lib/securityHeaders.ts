/**
 * Kanonische Security-Header für das Next.js-Frontend (VEC-166).
 *
 * Die CSP wurde zuvor nur in der Host-Traefik-Middleware gesetzt — mit
 * malformiertem Namen (`contentsecuritypolicy` ohne Bindestriche), den Browser
 * ignorieren. Wir setzen sie jetzt versioniert und testbar über Next.js
 * `headers()` mit dem garantiert kanonischen Namen `Content-Security-Policy`.
 *
 * `connect-src` wird aus `NEXT_PUBLIC_API_URL` abgeleitet, damit die Policy in
 * allen Umgebungen (Dev localhost:4000, Prod scan-api.vectigal.tech) korrekt
 * ist und das Frontend nicht versehentlich vom Backend abgeschnitten wird.
 *
 * Härtung (script-src ohne 'unsafe-inline' via Nonce/Hash) ist bewusst
 * ausgelagert — siehe Follow-up.
 */

const DEFAULT_API_URL = 'http://localhost:4000';

export function buildCsp(apiUrl: string = process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL): string {
  // ws(s)-Origin = gleiche Host:Port, http→ws / https→wss.
  const wsUrl = apiUrl.replace(/^http/, 'ws');
  const connectSrc = ["'self'", apiUrl, wsUrl].join(' ');

  return [
    "default-src 'self'",
    `connect-src ${connectSrc}`,
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
  ].join('; ');
}

export function securityHeaders(): { key: string; value: string }[] {
  return [{ key: 'Content-Security-Policy', value: buildCsp() }];
}
