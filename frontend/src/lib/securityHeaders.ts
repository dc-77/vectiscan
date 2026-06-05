/**
 * Kanonische Content-Security-Policy für das Next.js-Frontend.
 *
 * Geschichte:
 * - VEC-166: Die CSP wurde zuvor nur in der Host-Traefik-Middleware gesetzt —
 *   mit malformiertem Namen (`contentsecuritypolicy` ohne Bindestriche), den
 *   Browser ignorieren. Seither setzen wir sie versioniert und testbar aus der
 *   App mit dem garantiert kanonischen Namen `Content-Security-Policy`.
 * - VEC-186 (Härtung): `script-src` trägt kein `'unsafe-inline'` mehr, sondern
 *   ein pro Request frisch generiertes Nonce. Erst dadurch greift die CSP wieder
 *   als echter XSS-Schutz. Das Nonce wird in `middleware.ts` erzeugt und gesetzt;
 *   `buildCsp` bindet es an `script-src`.
 *
 * `connect-src` wird aus den Origins abgeleitet, zu denen das Frontend
 * client-seitig tatsächlich Verbindungen aufbaut:
 *   - `NEXT_PUBLIC_API_URL`      → Backend-API (http) + WebSocket (ws/wss).
 *   - `NEXT_PUBLIC_LEAD_ENDPOINT`→ Lead-Submit aus `WebCheckLeadForm` (Prod:
 *     cross-origin n8n-Webhook). Fehlt dieses Origin in einer DURCHGESETZTEN
 *     CSP, blockt der Browser den Lead-`fetch` — und der Catch-Fallback im
 *     Formular meldet trotzdem „success", d.h. Leads gehen STILL verloren
 *     (VEC-166: Live-Traefik-Policy enthielt dieses Origin bewusst; die
 *     App-Schicht muss die Live-Policy faithful spiegeln, nicht verengen).
 *
 * `style-src` behält bewusst `'unsafe-inline'`: Tailwind und `next/font`
 * injizieren Inline-Styles ohne Nonce-Unterstützung. Style-Injection ist ein
 * deutlich schwächerer Angriffsvektor als Script-Injection; eine Hash-/Nonce-
 * Härtung der Styles ist separat zu bewerten.
 */

const DEFAULT_API_URL = 'http://localhost:4000';

/**
 * Origin (scheme://host[:port]) einer absoluten URL; `null` bei relativen
 * Pfaden (z.B. `/api/lead`, von `'self'` abgedeckt), leer oder ungültig.
 */
function originOf(url?: string): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * Baut den CSP-Header-Wert. Das `nonce` MUSS pro Request frisch sein
 * (siehe `middleware.ts`); es wird an `script-src` gebunden.
 */
export function buildCsp(
  nonce: string,
  apiUrl: string = process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL,
  leadEndpoint: string | undefined = process.env.NEXT_PUBLIC_LEAD_ENDPOINT,
): string {
  // ws(s)-Origin = gleiche Host:Port, http→ws / https→wss.
  const wsUrl = apiUrl.replace(/^http/, 'ws');

  const connectParts = ["'self'", apiUrl, wsUrl];
  // Lead-Endpoint nur aufnehmen, wenn es ein eigenes (cross-origin) Origin hat;
  // relative Endpoints sind bereits durch 'self' gedeckt.
  const leadOrigin = originOf(leadEndpoint);
  if (leadOrigin && !connectParts.includes(leadOrigin)) connectParts.push(leadOrigin);

  const connectSrc = connectParts.join(' ');

  return [
    "default-src 'self'",
    `connect-src ${connectSrc}`,
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}
