/**
 * Kanonische Security-Header für das Next.js-Frontend (VEC-166).
 *
 * Die CSP wurde zuvor nur in der Host-Traefik-Middleware gesetzt — mit
 * malformiertem Namen (`contentsecuritypolicy` ohne Bindestriche), den Browser
 * ignorieren. Wir setzen sie jetzt versioniert und testbar über Next.js
 * `headers()` mit dem garantiert kanonischen Namen `Content-Security-Policy`.
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
 * Härtung (script-src ohne 'unsafe-inline' via Nonce/Hash) ist bewusst
 * ausgelagert — siehe Follow-up.
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

export function buildCsp(
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
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
  ].join('; ');
}

export function securityHeaders(): { key: string; value: string }[] {
  return [{ key: 'Content-Security-Policy', value: buildCsp() }];
}
