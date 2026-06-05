import type { FastifyInstance } from 'fastify';

/**
 * Kanonischer Content-Security-Policy-Header für die API.
 *
 * VEC-166: Die CSP wurde zuvor ausschließlich in der Host-Traefik-Middleware
 * `security-headers@file` gesetzt — dort mit malformiertem Header-Namen
 * (`contentsecuritypolicy` ohne Bindestriche, vermutlich camelCase-Key in
 * `customResponseHeaders`). Browser parsen nur `Content-Security-Policy`,
 * weshalb die Policy faktisch wirkungslos war.
 *
 * Wir setzen den Header jetzt zusätzlich in der App-Schicht: versioniert,
 * per CI-Regressionstest abgesichert und garantiert mit kanonischem Namen.
 * Die Direktiven spiegeln die zuvor (unwirksam) konfigurierte Policy 1:1,
 * damit das Scharfschalten der Durchsetzung keine Verhaltensänderung über
 * den eigentlichen Fix hinaus bringt.
 *
 * Härtung (script-src ohne 'unsafe-inline' via Nonce/Hash) ist bewusst
 * ausgelagert — siehe Follow-up.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "connect-src 'self' https://scan-api.vectigal.tech wss://scan-api.vectigal.tech",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
].join('; ');

/**
 * Registriert einen onSend-Hook, der den kanonischen CSP-Header auf jede
 * Antwort setzt. Andere Security-Header (HSTS, X-Content-Type-Options,
 * X-Frame-Options) bleiben bei der Traefik-Middleware, die sie korrekt
 * emittiert — wir greifen hier nur den nachweislich defekten Header ab.
 */
export function registerSecurityHeaders(server: FastifyInstance): void {
  server.addHook('onSend', async (_request, reply, payload) => {
    reply.header('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    return payload;
  });
}
