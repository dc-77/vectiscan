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
 *
 * VEC-207: Diese API liefert ausschließlich `application/json` (kein
 * Dokument/Worker/Frame, keine HTML-/Static-Routen). Browser setzen CSP auf
 * JSON-Responses ohnehin nicht durch — `script-src`/`style-src` etc. sind
 * für ein reines JSON-Backend bedeutungslos, und das gespiegelte
 * `'unsafe-inline'` ist irreführend (lädt zu False-Positive-Rechecks ein).
 * Wir straffen daher auf eine minimale Lockdown-Policy: `default-src 'none'`
 * verbietet jede Ressourcenklasse, `frame-ancestors 'none'` unterbindet das
 * Einbetten einer (hypothetischen) Dokument-Response. Das Frontend bleibt
 * unberührt — dessen Nonce-CSP wird in `frontend/middleware.ts` gesetzt
 * (VEC-186/VEC-201). Sollte die API künftig HTML/Docs ausliefern, ist für
 * diese Routen eine separate, lockerere Policy zu setzen.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "frame-ancestors 'none'",
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
