import { NextRequest, NextResponse } from 'next/server';
import { buildCsp } from '@/lib/securityHeaders';

/**
 * VEC-186: Nonce-basierte Content-Security-Policy.
 *
 * Pro Request wird ein frisches Nonce erzeugt und an `script-src` gebunden
 * (statt `'unsafe-inline'`). Next.js liest das Nonce aus dem CSP-Header des
 * REQUESTS und versieht damit automatisch seine eigenen Hydration-/Bootstrap-
 * Scripts — deshalb wird der Header sowohl auf den Request (für das Framework)
 * als auch auf die Response (für den Browser) gesetzt.
 *
 * `btoa(crypto.randomUUID())` statt `Buffer`: beides ist im Edge-Runtime
 * verfügbar, btoa vermeidet jede Polyfill-Abhängigkeit.
 */
export function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const csp = buildCsp(nonce);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', csp);

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}

export const config = {
  matcher: [
    /*
     * Auf allen Seiten-Routen laufen — aber NICHT auf statischen Assets
     * (`_next/static`, `_next/image`, Favicon) und NICHT auf Prefetch-Requests.
     * Statische Assets brauchen kein per-Request-Nonce; sie auszunehmen hält
     * Next.js' Static-Optimization für diese Auslieferungen intakt.
     */
    {
      source: '/((?!_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
