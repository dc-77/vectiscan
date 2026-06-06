import type { NextConfig } from 'next';

/**
 * Der Content-Security-Policy-Header wird seit VEC-186 nicht mehr statisch hier,
 * sondern pro Request in `src/middleware.ts` gesetzt (Nonce-basierte CSP, kein
 * `'unsafe-inline'` mehr in `script-src`). Ein statischer Header an dieser Stelle
 * würde einen zweiten, konfligierenden CSP-Header erzeugen.
 */
const nextConfig: NextConfig = {
  output: 'standalone',
};

export default nextConfig;
