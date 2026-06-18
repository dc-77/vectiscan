/**
 * Live-Check (SofortScan) — Fassaden-Kern (VEC-363, Phase 1 aus VEC-360 §5/§7/§9).
 *
 * Kapselt den internen `webcheck-core`-Microservice (`Lissy93/web-check`, MIT)
 * hinter unserer Fastify-API. Dieses Modul ist die einzige Wahrheit darüber,
 *
 *   1. WELCHE Upstream-Module durchgereicht werden dürfen (BEHALTEN-Liste, §7),
 *   2. WIE ein Ziel (Target) validiert + SSRF-gehärtet wird, und
 *   3. WIE Upstream-Antworten ins `{ success, data }`-Schema normalisiert werden.
 *
 * Bewusst KEINE Astro-UI, KEINE Upstream-Endpunkte ungefiltert: nur die hier
 * gelisteten Slugs sind erreichbar (Default-Deny). Tech-Stack ist v1
 * ausgeschlossen, weil der Upstream-Detektor (wappalyzer) GPL-lizenziert ist
 * (Spike VEC-362) — License-Hygiene vor Feature-Vollständigkeit.
 */
import dns from 'dns';
import { isBlockedAddress } from './ssrf-guard.js';
import { isValidDomain } from './validate.js';

// ---------------------------------------------------------------------------
// 1. BEHALTEN-Modul-Allowlist (Default-Deny)
// ---------------------------------------------------------------------------

export type LiveCheckGroup = 'security' | 'tls' | 'dns' | 'mail' | 'network' | 'info';

export interface LiveCheckModule {
  /** Stabiler API-Key (unsere Fassade) — vom Frontend referenziert. */
  key: string;
  /** Deutsches UI-Label. */
  label: string;
  /** Upstream-Endpunkt-Slug in `webcheck-core` (`/api/<slug>?url=`). */
  upstream: string;
  /** Gruppierung für die UI (VEC-366). */
  group: LiveCheckGroup;
}

/**
 * Kuratierte BEHALTEN-Liste (VEC-360 §7). Nur Security-/Vertrauens-relevante,
 * im Upstream als eigenständiger `/api/<slug>.js`-Endpunkt vorhandene Module.
 *
 * Ausgeschlossen (bewusst): tech-stack (GPL-Detektor, Spike), carbon, rank,
 * social-tags, sitemap/linked-pages/features (SEO), quality/lighthouse,
 * traceroute (laut, geringer Mehrwert). Whois/Archives = optional via PM/UX
 * (VEC-366), daher hier noch nicht freigeschaltet.
 */
export const LIVE_CHECK_MODULES: readonly LiveCheckModule[] = [
  { key: 'ssl', label: 'SSL/TLS-Zertifikat', upstream: 'ssl', group: 'tls' },
  { key: 'tls', label: 'TLS-Sicherheitskonfiguration', upstream: 'tls', group: 'tls' },
  { key: 'hsts', label: 'HSTS', upstream: 'hsts', group: 'tls' },
  { key: 'http-headers', label: 'HTTP-Header', upstream: 'headers', group: 'security' },
  { key: 'http-security', label: 'HTTP-Security-Features', upstream: 'http-security', group: 'security' },
  { key: 'mail-config', label: 'E-Mail-Sicherheit (SPF/DKIM/DMARC/BIMI)', upstream: 'mail-config', group: 'mail' },
  { key: 'dns', label: 'DNS-Records', upstream: 'dns', group: 'dns' },
  { key: 'dnssec', label: 'DNSSEC', upstream: 'dnssec', group: 'dns' },
  { key: 'dns-server', label: 'DNS-Server', upstream: 'dns-server', group: 'dns' },
  { key: 'txt-records', label: 'TXT-Records', upstream: 'txt-records', group: 'dns' },
  { key: 'ports', label: 'Offene Ports', upstream: 'ports', group: 'network' },
  { key: 'firewall', label: 'WAF / Firewall', upstream: 'firewall', group: 'security' },
  { key: 'cookies', label: 'Cookies', upstream: 'cookies', group: 'security' },
  { key: 'security-txt', label: 'security.txt', upstream: 'security-txt', group: 'security' },
  { key: 'redirects', label: 'Redirect-Kette', upstream: 'redirects', group: 'network' },
  { key: 'threats', label: 'Malware / Phishing / Blocklisten', upstream: 'threats', group: 'security' },
  { key: 'block-lists', label: 'Blocklisten-Status', upstream: 'block-lists', group: 'security' },
  { key: 'get-ip', label: 'IP-Information', upstream: 'get-ip', group: 'info' },
  { key: 'server-status', label: 'Server-Status', upstream: 'status', group: 'info' },
  { key: 'screenshot', label: 'Screenshot', upstream: 'screenshot', group: 'info' },
] as const;

const MODULE_BY_KEY = new Map(LIVE_CHECK_MODULES.map((m) => [m.key, m]));

/** Liefert das Modul zu einem Key, oder `undefined` wenn nicht freigeschaltet. */
export function getLiveCheckModule(key: string): LiveCheckModule | undefined {
  return MODULE_BY_KEY.get(key);
}

/**
 * Baut den schema-qualifizierten `?url=`-Parameter für webcheck-core (VEC-411).
 *
 * Mehrere Upstream-Module (ssl, tls, headers, http-security, redirects, …)
 * rufen intern `new URL(url)` — auf einem NACKTEN Hostnamen wirft das
 * ("Invalid URL"), das Modul liefert dann `{ error }`/500 und unsere Fassade
 * reicht das als "nicht verfügbar" durch (Symptom: SSL-Erkennung scheint kaputt).
 *
 * web-check.xyz selbst übergibt nie einen nackten Hostnamen: seine Vercel-/
 * Netlify-Wrapper normalisieren via `normalizeUrl` (https:// voranstellen). Der
 * von uns betriebene standalone `server.js` (DISABLE_GUI) macht das NICHT und
 * reicht `req.query.url` roh an die Handler. Wir replizieren `normalizeUrl`
 * deshalb hier identisch — damit ist der an den Upstream gelieferte Input
 * exakt der von web-check.xyz getestete (maximale Parität).
 *
 * Idempotent: ein bereits http(s)-präfigiertes Ziel bleibt unverändert.
 */
export function toUpstreamTarget(host: string): string {
  return /^https?:\/\//i.test(host) ? host : `https://${host}`;
}

// ---------------------------------------------------------------------------
// 2. Target-Validierung + SSRF-Härtung
// ---------------------------------------------------------------------------

export type TargetRejectReason = 'invalid_format' | 'ssrf_blocked' | 'resolve_failed';

export interface TargetCheckResult {
  ok: boolean;
  /** Normalisierter Hostname (lowercase, ohne Schema/Port/Pfad). */
  host?: string;
  /** Erste aufgelöste, freigegebene öffentliche IP (für Audit). */
  resolvedIp?: string;
  reason?: TargetRejectReason;
  message?: string;
}

// Defense-in-depth: Hostnamen, die nie öffentlich auflösen sollten, hart blocken,
// unabhängig vom DNS-Ergebnis (Split-Horizon / interne Resolver).
const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain'];
const BLOCKED_HOST_EXACT = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata',
]);

/**
 * Extrahiert + normalisiert den Hostnamen aus einer Nutzereingabe (Hostname
 * oder http(s)-URL). Lehnt alles ab, was kein gültiger FQDN oder IPv4-Literal
 * ist. Gibt `null` bei ungültigem Format zurück.
 */
export function normalizeTargetHost(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  let raw = input.trim();
  if (!raw || raw.length > 255) return null;

  // http(s)-URL → Hostname extrahieren; andere Schemata ablehnen.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      raw = u.hostname;
    } catch {
      return null;
    }
  }

  // IPv6 in eckigen Klammern → entpacken.
  raw = raw.replace(/^\[|\]$/g, '');
  const host = raw.toLowerCase();

  // FQDN oder IPv4-Literal; alles andere (auch nackte IPv6/Hostnamen ohne TLD)
  // wird abgelehnt. IPv6-Literale lassen wir v1 nicht zu (Upstream-Module sind
  // primär hostname-/IPv4-orientiert).
  if (isValidDomain(host)) return host;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return host;
  return null;
}

/**
 * Validiert ein Ziel vollständig: Format → Hostname-Blockliste → DNS-Auflösung
 * → SSRF-Blockprüfung (RFC1918/Loopback/Link-Local/Cloud-Metadata). Ein Ziel
 * wird abgelehnt, sobald *irgendeine* aufgelöste Adresse intern/reserviert ist
 * (strikt gegen Split-Horizon/DNS-Rebinding — fail-closed).
 *
 * `resolver` ist für Tests injizierbar.
 */
export async function checkTarget(
  input: unknown,
  resolver: (host: string) => Promise<dns.LookupAddress[]> = (host) =>
    dns.promises.lookup(host, { all: true }),
): Promise<TargetCheckResult> {
  const host = normalizeTargetHost(input);
  if (!host) {
    return { ok: false, reason: 'invalid_format', message: 'Ungültiges Ziel-Format.' };
  }

  // Hostname-Blockliste (defense-in-depth, vor DNS).
  if (BLOCKED_HOST_EXACT.has(host) || BLOCKED_HOST_SUFFIXES.some((s) => host.endsWith(s))) {
    return { ok: false, reason: 'ssrf_blocked', message: 'Internes/lokales Ziel ist nicht erlaubt.' };
  }

  // IPv4-Literal: direkt prüfen (keine Auflösung nötig).
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    if (isBlockedAddress(host)) {
      return { ok: false, reason: 'ssrf_blocked', message: 'Interne/reservierte IP ist nicht erlaubt.' };
    }
    return { ok: true, host, resolvedIp: host };
  }

  // Hostname auflösen und JEDE Adresse gegen die Blockliste prüfen.
  let addresses: dns.LookupAddress[];
  try {
    addresses = await resolver(host);
  } catch {
    return { ok: false, reason: 'resolve_failed', message: 'Ziel konnte nicht aufgelöst werden.' };
  }
  if (!addresses || addresses.length === 0) {
    return { ok: false, reason: 'resolve_failed', message: 'Ziel konnte nicht aufgelöst werden.' };
  }
  const blocked = addresses.find((a) => isBlockedAddress(a.address));
  if (blocked) {
    return {
      ok: false,
      reason: 'ssrf_blocked',
      message: 'Ziel löst auf eine interne/reservierte Adresse auf (SSRF-Schutz).',
    };
  }
  return { ok: true, host, resolvedIp: addresses[0].address };
}
