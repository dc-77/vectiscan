/**
 * SSRF-Guard: Resolve-and-Pin + Block privater/link-local/loopback/metadata-Ranges.
 *
 * Härtung gegen DNS-Rebinding (VEC-175): Ein Angreifer, der die DNS seiner
 * Domain kontrolliert, kann nach bestandener Verifikation die Domain zur
 * Verbindungszeit auf eine interne IP (z. B. 169.254.169.254, RFC1918) zeigen.
 * Wir lösen genau einmal auf, validieren die Adresse gegen eine Blockliste und
 * verbinden gegen die so gepinnte öffentliche IP. Da `http.request({ lookup })`
 * die Auflösung selbst übernimmt, gibt es kein TOCTOU-Fenster zwischen unserer
 * Validierung und dem tatsächlichen Connect — der Connect nutzt exakt die von
 * uns freigegebene Adresse.
 */

import dns from 'dns';
import http from 'http';
import https from 'https';
import net from 'net';
import { URL } from 'url';

export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_REDIRECTS = 5;
export const DEFAULT_MAX_BYTES = 1_000_000; // 1 MB — reicht für TXT/HTML-Verify

/** Fehler, der bei geblockter (interner) Zieladresse geworfen wird. */
export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
  }
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

function inV4Cidr(ipInt: number, network: string, prefix: number): boolean {
  const netInt = ipv4ToInt(network);
  if (netInt === null) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// RFC1918 + Loopback + Link-Local (inkl. 169.254.169.254 Cloud-Metadata) +
// CGNAT, Benchmark, "this network", Multicast, reserviert/Broadcast.
const BLOCKED_V4: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
  ['255.255.255.255', 32],
];

function isBlockedV4(ip: string): boolean {
  const ipInt = ipv4ToInt(ip);
  if (ipInt === null) return true; // unparsebar → fail-closed
  return BLOCKED_V4.some(([net, prefix]) => inV4Cidr(ipInt, net, prefix));
}

/** Expandiert einen IPv6-String auf 16 Bytes oder gibt null bei Fehler. */
function ipv6ToBytes(ip: string): Uint8Array | null {
  let zone = ip;
  const pct = zone.indexOf('%');
  if (pct !== -1) zone = zone.slice(0, pct); // Scope-ID entfernen
  if (zone.indexOf(':') === -1) return null;

  const halves = zone.split('::');
  if (halves.length > 2) return null;

  const parseGroups = (segment: string): number[] | null => {
    if (segment === '') return [];
    const groups: number[] = [];
    for (const g of segment.split(':')) {
      if (g.indexOf('.') !== -1) {
        // Eingebettete IPv4 (z. B. ::ffff:1.2.3.4)
        const v4 = ipv4ToInt(g);
        if (v4 === null) return null;
        groups.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        groups.push(parseInt(g, 16));
      }
    }
    return groups;
  };

  const head = parseGroups(halves[0]);
  const tail = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (head === null || tail === null) return null;

  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...new Array(fill).fill(0), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i] >> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}

function isBlockedV6(ip: string): boolean {
  const b = ipv6ToBytes(ip);
  if (b === null) return true; // fail-closed

  // ::  (unspecified) und ::1 (loopback)
  const allButLastZero = b.slice(0, 15).every((x) => x === 0);
  if (allButLastZero && (b[15] === 0 || b[15] === 1)) return true;

  // fc00::/7  ULA  (erstes Byte 0xfc oder 0xfd)
  if ((b[0] & 0xfe) === 0xfc) return true;

  // fe80::/10  link-local  und  fec0::/10  site-local (deprecated)
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;

  // ff00::/8  multicast
  if (b[0] === 0xff) return true;

  // ::ffff:0:0/96  IPv4-mapped → eingebettete IPv4 prüfen
  const mappedPrefix =
    b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  if (mappedPrefix) {
    const v4 = `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
    return isBlockedV4(v4);
  }

  // 64:ff9b::/96  NAT64 → eingebettete IPv4 prüfen
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    const v4 = `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
    return isBlockedV4(v4);
  }

  return false;
}

/**
 * True, wenn die Adresse in einem geblockten (internen/reservierten) Bereich
 * liegt. Unparsebare Eingaben gelten als geblockt (fail-closed).
 */
export function isBlockedAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) return isBlockedV4(ip);
  if (family === 6) return isBlockedV6(ip);
  return true; // kein gültiges IP-Literal → fail-closed
}

/**
 * `lookup`-Funktion kompatibel mit http(s).request: löst den Hostnamen auf,
 * verwirft geblockte Adressen und pinnt auf die erste verbleibende öffentliche
 * IP. Bleibt keine öffentliche Adresse übrig → Fehler (fail-closed).
 *
 * `resolver` ist injizierbar für Tests; Default ist dns.lookup(all).
 */
export function makeGuardedLookup(
  resolver: (
    hostname: string,
    options: { all: true },
    cb: (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void,
  ) => void = dns.lookup as never,
) {
  return function guardedLookup(
    hostname: string,
    options: dns.LookupOneOptions | dns.LookupAllOptions | number,
    callback: (
      err: NodeJS.ErrnoException | null,
      address: string | dns.LookupAddress[],
      family?: number,
    ) => void,
  ): void {
    // Node ruft `lookup` je nach Aufrufer mit `all: true` (z. B. bei
    // autoSelectFamily/Happy-Eyeballs, Default in Node ≥18) ODER `all: false`
    // auf. Im all-Modus MUSS ein Array zurückgegeben werden, sonst wirft Node
    // ERR_INVALID_IP_ADDRESS und die Verbindung schlägt für JEDEN legitimen
    // Host fehl. Wir respektieren den Modus des Aufrufers.
    const wantAll =
      typeof options === 'object' && options !== null && (options as dns.LookupAllOptions).all === true;
    const succeed = (address: string, family: number): void => {
      if (wantAll) {
        callback(null, [{ address, family }], family);
      } else {
        callback(null, address, family);
      }
    };

    // IP-Literale direkt prüfen (keine Auflösung nötig).
    const literalFamily = net.isIP(hostname);
    if (literalFamily !== 0) {
      if (isBlockedAddress(hostname)) {
        callback(new SsrfBlockedError(`Geblockte Zieladresse: ${hostname}`), '', literalFamily);
        return;
      }
      succeed(hostname, literalFamily);
      return;
    }

    resolver(hostname, { all: true }, (err, addresses) => {
      if (err) {
        callback(err, '', 0);
        return;
      }
      const allowed = addresses.filter((a) => !isBlockedAddress(a.address));
      if (allowed.length === 0) {
        callback(
          new SsrfBlockedError(
            `Alle aufgelösten Adressen für ${hostname} sind geblockt (mögliches DNS-Rebinding).`,
          ),
          '',
          0,
        );
        return;
      }
      const pinned = allowed[0];
      succeed(pinned.address, pinned.family);
    });
  };
}

const guardedLookup = makeGuardedLookup();

export interface SafeResponse {
  status: number;
  url: string;
  text(): Promise<string>;
}

export interface SafeFetchOptions {
  timeoutMs?: number;
  maxRedirects?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
}

/**
 * Minimaler HTTP(S)-GET mit SSRF-Schutz: pinnt jede Verbindung (auch nach
 * Redirects) auf eine validierte öffentliche IP, folgt Redirects gebounded und
 * begrenzt die Body-Größe. Nur http/https-Schemata sind erlaubt.
 */
export function safeFetch(url: string, opts: SafeFetchOptions = {}): Promise<SafeResponse> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;

  return new Promise<SafeResponse>((resolve, reject) => {
    const visit = (current: string, redirectsLeft: number): void => {
      let parsed: URL;
      try {
        parsed = new URL(current);
      } catch {
        reject(new SsrfBlockedError(`Ungültige URL: ${current}`));
        return;
      }
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        reject(new SsrfBlockedError(`Nicht erlaubtes Schema: ${parsed.protocol}`));
        return;
      }

      // IP-Literal-Hosts überspringt Node's net.connect bei der DNS-Auflösung,
      // d. h. unser `lookup`-Guard würde NICHT aufgerufen. Daher hier explizit
      // prüfen (URL-Hostname trägt IPv6 in eckigen Klammern → strippen).
      const rawHost = parsed.hostname.replace(/^\[|\]$/g, '');
      if (net.isIP(rawHost) !== 0 && isBlockedAddress(rawHost)) {
        reject(new SsrfBlockedError(`Geblockte Ziel-IP: ${rawHost}`));
        return;
      }

      const transport = parsed.protocol === 'https:' ? https : http;
      const req = transport.request(
        current,
        {
          method: 'GET',
          lookup: guardedLookup,
          headers: { 'User-Agent': 'VectiScan-Verify/1.0', ...(opts.headers ?? {}) },
        },
        (res) => {
          const status = res.statusCode ?? 0;
          const location = res.headers.location;
          if (status >= 300 && status < 400 && location) {
            res.resume(); // Body verwerfen
            if (redirectsLeft <= 0) {
              reject(new SsrfBlockedError('Zu viele Redirects.'));
              return;
            }
            let next: string;
            try {
              next = new URL(location, current).toString();
            } catch {
              reject(new SsrfBlockedError(`Ungültiger Redirect: ${location}`));
              return;
            }
            visit(next, redirectsLeft - 1);
            return;
          }

          const chunks: Buffer[] = [];
          let total = 0;
          res.on('data', (chunk: Buffer) => {
            total += chunk.length;
            if (total > maxBytes) {
              req.destroy();
              reject(new SsrfBlockedError('Antwort überschreitet Größenlimit.'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf8');
            resolve({ status, url: current, text: () => Promise.resolve(body) });
          });
        },
      );

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error('Timeout'));
      });
      req.on('error', (err) => reject(err));
      req.end();
    };

    visit(url, maxRedirects);
  });
}
