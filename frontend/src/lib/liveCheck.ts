/**
 * Live-Check (SofortScan) — Frontend-Lib (VEC-366).
 * Kapselt alle API-Calls an /api/live-check/* und leitet Modul-Roh-Daten
 * in CheckStatus (pass/warn/fail/error) + strukturierte Detail-Blöcke um.
 *
 * VEC-413: Das gesamte Upstream→Anzeige-Mapping (Status UND Detail) lebt jetzt
 * in DIESER Datei (vorher war `extractDetail` in der Results-Page dupliziert).
 * Eine Wahrheit, gegen die REALE web-check-2.1.9-Antwort geschrieben (nicht
 * gegen vermutete Feldnamen — das war der wiederkehrende Bug, vgl. VEC-411).
 */
import { getToken } from './auth';
import type { DetailBlock, BadgeVariant } from '@/components/ds/CheckTile';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export type CheckGroup = 'tls' | 'security' | 'dns' | 'mail' | 'network' | 'info';
export type CheckStatus = 'pending' | 'running' | 'pass' | 'warn' | 'fail' | 'error';

export interface CheckModule {
  key: string;
  label: string;
  group: CheckGroup;
}

export interface CheckResult extends CheckModule {
  status: CheckStatus;
  summary: string;
  detail?: unknown;
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ---------------------------------------------------------------------------
// Concurrency-/Retry-Parameter (VEC-381)
// ---------------------------------------------------------------------------

/**
 * Maximale gleichzeitig laufende Modul-Aufrufe im Client.
 * MUSS ≤ Server-Cap `liveCheckLimiter.maxConcurrent` (= 4) sein, damit der
 * SofortScan nicht 16 Module sofort in ein 429 `too_many_concurrent` laufen
 * lässt (VEC-381). Der gemeinsame Server-Slot wird erst in dessen `finally`
 * freigegeben — die kleine Race zwischen Antwort und `release()` fängt der
 * bounded Retry unten ab.
 */
export const CLIENT_CONCURRENCY = 4;

/** Bounded Retries bei transientem `too_many_concurrent`. */
const MAX_CONCURRENT_RETRIES = 4;
/** Untergrenze des Backoffs; Server liefert retryAfter=2s, wir reagieren schneller. */
const RETRY_BASE_MS = 400;
/** Deckel pro Wartezeit, damit ein einzelnes Modul den Scan nicht ausbremst. */
const RETRY_MAX_MS = 2_000;

/** Abbruchbarer Sleep — lehnt mit AbortError ab, wenn das Signal feuert. */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Aborted', 'AbortError'));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** 429-Body normalisieren: `{ error, retryAfter }` (siehe api/routes/live-check.ts). */
async function parse429(res: Response): Promise<{ error: string | null; retryAfter: number | null }> {
  try {
    const body = await res.json();
    return {
      error: typeof body?.error === 'string' ? body.error : null,
      retryAfter: typeof body?.retryAfter === 'number' ? body.retryAfter : null,
    };
  } catch {
    return { error: null, retryAfter: null };
  }
}

/**
 * Worker-Pool mit fester Nebenläufigkeit: verarbeitet `items` mit höchstens
 * `limit` gleichzeitig laufenden `worker`-Aufrufen. So respektiert der Client
 * den Server-Concurrency-Cap, statt alle Module gleichzeitig zu feuern.
 * `worker` darf NICHT werfen — Fehler/Abbruch behandelt der Aufrufer.
 */
export async function runPool<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;
  let cursor = 0;
  const size = Math.max(1, Math.min(limit, items.length));
  async function loop(): Promise<void> {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      await worker(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: size }, () => loop()));
}

export async function fetchModules(): Promise<CheckModule[]> {
  const res = await fetch(`${API_URL}/api/live-check/modules`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error('modules_failed');
  const body = await res.json();
  return (body.data?.modules ?? []) as CheckModule[];
}

export async function runModule(
  moduleKey: string,
  target: string,
  signal?: AbortSignal,
): Promise<Pick<CheckResult, 'status' | 'summary' | 'detail'>> {
  const url = `${API_URL}/api/live-check/run/${encodeURIComponent(moduleKey)}?target=${encodeURIComponent(target)}`;

  // Bounded Retry-Loop nur für transientes `too_many_concurrent`. Jeder andere
  // Ausgang (Erfolg, Fensterlimit, Fehler, Timeout) verlässt die Schleife sofort.
  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, { headers: authHeaders(), signal });
    } catch {
      if (signal?.aborted) return { status: 'error', summary: 'Abgebrochen', detail: null };
      return { status: 'error', summary: 'Nicht erreichbar', detail: null };
    }

    if (res.status === 429) {
      const { error, retryAfter } = await parse429(res);
      // Transient: der Concurrency-Slot ist gleich wieder frei → kurz warten,
      // erneut versuchen. Fensterlimit (`rate_limited`) ist NICHT transient.
      if (error === 'too_many_concurrent' && attempt < MAX_CONCURRENT_RETRIES) {
        const waitMs = Math.min(
          RETRY_MAX_MS,
          Math.max(RETRY_BASE_MS, (retryAfter ?? 0) * 1000),
        );
        try {
          await sleep(waitMs, signal);
        } catch {
          return { status: 'error', summary: 'Abgebrochen', detail: null };
        }
        continue;
      }
      // Fensterlimit erreicht oder Retries erschöpft → Meldung zeigen.
      return { status: 'error', summary: 'Bitte warten (Rate-Limit)', detail: null };
    }

    if (res.status === 504) return { status: 'error', summary: 'Timeout', detail: null };
    if (!res.ok) return { status: 'error', summary: 'Nicht verfügbar', detail: null };

    let body: { success: boolean; data?: { result?: unknown } };
    try {
      body = await res.json();
    } catch {
      return { status: 'error', summary: 'Ungültige Antwort', detail: null };
    }

    if (!body.success) return { status: 'error', summary: 'Nicht verfügbar', detail: null };
    return deriveStatus(moduleKey, body.data?.result);
  }
}

// ---------------------------------------------------------------------------
// Status-Ableitung aus Roh-Daten je Modul
// ---------------------------------------------------------------------------

type ObjLike = Record<string, unknown>;

function isObj(v: unknown): v is ObjLike {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// SSL-Zertifikat — Feld-Normalisierung (VEC-411)
//
// Der Upstream `webcheck-core` (Lissy93/web-check 2.1.9, /api/ssl) liefert das
// ROHE Node-`tls.getPeerCertificate()`-Objekt (ohne `raw`/`issuerCertificate`)
// plus `isValid` + `authError`:
//   { subject:{CN,O,…}, issuer:{CN,O,…}, valid_from, valid_to,
//     subjectaltname:"DNS:a, DNS:b", bits, serialNumber, isValid, authError }
// Es gibt KEIN `valid`, `daysUntilExpiry`, `issuer`(String), `validTo`,
// `keySize`, `signatureAlgorithm` oder `altNames`. Der frühere Code las genau
// diese nicht existenten Felder → jedes Zertifikat wurde als "ungültig"
// gewertet und die Detail-Karte blieb leer. Diese Helfer mappen beide Shapes
// (idealisiert UND roh), damit Status + Details korrekt sind.
// ---------------------------------------------------------------------------

/** Parst ein Node-Zertifikatsdatum ("Feb  1 23:59:59 2026 GMT") → ms oder null. */
export function sslParseCertDate(v: unknown): number | null {
  if (typeof v !== 'string') return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
}

/** Verbleibende Gültigkeitstage aus `daysUntilExpiry` ODER `valid_to`/`validTo`. */
export function sslDaysUntilExpiry(r: ObjLike, now: number = Date.now()): number | null {
  if (typeof r.daysUntilExpiry === 'number' && !Number.isNaN(r.daysUntilExpiry)) {
    return r.daysUntilExpiry;
  }
  const to = sslParseCertDate(r.valid_to ?? r.validTo ?? r.validUntil);
  if (to === null) return null;
  return Math.floor((to - now) / 86_400_000);
}

/** Cert-Distinguished-Name → Anzeige-String. `prefer` wählt CN- oder O-Vorrang. */
export function sslCertName(v: unknown, prefer: 'CN' | 'O' = 'CN'): string {
  if (typeof v === 'string') return v.trim();
  if (isObj(v)) {
    const first = prefer === 'O' ? v.O : v.CN;
    const second = prefer === 'O' ? v.CN : v.O;
    if (typeof first === 'string' && first.trim()) return first.trim();
    if (typeof second === 'string' && second.trim()) return second.trim();
  }
  return '';
}

/** Vertrauensstatus: idealisiertes `valid`, reales `isValid`/`authError`. */
export function sslIsTrusted(r: ObjLike): boolean {
  if (r.valid === true) return true;
  if (r.valid === false) return false;
  if (r.isValid === true) return true;
  if (r.isValid === false) return false;
  if (typeof r.authError === 'string' && r.authError.trim() !== '') return false;
  // Kein explizites Flag: als gültig werten, sobald überhaupt Cert-Daten da sind.
  return Boolean(r.valid_to || r.subject || r.subjectaltname);
}

/** SANs aus `altNames`-Array ODER `subjectaltname`-Komma-String ("DNS:a, DNS:b"). */
export function sslSans(r: ObjLike): string[] {
  const arr = Array.isArray(r.altNames)
    ? (r.altNames.filter((x) => typeof x === 'string') as string[])
    : [];
  if (arr.length > 0) return arr;
  if (typeof r.subjectaltname === 'string') {
    return r.subjectaltname
      .split(',')
      .map((s) => s.trim().replace(/^DNS:/i, '').trim())
      .filter(Boolean);
  }
  return [];
}

// ---------------------------------------------------------------------------
// Generische Typ-Helfer (VEC-413) — defensiv gegen jede Upstream-Shape
// ---------------------------------------------------------------------------

function asArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function asStr(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v : undefined;
}
function asNum(v: unknown): number | undefined {
  return typeof v === 'number' && !Number.isNaN(v) ? v : undefined;
}
function yesNo(v: unknown): string {
  return v === true ? 'ja' : 'nein';
}
function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
function expiryVariant(days: number): BadgeVariant {
  if (days < 14) return 'fail';
  if (days < 30) return 'warn';
  return 'ok';
}
function protoVariant(p: string): BadgeVariant {
  if (/TLSv?1\.3|TLSv?1\.2/i.test(p)) return 'ok';
  if (/TLSv?1\.1|TLSv?1\.0|SSLv/i.test(p)) return 'fail';
  return 'neutral';
}
// TLS-Grade-Badge (VEC-415): A+/A → ok, B → warn, C/D/E/F → fail, sonst neutral.
function gradeVariant(grade: string): BadgeVariant {
  const g = grade.trim().toUpperCase();
  if (/^A\+?$/.test(g)) return 'ok';
  if (g === 'B') return 'warn';
  if (/^[CDEF]$/.test(g)) return 'fail';
  return 'neutral';
}
function statusCodeVariant(code: number): BadgeVariant {
  if (code >= 200 && code < 300) return 'ok';
  if (code >= 300 && code < 400) return 'neutral';
  return 'fail';
}

/** TXT-Record-Eintrag → eine Zeile. web-check liefert Chunk-Arrays (string[]). */
function joinTxt(entry: unknown): string {
  if (typeof entry === 'string') return entry;
  if (Array.isArray(entry)) return entry.filter((x) => typeof x === 'string').join('');
  return '';
}

// Security-Header für http-headers (reale Antwort = lowercased Header-Map).
const SEC_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];
// Reihenfolge für DNS-Records (A/MX/NS zuerst).
const DNS_TYPE_ORDER = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA', 'SRV', 'PTR'];

// http-security (Upstream-Feldname → deutsches Header-Label).
const HTTP_SEC_LABELS: Record<string, string> = {
  contentSecurityPolicy: 'Content-Security-Policy',
  strictTransportPolicy: 'Strict-Transport-Security',
  xContentTypeOptions: 'X-Content-Type-Options',
  xFrameOptions: 'X-Frame-Options',
  xXSSProtection: 'X-XSS-Protection',
  referrerPolicy: 'Referrer-Policy',
  permissionsPolicy: 'Permissions-Policy',
  crossOriginOpenerPolicy: 'Cross-Origin-Opener-Policy',
  crossOriginResourcePolicy: 'Cross-Origin-Resource-Policy',
  crossOriginEmbedderPolicy: 'Cross-Origin-Embedder-Policy',
};
// Kern-Header, deren Fehlen die Severity treibt.
const HTTP_SEC_CORE = ['contentSecurityPolicy', 'strictTransportPolicy', 'xFrameOptions', 'xContentTypeOptions'];

// ---------------------------------------------------------------------------
// E-Mail-Sicherheit (mail-config) — reale Antwort hat KEINE spf/dkim/dmarc-
// Flags, nur `txtRecords` (Array von TXT-Chunk-Arrays). VEC-413 Bug #1: das
// alte Mapping las r.spf/r.dkim/r.dmarc → alle undefined → false CRITICAL.
// SPF/DMARC/DKIM/BIMI werden aus den TXT-Records erkannt. BIMI ist rein
// kosmetisch und DKIM-Selektor-Discovery ist unvollständig → keiner von beiden
// treibt die Severity (sonst entstehen wieder falsche kritische Befunde).
// ---------------------------------------------------------------------------

interface MailFacts {
  spf: string | null;
  dmarc: string | null;
  dkim: string | null;
  bimi: string | null;
  dmarcPolicy: string | null;
  hasSPF: boolean;
  hasDMARC: boolean;
  hasDKIM: boolean;
  hasBIMI: boolean;
}

function mailFacts(r: ObjLike): MailFacts {
  const txts = asArr(r.txtRecords).map(joinTxt).filter(Boolean);
  const spf = txts.find((t) => /^v=spf1\b/i.test(t)) ?? null;
  const dmarc = txts.find((t) => /^v=dmarc1\b/i.test(t)) ?? null;
  const bimi = txts.find((t) => /^v=bimi1\b/i.test(t)) ?? null;
  // DKIM-Record (von findDkim mit in txtRecords gepusht): v=DKIM1 ODER ein
  // domainkey-typischer "k=…; p=<base64>". SPF/DMARC/BIMI matchen das nicht.
  const dkim =
    txts.find((t) => /(^|;|\s)v=dkim1\b/i.test(t) || (/\bk=/.test(t) && /\bp=[A-Za-z0-9+/]/.test(t))) ?? null;
  const dmarcPolicy = dmarc ? (dmarc.match(/\bp=\s*([a-z]+)/i)?.[1]?.toLowerCase() ?? null) : null;
  return {
    spf,
    dmarc,
    dkim,
    bimi,
    dmarcPolicy,
    hasSPF: !!spf,
    hasDMARC: !!dmarc,
    hasDKIM: !!dkim,
    hasBIMI: !!bimi,
  };
}

/** HSTS-Direktiven aus dem rohen `Strict-Transport-Security`-Header parsen. */
function parseHsts(header: string | undefined): { maxAge?: number; includeSubDomains: boolean; preload: boolean } {
  if (!header) return { includeSubDomains: false, preload: false };
  const m = header.match(/max-age=(\d+)/i);
  return {
    maxAge: m ? Number(m[1]) : undefined,
    includeSubDomains: /includesubdomains/i.test(header),
    preload: /preload/i.test(header),
  };
}

/** DNS-Records aus der typ-keyed Upstream-Antwort in {type,value}-Zeilen. */
function dnsRecords(r: ObjLike): { type: string; value: string }[] {
  const out: { type: string; value: string }[] = [];
  for (const t of DNS_TYPE_ORDER) {
    const v = r[t];
    if (t === 'SOA') {
      // VEC-415: kompakt als "${mname} (serial: ${serial})"; Long-Layout greift
      // automatisch bei > 48 Zeichen.
      if (isObj(v)) {
        const mname = asStr(v.nsname) ?? asStr(v.mname) ?? asStr(v.primary);
        const serial = asNum(v.serial) ?? asStr(v.serial);
        const value = mname
          ? (serial !== undefined ? `${mname} (serial: ${serial})` : mname)
          : (asStr(v.hostmaster) ?? 'vorhanden');
        out.push({ type: 'SOA', value });
      }
      continue;
    }
    for (const item of asArr(v)) {
      if (t === 'MX' && isObj(item)) {
        // VEC-415: priority + exchange zusammenführen → "10 mail.example.com".
        const mxPrio = asNum(item.priority) ?? asNum(item.pref);
        const mxExch = asStr(item.exchange) ?? asStr(item.data);
        const value = mxPrio !== undefined
          ? `${mxPrio} ${mxExch ?? ''}`.trim()
          : (mxExch ?? asStr(item.address) ?? asStr(item.value) ?? '');
        if (value) out.push({ type: 'MX', value });
      } else if (t === 'TXT') {
        const line = truncate(joinTxt(item), 80);
        if (line) out.push({ type: 'TXT', value: line });
      } else if (typeof item === 'string') {
        out.push({ type: t, value: item });
      } else if (isObj(item)) {
        const val = asStr(item.value) ?? asStr(item.address);
        if (val) out.push({ type: t, value: val });
      }
    }
  }
  return out;
}

/** Threats: konservative Treffer-Erkennung über key-freie + key-pflichtige Quellen. */
function threatHit(r: ObjLike): boolean {
  const sb = isObj(r.safeBrowsing) && r.safeBrowsing.unsafe === true;
  const uh =
    isObj(r.urlHaus) &&
    (r.urlHaus.query_status === 'ok' || r.urlHaus.query_status === 'OK') &&
    asArr(r.urlHaus.urls).length > 0;
  const pt =
    isObj(r.phishTank) &&
    (r.phishTank.in_database === 'true' || r.phishTank.in_database === true) &&
    (r.phishTank.valid === 'true' || r.phishTank.valid === true);
  return sb || uh || pt;
}

export function deriveStatus(
  moduleKey: string,
  result: unknown,
): Pick<CheckResult, 'status' | 'summary' | 'detail'> {
  if (!result) return { status: 'error', summary: 'Keine Daten', detail: null };

  const r = isObj(result) ? result : {};

  // Upstream signalisiert "nicht anwendbar" als { skipped: "..." } mit HTTP 200
  // (z.B. mail-config ohne MX, threats ohne API-Keys). NIE als Befund werten —
  // sonst entsteht ein falsches HIGH/MEDIUM (VEC-413).
  if (typeof r.skipped === 'string') {
    return { status: 'pass', summary: 'Nicht anwendbar', detail: result };
  }

  switch (moduleKey) {
    case 'ssl': {
      // Reale web-check 2.1.9-Antwort = rohes getPeerCertificate + isValid/
      // authError (siehe sslHelfer oben, VEC-411). Defensiv gegen beide Shapes.
      const trusted = sslIsTrusted(r);
      const expiry = sslDaysUntilExpiry(r);
      if (!trusted) return { status: 'fail', summary: 'Ungültig oder nicht vertrauenswürdig', detail: result };
      if (expiry !== null && expiry < 0) return { status: 'fail', summary: 'Abgelaufen', detail: result };
      if (expiry !== null && expiry < 14) return { status: 'fail', summary: `Läuft in ${expiry} Tagen ab`, detail: result };
      if (expiry !== null && expiry < 30) return { status: 'warn', summary: `Läuft in ${expiry} Tagen ab`, detail: result };
      const issuer = sslCertName(r.issuer, 'O');
      return { status: 'pass', summary: `Gültig${expiry !== null ? ` · ${expiry} Tage` : ''}${issuer ? ` · ${issuer}` : ''}`, detail: result };
    }

    case 'tls': {
      // Reale Antwort = `tls-connection` (VEC-413): EIN ausgehandeltes Protokoll
      // (kein supportedProtocols[]), cipher als Objekt {name,…}, forwardSecrecy,
      // ocspStapled. Slug in api/lib/liveCheck.ts auf `tls-connection` korrigiert.
      const proto = asStr(r.protocol);
      // VEC-415: Grade (sofern vorhanden) führt die Summary an.
      const grade = asStr(r.grade) ?? asStr(asObj(r.report)?.grade);
      if (!proto) {
        return { status: 'pass', summary: grade ? `Grade ${grade}` : 'Konfiguration OK', detail: result };
      }
      if (/TLSv?1\.0|TLSv?1\.1|SSLv/i.test(proto)) {
        return { status: 'warn', summary: `Veraltetes Protokoll: ${proto}`, detail: result };
      }
      const cipher = asStr(asObj(r.cipher)?.name);
      if (grade) return { status: 'pass', summary: `Grade ${grade} · ${proto}`, detail: result };
      return { status: 'pass', summary: `${proto}${cipher ? ` · ${cipher}` : ''}`, detail: result };
    }

    case 'hsts': {
      const enabled = r.compatible === true || !!asStr(r.hstsHeader);
      const { maxAge } = parseHsts(asStr(r.hstsHeader));
      return enabled
        ? { status: 'pass', summary: `Aktiv${maxAge ? ` · ${Math.round(maxAge / 86400)} Tage` : ''}`, detail: result }
        : { status: 'warn', summary: 'HSTS nicht aktiv', detail: result };
    }

    case 'http-headers': {
      // Reale Antwort IST die (lowercased) Header-Map. present/missing aus Keys.
      const keys = Object.keys(r).map((k) => k.toLowerCase());
      const missing = SEC_HEADERS.filter((h) => !keys.includes(h));
      if (missing.length >= 4) return { status: 'fail', summary: `${missing.length} wichtige Header fehlen`, detail: result };
      if (missing.length > 0) return { status: 'warn', summary: `${missing.length} Header fehlen`, detail: result };
      return { status: 'pass', summary: 'Sicherheits-Header gesetzt', detail: result };
    }

    case 'http-security': {
      // Reale Antwort = 10 Booleans (Header vorhanden ja/nein).
      const present = Object.keys(HTTP_SEC_LABELS).filter((k) => r[k] === true).length;
      const total = Object.keys(HTTP_SEC_LABELS).length;
      const coreMissing = HTTP_SEC_CORE.filter((k) => r[k] !== true).length;
      if (coreMissing >= 3) return { status: 'fail', summary: `${present}/${total} Security-Header`, detail: result };
      if (coreMissing >= 1) return { status: 'warn', summary: `${present}/${total} Security-Header`, detail: result };
      return { status: 'pass', summary: `${present}/${total} Security-Header`, detail: result };
    }

    case 'cookies': {
      // Reale Antwort = { headerCookies[], clientCookies[{secure,httpOnly,…}] }.
      const client = asArr(r.clientCookies).filter(isObj);
      const insecure = client.filter((c) => c.secure === false);
      if (insecure.length > 0) {
        return { status: 'warn', summary: `${insecure.length} Cookie${insecure.length > 1 ? 's' : ''} ohne Secure`, detail: result };
      }
      const n = client.length || asArr(r.headerCookies).length;
      return { status: 'pass', summary: n > 0 ? `${n} Cookie${n > 1 ? 's' : ''}` : 'Keine Cookies', detail: result };
    }

    case 'firewall': {
      // Reale Antwort = { hasWaf, waf }. (Alt: hasFirewall/detected — existierte nie.)
      const detected = r.hasWaf === true;
      const name = asStr(r.waf);
      return detected
        ? { status: 'pass', summary: name ?? 'WAF erkannt', detail: result }
        : { status: 'warn', summary: 'Kein WAF erkannt', detail: result };
    }

    case 'ports': {
      const ports = asArr(r.openPorts).length > 0 ? asArr(r.openPorts) : asArr(r.ports);
      if (ports.length >= 5) return { status: 'warn', summary: `${ports.length} offene Ports`, detail: result };
      if (ports.length > 0) return { status: 'warn', summary: `${ports.length} offene Port${ports.length > 1 ? 's' : ''}`, detail: result };
      return { status: 'pass', summary: 'Keine unerwarteten Ports', detail: result };
    }

    case 'dns': {
      const recs = dnsRecords(r);
      return { status: 'pass', summary: recs.length > 0 ? `${recs.length} Records` : 'Records vorhanden', detail: result };
    }

    case 'dnssec': {
      // Reale Antwort = { DNSKEY:{isFound}, DS:{isFound}, RRSIG:{isFound} }.
      const found = (k: string) => isObj(r[k]) && (r[k] as ObjLike).isFound === true;
      const enabled = found('DNSKEY') || found('DS') || found('RRSIG');
      return enabled
        ? { status: 'pass', summary: 'DNSSEC aktiv', detail: result }
        : { status: 'warn', summary: 'DNSSEC nicht aktiv', detail: result };
    }

    case 'dns-server': {
      // Reale Antwort = { domain, dns:[{address,hostname}] }.
      const servers = asArr(r.dns);
      return { status: 'pass', summary: servers.length > 0 ? `${servers.length} DNS-Server` : 'OK', detail: result };
    }

    case 'txt-records': {
      // Reale Antwort = flaches Objekt { key: value }. Anzahl = Schlüssel.
      const n = Object.keys(r).filter((k) => k !== 'error' && k !== 'skipped').length;
      return { status: 'pass', summary: `${n} TXT-Record${n !== 1 ? 's' : ''}`, detail: result };
    }

    case 'mail-config': {
      // VEC-413 Bug #1: aus txtRecords parsen, nicht aus erfundenen Flags.
      const f = mailFacts(r);
      if (!f.hasSPF && !f.hasDMARC) return { status: 'fail', summary: 'SPF und DMARC fehlen', detail: result };
      if (!f.hasSPF) return { status: 'warn', summary: 'SPF fehlt', detail: result };
      if (!f.hasDMARC) return { status: 'warn', summary: 'DMARC fehlt', detail: result };
      if (f.dmarcPolicy === 'none') return { status: 'warn', summary: 'DMARC nur im Monitoring (p=none)', detail: result };
      const note = !f.hasDKIM ? ' · DKIM nicht erkannt' : '';
      return { status: 'pass', summary: `SPF + DMARC aktiv${f.dmarcPolicy ? ` (p=${f.dmarcPolicy})` : ''}${note}`, detail: result };
    }

    case 'security-txt': {
      const found = r.isPresent === true || r.found === true || r.exists === true || !!r.securityTxt;
      return found
        ? { status: 'pass', summary: 'security.txt vorhanden', detail: result }
        : { status: 'warn', summary: 'security.txt fehlt', detail: result };
    }

    case 'redirects': {
      const chain = asArr(r.redirects);
      if (chain.length > 4) return { status: 'warn', summary: `${chain.length - 1} Weiterleitungen`, detail: result };
      const hops = Math.max(0, chain.length - 1);
      return { status: 'pass', summary: hops > 0 ? `${hops} Weiterleitung${hops > 1 ? 'en' : ''}` : 'Keine Weiterleitungen', detail: result };
    }

    case 'threats': {
      // Reale Antwort = { safeBrowsing, urlHaus, phishTank, cloudmersive }.
      return threatHit(r)
        ? { status: 'fail', summary: 'Bedrohung erkannt', detail: result }
        : { status: 'pass', summary: 'Keine Bedrohungen', detail: result };
    }

    case 'block-lists': {
      // Reale Antwort = { blocklists:[{server,serverIp,isBlocked}] }.
      const lists = asArr(r.blocklists).filter(isObj);
      const blocked = lists.filter((l) => l.isBlocked === true).length;
      if (blocked > 0) return { status: 'fail', summary: `Auf ${blocked} Resolver${blocked !== 1 ? 'n' : ''} blockiert`, detail: result };
      return { status: 'pass', summary: 'Nicht blockiert', detail: result };
    }

    case 'get-ip': {
      // Reale Antwort = { ip, family }. (Geo/ASN steckt im separaten location-Modul.)
      const ip = asStr(r.ip);
      const family = asNum(r.family);
      return { status: 'pass', summary: ip ? `${ip}${family ? ` · IPv${family}` : ''}` : 'IP-Info verfügbar', detail: result };
    }

    case 'location': {
      // VEC-416: `location`-Modul (web-check 2.1.9, key-frei via ipwho.is/
      // ip-api.com/geojs.io/reallyfreegeoip + restcountries). Reale Antwort:
      // { ip, city, region, country_name, country_code, postal, latitude,
      //   longitude, org, timezone, ... }. Reines Info-Modul → immer pass.
      // Defensiv gegen Provider-Varianten (country/lat/lon, timezone als Objekt).
      const country = asStr(r.country_name) ?? asStr(r.country);
      const city = asStr(r.city);
      const parts = [country, city].filter(Boolean);
      return {
        status: 'pass',
        summary: parts.length > 0 ? parts.join(' · ') : 'Standort-Info verfügbar',
        detail: result,
      };
    }

    case 'server-status': {
      // Reale Antwort = { isUp, responseCode, responseTime, dnsLookupTime }.
      if (r.isUp === false) return { status: 'fail', summary: 'Nicht erreichbar', detail: result };
      const code = asNum(r.responseCode) ?? asNum(r.statusCode) ?? 200;
      if (code >= 500) return { status: 'fail', summary: `HTTP ${code}`, detail: result };
      if (code >= 400) return { status: 'warn', summary: `HTTP ${code}`, detail: result };
      return { status: 'pass', summary: `HTTP ${code} OK`, detail: result };
    }

    case 'screenshot': {
      const hasData = !!asStr(r.image) || !!asStr(r.screenshot);
      return hasData
        ? { status: 'pass', summary: 'Screenshot erstellt', detail: result }
        : { status: 'warn', summary: 'Screenshot nicht verfügbar', detail: result };
    }

    default:
      return { status: 'pass', summary: 'OK', detail: result };
  }
}

// ---------------------------------------------------------------------------
// Detail-Extraktion (treibt CheckTile progressive disclosure) — VEC-395/399/413
//
// Liefert pro Modul strukturierte Detail-Blöcke. Mapping gegen die REALE
// web-check-2.1.9-Antwort (VEC-413). Defensiv: jedes Feld wird typgeprüft;
// fehlt/ist ein Feld unerwartet, entfällt lieber der Block als ein Crash.
// `hiddenCount` bleibt 0 (VEC-399: keine Caps, alle Rohdaten frei sichtbar).
// ---------------------------------------------------------------------------

function asObj(v: unknown): ObjLike | null {
  return isObj(v) ? v : null;
}

type KvItem = { key: string; value: string; badge?: BadgeVariant };

export function extractDetail(result: CheckResult): { detail: DetailBlock[]; hiddenCount: number } {
  const r = asObj(result.detail);
  const hiddenCount = 0;
  if (!r) return { detail: [], hiddenCount };
  // "Nicht anwendbar" (skipped) → kein Detail-Block (Summary trägt die Aussage).
  if (typeof r.skipped === 'string') return { detail: [], hiddenCount };

  const detail: DetailBlock[] = [];

  switch (result.key) {
    case 'ssl': {
      const kv: KvItem[] = [];
      const issuer = sslCertName(r.issuer, 'O');
      const subject = sslCertName(r.subject, 'CN');
      const validFrom = asStr(r.valid_from) ?? asStr(r.validFrom);
      const validTo = asStr(r.valid_to) ?? asStr(r.validTo) ?? asStr(r.validUntil);
      const days = sslDaysUntilExpiry(r);
      const keySize = asNum(r.bits) ?? asNum(r.keySize);
      const serial = asStr(r.serialNumber);
      if (issuer) kv.push({ key: 'Aussteller', value: issuer });
      if (subject) kv.push({ key: 'Domain', value: subject });
      if (validFrom) kv.push({ key: 'Gültig ab', value: validFrom });
      if (validTo) kv.push({ key: 'Gültig bis', value: validTo });
      if (days !== null) kv.push({ key: 'Noch gültig', value: `${days} Tage`, badge: expiryVariant(days) });
      if (keySize !== undefined) kv.push({ key: 'Schlüssellänge', value: `${keySize} bit` });
      if (serial) kv.push({ key: 'Seriennummer', value: truncate(serial, 40) });
      // VEC-415: SHA-256-Fingerprint (~95 Zeichen → automatisch Long-Layout im Tile).
      const fp256 = asStr(r.fingerprint256);
      if (fp256) kv.push({ key: 'SHA-256', value: fp256 });
      if (kv.length > 0) detail.push({ type: 'kv', items: kv });
      // Extended Key Usage als badge-row nach dem KV-Block (VEC-415).
      const eku = asArr(r.ext).filter((e): e is string => typeof e === 'string');
      if (eku.length > 0) {
        detail.push({
          type: 'badge-row',
          title: 'Extended Key Usage',
          items: eku.map((e) => ({ label: e, variant: 'neutral' as BadgeVariant })),
        });
      }
      const sans = sslSans(r);
      if (sans.length > 0) {
        detail.push({ type: 'kv', items: sans.map((s) => ({ key: 'SAN', value: s })), scrollable: sans.length > 8 });
      }
      break;
    }

    case 'tls': {
      // tls-connection: protocol (string), cipher{name,standardName,version},
      // alpnProtocol, forwardSecrecy, ocspStapled, ephemeralKey, sessionResumption.
      // VEC-415: Grade + Vulnerability-Checks werden defensiv gemappt — sind sie
      // (noch) nicht in der Upstream-Antwort, entsteht schlicht kein Block.

      // 1. TLS-Grade als erste Info (sofern vorhanden).
      const grade = asStr(r.grade) ?? asStr(asObj(r.report)?.grade);
      if (grade) detail.push({ type: 'kv', items: [{ key: 'TLS-Grade', value: grade, badge: gradeVariant(grade) }] });

      // 2. Protokolle.
      const proto = asStr(r.protocol);
      if (proto) detail.push({ type: 'badge-row', title: 'Protokolle', items: [{ label: proto, variant: protoVariant(proto) }] });

      // 3. Verbindungsqualität.
      const kv: KvItem[] = [];
      const cipher = asObj(r.cipher);
      const cipherName = asStr(cipher?.name);
      if (cipherName) kv.push({ key: 'Cipher', value: cipherName });
      const stdName = asStr(cipher?.standardName);
      if (stdName && stdName !== cipherName) kv.push({ key: 'Standard-Name', value: stdName });
      const alpn = asStr(r.alpnProtocol);
      if (alpn) kv.push({ key: 'ALPN', value: alpn });
      if (typeof r.forwardSecrecy === 'boolean')
        kv.push({ key: 'Forward Secrecy', value: yesNo(r.forwardSecrecy), badge: r.forwardSecrecy ? 'ok' : 'warn' });
      if (typeof r.ocspStapled === 'boolean')
        kv.push({ key: 'OCSP Stapling', value: yesNo(r.ocspStapled), badge: r.ocspStapled ? 'ok' : 'warn' });
      const ek = asObj(r.ephemeralKey);
      const ekName = asStr(ek?.name) ?? asStr(ek?.type);
      const ekSize = asNum(ek?.size);
      if (ekName) kv.push({ key: 'Ephemeral Key', value: ekSize ? `${ekName} (${ekSize} bit)` : ekName });
      if (typeof r.sessionResumption === 'boolean') kv.push({ key: 'Session-Resumption', value: yesNo(r.sessionResumption) });
      if (kv.length > 0) detail.push({ type: 'kv', title: 'Verbindungsqualität', items: kv });

      // 4. Schwachstellen-Prüfungen (Heartbleed/POODLE/…): true = verwundbar (fail),
      // false = bestanden (ok). Defensiv über vulnerabilities-Objekt; fehlgeschlagene
      // zuerst, dann bestanden. Leere Liste → Block weglassen.
      const vulns = asObj(r.vulnerabilities) ?? asObj(r.vulns);
      if (vulns) {
        const checks = Object.entries(vulns)
          .filter(([, v]) => typeof v === 'boolean')
          .map(([name, v]) => ({ name, vulnerable: v === true }))
          .sort((a, b) => Number(b.vulnerable) - Number(a.vulnerable));
        if (checks.length > 0) {
          detail.push({
            type: 'list',
            title: 'Schwachstellen-Prüfungen',
            scrollable: true,
            items: checks.map((c) => ({ text: c.name, badge: (c.vulnerable ? 'fail' : 'ok') as BadgeVariant })),
          });
        }
      }
      break;
    }

    case 'hsts': {
      const enabled = r.compatible === true || !!asStr(r.hstsHeader);
      const h = parseHsts(asStr(r.hstsHeader));
      const kv: KvItem[] = [{ key: 'Status', value: enabled ? 'aktiv' : 'inaktiv', badge: enabled ? 'ok' : 'warn' }];
      if (h.maxAge !== undefined) kv.push({ key: 'Max-Age', value: `${Math.round(h.maxAge / 86400)} Tage` });
      kv.push({ key: 'includeSubDomains', value: yesNo(h.includeSubDomains) });
      kv.push({ key: 'Preload', value: yesNo(h.preload) });
      if (typeof r.compatible === 'boolean')
        kv.push({ key: 'Preload-Liste-fähig', value: yesNo(r.compatible), badge: r.compatible ? 'ok' : 'neutral' });
      detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'http-headers': {
      // r IST die Header-Map. present/missing aus Keys; Server-Header zeigen.
      const keys = Object.keys(r);
      const lower = keys.map((k) => k.toLowerCase());
      const present = SEC_HEADERS.filter((h) => lower.includes(h));
      const missing = SEC_HEADERS.filter((h) => !lower.includes(h));
      if (present.length > 0) {
        detail.push({ type: 'list', items: present.map((h) => ({ text: h, badge: 'ok' as BadgeVariant })), scrollable: present.length > 8 });
      }
      if (missing.length > 0) {
        detail.push({ type: 'list', items: missing.map((h) => ({ text: h, badge: 'fail' as BadgeVariant })), scrollable: missing.length > 8 });
      }
      const server = asStr(r.server);
      if (server) detail.push({ type: 'kv', items: [{ key: 'Server', value: truncate(server, 60) }] });
      // VEC-415: vollständiger Header-Dump (alle Nicht-Security-Header, ohne
      // Meta-/bereits-gezeigte Keys), scrollbar bei > 8 Einträgen.
      const SKIP = new Set(['error', 'skipped', 'server', ...SEC_HEADERS]);
      const otherHeaders = Object.entries(r)
        .filter(([k]) => !SKIP.has(k.toLowerCase()))
        .map(([k, v]) => ({ key: k, value: truncate(String(v), 80) }));
      if (otherHeaders.length > 0) {
        detail.push({ type: 'kv', title: 'Alle Header', items: otherHeaders, scrollable: otherHeaders.length > 8 });
      }
      break;
    }

    case 'http-security': {
      const items = Object.entries(HTTP_SEC_LABELS).map(([k, label]) => ({
        text: label,
        badge: (r[k] === true ? 'ok' : 'fail') as BadgeVariant,
      }));
      detail.push({ type: 'list', items, scrollable: items.length > 8 });
      break;
    }

    case 'cookies': {
      const client = asArr(r.clientCookies).filter(isObj);
      if (client.length > 0) {
        const items: KvItem[] = client.map((c) => {
          const name = asStr(c.name) ?? 'Cookie';
          const flag = (label: string, v: unknown) => `${label} ${v === true ? '✓' : '✗'}`;
          const same = asStr(c.sameSite);
          const parts = [flag('Secure', c.secure), flag('HttpOnly', c.httpOnly), same ? `SameSite: ${same}` : null].filter(Boolean) as string[];
          return { key: name, value: parts.join(' · '), badge: c.secure === false ? ('warn' as BadgeVariant) : undefined };
        });
        detail.push({ type: 'kv', items, scrollable: items.length > 8 });
      } else {
        const header = asArr(r.headerCookies).filter((c): c is string => typeof c === 'string');
        if (header.length > 0) {
          detail.push({ type: 'list', items: header.map((c) => ({ text: truncate(c, 80) })), scrollable: header.length > 8 });
        }
      }
      break;
    }

    case 'firewall': {
      const detected = r.hasWaf === true;
      const name = asStr(r.waf);
      detail.push({ type: 'kv', items: [{ key: 'WAF erkannt', value: detected ? (name ?? 'ja') : 'nein', badge: detected ? 'ok' : 'warn' }] });
      break;
    }

    case 'ports': {
      const ports = asArr(r.openPorts).length > 0 ? asArr(r.openPorts) : asArr(r.ports);
      if (ports.length > 0) {
        const items: KvItem[] = ports.map((p) => {
          if (typeof p === 'number') return { key: String(p), value: '' };
          const o = asObj(p);
          const num = asNum(o?.port) ?? asNum(o?.portNumber);
          const svc = asStr(o?.service) ?? '';
          return { key: num !== undefined ? String(num) : '?', value: svc };
        });
        detail.push({ type: 'kv', items, scrollable: items.length > 8 });
      }
      break;
    }

    case 'dns': {
      const recs = dnsRecords(r);
      if (recs.length > 0) {
        detail.push({ type: 'kv', items: recs.map((x) => ({ key: x.type, value: x.value })), scrollable: recs.length > 8 });
      }
      break;
    }

    case 'dnssec': {
      const found = (k: string) => isObj(r[k]) && (r[k] as ObjLike).isFound === true;
      const dnskey = found('DNSKEY');
      const ds = found('DS');
      const rrsig = found('RRSIG');
      const enabled = dnskey || ds || rrsig;
      detail.push({
        type: 'kv',
        items: [
          { key: 'DNSSEC aktiv', value: yesNo(enabled), badge: enabled ? 'ok' : 'warn' },
          { key: 'DNSKEY', value: yesNo(dnskey) },
          { key: 'DS', value: yesNo(ds) },
          { key: 'RRSIG (AD)', value: yesNo(rrsig) },
        ],
      });
      break;
    }

    case 'dns-server': {
      // VEC-415: Hostname → IP als KV (statt flacher Liste). Reale 2.1.9-Form ist
      // { dns:[{ address, hostname }] }; fällt auf String-Servernamen zurück.
      const items: KvItem[] = asArr(r.dns)
        .map((s) => {
          const o = asObj(s);
          if (o) {
            const host = asStr(o.hostname) ?? asStr(o.name);
            const ip = asStr(o.address) ?? asStr(o.ip);
            if (host && ip && host !== ip) return { key: host, value: ip };
            return { key: 'Server', value: host ?? ip ?? '' };
          }
          return { key: 'Server', value: asStr(s) ?? '' };
        })
        .filter((it) => it.value);
      if (items.length > 0) detail.push({ type: 'kv', items, scrollable: items.length > 8 });
      break;
    }

    case 'txt-records': {
      // r = flaches Objekt { key: value } → "key=value" rekonstruieren, SPF zuerst.
      const recs = Object.entries(r)
        .filter(([k]) => k !== 'error' && k !== 'skipped')
        .map(([k, v]) => (typeof v === 'string' && v !== '' ? `${k}=${v}` : k));
      if (recs.length > 0) {
        const sorted = [...recs].sort((a, b) => (/^v=spf1/i.test(b) ? 1 : 0) - (/^v=spf1/i.test(a) ? 1 : 0));
        detail.push({ type: 'list', items: sorted.map((t) => ({ text: truncate(t, 120) })), scrollable: sorted.length > 8 });
      }
      break;
    }

    case 'mail-config': {
      const f = mailFacts(r);
      const dmarcBadge: BadgeVariant = !f.hasDMARC ? 'fail' : /reject|quarantine/.test(f.dmarcPolicy ?? '') ? 'ok' : 'warn';
      const dmarcVal = !f.hasDMARC ? 'nicht konfiguriert' : f.dmarcPolicy ? `p=${f.dmarcPolicy}` : 'konfiguriert';
      detail.push({
        type: 'kv',
        items: [
          { key: 'SPF', value: f.spf ? truncate(f.spf, 60) : 'nicht konfiguriert', badge: f.hasSPF ? 'ok' : 'warn' },
          { key: 'DMARC', value: dmarcVal, badge: dmarcBadge },
          { key: 'DKIM', value: f.hasDKIM ? 'erkannt' : 'nicht erkannt', badge: f.hasDKIM ? 'ok' : 'neutral' },
          { key: 'BIMI', value: f.hasBIMI ? 'konfiguriert' : 'nicht konfiguriert', badge: f.hasBIMI ? 'ok' : 'neutral' },
        ],
      });
      const mx = asArr(r.mxRecords)
        .map((m) => {
          const o = asObj(m);
          return asStr(o?.exchange);
        })
        .filter((s): s is string => !!s);
      if (mx.length > 0) detail.push({ type: 'list', items: mx.map((t) => ({ text: t })), scrollable: mx.length > 8 });
      const services = asArr(r.mailServices)
        .map((s) => asStr(asObj(s)?.provider))
        .filter((s): s is string => !!s);
      if (services.length > 0) detail.push({ type: 'kv', items: [{ key: 'Mail-Provider', value: services.join(', ') }] });
      break;
    }

    case 'security-txt': {
      const found = r.isPresent === true || r.found === true || r.exists === true || !!r.securityTxt;
      const fields = asObj(r.fields) ?? r;
      // Felder sind RFC-9116-case ("Contact", "Expires") → case-insensitiv lesen.
      const fieldVal = (name: string): string | undefined => {
        for (const [k, v] of Object.entries(fields)) {
          if (k.toLowerCase() === name && typeof v === 'string' && v.trim() !== '') return v;
        }
        return undefined;
      };
      const kv: KvItem[] = [{ key: 'Gefunden', value: yesNo(found), badge: found ? 'ok' : 'warn' }];
      const contact = fieldVal('contact');
      const expires = fieldVal('expires');
      if (contact) kv.push({ key: 'Contact', value: truncate(contact, 60) });
      if (expires) kv.push({ key: 'Expires', value: expires });
      detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'redirects': {
      const chain = asArr(r.redirects).filter((s): s is string => typeof s === 'string');
      if (chain.length > 0) {
        detail.push({ type: 'list', items: chain.map((s) => ({ text: truncate(s, 100) })), scrollable: chain.length > 8 });
      }
      break;
    }

    case 'threats': {
      const verdict = (label: string, src: unknown): KvItem | null => {
        const o = asObj(src);
        if (!o) return null;
        if (typeof o.skipped === 'string') return { key: label, value: 'nicht geprüft' };
        if (typeof o.error === 'string') return { key: label, value: 'Quelle nicht erreichbar' };
        return null;
      };
      const items: KvItem[] = [
        { key: 'Bedrohung', value: threatHit(r) ? 'erkannt' : 'keine', badge: threatHit(r) ? 'fail' : 'ok' },
      ];
      for (const [label, key] of [
        ['Safe Browsing', 'safeBrowsing'],
        ['URLhaus', 'urlHaus'],
        ['PhishTank', 'phishTank'],
        ['Cloudmersive', 'cloudmersive'],
      ] as const) {
        const v = verdict(label, r[key]);
        if (v) items.push(v);
      }
      detail.push({ type: 'kv', items });
      break;
    }

    case 'block-lists': {
      const lists = asArr(r.blocklists).filter(isObj);
      const blocked = lists.filter((l) => l.isBlocked === true);
      detail.push({
        type: 'kv',
        items: [{ key: 'Blockierende Resolver', value: `${blocked.length} / ${lists.length}`, badge: blocked.length > 0 ? 'fail' : 'ok' }],
      });
      if (blocked.length > 0) {
        const names = blocked.map((l) => asStr(l.server)).filter((s): s is string => !!s);
        if (names.length > 0) detail.push({ type: 'list', items: names.map((t) => ({ text: t, badge: 'fail' as BadgeVariant })) });
      }
      break;
    }

    case 'get-ip': {
      const ip = asStr(r.ip);
      const family = asNum(r.family);
      const kv: KvItem[] = [];
      if (ip) kv.push({ key: 'IP-Adresse', value: ip });
      if (family) kv.push({ key: 'IP-Version', value: `IPv${family}` });
      // VEC-415: ASN/ISP separat, sofern vorhanden ("AS12345 · Cloudflare, Inc.").
      const asnNum = asNum(r.asn) ?? asNum(r.asnNumber);
      const asnOrg = asStr(r.asOrganization) ?? asStr(r.org) ?? asStr(r.isp);
      const ispDisplay = [asnNum ? `AS${asnNum}` : null, asnOrg].filter(Boolean).join(' · ');
      if (ispDisplay) kv.push({ key: 'ISP / AS', value: ispDisplay });
      if (kv.length > 0) detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'location': {
      // VEC-416: Geo/ASN aus dem `location`-Modul. Mapping gegen die reale
      // 2.1.9-Antwort, defensiv gegen Provider-Varianten (org↔asn/isp,
      // latitude/longitude↔lat/lon, timezone als String ODER { id }).
      const kv: KvItem[] = [];
      const country = asStr(r.country_name) ?? asStr(r.country);
      const cc = asStr(r.country_code);
      if (country) kv.push({ key: 'Land', value: cc ? `${country} (${cc})` : country });
      const city = asStr(r.city);
      const region = asStr(r.region) ?? asStr(r.region_code);
      if (city) kv.push({ key: 'Stadt', value: region ? `${city}, ${region}` : city });
      const postal = asStr(r.postal);
      if (postal) kv.push({ key: 'PLZ', value: postal });
      const org = asStr(r.org) ?? asStr(r.asn) ?? asStr(r.isp);
      if (org) kv.push({ key: 'Netzbetreiber (ASN/Org)', value: truncate(org, 60) });
      const tz = asStr(r.timezone) ?? asStr(asObj(r.timezone)?.id);
      if (tz) kv.push({ key: 'Zeitzone', value: tz });
      const lat = asNum(r.latitude) ?? asNum(r.lat);
      const lon = asNum(r.longitude) ?? asNum(r.lon) ?? asNum(r.lng);
      if (lat !== undefined && lon !== undefined) {
        kv.push({ key: 'Koordinaten', value: `${lat}, ${lon}` });
      }
      if (kv.length > 0) detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'server-status': {
      const code = asNum(r.responseCode) ?? asNum(r.statusCode) ?? 200;
      const rt = asNum(r.responseTime);
      const dnsT = asNum(r.dnsLookupTime);
      const kv: KvItem[] = [{ key: 'HTTP-Status', value: String(code), badge: statusCodeVariant(code) }];
      if (r.isUp === false) kv.push({ key: 'Erreichbar', value: 'nein', badge: 'fail' });
      if (rt !== undefined) kv.push({ key: 'Antwortzeit', value: `${Math.round(rt)} ms` });
      if (dnsT !== undefined) kv.push({ key: 'DNS-Lookup', value: `${Math.round(dnsT)} ms` });
      detail.push({ type: 'kv', items: kv });
      break;
    }

    // screenshot: separat als ScreenshotSection gerendert — kein Detail-Block.
    default:
      break;
  }

  return { detail, hiddenCount };
}

// ---------------------------------------------------------------------------
// Kategorie-Mapping für die UI
// ---------------------------------------------------------------------------

export const GROUP_LABELS: Record<CheckGroup, string> = {
  tls: 'Zertifikat & TLS',
  security: 'HTTP-Sicherheit',
  dns: 'DNS',
  mail: 'E-Mail',
  network: 'Infrastruktur',
  info: 'Info',
};

export const GROUP_ORDER: CheckGroup[] = ['tls', 'security', 'dns', 'mail', 'network', 'info'];

// Severity-Score für Sortierung (fail zuerst)
export function statusScore(s: CheckStatus): number {
  switch (s) {
    case 'fail': return 0;
    case 'warn': return 1;
    case 'pass': return 2;
    case 'error': return 3;
    default: return 4;
  }
}

// Gesamtampel aus allen Ergebnissen
export function overallStatus(results: CheckResult[]): 'fail' | 'warn' | 'pass' | null {
  if (results.length === 0) return null;
  const terminal = results.filter(r => ['pass', 'warn', 'fail'].includes(r.status));
  if (terminal.length === 0) return null;
  if (terminal.some(r => r.status === 'fail')) return 'fail';
  if (terminal.some(r => r.status === 'warn')) return 'warn';
  return 'pass';
}
