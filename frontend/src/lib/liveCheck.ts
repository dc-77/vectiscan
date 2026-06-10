/**
 * Live-Check (SofortScan) — Frontend-Lib (VEC-366).
 * Kapselt alle API-Calls an /api/live-check/* und leitet Modul-Roh-Daten
 * in CheckStatus (pass/warn/fail/error) um.
 */
import { getToken } from './auth';

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

function deriveStatus(
  moduleKey: string,
  result: unknown,
): Pick<CheckResult, 'status' | 'summary' | 'detail'> {
  if (!result) return { status: 'error', summary: 'Keine Daten', detail: null };

  const r = isObj(result) ? result : {};

  switch (moduleKey) {
    case 'ssl': {
      // Upstream: { valid, daysUntilExpiry, issuer, ... }
      const expiry = typeof r.daysUntilExpiry === 'number' ? r.daysUntilExpiry : null;
      const valid = r.valid === true || (expiry !== null && expiry > 0);
      if (!valid) return { status: 'fail', summary: 'Ungültig oder abgelaufen', detail: result };
      if (expiry !== null && expiry < 14) return { status: 'fail', summary: `Läuft in ${expiry} Tagen ab`, detail: result };
      if (expiry !== null && expiry < 30) return { status: 'warn', summary: `Läuft in ${expiry} Tagen ab`, detail: result };
      const issuer = typeof r.issuer === 'string' ? r.issuer : '';
      return { status: 'pass', summary: `Gültig${expiry !== null ? ` · ${expiry} Tage` : ''}${issuer ? ` · ${issuer}` : ''}`, detail: result };
    }

    case 'tls': {
      // Look for weak protocols (TLS 1.0/1.1, SSL)
      const protocols: string[] = Array.isArray(r.supportedProtocols)
        ? (r.supportedProtocols as string[])
        : [];
      const weak = protocols.filter(p => /TLSv1\.0|TLSv1\.1|SSLv/i.test(p));
      if (weak.length > 0) return { status: 'warn', summary: `Veraltete Protokolle: ${weak.join(', ')}`, detail: result };
      return { status: 'pass', summary: protocols.length > 0 ? protocols[protocols.length - 1] : 'Konfiguration OK', detail: result };
    }

    case 'hsts': {
      const enabled = r.compatible === true || r.isEnabled === true || !!r.hstsHeader;
      const maxAge = typeof r.maxAge === 'number' ? r.maxAge : 0;
      return enabled
        ? { status: 'pass', summary: `Aktiv${maxAge > 0 ? ` · ${Math.round(maxAge / 86400)} Tage` : ''}`, detail: result }
        : { status: 'warn', summary: 'HSTS nicht aktiv', detail: result };
    }

    case 'http-headers': {
      const missing: string[] = Array.isArray(r.missingHeaders) ? (r.missingHeaders as string[]) : [];
      if (missing.length >= 4) return { status: 'fail', summary: `${missing.length} wichtige Header fehlen`, detail: result };
      if (missing.length > 0) return { status: 'warn', summary: `${missing.length} Header fehlen`, detail: result };
      return { status: 'pass', summary: 'Sicherheits-Header gesetzt', detail: result };
    }

    case 'http-security': {
      const score = typeof r.score === 'number' ? r.score : null;
      if (score !== null) {
        if (score < 50) return { status: 'fail', summary: `Score ${score}/100`, detail: result };
        if (score < 75) return { status: 'warn', summary: `Score ${score}/100`, detail: result };
        return { status: 'pass', summary: `Score ${score}/100`, detail: result };
      }
      const issues: unknown[] = Array.isArray(r.issues) ? r.issues : [];
      if (issues.length > 2) return { status: 'warn', summary: `${issues.length} Probleme`, detail: result };
      return { status: 'pass', summary: 'Features konfiguriert', detail: result };
    }

    case 'cookies': {
      const insecure: unknown[] = Array.isArray(r.insecureCookies)
        ? r.insecureCookies
        : Array.isArray(r.unsecureCookies) ? r.unsecureCookies : [];
      if (insecure.length >= 3) return { status: 'fail', summary: `${insecure.length} unsichere Cookies`, detail: result };
      if (insecure.length > 0) return { status: 'warn', summary: `${insecure.length} unsichere Cookie${insecure.length > 1 ? 's' : ''}`, detail: result };
      return { status: 'pass', summary: 'Cookies korrekt gesetzt', detail: result };
    }

    case 'firewall': {
      const detected = r.hasFirewall === true || r.detected === true || r.firewallDetected === true;
      const name = typeof r.firewall === 'string' ? r.firewall : typeof r.waf === 'string' ? r.waf : '';
      return detected
        ? { status: 'pass', summary: name || 'WAF erkannt', detail: result }
        : { status: 'warn', summary: 'Kein WAF erkannt', detail: result };
    }

    case 'ports': {
      const ports: unknown[] = Array.isArray(r.ports) ? r.ports : Array.isArray(r.openPorts) ? r.openPorts : [];
      if (ports.length >= 5) return { status: 'warn', summary: `${ports.length} offene Ports`, detail: result };
      if (ports.length > 0) return { status: 'warn', summary: `${ports.length} offene Port${ports.length > 1 ? 's' : ''}`, detail: result };
      return { status: 'pass', summary: 'Keine unerwarteten Ports', detail: result };
    }

    case 'dns': {
      const types: string[] = Array.isArray(r.dns)
        ? (r.dns as Array<{ type: string }>).map(d => d.type)
        : [];
      return { status: 'pass', summary: types.length > 0 ? `${types.length} Records` : 'Records vorhanden', detail: result };
    }

    case 'dnssec': {
      const enabled = r.isDnssecEnabled === true || r.dnssecEnabled === true || r.valid === true || r.isPresent === true;
      return enabled
        ? { status: 'pass', summary: 'DNSSEC aktiv', detail: result }
        : { status: 'warn', summary: 'DNSSEC nicht aktiv', detail: result };
    }

    case 'dns-server': {
      const servers: unknown[] = Array.isArray(r.dnsServer) ? r.dnsServer : [];
      return { status: 'pass', summary: servers.length > 0 ? `${servers.length} DNS-Server` : 'OK', detail: result };
    }

    case 'txt-records': {
      const records: unknown[] = Array.isArray(r.txtRecords) ? r.txtRecords : Array.isArray(r.records) ? r.records : [];
      return { status: 'pass', summary: `${records.length} TXT-Record${records.length !== 1 ? 's' : ''}`, detail: result };
    }

    case 'mail-config': {
      const hasSPF = !!(r.spf || r.hasSPF);
      const hasDKIM = !!(r.dkim || r.hasDKIM);
      const hasDMARC = !!(r.dmarc || r.hasDMARC);
      const missing = [!hasSPF && 'SPF', !hasDKIM && 'DKIM', !hasDMARC && 'DMARC'].filter(Boolean) as string[];
      if (missing.length >= 2) return { status: 'fail', summary: `${missing.join(', ')} fehlt`, detail: result };
      if (missing.length === 1) return { status: 'warn', summary: `${missing[0]} fehlt`, detail: result };
      return { status: 'pass', summary: 'SPF, DKIM, DMARC aktiv', detail: result };
    }

    case 'security-txt': {
      const found = r.found === true || r.isPresent === true || r.exists === true || !!r.securityTxt;
      return found
        ? { status: 'pass', summary: 'security.txt vorhanden', detail: result }
        : { status: 'warn', summary: 'security.txt fehlt', detail: result };
    }

    case 'redirects': {
      const chain: unknown[] = Array.isArray(r.redirects) ? r.redirects : [];
      if (chain.length > 3) return { status: 'warn', summary: `${chain.length} Weiterleitungen`, detail: result };
      return { status: 'pass', summary: chain.length > 0 ? `${chain.length} Weiterleitung${chain.length > 1 ? 'en' : ''}` : 'Keine Weiterleitungen', detail: result };
    }

    case 'threats': {
      const total = typeof r.totalThreats === 'number' ? r.totalThreats : 0;
      const malicious = r.malicious === true;
      if (malicious || total > 0) return { status: 'fail', summary: `${total || '?'} Bedrohungen erkannt`, detail: result };
      return { status: 'pass', summary: 'Keine Bedrohungen', detail: result };
    }

    case 'block-lists': {
      const listed = r.isListed === true || r.listed === true || (typeof r.listedOn === 'number' && r.listedOn > 0);
      const count = typeof r.listedOn === 'number' ? r.listedOn : 0;
      if (listed) return { status: 'fail', summary: `Auf ${count || '?'} Blockliste${count !== 1 ? 'n' : ''}`, detail: result };
      return { status: 'pass', summary: 'Nicht auf Blocklisten', detail: result };
    }

    case 'get-ip': {
      const ip = typeof r.ip === 'string' ? r.ip : typeof r.ipAddress === 'string' ? r.ipAddress : '';
      const country = typeof r.country === 'string' ? r.country : '';
      return { status: 'pass', summary: [ip, country].filter(Boolean).join(' · ') || 'IP-Info verfügbar', detail: result };
    }

    case 'server-status': {
      const status = typeof r.statusCode === 'number' ? r.statusCode : typeof r.status === 'number' ? r.status : 200;
      if (status >= 500) return { status: 'fail', summary: `HTTP ${status}`, detail: result };
      if (status >= 400) return { status: 'warn', summary: `HTTP ${status}`, detail: result };
      return { status: 'pass', summary: `HTTP ${status} OK`, detail: result };
    }

    case 'screenshot': {
      const hasData = !!r.screenshot || !!r.image || !!r.url;
      return hasData
        ? { status: 'pass', summary: 'Screenshot erstellt', detail: result }
        : { status: 'warn', summary: 'Screenshot nicht verfügbar', detail: result };
    }

    default:
      return { status: 'pass', summary: 'OK', detail: result };
  }
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
