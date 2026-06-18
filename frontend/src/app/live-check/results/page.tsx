'use client';

// ── SofortScan: Ergebnis-Dashboard (Screen 3 + 4) ────────────────
// Route: /live-check/results?target=example.com
// VEC-366 — UX nach VEC-365 §3/§4/§5

import { useEffect, useRef, useState, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn } from '@/lib/auth';

import CheckTile, { type DetailBlock, type BadgeVariant } from '@/components/ds/CheckTile';
import LiveCheckProgress from '@/components/ds/LiveCheckProgress';
import CTAStaircase from '@/components/ds/CTAStaircase';
import StateView from '@/components/ds/StateView';
import SeverityCounts from '@/components/SeverityCounts';
import SeverityDrilldown from '@/components/ds/SeverityDrilldown';

import {
  fetchModules,
  runModule,
  runPool,
  CLIENT_CONCURRENCY,
  overallStatus,
  statusScore,
  GROUP_LABELS,
  GROUP_ORDER,
  sslDaysUntilExpiry,
  sslCertName,
  sslSans,
  type CheckModule,
  type CheckResult,
  type CheckGroup,
  type CheckStatus,
} from '@/lib/liveCheck';

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

function ZapIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

function PassBigIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
function WarnBigIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 9v4" /><path d="M12 17h.01" />
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
    </svg>
  );
}
function FailBigIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="m15 9-6 6" /><path d="m9 9 6 6" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// useLiveCheck hook
// ---------------------------------------------------------------------------

type Phase = 'init' | 'running' | 'done' | 'aborted' | 'error';

function useLiveCheck(target: string) {
  const [modules, setModules] = useState<CheckModule[]>([]);
  const [results, setResults] = useState<Map<string, CheckResult>>(new Map());
  const [phase, setPhase] = useState<Phase>('init');
  const abortRef = useRef<AbortController | null>(null);
  const startedRef = useRef(false);

  const abort = useCallback(() => {
    abortRef.current?.abort();
    setPhase('aborted');
  }, []);

  useEffect(() => {
    if (!target || startedRef.current) return;
    startedRef.current = true;

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    async function run() {
      let mods: CheckModule[];
      try {
        mods = await fetchModules();
      } catch {
        if (!ctrl.signal.aborted) setPhase('error');
        return;
      }

      if (ctrl.signal.aborted) return;

      setModules(mods);
      setPhase('running');

      // Init all as 'running'
      setResults(new Map(mods.map(m => [m.key, { ...m, status: 'running' as CheckStatus, summary: 'Läuft…' }])));

      // Global 60s timeout
      const globalTimer = setTimeout(() => ctrl.abort(), 60_000);

      // Worker-Pool statt allSettled über alle Module: höchstens
      // CLIENT_CONCURRENCY (= Server-Cap 4) Modul-Aufrufe gleichzeitig, damit
      // die übrigen nicht sofort in 429 too_many_concurrent laufen (VEC-381).
      await runPool(mods, CLIENT_CONCURRENCY, async (m) => {
        if (ctrl.signal.aborted) return;
        try {
          const r = await runModule(m.key, target, ctrl.signal);
          if (!ctrl.signal.aborted) {
            setResults(prev => {
              const next = new Map(prev);
              next.set(m.key, { ...m, ...r });
              return next;
            });
          }
        } catch {
          if (!ctrl.signal.aborted) {
            setResults(prev => {
              const next = new Map(prev);
              next.set(m.key, { ...m, status: 'error', summary: 'Nicht verfügbar' });
              return next;
            });
          }
        }
      });

      clearTimeout(globalTimer);

      if (!ctrl.signal.aborted) {
        setPhase('done');
      } else {
        setPhase('aborted');
      }
    }

    run();

    return () => {
      ctrl.abort();
    };
  }, [target]);

  const done = Array.from(results.values()).filter(r => !['running', 'pending'].includes(r.status)).length;
  const total = modules.length;

  return { modules, results, phase, done, total, abort };
}

// ---------------------------------------------------------------------------
// Derived severity counts (for SeverityCounts component)
// ---------------------------------------------------------------------------

function buildSeverityCounts(results: Map<string, CheckResult>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const r of results.values()) {
    if (r.status === 'fail') counts['HIGH'] = (counts['HIGH'] ?? 0) + 1;
    else if (r.status === 'warn') counts['MEDIUM'] = (counts['MEDIUM'] ?? 0) + 1;
    else if (r.status === 'pass') counts['INFO'] = (counts['INFO'] ?? 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// Detail extraction (drives CheckTile progressive disclosure) — VEC-395
//
// Liefert pro Modul strukturierte Detail-Blöcke + hiddenCount. Mapping exakt
// nach UX-Spec VEC-394 §3/§5. Free zeigt 3–5 sinnvolle Datenpunkte; alles
// darüber bleibt hinter `hiddenCount` ("+N weitere im vollständigen Report").
//
// Defensiv wie deriveStatus(): jedes Feld wird typgeprüft. Fehlt/ist ein Feld
// unerwartet, entfällt lieber der Block als ein Crash.
// ---------------------------------------------------------------------------

type Obj = Record<string, unknown>;

function asObj(v: unknown): Obj | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Obj) : null;
}
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
function statusCodeVariant(code: number): BadgeVariant {
  if (code >= 200 && code < 300) return 'ok';
  if (code >= 300 && code < 400) return 'neutral';
  return 'fail';
}
// Häufige Security-Header für den "vorhanden"-Block (http-headers).
const SEC_HEADERS = [
  'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
  'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
];
// Reihenfolge für DNS-Records (A/MX/NS zuerst).
const DNS_TYPE_ORDER = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA'];

function extractDetail(result: CheckResult): { detail: DetailBlock[]; hiddenCount: number } {
  const r = asObj(result.detail);
  if (!r) return { detail: [], hiddenCount: 0 };

  const detail: DetailBlock[] = [];
  // VEC-399: Caps entfernt — alle Rohdaten frei sichtbar; hiddenCount bleibt 0
  // (Prop für Backwards-Compat behalten, wird nach diesem Spec nie > 0).
  const hiddenCount = 0;

  switch (result.key) {
    case 'ssl': {
      // Felder nach realer web-check-2.1.9-Antwort (rohes getPeerCertificate):
      // subject/issuer = Objekte, valid_from/valid_to = Strings, bits =
      // Schlüssellänge, subjectaltname = Komma-String. Mapping via sslHelfer
      // (VEC-411) — alte Feldnamen (validTo/keySize/altNames/issuer-String)
      // existierten upstream nie → Karte blieb leer.
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [];
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
      if (kv.length > 0) detail.push({ type: 'kv', items: kv });
      // Alle SANs — eine Zeile je SAN, scrollbar ab 8 (VEC-399, kein slice)
      const sans = sslSans(r);
      if (sans.length > 0) {
        detail.push({
          type: 'kv',
          items: sans.map(s => ({ key: 'SAN', value: s })),
          scrollable: sans.length > 8,
        });
      }
      break;
    }

    case 'tls': {
      const protos = asArr(r.supportedProtocols).filter((p): p is string => typeof p === 'string');
      if (protos.length > 0) {
        detail.push({ type: 'badge-row', items: protos.map(p => ({ label: p, variant: protoVariant(p) })) });
      }
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [];
      if (typeof r.ocspStapling === 'boolean')
        kv.push({ key: 'OCSP Stapling', value: r.ocspStapling ? 'aktiv' : 'inaktiv', badge: r.ocspStapling ? 'ok' : 'warn' });
      if (typeof r.forwardSecrecy === 'boolean')
        kv.push({ key: 'Forward Secrecy', value: r.forwardSecrecy ? 'aktiv' : 'inaktiv', badge: r.forwardSecrecy ? 'ok' : 'warn' });
      if (kv.length > 0) detail.push({ type: 'kv', items: kv });
      // Cipher Suites vollständig als scrollbare Liste (VEC-399, vorher nur gezählt+gated)
      const ciphers = (asArr(r.cipherSuites).length > 0 ? asArr(r.cipherSuites) : asArr(r.ciphers))
        .map(c => asStr(c) ?? asStr(asObj(c)?.name) ?? asStr(asObj(c)?.cipher))
        .filter((s): s is string => !!s);
      if (ciphers.length > 0) {
        detail.push({ type: 'list', items: ciphers.map(c => ({ text: c })), scrollable: ciphers.length > 8 });
      }
      break;
    }

    case 'hsts': {
      const enabled = r.compatible === true || r.isEnabled === true || !!r.hstsHeader;
      const maxAge = asNum(r.maxAge);
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [
        { key: 'Status', value: enabled ? 'aktiv' : 'inaktiv', badge: enabled ? 'ok' : 'warn' },
      ];
      if (maxAge !== undefined) kv.push({ key: 'Max-Age', value: `${Math.round(maxAge / 86400)} Tage` });
      if (typeof r.includeSubDomains === 'boolean') kv.push({ key: 'includeSubDomains', value: yesNo(r.includeSubDomains) });
      if (typeof r.preload === 'boolean') kv.push({ key: 'Preload', value: yesNo(r.preload) });
      detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'http-headers': {
      const missing = asArr(r.missingHeaders).filter((h): h is string => typeof h === 'string');
      const headersObj = asObj(r.headers);
      const present: string[] = headersObj
        ? SEC_HEADERS.filter(h => Object.keys(headersObj).some(k => k.toLowerCase() === h.toLowerCase()))
        : [];
      if (present.length > 0) {
        detail.push({
          type: 'list',
          items: present.map(h => ({ text: h, badge: 'ok' as BadgeVariant })),
          scrollable: present.length > 8,
        });
      }
      if (missing.length > 0) {
        detail.push({
          type: 'list',
          items: missing.map(h => ({ text: h, badge: 'fail' as BadgeVariant })),
          scrollable: missing.length > 8,
        });
      }
      break;
    }

    case 'http-security': {
      const score = asNum(r.score);
      if (score !== undefined) {
        const badge: BadgeVariant = score >= 75 ? 'ok' : score >= 50 ? 'warn' : 'fail';
        detail.push({ type: 'kv', items: [{ key: 'Score', value: `${score}/100`, badge }] });
      }
      const issues = asArr(r.issues);
      if (issues.length > 0) {
        const items = issues.map(it => {
          const o = asObj(it);
          const text = asStr(it) ?? asStr(o?.title) ?? asStr(o?.message) ?? 'Problem';
          return { text, badge: 'fail' as BadgeVariant };
        });
        detail.push({ type: 'list', items, scrollable: items.length > 8 });
      }
      break;
    }

    case 'firewall': {
      const detected = r.hasFirewall === true || r.detected === true || r.firewallDetected === true;
      const name = asStr(r.firewall) ?? asStr(r.waf);
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [
        { key: 'WAF erkannt', value: detected ? (name ?? 'ja') : 'nein', badge: detected ? 'ok' : 'warn' },
      ];
      const type = asStr(r.type);
      if (type) kv.push({ key: 'Typ', value: type });
      detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'cookies': {
      const cookies = asArr(r.cookies);
      const src = cookies.length > 0
        ? cookies
        : asArr(r.insecureCookies).length > 0 ? asArr(r.insecureCookies) : asArr(r.unsecureCookies);
      if (src.length > 0) {
        const items = src.map(c => {
          const o = asObj(c);
          const name = asStr(o?.name) ?? asStr(c) ?? 'Cookie';
          const flag = (label: string, v: unknown) => `${label} ${v === true ? '✓' : '✗'}`;
          const same = asStr(o?.sameSite);
          const parts = o
            ? [flag('Secure', o.secure), flag('HttpOnly', o.httpOnly), same ? `SameSite: ${same}` : null].filter(Boolean)
            : [];
          return { key: name, value: parts.join(' · ') };
        });
        detail.push({ type: 'kv', items, scrollable: items.length > 8 });
      }
      break;
    }

    case 'security-txt': {
      const found = r.found === true || r.isPresent === true || r.exists === true || !!r.securityTxt;
      const fields = asObj(r.fields) ?? r;
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [
        { key: 'Gefunden', value: yesNo(found), badge: found ? 'ok' : 'warn' },
      ];
      const contact = asStr(fields.contact) ?? asStr(r.contact);
      const expires = asStr(fields.expires) ?? asStr(r.expires);
      if (contact) kv.push({ key: 'Contact', value: contact });
      if (expires) kv.push({ key: 'Expires', value: expires });
      detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'threats': {
      const total = asNum(r.totalThreats) ?? 0;
      const cats = asArr(r.categories).filter((c): c is string => typeof c === 'string');
      detail.push({
        type: 'kv',
        items: [
          { key: 'Bedrohungen', value: String(total), badge: total > 0 ? 'fail' : 'ok' },
          { key: 'Kategorien', value: cats.length > 0 ? cats.join(', ') : '—' },
        ],
      });
      const sources = asArr(r.sources).filter((s): s is string => typeof s === 'string');
      if (sources.length > 0) {
        detail.push({ type: 'list', items: sources.map(s => ({ text: s })), scrollable: sources.length > 8 });
      }
      break;
    }

    case 'block-lists': {
      const listedOn = asNum(r.listedOn) ?? 0;
      detail.push({
        type: 'kv',
        items: [{ key: 'Gelistet auf', value: `${listedOn} Listen`, badge: listedOn > 0 ? 'fail' : 'ok' }],
      });
      const lists = asArr(r.lists).length > 0 ? asArr(r.lists) : asArr(r.blocklists);
      const names = lists
        .map(l => asStr(l) ?? asStr(asObj(l)?.name))
        .filter((s): s is string => !!s);
      if (names.length > 0) {
        detail.push({
          type: 'list',
          items: names.map(t => ({ text: t, badge: 'fail' as BadgeVariant })),
          scrollable: names.length > 8,
        });
      }
      break;
    }

    case 'dns': {
      const recs = asArr(r.dns)
        .map(d => asObj(d))
        .filter((o): o is Obj => !!o);
      if (recs.length > 0) {
        const sorted = [...recs].sort((a, b) => {
          const ia = DNS_TYPE_ORDER.indexOf(asStr(a.type) ?? '');
          const ib = DNS_TYPE_ORDER.indexOf(asStr(b.type) ?? '');
          return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
        });
        const items = sorted.map(o => ({
          key: asStr(o.type) ?? '?',
          value: asStr(o.address) ?? asStr(o.value) ?? asStr(o.data) ?? '',
        }));
        detail.push({ type: 'kv', items, scrollable: items.length > 8 });
      }
      break;
    }

    case 'dnssec': {
      const enabled = r.isDnssecEnabled === true || r.dnssecEnabled === true || r.valid === true || r.isPresent === true;
      const algo = asStr(r.algorithm);
      detail.push({
        type: 'kv',
        items: [
          { key: 'DNSSEC aktiv', value: yesNo(enabled), badge: enabled ? 'ok' : 'warn' },
          { key: 'Algorithmus', value: algo ?? '—' },
        ],
      });
      break;
    }

    case 'dns-server': {
      const servers = asArr(r.dnsServer)
        .map(s => asStr(s) ?? asStr(asObj(s)?.address) ?? asStr(asObj(s)?.hostname))
        .filter((s): s is string => !!s);
      if (servers.length > 0) detail.push({ type: 'list', items: servers.map(t => ({ text: t })) });
      break;
    }

    case 'txt-records': {
      const recs = (asArr(r.txtRecords).length > 0 ? asArr(r.txtRecords) : asArr(r.records))
        .map(t => asStr(t) ?? asStr(asObj(t)?.value))
        .filter((s): s is string => !!s);
      if (recs.length > 0) {
        const sorted = [...recs].sort((a, b) => (/^v=spf1/i.test(b) ? 1 : 0) - (/^v=spf1/i.test(a) ? 1 : 0));
        detail.push({
          type: 'list',
          items: sorted.map(t => ({ text: truncate(t, 120) })),
          scrollable: sorted.length > 8,
        });
      }
      break;
    }

    case 'mail-config': {
      const hasSPF = !!(r.spf || r.hasSPF);
      const hasDKIM = !!(r.dkim || r.hasDKIM);
      const hasDMARC = !!(r.dmarc || r.hasDMARC);
      const hasBIMI = !!(r.bimi || r.hasBIMI);
      const spfVal = asStr(r.spf) ?? (hasSPF ? 'konfiguriert' : 'nicht konfiguriert');
      const dkimSel = asStr(r.dkimSelector);
      const dkimVal = hasDKIM ? (dkimSel ? `Selektor: ${dkimSel}` : 'konfiguriert') : 'nicht konfiguriert';
      const policy = (asStr(r.dmarcPolicy) ?? asStr(r.policy) ?? '').toLowerCase();
      const dmarcBadge: BadgeVariant = !hasDMARC ? 'fail' : /reject|quarantine/.test(policy) ? 'ok' : 'warn';
      const dmarcVal = !hasDMARC ? 'nicht konfiguriert' : policy ? `p=${policy}` : 'konfiguriert';
      detail.push({
        type: 'kv',
        items: [
          { key: 'SPF', value: truncate(spfVal, 48), badge: hasSPF ? 'ok' : 'fail' },
          { key: 'DKIM', value: dkimVal, badge: hasDKIM ? 'ok' : 'fail' },
          { key: 'DMARC', value: dmarcVal, badge: dmarcBadge },
          { key: 'BIMI', value: hasBIMI ? 'konfiguriert' : 'nicht konfiguriert', badge: hasBIMI ? 'ok' : 'fail' },
        ],
      });
      break;
    }

    case 'ports': {
      const ports = asArr(r.ports).length > 0 ? asArr(r.ports) : asArr(r.openPorts);
      if (ports.length > 0) {
        const items = ports.map(p => {
          if (typeof p === 'number') return { key: String(p), value: '' };
          const o = asObj(p);
          const num = asNum(o?.port) ?? asNum(o?.portNumber);
          const svc = asStr(o?.service) ?? '';
          const proto = asStr(o?.protocol);
          const value = [svc, proto].filter(Boolean).join(' / ');
          return { key: num !== undefined ? String(num) : '?', value };
        });
        detail.push({ type: 'kv', items, scrollable: items.length > 8 });
      }
      break;
    }

    case 'redirects': {
      const chain = asArr(r.redirects);
      if (chain.length > 0) {
        const items = chain.map(s => {
          if (typeof s === 'string') return { text: s };
          const o = asObj(s);
          const url = asStr(o?.url) ?? '';
          const code = asNum(o?.status) ?? asNum(o?.statusCode);
          return code !== undefined
            ? { text: `${url} (${code})`, badge: statusCodeVariant(code) }
            : { text: url };
        }).filter(it => it.text.trim() !== '');
        if (items.length > 0) detail.push({ type: 'list', items });
      }
      break;
    }

    case 'get-ip': {
      const ip = asStr(r.ip) ?? asStr(r.ipAddress);
      const country = asStr(r.country);
      const cc = asStr(r.countryCode);
      const city = asStr(r.city);
      const isp = asStr(r.org) ?? asStr(r.isp) ?? asStr(r.asn);
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [];
      if (ip) kv.push({ key: 'IP-Adresse', value: ip });
      if (country) kv.push({ key: 'Land', value: cc ? `${country} [${cc}]` : country });
      if (city) kv.push({ key: 'Stadt', value: city });
      if (isp) kv.push({ key: 'ISP / AS', value: isp });
      if (kv.length > 0) detail.push({ type: 'kv', items: kv });
      break;
    }

    case 'server-status': {
      const code = asNum(r.statusCode) ?? asNum(r.status) ?? 200;
      const server = asStr(r.server);
      const rt = asNum(r.responseTime) ?? asNum(r.responseTimeMs);
      const kv: { key: string; value: string; badge?: BadgeVariant }[] = [
        { key: 'HTTP-Status', value: String(code), badge: statusCodeVariant(code) },
      ];
      if (server) kv.push({ key: 'Server', value: server });
      if (rt !== undefined) kv.push({ key: 'Antwortzeit', value: `${rt} ms` });
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
// Screenshot rendering
// ---------------------------------------------------------------------------

function ScreenshotSection({ result }: { result: CheckResult }) {
  const r = result.detail as Record<string, unknown> | null;
  if (!r) return null;

  // Only data: URIs render inline — external URLs would be blocked by CSP img-src 'self' data:
  const src: string | null =
    typeof r.screenshot === 'string' ? r.screenshot
    : typeof r.image === 'string' ? r.image
    : null;

  if (!src) {
    return (
      <div className="mt-8">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Snapshot</h2>
        <StateView variant="info" title="Screenshot nicht verfügbar" description="Kein Screenshot wurde erstellt." />
      </div>
    );
  }

  return (
    <div className="mt-8">
      <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Snapshot</h2>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={src}
        alt="Screenshot"
        onError={e => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }}
        className="rounded-lg overflow-hidden border border-slate-700 w-full max-h-64 object-cover object-top"
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function LiveCheckResultsPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const target = searchParams.get('target') ?? '';

  const { modules, results, phase, done, total, abort } = useLiveCheck(target);

  // "Alle aufklappen" pro Gruppe (VEC-395 §4). Wert übersteuert lokalen
  // CheckTile-State via forceExpanded; undefined = Tile entscheidet selbst.
  const [groupAllExpanded, setGroupAllExpanded] = useState<Map<CheckGroup, boolean>>(new Map());

  // Severity-Drilldown (VEC-399): Klick auf einen Befund expandiert die
  // zugehörige Tile gezielt (übersteuert groupAllExpanded) + scrollt sie an.
  const [keyExpanded, setKeyExpanded] = useState<Map<string, boolean>>(new Map());

  const onDrilldownSelect = useCallback((key: string) => {
    setKeyExpanded(prev => new Map(prev).set(key, true));
    // Kurze Verzögerung, damit die Tile vor dem Scroll aufgeklappt gerendert ist.
    setTimeout(() => {
      document.getElementById(`tile-${key}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  }, []);

  // Auth guard — must be logged in to access live-check
  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
    }
  }, [router]);

  // Redirect to input if no target
  useEffect(() => {
    if (!target) router.replace('/live-check');
  }, [target, router]);

  if (!target) return null;

  // ── Phase: init / loading modules ────────────────────────────
  if (phase === 'init') {
    return (
      <div className="max-w-2xl mx-auto px-4 pt-10">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-5 h-5 rounded-full border-2 border-teal-500 border-t-transparent ds-spin" aria-hidden />
          <span className="text-sm text-slate-400">Sofort-Check wird vorbereitet…</span>
        </div>
      </div>
    );
  }

  // ── Phase: error ──────────────────────────────────────────────
  if (phase === 'error') {
    return (
      <div className="max-w-2xl mx-auto px-4 pt-10">
        <StateView
          variant="error"
          title="Sofort-Check nicht verfügbar"
          description="Die Checks konnten nicht gestartet werden. Bitte versuchen Sie es erneut."
          actions={[{ label: 'Neuer Sofort-Check', href: '/live-check' }]}
        />
      </div>
    );
  }

  const resultsList = Array.from(results.values());
  const overall = overallStatus(resultsList.filter(r => ['pass', 'warn', 'fail'].includes(r.status)));
  const severityCounts = buildSeverityCounts(results);
  const isRunning = phase === 'running';

  const OVERALL_META = {
    pass: { color: '#10B981', Icon: PassBigIcon, headline: 'Gute Basislage — Details unten' },
    warn: { color: '#F59E0B', Icon: WarnBigIcon, headline: `Handlungsbedarf` },
    fail: { color: '#EF4444', Icon: FailBigIcon, headline: 'Kritische Lücken gefunden' },
  };

  // Group results by category, sort fail first within each group
  const grouped = new Map<CheckGroup, CheckResult[]>();
  for (const g of GROUP_ORDER) grouped.set(g, []);
  for (const r of resultsList) {
    grouped.get(r.group as CheckGroup)?.push(r);
  }
  for (const [, arr] of grouped) {
    arr.sort((a, b) => statusScore(a.status) - statusScore(b.status));
  }

  // Screenshot module separate
  const screenshotResult = results.get('screenshot');

  return (
    <div className="max-w-2xl mx-auto px-4 pt-8 pb-16">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100 truncate">{target}</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Sofort-Check ·{' '}
            {new Date().toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })}
            {' '}
            {new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {isRunning && (
            <button
              type="button"
              onClick={abort}
              className="px-3 py-1.5 rounded-lg text-xs border text-slate-400 hover:text-slate-200 transition-colors min-h-[36px]"
              style={{ borderColor: 'var(--border-muted)' }}
            >
              Abbrechen
            </button>
          )}
          <Link
            href="/live-check"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors min-h-[36px]"
            style={{ color: 'var(--text-muted)', borderColor: 'var(--border-muted)' }}
          >
            <ZapIcon />
            Neuer Sofort-Check
          </Link>
        </div>
      </div>

      {/* Progress bar (while running) */}
      {isRunning && total > 0 && (
        <LiveCheckProgress done={done} total={total} className="mb-6" />
      )}

      {/* Aborted banner */}
      {phase === 'aborted' && (
        <div className="mb-6 px-4 py-3 rounded-lg text-sm text-amber-300 border border-amber-400/20"
          style={{ background: 'rgba(245,158,11,0.08)' }}>
          Einige Checks wurden abgebrochen. Verfügbare Ergebnisse werden angezeigt.
        </div>
      )}

      {/* Hero summary (only when we have results) */}
      {overall && (() => {
        const meta = OVERALL_META[overall];
        const OverallIcon = meta.Icon;
        return (
          <div key="hero" className="mb-8 flex items-center gap-4 p-5 rounded-xl border"
            style={{
              background: `color-mix(in srgb, ${meta.color} 6%, var(--slate-light))`,
              borderColor: `color-mix(in srgb, ${meta.color} 24%, transparent)`,
            }}>
            <span className="shrink-0 w-12 h-12 rounded-full flex items-center justify-center"
              style={{
                color: meta.color,
                background: `color-mix(in srgb, ${meta.color} 14%, transparent)`,
              }}>
              <OverallIcon />
            </span>
            <div>
              <p className="font-semibold text-slate-100">{meta.headline}</p>
              <div className="mt-1">
                <SeverityCounts counts={severityCounts} />
              </div>
            </div>
          </div>
        );
      })()}

      {/* Severity-Drilldown (VEC-399): welche Checks machen H/M aus.
          Nur bei abgeschlossenem Scan — während running sind Counts unvollständig. */}
      {(phase === 'done' || phase === 'aborted') && (
        <SeverityDrilldown results={resultsList} onSelect={onDrilldownSelect} />
      )}

      {/* Check sections by group */}
      <div className="space-y-8">
        {GROUP_ORDER.map(group => {
          const items = grouped.get(group) ?? [];
          if (items.length === 0) return null;
          // Hide screenshot from main grid (rendered separately)
          const displayItems = group === 'info' ? items.filter(r => r.key !== 'screenshot') : items;
          if (displayItems.length === 0) return null;

          // Detail einmal pro Item ableiten; bestimmt auch, ob "Alle aufklappen" sinnvoll ist.
          const itemDetails = displayItems.map(r => ({ result: r, ...extractDetail(r) }));
          const groupHasDetail = itemDetails.some(d => d.detail.length > 0);
          const allExpanded = groupAllExpanded.get(group) === true;

          return (
            <section key={group}>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  {GROUP_LABELS[group]}
                </h2>
                {groupHasDetail && (
                  <button
                    type="button"
                    onClick={() => setGroupAllExpanded(prev => {
                      const next = new Map(prev);
                      next.set(group, !allExpanded);
                      return next;
                    })}
                    className="text-xs text-slate-600 hover:text-slate-400 transition-colors"
                    aria-expanded={allExpanded}
                  >
                    {allExpanded ? 'Alle einklappen' : 'Alle aufklappen'}
                  </button>
                )}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-start">
                {itemDetails.map(({ result: r, detail, hiddenCount }) => (
                  <CheckTile
                    key={r.key}
                    tileId={r.key}
                    label={r.label}
                    status={r.status}
                    summary={r.summary}
                    detail={detail}
                    hiddenCount={hiddenCount}
                    forceExpanded={
                      keyExpanded.has(r.key)
                        ? keyExpanded.get(r.key)
                        : groupAllExpanded.has(group) ? allExpanded : undefined
                    }
                  />
                ))}
              </div>
            </section>
          );
        })}
      </div>

      {/* Screenshot section */}
      {screenshotResult && <ScreenshotSection result={screenshotResult} />}

      {/* CTA Staircase — only when scan is done */}
      {(phase === 'done' || phase === 'aborted') && (
        <CTAStaircase domain={target} />
      )}

      {/* Disclaimer */}
      {(phase === 'done' || phase === 'aborted') && (
        <p className="mt-6 text-xs text-slate-600 text-center">
          Momentaufnahme öffentlich erreichbarer Dienste. Kein Penetrationstest.
          Zeitstempel: {new Date().toLocaleString('de-DE')}.
        </p>
      )}
    </div>
  );
}
