import type { LookupAddress } from 'dns';
import {
  LIVE_CHECK_MODULES,
  getLiveCheckModule,
  normalizeTargetHost,
  checkTarget,
  toUpstreamTarget,
} from '../lib/liveCheck';
import { LiveCheckLimiter, DEFAULT_LIVE_CHECK_LIMITS } from '../lib/liveCheckLimiter';
import { summarizeAbuse, type LiveCheckAuditRow } from '../lib/liveCheckAbuse';

// ──────────────────────────────────────────────────────────────────────────
// VEC-363 — Live-Check-Fassade: Modul-Allowlist, SSRF-Target-Härtung, Limiter
// ──────────────────────────────────────────────────────────────────────────

describe('Modul-Allowlist (Default-Deny)', () => {
  it('liefert die kuratierte BEHALTEN-Liste', () => {
    expect(LIVE_CHECK_MODULES.length).toBeGreaterThan(0);
    expect(getLiveCheckModule('ports')).toMatchObject({ upstream: 'ports' });
    expect(getLiveCheckModule('mail-config')?.upstream).toBe('mail-config');
  });

  it('schaltet GPL-/SEO-Module NICHT frei', () => {
    // tech-stack (wappalyzer = GPL, Spike VEC-362) + CO2/Ranking/Social/Sitemap
    for (const denied of ['tech-stack', 'carbon', 'rank', 'social-tags', 'sitemap', 'quality']) {
      expect(getLiveCheckModule(denied)).toBeUndefined();
    }
  });

  it('hat eindeutige Keys', () => {
    const keys = LIVE_CHECK_MODULES.map((m) => m.key);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe('toUpstreamTarget — schema-qualifizierter Upstream-Param (VEC-411)', () => {
  it('stellt https:// vor einen nackten Hostnamen (sonst wirft new URL upstream)', () => {
    expect(toUpstreamTarget('securess.de')).toBe('https://securess.de');
    expect(toUpstreamTarget('bergersysteme.com')).toBe('https://bergersysteme.com');
    expect(toUpstreamTarget('8.8.8.8')).toBe('https://8.8.8.8');
  });

  it('ist idempotent für bereits schema-präfigierte Ziele', () => {
    expect(toUpstreamTarget('https://example.com')).toBe('https://example.com');
    expect(toUpstreamTarget('http://example.com')).toBe('http://example.com');
  });
});

describe('normalizeTargetHost', () => {
  it('akzeptiert FQDNs (lowercase)', () => {
    expect(normalizeTargetHost('Example.COM')).toBe('example.com');
    expect(normalizeTargetHost(' sub.example.org ')).toBe('sub.example.org');
  });

  it('extrahiert den Hostnamen aus http(s)-URLs', () => {
    expect(normalizeTargetHost('https://example.com/pfad?x=1')).toBe('example.com');
    expect(normalizeTargetHost('http://example.com:8080')).toBe('example.com');
  });

  it('akzeptiert IPv4-Literale', () => {
    expect(normalizeTargetHost('8.8.8.8')).toBe('8.8.8.8');
  });

  it('lehnt Müll, Nicht-http-Schemata und IPv6 ab', () => {
    expect(normalizeTargetHost('ftp://example.com')).toBeNull();
    expect(normalizeTargetHost('not a host')).toBeNull();
    expect(normalizeTargetHost('localhost-no-tld')).toBeNull();
    expect(normalizeTargetHost('[::1]')).toBeNull();
    expect(normalizeTargetHost(42)).toBeNull();
  });
});

describe('checkTarget — SSRF-Härtung', () => {
  const resolveTo = (addrs: string[]) => async (): Promise<LookupAddress[]> =>
    addrs.map((address) => ({ address, family: 4 }));

  it('lässt ein öffentliches Ziel passieren', async () => {
    const r = await checkTarget('example.com', resolveTo(['93.184.216.34']));
    expect(r.ok).toBe(true);
    expect(r.host).toBe('example.com');
    expect(r.resolvedIp).toBe('93.184.216.34');
  });

  it('blockt ein IPv4-Literal im RFC1918-Bereich ohne Auflösung', async () => {
    const r = await checkTarget('192.168.0.1');
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('ssrf_blocked');
  });

  it('blockt Cloud-Metadata-IP', async () => {
    const r = await checkTarget('169.254.169.254');
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('ssrf_blocked');
  });

  it('blockt Hostnamen, die auf eine interne IP auflösen (DNS-Rebinding)', async () => {
    const r = await checkTarget('evil.example.com', resolveTo(['10.0.0.5']));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('ssrf_blocked');
  });

  it('blockt, wenn AUCH NUR EINE aufgelöste Adresse intern ist (Split-Horizon)', async () => {
    const r = await checkTarget('mix.example.com', resolveTo(['93.184.216.34', '127.0.0.1']));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('ssrf_blocked');
  });

  it('blockt interne Hostnamen (Blockliste bzw. Format-Ablehnung)', async () => {
    // Single-Label 'localhost' scheitert bereits am Format (kein FQDN) → ok:false.
    expect((await checkTarget('localhost')).ok).toBe(false);
    // FQDN-Form interner Namen wird per Suffix-/Exact-Blockliste hart geblockt,
    // unabhängig vom DNS-Ergebnis (Split-Horizon-Schutz).
    expect((await checkTarget('foo.internal')).reason).toBe('ssrf_blocked');
    expect((await checkTarget('metadata.google.internal')).reason).toBe('ssrf_blocked');
  });

  it('meldet resolve_failed sauber', async () => {
    const r = await checkTarget('nx.example.com', async () => {
      throw new Error('ENOTFOUND');
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('resolve_failed');
  });

  it('lehnt ungültiges Format ab', async () => {
    const r = await checkTarget('not a host');
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('invalid_format');
  });
});

describe('LiveCheckLimiter', () => {
  it('erzwingt das Rate-Limit pro User im Fenster', () => {
    const lim = new LiveCheckLimiter({ windowMs: 1000, maxPerWindow: 2, maxConcurrent: 10 });
    const t = 1_000_000;
    expect(lim.acquire('u1', t).ok).toBe(true);
    lim.release('u1');
    expect(lim.acquire('u1', t).ok).toBe(true);
    lim.release('u1');
    const third = lim.acquire('u1', t);
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.reason).toBe('rate_limited');
  });

  it('isoliert User voneinander', () => {
    const lim = new LiveCheckLimiter({ windowMs: 1000, maxPerWindow: 1, maxConcurrent: 10 });
    const t = 2_000_000;
    expect(lim.acquire('a', t).ok).toBe(true);
    expect(lim.acquire('b', t).ok).toBe(true);
  });

  it('gibt das Fenster nach Ablauf wieder frei', () => {
    const lim = new LiveCheckLimiter({ windowMs: 1000, maxPerWindow: 1, maxConcurrent: 10 });
    expect(lim.acquire('u', 0).ok).toBe(true);
    lim.release('u');
    expect(lim.acquire('u', 500).ok).toBe(false);
    expect(lim.acquire('u', 1500).ok).toBe(true);
  });

  it('erzwingt den Concurrency-Cap und gibt per release() frei', () => {
    const lim = new LiveCheckLimiter({ windowMs: 60_000, maxPerWindow: 100, maxConcurrent: 2 });
    const t = 5_000_000;
    expect(lim.acquire('u', t).ok).toBe(true);
    expect(lim.acquire('u', t).ok).toBe(true);
    const third = lim.acquire('u', t);
    expect(third.ok).toBe(false);
    if (!third.ok) expect(third.reason).toBe('too_many_concurrent');
    lim.release('u');
    expect(lim.acquire('u', t).ok).toBe(true);
  });

  // VEC-381 — Window-Headroom: 2 volle SofortScans (20+20 Calls) müssen ins
  // Fenster passen; erst der 41. Call läuft ins Fensterlimit.
  it('bietet Headroom für zwei volle Scans (Default-Limits)', () => {
    expect(DEFAULT_LIVE_CHECK_LIMITS.maxPerWindow).toBe(40);
    const lim = new LiveCheckLimiter(); // produktive Default-Limits
    const t = 7_000_000;
    for (let i = 0; i < DEFAULT_LIVE_CHECK_LIMITS.maxPerWindow; i++) {
      const r = lim.acquire('u', t);
      expect(r.ok).toBe(true);
      lim.release('u'); // sequenziell, damit nur das Fenster (nicht Concurrency) greift
    }
    const over = lim.acquire('u', t);
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.reason).toBe('rate_limited');
  });

  // VEC-381 — too_many_concurrent zählt NICHT ins Sliding-Window (acquire pusht
  // erst nach dem Concurrency-Check). Client-Retries kosten so kein Window-Budget.
  it('verbraucht bei too_many_concurrent kein Fenster-Budget', () => {
    const lim = new LiveCheckLimiter({ windowMs: 60_000, maxPerWindow: 5, maxConcurrent: 1 });
    const t = 8_000_000;
    expect(lim.acquire('u', t).ok).toBe(true); // 1 Fenster-Hit, Slot belegt
    for (let i = 0; i < 10; i++) {
      const r = lim.acquire('u', t); // jeweils too_many_concurrent
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('too_many_concurrent');
    }
    lim.release('u');
    // Trotz 10 abgewiesener Versuche sind erst 1 Fenster-Hit verbraucht → 4 frei.
    for (let i = 0; i < 4; i++) {
      const r = lim.acquire('u', t);
      expect(r.ok).toBe(true);
      lim.release('u');
    }
    const over = lim.acquire('u', t);
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.reason).toBe('rate_limited');
  });
});

// ──────────────────────────────────────────────────────────────────────────
// VEC-368 — Abuse-Monitoring: Aggregation über live_check_audit
// ──────────────────────────────────────────────────────────────────────────
describe('summarizeAbuse', () => {
  const row = (
    userId: string | null,
    ip: string | null,
    status: LiveCheckAuditRow['status'],
  ): LiveCheckAuditRow => ({ userId, ip, status });

  it('zählt Totals und distinct Akteure korrekt', () => {
    const s = summarizeAbuse([
      row('u1', '1.1.1.1', 'ok'),
      row('u1', '1.1.1.1', 'ok'),
      row('u2', '2.2.2.2', 'rate_limited'),
    ]);
    expect(s.totals.total).toBe(3);
    expect(s.totals.ok).toBe(2);
    expect(s.totals.rateLimited).toBe(1);
    expect(s.totals.distinctActors).toBe(2);
  });

  it('flaggt einen SSRF-Prober ab 3 blocked und sortiert ihn nach oben', () => {
    const s = summarizeAbuse([
      row('attacker', '6.6.6.6', 'blocked'),
      row('attacker', '6.6.6.6', 'blocked'),
      row('attacker', '6.6.6.6', 'blocked'),
      row('normal', '9.9.9.9', 'ok'),
    ]);
    expect(s.actors[0].userId).toBe('attacker');
    expect(s.actors[0].blocked).toBe(3);
    expect(s.actors[0].flagged).toBe(true);
    expect(s.totals.flaggedActors).toBe(1);
    // blocked-Gewicht 5 → Score 15.
    expect(s.actors[0].score).toBe(15);
  });

  it('flaggt über den Score-Schwellwert (gemischte Signale)', () => {
    // 2×blocked(10) + 3×rate_limited(6) = 16 >= 15.
    const s = summarizeAbuse([
      row('mix', '5.5.5.5', 'blocked'),
      row('mix', '5.5.5.5', 'blocked'),
      row('mix', '5.5.5.5', 'rate_limited'),
      row('mix', '5.5.5.5', 'rate_limited'),
      row('mix', '5.5.5.5', 'rate_limited'),
    ]);
    expect(s.actors[0].score).toBe(16);
    expect(s.actors[0].flagged).toBe(true);
  });

  it('flaggt einen sauberen Vielnutzer NICHT', () => {
    const rows = Array.from({ length: 30 }, () => row('poweruser', '8.8.8.8', 'ok'));
    const s = summarizeAbuse(rows);
    expect(s.actors[0].total).toBe(30);
    expect(s.actors[0].flagged).toBe(false);
    expect(s.totals.flaggedActors).toBe(0);
  });

  it('fällt auf die IP zurück, wenn keine userId vorhanden ist', () => {
    const s = summarizeAbuse([row(null, '7.7.7.7', 'blocked')]);
    expect(s.actors[0].actor).toBe('ip:7.7.7.7');
  });

  it('respektiert topN', () => {
    const rows = Array.from({ length: 10 }, (_, i) => row(`u${i}`, null, 'ok'));
    const s = summarizeAbuse(rows, { topN: 3 });
    expect(s.actors.length).toBe(3);
    expect(s.totals.distinctActors).toBe(10);
  });
});
