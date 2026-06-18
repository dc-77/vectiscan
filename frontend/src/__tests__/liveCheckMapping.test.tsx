/**
 * VEC-413 — Regression: Modul-Mapping gegen die REALE web-check-2.1.9-Antwort.
 *
 * Jede Fixture ist eine echte 2.1.9-Handler-Response-Shape (verifiziert gegen
 * Lissy93/web-check@2.1.9/api/*.js). Schützt gegen den wiederkehrenden Bug, dass
 * Mapping gegen vermutete Feldnamen geschrieben wird (false-positives wie das
 * mail-config-HIGH und „0 TXT-Records", VEC-411/VEC-413).
 */
import { deriveStatus, extractDetail, type CheckResult, type CheckGroup } from '@/lib/liveCheck';

function res(key: string, detail: unknown, group: CheckGroup = 'info'): CheckResult {
  return { key, label: key, group, status: 'pass', summary: '', detail };
}

describe('VEC-413 deriveStatus — reale web-check-2.1.9-Shapes', () => {
  // ── mail-config: DER false-positive (securess.de: SPF + DMARC p=reject) ──
  it('mail-config: SPF + DMARC p=reject vorhanden → KEIN kritischer Befund (pass)', () => {
    const real = {
      mxRecords: [{ exchange: 'mail.securess.de', priority: 10 }],
      txtRecords: [
        ['v=spf1 a mx ~all'],
        ['v=DMARC1; p=reject; rua=mailto:dmarc@securess.de'],
      ],
      mailServices: [],
    };
    const r = deriveStatus('mail-config', real);
    expect(r.status).toBe('pass');
    expect(r.summary).toMatch(/SPF \+ DMARC/);
    expect(r.summary).toMatch(/p=reject/);
  });

  it('mail-config: weder SPF noch DMARC → fail', () => {
    const r = deriveStatus('mail-config', { mxRecords: [], txtRecords: [], mailServices: [] });
    expect(r.status).toBe('fail');
  });

  it('mail-config: DMARC p=none → nur warn (Monitoring)', () => {
    const r = deriveStatus('mail-config', {
      txtRecords: [['v=spf1 -all'], ['v=DMARC1; p=none']],
      mxRecords: [],
      mailServices: [],
    });
    expect(r.status).toBe('warn');
  });

  it('mail-config: kein Mailserver (skipped) → pass „Nicht anwendbar", NIE fail', () => {
    const r = deriveStatus('mail-config', { skipped: 'No mail server in use on this domain' });
    expect(r.status).toBe('pass');
  });

  it('mail-config detail: SPF ok, DKIM/BIMI neutral (kein rotes Badge)', () => {
    const { detail } = extractDetail(
      res('mail-config', { txtRecords: [['v=spf1 ~all'], ['v=DMARC1; p=reject']], mxRecords: [], mailServices: [] }, 'mail'),
    );
    const kv = detail.find((d) => d.type === 'kv');
    expect(kv).toBeTruthy();
    const items = (kv as { items: { key: string; badge?: string }[] }).items;
    expect(items.find((i) => i.key === 'SPF')?.badge).toBe('ok');
    expect(items.find((i) => i.key === 'DKIM')?.badge).toBe('neutral');
    expect(items.find((i) => i.key === 'BIMI')?.badge).toBe('neutral');
  });

  // ── txt-records: flaches Objekt, NICHT Array ──
  it('txt-records: flaches { key: value }-Objekt → korrekte Anzahl (nicht 0)', () => {
    const real = {
      v: 'spf1 a mx ~all',
      'google-site-verification': 'abc123',
      'swisssign-check': 'xyz',
    };
    const r = deriveStatus('txt-records', real);
    expect(r.summary).toBe('3 TXT-Records');
    const { detail } = extractDetail(res('txt-records', real, 'dns'));
    const list = detail.find((d) => d.type === 'list') as { items: { text: string }[] };
    expect(list.items.length).toBe(3);
    // SPF zuerst
    expect(list.items[0].text).toMatch(/^v=spf1/);
  });

  // ── tls → tls-connection-Shape ──
  it('tls: tls-connection { protocol, cipher{name} } → pass + Cipher im Detail', () => {
    const real = {
      protocol: 'TLSv1.3',
      cipher: { name: 'TLS_AES_256_GCM_SHA384', standardName: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' },
      forwardSecrecy: true,
      ocspStapled: false,
      alpnProtocol: 'h2',
    };
    const r = deriveStatus('tls', real);
    expect(r.status).toBe('pass');
    expect(r.summary).toMatch(/TLSv1\.3/);
    const { detail } = extractDetail(res('tls', real, 'tls'));
    const kv = detail.find((d) => d.type === 'kv') as { items: { key: string }[] };
    expect(kv.items.find((i) => i.key === 'Cipher')).toBeTruthy();
    expect(kv.items.find((i) => i.key === 'Forward Secrecy')).toBeTruthy();
  });

  it('tls: veraltetes Protokoll → warn', () => {
    expect(deriveStatus('tls', { protocol: 'TLSv1.0' }).status).toBe('warn');
  });

  // ── http-headers: Antwort IST die Header-Map ──
  it('http-headers: rohe Header-Map ohne Security-Header → fail', () => {
    const real = { server: 'nginx', 'content-type': 'text/html', date: 'x' };
    expect(deriveStatus('http-headers', real).status).toBe('fail');
  });

  it('http-headers: alle Security-Header vorhanden → pass', () => {
    const real = {
      'strict-transport-security': 'max-age=63072000',
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
    };
    expect(deriveStatus('http-headers', real).status).toBe('pass');
  });

  // ── http-security: 10 Booleans ──
  it('http-security: alle Booleans false → fail; alle true → pass', () => {
    const allFalse = Object.fromEntries(
      ['contentSecurityPolicy', 'strictTransportPolicy', 'xContentTypeOptions', 'xFrameOptions', 'referrerPolicy'].map((k) => [k, false]),
    );
    expect(deriveStatus('http-security', allFalse).status).toBe('fail');
    const allTrue = {
      contentSecurityPolicy: true, strictTransportPolicy: true, xContentTypeOptions: true,
      xFrameOptions: true, xXSSProtection: true, referrerPolicy: true, permissionsPolicy: true,
      crossOriginOpenerPolicy: true, crossOriginResourcePolicy: true, crossOriginEmbedderPolicy: true,
    };
    expect(deriveStatus('http-security', allTrue).status).toBe('pass');
  });

  // ── dnssec: DNSKEY/DS/RRSIG.isFound ──
  it('dnssec: DNSKEY.isFound true → aktiv (pass)', () => {
    const real = {
      DNSKEY: { isFound: true, answer: [{}] },
      DS: { isFound: false, answer: null },
      RRSIG: { isFound: true, answer: null },
    };
    expect(deriveStatus('dnssec', real).status).toBe('pass');
    expect(deriveStatus('dnssec', { DNSKEY: { isFound: false }, DS: { isFound: false }, RRSIG: { isFound: false } }).status).toBe('warn');
  });

  // ── firewall: hasWaf ──
  it('firewall: { hasWaf:true, waf } → pass mit Namen', () => {
    const r = deriveStatus('firewall', { hasWaf: true, waf: 'Cloudflare' });
    expect(r.status).toBe('pass');
    expect(r.summary).toBe('Cloudflare');
    expect(deriveStatus('firewall', { hasWaf: false }).status).toBe('warn');
  });

  // ── dns-server: { dns:[{address,hostname}] } ──
  it('dns-server: reale { dns:[...] }-Form → Detail-Liste nicht leer', () => {
    const real = { domain: 'securess.de', dns: [{ address: '1.2.3.4', hostname: 'ns1.example.com' }] };
    expect(deriveStatus('dns-server', real).summary).toMatch(/1 DNS-Server/);
    const { detail } = extractDetail(res('dns-server', real, 'dns'));
    expect((detail[0] as { items: unknown[] }).items.length).toBe(1);
  });

  // ── dns: typ-keyed Objekt ──
  it('dns: typ-keyed { A, MX, NS } → Records-Detail nicht leer', () => {
    const real = {
      A: ['1.2.3.4'], AAAA: [], MX: [{ exchange: 'mail.x.de', priority: 10 }],
      TXT: [['v=spf1 ~all']], NS: ['ns1.x.de'], CNAME: [], SOA: { nsname: 'ns1.x.de' }, SRV: [], PTR: [],
    };
    const r = deriveStatus('dns', real);
    expect(r.summary).toMatch(/Records/);
    const { detail } = extractDetail(res('dns', real, 'dns'));
    const kv = detail.find((d) => d.type === 'kv') as { items: unknown[] };
    expect(kv.items.length).toBeGreaterThanOrEqual(5);
  });

  // ── block-lists: blocklists[].isBlocked ──
  it('block-lists: isBlocked-Treffer → fail', () => {
    const real = { blocklists: [{ server: 'CleanBrowsing', serverIp: '1.1.1.1', isBlocked: true }, { server: 'Google DNS', isBlocked: false }] };
    expect(deriveStatus('block-lists', real).status).toBe('fail');
    expect(deriveStatus('block-lists', { blocklists: [{ server: 'a', isBlocked: false }] }).status).toBe('pass');
  });

  // ── get-ip: { ip, family } ──
  it('get-ip: { ip, family } → pass mit IP', () => {
    const r = deriveStatus('get-ip', { ip: '203.0.113.7', family: 4 });
    expect(r.status).toBe('pass');
    expect(r.summary).toMatch(/203\.0\.113\.7/);
  });

  // ── location (VEC-416): Geo/ASN aus dem separaten location-Modul ──
  it('location: reale 2.1.9-Shape → pass + Land·Stadt im Summary', () => {
    const real = {
      ip: '203.0.113.7',
      city: 'Frankfurt am Main',
      region: 'Hesse',
      region_code: 'HE',
      country_name: 'Germany',
      country_code: 'DE',
      postal: '60313',
      latitude: 50.1109,
      longitude: 8.6821,
      org: 'AS24940 Hetzner Online GmbH',
      timezone: 'Europe/Berlin',
    };
    const r = deriveStatus('location', real);
    expect(r.status).toBe('pass');
    expect(r.summary).toBe('Germany · Frankfurt am Main');
    const { detail } = extractDetail(res('location', real, 'info'));
    const kv = detail.find((d) => d.type === 'kv') as { items: { key: string; value: string }[] };
    expect(kv).toBeTruthy();
    expect(kv.items.find((i) => i.key === 'Land')?.value).toBe('Germany (DE)');
    expect(kv.items.find((i) => i.key === 'Stadt')?.value).toBe('Frankfurt am Main, Hesse');
    expect(kv.items.find((i) => i.key === 'Netzbetreiber (ASN/Org)')?.value).toMatch(/Hetzner/);
    expect(kv.items.find((i) => i.key === 'Zeitzone')?.value).toBe('Europe/Berlin');
    expect(kv.items.find((i) => i.key === 'Koordinaten')?.value).toBe('50.1109, 8.6821');
  });

  it('location: Provider-Variante (country/lat/lon, timezone-Objekt, isp) → robust gemappt', () => {
    // Fallback-Provider (z.B. ipwho.is) liefern abweichende Feldnamen.
    const variant = {
      ip: '198.51.100.4',
      city: 'Paris',
      country: 'France',
      country_code: 'FR',
      isp: 'OVH SAS',
      timezone: { id: 'Europe/Paris', abbr: 'CET' },
      lat: 48.8566,
      lng: 2.3522,
    };
    const r = deriveStatus('location', variant);
    expect(r.status).toBe('pass');
    expect(r.summary).toBe('France · Paris');
    const { detail } = extractDetail(res('location', variant, 'info'));
    const kv = detail.find((d) => d.type === 'kv') as { items: { key: string; value: string }[] };
    expect(kv.items.find((i) => i.key === 'Land')?.value).toBe('France (FR)');
    expect(kv.items.find((i) => i.key === 'Netzbetreiber (ASN/Org)')?.value).toBe('OVH SAS');
    expect(kv.items.find((i) => i.key === 'Zeitzone')?.value).toBe('Europe/Paris');
    expect(kv.items.find((i) => i.key === 'Koordinaten')?.value).toBe('48.8566, 2.3522');
  });

  // ── server-status: responseCode ──
  it('server-status: { responseCode:200, isUp:true } → pass', () => {
    expect(deriveStatus('server-status', { isUp: true, responseCode: 200, responseTime: 120 }).status).toBe('pass');
    expect(deriveStatus('server-status', { isUp: true, responseCode: 503 }).status).toBe('fail');
  });

  // ── ssl bleibt korrekt (VEC-411, rohes Cert) ──
  it('ssl: rohes getPeerCertificate + isValid → pass', () => {
    const real = {
      subject: { CN: 'securess.de' }, issuer: { O: "Let's Encrypt", CN: 'R3' },
      valid_from: 'Jan  1 00:00:00 2026 GMT', valid_to: 'Dec 31 23:59:59 2099 GMT',
      subjectaltname: 'DNS:securess.de, DNS:www.securess.de', bits: 256, isValid: true, authError: null,
    };
    expect(deriveStatus('ssl', real).status).toBe('pass');
  });
});
