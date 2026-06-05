import http from 'http';
import { AddressInfo } from 'net';
import { isBlockedAddress, makeGuardedLookup, safeFetch, SsrfBlockedError } from '../lib/ssrf-guard';

// ──────────────────────────────────────────────
// VEC-175 — SSRF-Guard: Block-Ranges + Resolve-and-Pin
// ──────────────────────────────────────────────

describe('isBlockedAddress', () => {
  describe('blockt interne / reservierte IPv4', () => {
    const blocked = [
      '127.0.0.1',          // loopback
      '127.99.1.2',
      '10.0.0.1',           // RFC1918
      '10.255.255.255',
      '172.16.0.1',         // RFC1918
      '172.31.255.254',
      '192.168.1.1',        // RFC1918
      '169.254.169.254',    // Cloud-Metadata (AWS/GCP/Azure)
      '169.254.0.1',        // link-local
      '100.64.0.1',         // CGNAT
      '0.0.0.0',            // "this network"
      '192.0.0.1',          // IETF protocol assignments
      '198.18.0.1',         // benchmark
      '224.0.0.1',          // multicast
      '240.0.0.1',          // reserved
      '255.255.255.255',    // broadcast
    ];
    it.each(blocked)('blockt %s', (ip) => {
      expect(isBlockedAddress(ip)).toBe(true);
    });
  });

  describe('erlaubt öffentliche IPv4', () => {
    const allowed = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '100.63.255.255', '11.0.0.1'];
    it.each(allowed)('erlaubt %s', (ip) => {
      expect(isBlockedAddress(ip)).toBe(false);
    });
  });

  describe('blockt interne / reservierte IPv6', () => {
    const blocked = [
      '::1',                       // loopback
      '::',                        // unspecified
      'fe80::1',                   // link-local
      'fc00::1',                   // ULA
      'fd12:3456::1',              // ULA
      'ff02::1',                   // multicast
      '::ffff:127.0.0.1',          // IPv4-mapped loopback
      '::ffff:169.254.169.254',    // IPv4-mapped metadata
      '64:ff9b::a9fe:a9fe',        // NAT64 → 169.254.169.254
    ];
    it.each(blocked)('blockt %s', (ip) => {
      expect(isBlockedAddress(ip)).toBe(true);
    });
  });

  describe('erlaubt öffentliche IPv6', () => {
    it.each(['2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8'])(
      'erlaubt %s',
      (ip) => {
        expect(isBlockedAddress(ip)).toBe(false);
      },
    );
  });

  it('blockt unparsebare Eingaben (fail-closed)', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
    expect(isBlockedAddress('')).toBe(true);
    expect(isBlockedAddress('999.999.999.999')).toBe(true);
  });
});

describe('makeGuardedLookup (Resolve-and-Pin)', () => {
  const fakeResolver = (addresses: Array<{ address: string; family: number }>) =>
    ((_h: string, _o: unknown, cb: (e: unknown, a: unknown) => void) => cb(null, addresses)) as never;

  it('pinnt auf die öffentliche IP, wenn nur eine aufgelöst wird', (done) => {
    const lookup = makeGuardedLookup(fakeResolver([{ address: '93.184.216.34', family: 4 }]));
    lookup('example.com', { all: true } as never, (err, address) => {
      expect(err).toBeNull();
      expect(address).toBe('93.184.216.34');
      done();
    });
  });

  it('verwirft die geblockte IP und pinnt auf die verbleibende öffentliche (Rebind mit Mix)', (done) => {
    const lookup = makeGuardedLookup(
      fakeResolver([
        { address: '169.254.169.254', family: 4 },
        { address: '93.184.216.34', family: 4 },
      ]),
    );
    lookup('rebind.example', { all: true } as never, (err, address) => {
      expect(err).toBeNull();
      expect(address).toBe('93.184.216.34');
      done();
    });
  });

  it('blockt, wenn ALLE aufgelösten Adressen intern sind (klassisches Rebinding)', (done) => {
    const lookup = makeGuardedLookup(fakeResolver([{ address: '169.254.169.254', family: 4 }]));
    lookup('evil.example', { all: true } as never, (err, address) => {
      expect(err).toBeInstanceOf(SsrfBlockedError);
      expect(address).toBe('');
      done();
    });
  });

  it('blockt IP-Literal-Hostnamen, die intern sind (ohne Auflösung)', (done) => {
    const lookup = makeGuardedLookup(fakeResolver([{ address: '8.8.8.8', family: 4 }]));
    lookup('127.0.0.1', { all: true } as never, (err) => {
      expect(err).toBeInstanceOf(SsrfBlockedError);
      done();
    });
  });

  it('reicht DNS-Auflösungsfehler durch (fail-closed, kein Verify)', (done) => {
    const errResolver = ((_h: string, _o: unknown, cb: (e: unknown, a: unknown) => void) =>
      cb(new Error('ENOTFOUND'), [])) as never;
    const lookup = makeGuardedLookup(errResolver);
    lookup('nx.example', { all: true } as never, (err) => {
      expect(err).toBeInstanceOf(Error);
      done();
    });
  });
});

describe('safeFetch (Integration, echte DNS + HTTP-Pfad)', () => {
  let server: http.Server;
  let port: number;

  beforeAll((done) => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('SECRET-INTERNAL-RESPONSE');
    });
    server.listen(0, '127.0.0.1', () => {
      port = (server.address() as AddressInfo).port;
      done();
    });
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it('blockt einen echten Connect zu einem Loopback-Server (localhost)', async () => {
    // 'localhost' löst auf 127.0.0.1/::1 auf → beide geblockt → SsrfBlockedError,
    // der interne Response wird NIE gelesen.
    await expect(safeFetch(`http://localhost:${port}/`, { timeoutMs: 2000 })).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it('blockt einen echten Connect zu einem 127.0.0.1-Literal', async () => {
    await expect(
      safeFetch(`http://127.0.0.1:${port}/`, { timeoutMs: 2000 }),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('lehnt nicht-http(s)-Schemata ab', async () => {
    await expect(safeFetch('file:///etc/passwd')).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});
