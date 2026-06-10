/**
 * VEC-381 — SofortScan Client-Concurrency-Pool + Retry.
 * Beweist:
 *  - runPool hält die Nebenläufigkeit ≤ limit und verarbeitet alle Items.
 *  - runModule unterscheidet transientes `too_many_concurrent` (bounded Retry)
 *    von `rate_limited` (Fensterlimit → Meldung, kein Retry).
 */

// getToken aus '@/lib/auth' deterministisch halten (kein localStorage nötig).
jest.mock('@/lib/auth', () => ({
  getToken: () => 'test-token',
}));

import { runPool, runModule, CLIENT_CONCURRENCY } from '@/lib/liveCheck';

type Body = Record<string, unknown>;
function mockRes(status: number, body: Body): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
  } as unknown as Response;
}

describe('runPool (Client-Concurrency-Pool)', () => {
  it('hält die Nebenläufigkeit ≤ limit und verarbeitet alle Items', async () => {
    let active = 0;
    let maxActive = 0;
    let processed = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);

    await runPool(items, CLIENT_CONCURRENCY, async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      processed++;
    });

    expect(processed).toBe(20);
    expect(maxActive).toBeLessThanOrEqual(CLIENT_CONCURRENCY);
    expect(maxActive).toBeGreaterThan(1); // läuft tatsächlich parallel
  });

  it('verarbeitet eine leere Liste ohne Fehler', async () => {
    let calls = 0;
    await runPool([], 4, async () => { calls++; });
    expect(calls).toBe(0);
  });
});

describe('runModule — Retry-Verhalten (VEC-381)', () => {
  const origFetch = global.fetch;
  afterEach(() => { global.fetch = origFetch; });

  it('wiederholt bei transientem too_many_concurrent und liefert dann das Ergebnis', async () => {
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(mockRes(429, { success: false, error: 'too_many_concurrent', retryAfter: 0 }))
      .mockResolvedValueOnce(mockRes(200, {
        success: true,
        data: { result: { valid: true, daysUntilExpiry: 90, issuer: 'Let’s Encrypt' } },
      }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const r = await runModule('ssl', 'example.com');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(r.status).toBe('pass');
  });

  it('zeigt bei rate_limited (Fensterlimit) die Meldung OHNE Retry', async () => {
    const fetchMock = jest.fn()
      .mockResolvedValue(mockRes(429, { success: false, error: 'rate_limited', retryAfter: 30 }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const r = await runModule('ssl', 'example.com');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(r.status).toBe('error');
    expect(r.summary).toBe('Bitte warten (Rate-Limit)');
  });

  it('gibt nach erschöpften Retries die Rate-Limit-Meldung zurück', async () => {
    const fetchMock = jest.fn()
      .mockResolvedValue(mockRes(429, { success: false, error: 'too_many_concurrent', retryAfter: 0 }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const r = await runModule('ssl', 'example.com');

    // 1 Erstversuch + MAX_CONCURRENT_RETRIES (4) = 5 Aufrufe.
    expect(fetchMock).toHaveBeenCalledTimes(5);
    expect(r.summary).toBe('Bitte warten (Rate-Limit)');
  });
});
