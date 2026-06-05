/**
 * Resend Bounce-/Complaint-/Suppression-Webhook — Route-Level-Tests (VEC-188).
 *
 * Sichert die Sicherheits-/Verhaltens-Invarianten des öffentlichen Endpoints:
 *   - fail-closed: 503 ohne Secret, 400 bei fehlender/ungültiger Svix-Signatur
 *   - bounce/complaint → Adresse in email_suppressions + Audit
 *   - Idempotenz: Replay derselben svix-id ohne Seiteneffekt (200 duplicate)
 *   - Verarbeitungsfehler → 500 + Idempotenz-Claim freigegeben (Resend-Retry)
 */
import Fastify, { FastifyInstance } from 'fastify';

// --- Mocks -------------------------------------------------------------

jest.mock('../lib/resend', () => {
  const verify = jest.fn();
  return {
    __verify: verify,
    isResendWebhookConfigured: jest.fn().mockReturnValue(true),
    verifyResendWebhook: verify,
  };
});

jest.mock('../lib/db', () => ({ query: jest.fn(), withTransaction: jest.fn() }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { resendWebhookRoutes } from '../routes/resend-webhook';
import * as resendLib from '../lib/resend';
import { query, withTransaction } from '../lib/db';
import { audit } from '../lib/audit';

const verify = (resendLib as unknown as { __verify: jest.Mock }).__verify;
const mockConfigured = resendLib.isResendWebhookConfigured as jest.Mock;
const mockQuery = query as jest.Mock;
const mockTx = withTransaction as jest.Mock;
const mockAudit = audit as jest.Mock;

// withTransaction(fn) fuehrt die Route-Verarbeitung gegen die an den TX-Client
// gebundene query-Funktion aus. Im Test delegieren wir sie auf denselben
// mockQuery — so wirkt der gesamte Ledger-/Suppression-Pfad weiter ueber das
// installDbMock, und ein geworfener Fehler propagiert (= echtes Rollback-/500-
// Verhalten der Route, ohne echte DB).
function installTxMock() {
  mockTx.mockImplementation(async (fn: (q: typeof mockQuery) => Promise<unknown>) =>
    fn(mockQuery),
  );
}

/**
 * Idempotenz-Ledger-Mock: der erste INSERT je svix-id liefert rowCount 1,
 * Replays 0. Suppression-INSERT und übrige Statements liefern neutral.
 */
function installDbMock(opts: { seenIds?: Set<string> } = {}) {
  const seen = opts.seenIds ?? new Set<string>();
  mockQuery.mockImplementation(async (sql: string, params: unknown[] = []) => {
    if (sql.includes('INSERT INTO resend_webhook_events')) {
      const id = params[0] as string;
      if (seen.has(id)) return { rowCount: 0, rows: [] };
      seen.add(id);
      return { rowCount: 1, rows: [{ id }] };
    }
    return { rowCount: 1, rows: [] };
  });
}

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(resendWebhookRoutes);
  await app.ready();
  return app;
}

const SIG_HEADERS = {
  'svix-id': 'msg_1',
  'svix-timestamp': '1700000000',
  'svix-signature': 'v1,deadbeef',
};

function post(
  app: FastifyInstance,
  body = '{}',
  headers: Record<string, string> = SIG_HEADERS,
) {
  return app.inject({
    method: 'POST',
    url: '/api/webcheck/resend-webhook',
    headers: { 'content-type': 'application/json', ...headers },
    payload: body,
  });
}

function suppressionCalls() {
  return mockQuery.mock.calls.filter(([sql]) =>
    String(sql).includes('INSERT INTO email_suppressions'),
  );
}

beforeEach(() => {
  jest.clearAllMocks();
  mockConfigured.mockReturnValue(true);
  installTxMock();
});

describe('POST /api/webcheck/resend-webhook', () => {
  it('returns 503 when the webhook secret is not configured', async () => {
    mockConfigured.mockReturnValue(false);
    installDbMock();
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(503);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'webhook_not_configured' });
    // fail-closed: nichts verarbeitet
    expect(mockQuery).not.toHaveBeenCalled();
    await app.close();
  });

  it('rejects a request missing the svix signature headers with 400', async () => {
    installDbMock();
    const app = await buildApp();
    const res = await post(app, '{}', {});
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'missing_signature' });
    expect(mockQuery).not.toHaveBeenCalled();
    await app.close();
  });

  it('rejects an invalid signature with 400 and writes no ledger row', async () => {
    installDbMock();
    verify.mockImplementation(() => {
      throw new Error('No matching signature found');
    });
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'invalid_signature' });
    expect(mockQuery).not.toHaveBeenCalled();
    await app.close();
  });

  it('suppresses the recipient on email.bounced and audits it', async () => {
    installDbMock();
    verify.mockReturnValue({
      type: 'email.bounced',
      data: { email_id: 'eml_1', to: ['Foo@Example.com'], bounce: { type: 'Permanent' } },
    });
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(200);

    const supp = suppressionCalls();
    expect(supp).toHaveLength(1);
    // normalisiert (lowercase/trim), reason=bounce, source_event_id=svix-id
    expect(supp[0]![1]).toEqual(['foo@example.com', 'bounce', expect.any(String), 'msg_1']);
    expect(mockAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'webcheck.email_suppressed',
        details: expect.objectContaining({ email: 'foo@example.com', reason: 'bounce' }),
      }),
    );
    await app.close();
  });

  it('suppresses the recipient on email.complained with reason=complaint', async () => {
    installDbMock();
    verify.mockReturnValue({
      type: 'email.complained',
      data: { email_id: 'eml_2', to: 'spamhater@gmail.com' },
    });
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(200);
    const supp = suppressionCalls();
    expect(supp).toHaveLength(1);
    expect(supp[0]![1]![1]).toBe('complaint');
    await app.close();
  });

  it('ignores unhandled event types without suppressing', async () => {
    installDbMock();
    verify.mockReturnValue({ type: 'email.delivered', data: { to: ['ok@example.com'] } });
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(200);
    expect(suppressionCalls()).toHaveLength(0);
    expect(mockAudit).not.toHaveBeenCalled();
    await app.close();
  });

  it('is idempotent: a replayed svix-id does not suppress twice', async () => {
    const seen = new Set<string>();
    installDbMock({ seenIds: seen });
    verify.mockReturnValue({
      type: 'email.bounced',
      data: { email_id: 'eml_3', to: ['dup@example.com'] },
    });
    const app = await buildApp();

    const first = await post(app);
    expect(first.statusCode).toBe(200);
    expect(suppressionCalls()).toHaveLength(1);

    const second = await post(app);
    expect(second.statusCode).toBe(200);
    expect(JSON.parse(second.body)).toMatchObject({ duplicate: true });
    // kein zweiter Suppression-Insert
    expect(suppressionCalls()).toHaveLength(1);
    await app.close();
  });

  it('returns 500 and rolls back the idempotency claim when processing fails', async () => {
    const seen = new Set<string>();
    mockQuery.mockImplementation(async (sql: string, params: unknown[] = []) => {
      if (sql.includes('INSERT INTO resend_webhook_events')) {
        const id = params[0] as string;
        if (seen.has(id)) return { rowCount: 0, rows: [] };
        seen.add(id);
        return { rowCount: 1, rows: [{ id }] };
      }
      if (sql.includes('INSERT INTO email_suppressions')) {
        throw new Error('db down');
      }
      return { rowCount: 1, rows: [] };
    });
    verify.mockReturnValue({
      type: 'email.bounced',
      data: { email_id: 'eml_4', to: ['boom@example.com'] },
    });
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(500);
    // Verarbeitung lief in withTransaction → der Fehler rollt Claim + Upsert
    // gemeinsam zurueck. processed_at darf NIE markiert worden sein (sonst waere
    // der Claim als „erledigt" zementiert und der Retry praellte als Duplikat ab).
    expect(mockTx).toHaveBeenCalledTimes(1);
    const processed = mockQuery.mock.calls.find(([sql]) =>
      String(sql).includes('UPDATE resend_webhook_events SET processed_at'),
    );
    expect(processed).toBeUndefined();
    await app.close();
  });

  it('processes claim, suppression and processed_at atomically (VEC-193/F-2)', async () => {
    // Regression: Idempotenz-Claim, Suppression-Upsert UND processed_at-Update
    // muessen in EINER Transaktion laufen. Sonst lässt ein harter Crash nach dem
    // Upsert und vor processed_at den Claim gesetzt → Resend-Retry trifft
    // ON CONFLICT → 200-Duplikat → restliche Empfaenger werden nie suppressed.
    installDbMock();
    verify.mockReturnValue({
      type: 'email.bounced',
      data: { email_id: 'eml_5', to: ['a@example.com', 'b@example.com'] },
    });
    const app = await buildApp();
    const res = await post(app);
    expect(res.statusCode).toBe(200);

    // Genau eine Transaktion umschliesst die gesamte Wirkung.
    expect(mockTx).toHaveBeenCalledTimes(1);

    // Claim + beide Upserts + processed_at gehoeren zusammen in diese Transaktion.
    const ledgerClaim = mockQuery.mock.calls.filter(([sql]) =>
      String(sql).includes('INSERT INTO resend_webhook_events'),
    );
    const processed = mockQuery.mock.calls.filter(([sql]) =>
      String(sql).includes('UPDATE resend_webhook_events SET processed_at'),
    );
    expect(ledgerClaim).toHaveLength(1);
    expect(suppressionCalls()).toHaveLength(2);
    expect(processed).toHaveLength(1);
    await app.close();
  });
});
