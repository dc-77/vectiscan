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

jest.mock('../lib/db', () => ({ query: jest.fn() }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { resendWebhookRoutes } from '../routes/resend-webhook';
import * as resendLib from '../lib/resend';
import { query } from '../lib/db';
import { audit } from '../lib/audit';

const verify = (resendLib as unknown as { __verify: jest.Mock }).__verify;
const mockConfigured = resendLib.isResendWebhookConfigured as jest.Mock;
const mockQuery = query as jest.Mock;
const mockAudit = audit as jest.Mock;

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

  it('returns 500 and releases the idempotency claim when processing fails', async () => {
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
    // Claim wieder freigegeben, damit Resends Retry erneut zustellen kann
    const del = mockQuery.mock.calls.find(([sql]) =>
      String(sql).includes('DELETE FROM resend_webhook_events'),
    );
    expect(del).toBeDefined();
    await app.close();
  });
});
