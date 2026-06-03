import Fastify, { FastifyInstance } from 'fastify';
import { webhookRoutes } from '../routes/webhooks';

// --- Mocks -------------------------------------------------------------

jest.mock('../lib/stripe', () => {
  const constructEvent = jest.fn();
  return {
    __constructEvent: constructEvent,
    isStripeConfigured: () => true,
    getStripe: () => ({ webhooks: { constructEvent } }),
    getWebhookSecret: () => 'whsec_test',
  };
});

jest.mock('../lib/db', () => ({ query: jest.fn() }));
jest.mock('../lib/queue', () => ({ enqueuePrecheck: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import * as stripeLib from '../lib/stripe';
import { query } from '../lib/db';
import { enqueuePrecheck } from '../lib/queue';

const constructEvent = (stripeLib as unknown as { __constructEvent: jest.Mock }).__constructEvent;
const mockQuery = query as jest.Mock;
const mockEnqueue = enqueuePrecheck as jest.Mock;

/**
 * Configurable db.query mock. `seenEventIds` simulates the idempotency ledger:
 * the first INSERT for a given event id returns rowCount 1, replays return 0.
 */
function installDbMock(opts: { seenEventIds?: Set<string>; updateRowCount?: number; targetRows?: Array<{ id: string }> } = {}) {
  const seen = opts.seenEventIds ?? new Set<string>();
  const updateRowCount = opts.updateRowCount ?? 1;
  const targetRows = opts.targetRows ?? [{ id: 't1' }];

  mockQuery.mockImplementation(async (sql: string, params: unknown[] = []) => {
    if (sql.includes('INSERT INTO stripe_webhook_events')) {
      const id = params[0] as string;
      if (seen.has(id)) return { rowCount: 0, rows: [] };
      seen.add(id);
      return { rowCount: 1, rows: [{ id }] };
    }
    if (sql.includes('UPDATE subscriptions')) {
      return updateRowCount > 0
        ? { rowCount: updateRowCount, rows: [{ id: params[0] }] }
        : { rowCount: 0, rows: [] };
    }
    if (sql.includes('SELECT id FROM scan_targets')) {
      return { rowCount: targetRows.length, rows: targetRows };
    }
    // processed_at update / delete / fallback
    return { rowCount: 1, rows: [] };
  });
}

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(webhookRoutes);
  await app.ready();
  return app;
}

function post(app: FastifyInstance, body: string, headers: Record<string, string> = { 'stripe-signature': 'sig_ok' }) {
  return app.inject({
    method: 'POST',
    url: '/api/webhooks/stripe',
    headers: { 'content-type': 'application/json', ...headers },
    payload: body,
  });
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('POST /api/webhooks/stripe', () => {
  it('activates subscription and unlocks scan quota on checkout.session.completed', async () => {
    installDbMock();
    constructEvent.mockReturnValue({
      id: 'evt_paid_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_1',
          payment_status: 'paid',
          amount_total: 49000,
          currency: 'eur',
          subscription: 'sub_stripe_1',
          metadata: { subscription_id: 'sub-uuid-1', price_id: 'price_perimeter' },
        },
      },
    });

    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);

    // subscription was activated with the paid amount
    const updateCall = mockQuery.mock.calls.find(([sql]) => String(sql).includes('UPDATE subscriptions') && String(sql).includes("status = 'active'"));
    expect(updateCall).toBeDefined();
    expect(updateCall![1]).toEqual(expect.arrayContaining(['sub-uuid-1', 49000, 'EUR', 'sub_stripe_1', 'price_perimeter', 'cs_1']));

    // scan quota unlocked exactly once
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    expect(mockEnqueue).toHaveBeenCalledWith({ subscriptionId: 'sub-uuid-1', targetIds: ['t1'] });
    await app.close();
  });

  it('is idempotent: a replayed event does not re-activate or re-enqueue', async () => {
    const seen = new Set<string>();
    installDbMock({ seenEventIds: seen });
    const event = {
      id: 'evt_paid_dup',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_2', payment_status: 'paid', amount_total: 49000, currency: 'eur',
          subscription: 'sub_stripe_2', metadata: { subscription_id: 'sub-uuid-2', price_id: 'price_x' },
        },
      },
    };
    constructEvent.mockReturnValue(event);

    const app = await buildApp();
    const first = await post(app, '{}');
    expect(first.statusCode).toBe(200);
    expect(mockEnqueue).toHaveBeenCalledTimes(1);

    // Replay the exact same event id
    const second = await post(app, '{}');
    expect(second.statusCode).toBe(200);
    expect(JSON.parse(second.body)).toMatchObject({ duplicate: true });
    // No second activation / enqueue
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    const activations = mockQuery.mock.calls.filter(([sql]) => String(sql).includes('UPDATE subscriptions') && String(sql).includes("status = 'active'"));
    expect(activations).toHaveLength(1);
    await app.close();
  });

  it('does not re-activate an already-active subscription (DB-level guard)', async () => {
    // updateRowCount 0 => WHERE status IN (pending,payment_failed) matched nothing
    installDbMock({ updateRowCount: 0 });
    constructEvent.mockReturnValue({
      id: 'evt_paid_3',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_3', payment_status: 'paid', amount_total: 1, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-3' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    expect(mockEnqueue).not.toHaveBeenCalled();
    await app.close();
  });

  it('activates on checkout.session.async_payment_succeeded (delayed SEPA/Sofort payment)', async () => {
    // M1: bei verzoegerten Zahlarten feuert 'completed' zuerst unpaid (Abo
    // bleibt pending), und erst 'async_payment_succeeded' bestaetigt den
    // Geldeingang. Dieses Event muss dieselbe Aktivierung ausloesen.
    installDbMock();
    constructEvent.mockReturnValue({
      id: 'evt_async_ok_1',
      type: 'checkout.session.async_payment_succeeded',
      data: {
        object: {
          id: 'cs_async_1',
          payment_status: 'paid',
          amount_total: 49000,
          currency: 'eur',
          subscription: 'sub_stripe_async',
          metadata: { subscription_id: 'sub-uuid-async', price_id: 'price_perimeter' },
        },
      },
    });

    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);

    const updateCall = mockQuery.mock.calls.find(([sql]) => String(sql).includes('UPDATE subscriptions') && String(sql).includes("status = 'active'"));
    expect(updateCall).toBeDefined();
    expect(updateCall![1]).toEqual(expect.arrayContaining(['sub-uuid-async', 49000, 'EUR', 'sub_stripe_async', 'price_perimeter', 'cs_async_1']));
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    await app.close();
  });

  it('marks payment_failed and unlocks no quota on checkout.session.expired', async () => {
    installDbMock();
    constructEvent.mockReturnValue({
      id: 'evt_expired_1',
      type: 'checkout.session.expired',
      data: { object: { id: 'cs_4', metadata: { subscription_id: 'sub-uuid-4' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    expect(mockEnqueue).not.toHaveBeenCalled();
    const failedCall = mockQuery.mock.calls.find(([sql]) => String(sql).includes('UPDATE subscriptions') && String(sql).includes("status = 'payment_failed'"));
    expect(failedCall).toBeDefined();
    expect(failedCall![1]).toEqual(['sub-uuid-4']);
    await app.close();
  });

  it('rejects an invalid signature with 400', async () => {
    installDbMock();
    constructEvent.mockImplementation(() => {
      throw new Error('No signatures found matching the expected signature');
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(400);
    // no ledger write, no activation
    expect(mockQuery).not.toHaveBeenCalled();
    await app.close();
  });

  it('rejects a missing signature header with 400', async () => {
    installDbMock();
    const app = await buildApp();
    const res = await post(app, '{}', {});
    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({ error: 'missing_signature' });
    await app.close();
  });
});
