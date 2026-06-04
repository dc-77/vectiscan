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
    // VEC-112/L2: per Default keine kostenlose Aktivierung; per ENV schaltbar.
    isFreeActivationAllowed: () => process.env.STRIPE_ALLOW_FREE_ACTIVATION === 'true',
  };
});

// VEC-112/L1: withTransaction faehrt die Callback-Query gegen denselben
// query-Mock — so deckt der vorhandene query-basierte Mock auch die
// transaktionalen Statements ab.
jest.mock('../lib/db', () => {
  const query = jest.fn();
  return { query, withTransaction: (fn: (q: unknown) => unknown) => fn(query) };
});
jest.mock('../lib/queue', () => ({ enqueuePrecheck: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import * as stripeLib from '../lib/stripe';
import { query } from '../lib/db';
import { enqueuePrecheck } from '../lib/queue';
import { audit } from '../lib/audit';

const constructEvent = (stripeLib as unknown as { __constructEvent: jest.Mock }).__constructEvent;
const mockQuery = query as jest.Mock;
const mockEnqueue = enqueuePrecheck as jest.Mock;
const mockAudit = audit as jest.Mock;

/**
 * Configurable db.query mock. `seenEventIds` simulates the idempotency ledger:
 * the first INSERT for a given event id returns rowCount 1, replays return 0.
 *
 * VEC-112 additions:
 *  - `subStatus` / `expectedPriceId` back the `SELECT stripe_price_id, status`
 *    lookup (I3 + activeNow gate),
 *  - `claimedRows` backs the atomic `UPDATE scan_targets ... RETURNING id`
 *    enqueue claim (L1).
 */
function installDbMock(
  opts: {
    seenEventIds?: Set<string>;
    updateRowCount?: number;
    claimedRows?: Array<{ id: string }>;
    subStatus?: string;
    expectedPriceId?: string | null;
    subFound?: boolean;
  } = {},
) {
  const seen = opts.seenEventIds ?? new Set<string>();
  const updateRowCount = opts.updateRowCount ?? 1;
  const claimedRows = opts.claimedRows ?? [{ id: 't1' }];
  const subStatus = opts.subStatus ?? 'pending';
  const expectedPriceId = opts.expectedPriceId ?? null;
  const subFound = opts.subFound ?? true;

  mockQuery.mockImplementation(async (sql: string, params: unknown[] = []) => {
    if (sql.includes('INSERT INTO stripe_webhook_events')) {
      const id = params[0] as string;
      if (seen.has(id)) return { rowCount: 0, rows: [] };
      seen.add(id);
      return { rowCount: 1, rows: [{ id }] };
    }
    if (sql.includes('SELECT stripe_price_id')) {
      return subFound
        ? { rowCount: 1, rows: [{ stripe_price_id: expectedPriceId, status: subStatus }] }
        : { rowCount: 0, rows: [] };
    }
    if (sql.includes('UPDATE subscriptions')) {
      return updateRowCount > 0
        ? { rowCount: updateRowCount, rows: [{ id: params[0] }] }
        : { rowCount: 0, rows: [] };
    }
    if (sql.includes('UPDATE scan_targets')) {
      return { rowCount: claimedRows.length, rows: claimedRows };
    }
    // ledger subscription_id link / processed_at update / delete / fallback
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

function activationCalls() {
  return mockQuery.mock.calls.filter(
    ([sql]) => String(sql).includes('UPDATE subscriptions') && String(sql).includes("status = 'active'"),
  );
}

beforeEach(() => {
  jest.clearAllMocks();
  delete process.env.STRIPE_ALLOW_FREE_ACTIVATION;
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
    const updateCall = activationCalls()[0];
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
    expect(activationCalls()).toHaveLength(1);
    await app.close();
  });

  it('does not re-enqueue an already-active subscription whose targets are claimed', async () => {
    // sub already 'active' from a prior run, activation UPDATE matches 0 rows,
    // and the targets were already enqueued (claim RETURNING -> 0 rows).
    installDbMock({ updateRowCount: 0, subStatus: 'active', claimedRows: [] });
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

  it('skips non-activatable end states (expired) entirely', async () => {
    installDbMock({ updateRowCount: 0, subStatus: 'expired', claimedRows: [{ id: 't1' }] });
    constructEvent.mockReturnValue({
      id: 'evt_paid_exp',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_exp', payment_status: 'paid', amount_total: 1, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-exp' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    // expired => not active => no enqueue even though targets are unclaimed
    expect(mockEnqueue).not.toHaveBeenCalled();
    await app.close();
  });

  // --- VEC-112/L1: lost-quota recovery -------------------------------------
  it('L1: recovers lost scan quota — already-active sub with unclaimed targets re-enqueues', async () => {
    // Simulates a prior attempt that activated the sub but crashed before the
    // enqueue (idempotency claim was rolled back, Stripe retries). The sub is
    // already 'active' (activation UPDATE matches 0), but the targets are still
    // unclaimed (precheck_enqueued_at IS NULL) => the quota must still be queued.
    installDbMock({ updateRowCount: 0, subStatus: 'active', claimedRows: [{ id: 't9' }] });
    constructEvent.mockReturnValue({
      id: 'evt_recover_1',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_rec', payment_status: 'paid', amount_total: 49000, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-rec' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    expect(mockEnqueue).toHaveBeenCalledWith({ subscriptionId: 'sub-uuid-rec', targetIds: ['t9'] });
    await app.close();
  });

  // --- VEC-112/L1: atomic rollback arms the Stripe retry --------------------
  it('L1: a failing enqueue returns 500 and releases the idempotency claim for retry', async () => {
    installDbMock();
    mockEnqueue.mockRejectedValueOnce(new Error('redis down'));
    constructEvent.mockReturnValue({
      id: 'evt_enqueue_fail',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_fail', payment_status: 'paid', amount_total: 49000, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-fail', price_id: 'p' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(500);
    // ledger claim deleted so Stripe's retry can re-process cleanly
    const del = mockQuery.mock.calls.find(([sql]) => String(sql).includes('DELETE FROM stripe_webhook_events'));
    expect(del).toBeDefined();
    // no confirmation audit on a failed activation
    expect(mockAudit).not.toHaveBeenCalledWith(expect.objectContaining({ action: 'subscription.payment_confirmed' }));
    await app.close();
  });

  it('activates on checkout.session.async_payment_succeeded (delayed SEPA/Sofort payment)', async () => {
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

    const updateCall = activationCalls()[0];
    expect(updateCall).toBeDefined();
    expect(updateCall![1]).toEqual(expect.arrayContaining(['sub-uuid-async', 49000, 'EUR', 'sub_stripe_async', 'price_perimeter', 'cs_async_1']));
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    await app.close();
  });

  // --- VEC-112/L2: no free activation by default ---------------------------
  it('L2: no_payment_required does NOT activate for free by default', async () => {
    installDbMock();
    constructEvent.mockReturnValue({
      id: 'evt_free_1',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_free', payment_status: 'no_payment_required', amount_total: 0, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-free' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    expect(activationCalls()).toHaveLength(0);
    expect(mockEnqueue).not.toHaveBeenCalled();
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({ action: 'subscription.free_activation_blocked' }));
    await app.close();
  });

  it('L2: no_payment_required activates when STRIPE_ALLOW_FREE_ACTIVATION=true', async () => {
    process.env.STRIPE_ALLOW_FREE_ACTIVATION = 'true';
    installDbMock();
    constructEvent.mockReturnValue({
      id: 'evt_free_2',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_free2', payment_status: 'no_payment_required', amount_total: 0, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-free2' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    expect(activationCalls()).toHaveLength(1);
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    await app.close();
  });

  // --- VEC-112/I2: ledger row is linked to the subscription ----------------
  it('I2: links the idempotency-ledger row to the subscription id', async () => {
    installDbMock();
    constructEvent.mockReturnValue({
      id: 'evt_link_1',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_link', payment_status: 'paid', amount_total: 49000, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-link', price_id: 'p' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    const link = mockQuery.mock.calls.find(
      ([sql]) => String(sql).includes('UPDATE stripe_webhook_events') && String(sql).includes('subscription_id = $2'),
    );
    expect(link).toBeDefined();
    expect(link![1]).toEqual(['evt_link_1', 'sub-uuid-link']);
    await app.close();
  });

  // --- VEC-112/I3: price-id plausibility -----------------------------------
  it('I3: still activates but flags a price-id mismatch in the audit trail', async () => {
    installDbMock({ expectedPriceId: 'price_expected' });
    constructEvent.mockReturnValue({
      id: 'evt_mismatch_1',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_mm', payment_status: 'paid', amount_total: 49000, currency: 'eur', subscription: 's', metadata: { subscription_id: 'sub-uuid-mm', price_id: 'price_unexpected' } } },
    });
    const app = await buildApp();
    const res = await post(app, '{}');
    expect(res.statusCode).toBe(200);
    // non-blocking: activation still happens
    expect(activationCalls()).toHaveLength(1);
    expect(mockEnqueue).toHaveBeenCalledTimes(1);
    // mismatch recorded in the confirmation audit
    expect(mockAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'subscription.payment_confirmed',
        details: expect.objectContaining({ priceMismatch: { expected: 'price_expected', got: 'price_unexpected' } }),
      }),
    );
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
