/**
 * PA-4 / VEC-32 — Report-Zustellung & Abschluss-Benachrichtigung.
 *
 * Covers the scan-complete notification handler:
 *  - AC#1: email to subscription report_emails AND customer email
 *  - AC#2: download_token is passed through to the email link
 *  - AC#3: idempotent — recipients with an existing `report.notified`
 *          audit entry are not re-mailed (regenerate / retry safe), and a
 *          `report.notified` audit event is written per dispatch.
 */
import { jest } from '@jest/globals';

jest.mock('../lib/db', () => ({
  query: jest.fn(),
  initDb: jest.fn(),
  pool: { end: jest.fn() },
}));

jest.mock('../lib/email', () => ({
  sendScanCompleteEmail: jest.fn(),
  sendPasswordResetEmail: jest.fn(),
}));

jest.mock('../lib/audit', () => ({
  audit: jest.fn(),
}));

import { handleReportComplete } from '../lib/ws-manager';
import { query } from '../lib/db';
import { sendScanCompleteEmail } from '../lib/email';
import { audit } from '../lib/audit';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockSend = sendScanCompleteEmail as jest.MockedFunction<typeof sendScanCompleteEmail>;
const mockAudit = audit as jest.MockedFunction<typeof audit>;

const ORDER_ID = 'order-uuid-1234';
const TOKEN = 'dl-token-abc';

function orderRow(overrides: Record<string, unknown> = {}) {
  return {
    email: 'customer@example.com',
    domain: 'example.com',
    subscription_id: 'sub-1',
    download_token: TOKEN,
    report_emails: ['team@acme.io', 'ops@acme.io'],
    ...overrides,
  };
}

/**
 * Wire the mocked db.query: first call loads the order/recipients,
 * second call loads the already-notified recipients from audit_log.
 */
function primeQueries(order: Record<string, unknown> | null, alreadyNotified: string[]) {
  mockQuery.mockReset();
  mockQuery
    // 1) order + recipients lookup
    .mockResolvedValueOnce({ rows: order ? [order] : [] } as never)
    // 2) already-notified recipients
    .mockResolvedValueOnce({
      rows: alreadyNotified.map((recipient) => ({ recipient })),
    } as never)
    // 3) UPDATE orders ... delivered
    .mockResolvedValue({ rows: [] } as never);
}

beforeEach(() => {
  mockSend.mockClear();
  mockAudit.mockClear();
});

describe('handleReportComplete (PA-4)', () => {
  it('AC#1/AC#2: mails every unique recipient with the download token', async () => {
    primeQueries(orderRow(), []);

    await handleReportComplete(ORDER_ID);

    // report_emails (2) + customer email (1) = 3 unique recipients
    expect(mockSend).toHaveBeenCalledTimes(3);
    const recipients = mockSend.mock.calls.map((c) => c[0]).sort();
    expect(recipients).toEqual(['customer@example.com', 'ops@acme.io', 'team@acme.io']);
    // AC#2: token + orderId + domain forwarded to the email builder
    for (const call of mockSend.mock.calls) {
      expect(call[1]).toBe('example.com'); // domain
      expect(call[2]).toBe(ORDER_ID); // orderId
      expect(call[3]).toBe(TOKEN); // downloadToken
    }
    // AC#3: one audit event per dispatch
    expect(mockAudit).toHaveBeenCalledTimes(3);
    expect(mockAudit.mock.calls[0][0]).toMatchObject({
      orderId: ORDER_ID,
      action: 'report.notified',
    });
  });

  it('AC#3: skips recipients already notified (regenerate is idempotent)', async () => {
    // Two of three recipients were already notified on a previous run.
    primeQueries(orderRow(), ['team@acme.io', 'customer@example.com']);

    await handleReportComplete(ORDER_ID);

    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(mockSend.mock.calls[0][0]).toBe('ops@acme.io');
    expect(mockAudit).toHaveBeenCalledTimes(1);
  });

  it('AC#3: full regenerate with all recipients notified sends nothing', async () => {
    primeQueries(orderRow(), ['team@acme.io', 'ops@acme.io', 'customer@example.com']);

    await handleReportComplete(ORDER_ID);

    expect(mockSend).not.toHaveBeenCalled();
    expect(mockAudit).not.toHaveBeenCalled();
  });

  it('falls back to the customer email when the subscription has no report_emails', async () => {
    primeQueries(orderRow({ report_emails: null, subscription_id: null }), []);

    await handleReportComplete(ORDER_ID);

    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(mockSend.mock.calls[0][0]).toBe('customer@example.com');
  });

  it('skips delivery when the report has no download token yet', async () => {
    primeQueries(orderRow({ download_token: null }), []);

    await handleReportComplete(ORDER_ID);

    expect(mockSend).not.toHaveBeenCalled();
    expect(mockAudit).not.toHaveBeenCalled();
  });

  it('does nothing when the order cannot be found', async () => {
    primeQueries(null, []);

    await handleReportComplete(ORDER_ID);

    expect(mockSend).not.toHaveBeenCalled();
  });
});
