/**
 * Pre-Send-Suppression-Gate in lib/email.ts (VEC-188).
 *
 * Belegt: eine suppressed Adresse (Bounce/Complaint aus dem Resend-Webhook) wird
 * VOR dem Versand übersprungen (kein Resend-Call, Audit), eine saubere Adresse
 * normal versendet. Fail-open bei DB-Fehler (Versand läuft trotzdem).
 */
const mockSend = jest.fn().mockResolvedValue({ error: null });

jest.mock('resend', () => ({
  Resend: jest.fn().mockImplementation(() => ({ emails: { send: mockSend } })),
}));
jest.mock('../lib/db', () => ({ query: jest.fn() }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { sendWebcheckDoiEmail, isEmailSuppressed } from '../lib/email';
import { query } from '../lib/db';
import { audit } from '../lib/audit';

const mockQuery = query as jest.Mock;
const mockAudit = audit as jest.Mock;

/** SELECT auf email_suppressions liefert je nach `suppressed` 1 oder 0 Zeilen. */
function installSuppression(suppressed: boolean) {
  mockQuery.mockImplementation(async (sql: string) => {
    if (sql.includes('FROM email_suppressions')) {
      return suppressed ? { rows: [{ email: 'x' }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 0 };
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.RESEND_API_KEY = 'test_key';
});

describe('email suppression pre-send gate', () => {
  it('skips the send for a suppressed recipient and audits it', async () => {
    installSuppression(true);
    await sendWebcheckDoiEmail('Bounced@Example.com', 'example.com', 'doi-token');
    expect(mockSend).not.toHaveBeenCalled();
    expect(mockAudit).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'webcheck.suppression_skipped' }),
    );
  });

  it('sends normally for a non-suppressed recipient', async () => {
    installSuppression(false);
    await sendWebcheckDoiEmail('fresh@example.com', 'example.com', 'doi-token');
    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(mockAudit).not.toHaveBeenCalledWith(
      expect.objectContaining({ action: 'webcheck.suppression_skipped' }),
    );
  });

  it('normalizes the address before the suppression lookup', async () => {
    installSuppression(false);
    await isEmailSuppressed('  MiXeD@Example.COM ');
    const sel = mockQuery.mock.calls.find(([sql]) =>
      String(sql).includes('FROM email_suppressions'),
    );
    expect(sel![1]).toEqual(['mixed@example.com']);
  });

  it('fails OPEN: a lookup error still sends the mail', async () => {
    mockQuery.mockRejectedValue(new Error('db down'));
    await sendWebcheckDoiEmail('fresh@example.com', 'example.com', 'doi-token');
    expect(mockSend).toHaveBeenCalledTimes(1);
  });
});
