/**
 * WebCheck-Free — Route-Level-Integrationstests (VEC-176, F5 aus VEC-169).
 *
 * Die bestehende Suite `webcheck.test.ts` deckt nur pure Helfer + Migrations-Schema.
 * Diese Suite fährt die echten Fastify-Handler (`webcheckRoutes`) gegen gemockte
 * DB/Queue/Verification an und sichert die Sicherheits-/Verhaltens-Invarianten der
 * öffentlichen, anonymen Endpunkte ab:
 *   - /start : 400 invalid email/domain, 429 Rate-Limit-Schwelle, 201 Happy-Path + Lead-Insert
 *   - /verify: 400 invalid leadId, 404 unbekannt, Idempotenz bei vorhandener order_id,
 *              429 free_scan_already_used, verify-false-Pfad, Happy-Path Order+Target+enqueue
 *   - /doi/confirm: idempotent, kein Token-Existenz-Oracle
 *
 * Auto-Approve-Scoping (VEC-172) ist NICHT Teil dieser Suite — der Auto-Approve-Pfad
 * ist noch nicht implementiert (VEC-172=todo). Diese Tests kodieren bewusst den
 * IST-Zustand: jede verifizierte Order läuft via `precheck_running` durch das normale
 * Admin-Gate. Bei VEC-172-Merge gehört die Scoping-Regression an VEC-172 (eigene DoD).
 */
import Fastify, { FastifyInstance } from 'fastify';
import { webcheckRoutes } from '../routes/webcheck';
import { query } from '../lib/db';
import { verifyAll, generateToken } from '../services/VerificationService';
import { enqueuePrecheck } from '../lib/queue';
import { sendWebcheckDoiEmail } from '../lib/email';
import { verifyCaptcha } from '../lib/captcha';

jest.mock('../lib/db', () => {
  const query = jest.fn();
  // withTransaction modelliert die echte Semantik so faithful wie für den TOCTOU-
  // Test nötig: alle Transaktionen werden SERIALISIERT (entspricht dem per-Domain
  // pg_advisory_xact_lock — alle Verifies dieser Suite betreffen dieselbe Domain)
  // und teilen sich denselben query-Mock als Transaktions-Client. So sieht ein
  // wartender zweiter Verify den committeten Zustand des ersten.
  let txChain: Promise<unknown> = Promise.resolve();
  const withTransaction = jest.fn((fn: (q: typeof query) => unknown) => {
    const run = txChain.then(() => fn(query));
    txChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  });
  return {
    query,
    withTransaction,
    initDb: jest.fn(),
    pool: { end: jest.fn() },
  };
});

jest.mock('../lib/queue', () => ({
  enqueuePrecheck: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/audit', () => ({
  audit: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/email', () => ({
  sendWebcheckDoiEmail: jest.fn().mockResolvedValue(undefined),
}));

// CAPTCHA standardmäßig „bestanden" (VEC-173, F2) — einzelne Tests übersteuern.
jest.mock('../lib/captcha', () => ({
  verifyCaptcha: jest.fn().mockResolvedValue({ ok: true, disabled: true }),
}));

jest.mock('../services/VerificationService', () => ({
  generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock12345678'),
  verifyAll: jest.fn(),
}));

// validate: echte isValidEmail/normalize* stammen aus webcheck.ts selbst; nur die
// DB-fremden Domain-/Target-Validatoren werden deterministisch gemockt.
jest.mock('../lib/validate', () => ({
  isValidDomain: jest.fn((d: unknown) => typeof d === 'string' && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)),
  validateTargetBatch: jest.fn((inputs: Array<{ raw_input?: unknown }>) => ({
    targets: inputs.map((i) => {
      const raw = String(i?.raw_input ?? '');
      return {
        raw_input: raw,
        valid: true,
        warnings: [],
        canonical: raw,
        target_type: 'fqdn_root',
        policy_default: 'enumerate',
      };
    }),
    errors: [],
  })),
}));

const mockQuery = query as jest.Mock;
const mockVerifyAll = verifyAll as jest.Mock;
const mockEnqueue = enqueuePrecheck as jest.Mock;
const mockDoiEmail = sendWebcheckDoiEmail as jest.Mock;
const mockVerifyCaptcha = verifyCaptcha as jest.Mock;

const VALID_LEAD_ID = '11111111-2222-3333-4444-555555555555';

/**
 * SQL-inhaltsbasierter Router für den query-Mock — robuster als reihenfolge-
 * abhängige mockResolvedValueOnce-Ketten. Pro Test wird `dbState` gesetzt.
 */
interface DbState {
  rateCounts?: { email: number; domain: number; ip: number };
  velocityCounts?: { global: number; recipientDomain: number };
  insertedLeadId?: string;
  lead?: {
    id: string;
    email: string;
    domain: string;
    verification_token: string;
    verified: boolean;
    order_id: string | null;
  } | null; // null => 404 (0 rows)
  recentFreeScans?: number;
  newOrderId?: string;
  newTargetId?: string;
  doiUpdatedRows?: number; // Anzahl Zeilen, die DOI-UPDATE ... RETURNING liefert
  // TOCTOU-Test (VEC-174): Lead-Lookup pro id + statefuler Free-Scan-Zähler.
  leadsById?: Record<string, DbState['lead']>;
  orderInsertCount?: number; // wie oft INSERT INTO orders tatsächlich lief
}

let dbState: DbState;

function installQueryRouter() {
  mockQuery.mockImplementation(async (sql: string, params?: unknown[]) => {
    const s = String(sql);
    // /verify: per-Domain Advisory-Lock (TOCTOU-Guard, VEC-174). Serialisierung
    // selbst übernimmt der withTransaction-Mock; hier nur sauber „acquired" melden.
    if (s.includes('pg_advisory_xact_lock')) {
      return { rows: [{ pg_advisory_xact_lock: '' }] };
    }
    // /start: Rate-Limit-Fensterzählung
    if (s.includes('COUNT(*) FILTER')) {
      const c = dbState.rateCounts ?? { email: 0, domain: 0, ip: 0 };
      const v = dbState.velocityCounts ?? { global: 0, recipientDomain: 0 };
      return {
        rows: [{
          email_count: String(c.email),
          domain_count: String(c.domain),
          ip_count: String(c.ip),
          global_count: String(v.global),
          recipient_domain_count: String(v.recipientDomain),
        }],
      };
    }
    // /start: Lead-Insert
    if (s.includes('INSERT INTO webcheck_leads')) {
      return { rows: [{ id: dbState.insertedLeadId ?? VALID_LEAD_ID }] };
    }
    // /verify: Lead-Lookup (per id, falls leadsById gesetzt — sonst Single-Lead)
    if (s.includes('FROM webcheck_leads WHERE id')) {
      const id = params?.[0] as string | undefined;
      if (dbState.leadsById && id) {
        const l = dbState.leadsById[id];
        return { rows: l ? [l] : [] };
      }
      return { rows: dbState.lead ? [dbState.lead] : [] };
    }
    // /verify: verified-Update
    if (s.includes('SET verified = TRUE')) {
      return { rows: [] };
    }
    // /verify: Free-Scan-Fensterzählung (statefuler Zähler → spiegelt committete
    // scan_started_at-Writes des bereits durchgelaufenen Verifies, VEC-174).
    if (s.includes('scan_started_at IS NOT NULL')) {
      return { rows: [{ count: String(dbState.recentFreeScans ?? 0) }] };
    }
    // /verify: Customer-Upsert
    if (s.includes('INSERT INTO customers')) {
      return { rows: [{ id: 'cust-1' }] };
    }
    // /verify: Order-Insert
    if (s.includes('INSERT INTO orders')) {
      dbState.orderInsertCount = (dbState.orderInsertCount ?? 0) + 1;
      return { rows: [{ id: dbState.newOrderId ?? 'order-1' }] };
    }
    // /verify: Scan-Target-Insert
    if (s.includes('INSERT INTO scan_targets')) {
      return { rows: [{ id: dbState.newTargetId ?? 'target-1' }] };
    }
    // /verify: order_id-Update auf Lead → schreibt den Free-Scan-Verbrauch fest,
    // den ein wartender zweiter Verify danach im Fenster-COUNT sieht (VEC-174).
    if (s.includes('SET order_id = $2, scan_started_at = NOW()')) {
      dbState.recentFreeScans = (dbState.recentFreeScans ?? 0) + 1;
      return { rows: [] };
    }
    // /doi/confirm: idempotenter Consent-Update
    if (s.includes("SET consent_status = 'confirmed'")) {
      const n = dbState.doiUpdatedRows ?? 0;
      return { rows: n > 0 ? [{ id: 'lead-doi-1' }] : [] };
    }
    throw new Error('Unmocked SQL in webcheck route test: ' + s.slice(0, 80));
  });
}

describe('WebCheck-Free Route-Level (VEC-176)', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    dbState = {};
    installQueryRouter();
    mockVerifyCaptcha.mockResolvedValue({ ok: true, disabled: true });
    mockVerifyAll.mockResolvedValue({ verified: true, method: 'dns_txt' });
    (generateToken as jest.Mock).mockReturnValue('vectiscan-verify-mock12345678');
    app = Fastify();
    await app.register(webcheckRoutes);
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  // --- /api/webcheck/start ------------------------------------------------------

  describe('POST /api/webcheck/start', () => {
    it('400 invalid_email für fehlerhafte E-Mail', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'not-an-email', domain: 'example.com' },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ success: false, error: 'invalid_email' });
      // Fail-closed: kein DB-Schreibzugriff bei Input-Reject
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it('400 invalid_domain für fehlerhafte Domain', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'alice@example.com', domain: 'not a domain' },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ success: false, error: 'invalid_domain' });
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it('429 rate_limited wenn eine Schwelle erreicht ist', async () => {
      dbState.rateCounts = { email: 3, domain: 0, ip: 0 }; // maxPerEmail = 3
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'alice@example.com', domain: 'example.com' },
      });
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ success: false, error: 'rate_limited' });
      // Bei Drosselung wird KEIN Lead angelegt und KEINE DOI-Mail versendet
      const insertCalls = mockQuery.mock.calls.filter((c) => String(c[0]).includes('INSERT INTO webcheck_leads'));
      expect(insertCalls).toHaveLength(0);
      expect(mockDoiEmail).not.toHaveBeenCalled();
    });

    it('201 Happy-Path legt Lead an, versendet DOI-Mail, liefert Verify-Instruktionen', async () => {
      dbState.rateCounts = { email: 0, domain: 0, ip: 0 };
      dbState.insertedLeadId = VALID_LEAD_ID;
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'Alice@Example.COM', domain: 'Example.com', utm_source: 'google' },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.leadId).toBe(VALID_LEAD_ID);
      expect(body.data.domain).toBe('example.com'); // normalisiert
      expect(body.data.verification.methods.map((m: { type: string }) => m.type).sort()).toEqual([
        'dns_txt',
        'file',
        'meta_tag',
      ]);
      // Lead wurde mit normalisierter (lowercase) E-Mail + Domain eingefügt
      const insert = mockQuery.mock.calls.find((c) => String(c[0]).includes('INSERT INTO webcheck_leads'));
      expect(insert).toBeDefined();
      expect(insert![1][0]).toBe('alice@example.com');
      expect(insert![1][1]).toBe('example.com');
      expect(mockDoiEmail).toHaveBeenCalledTimes(1);
    });

    // --- CAPTCHA-Gate (VEC-173, F2) ---------------------------------------------
    it('403 captcha_failed VOR jeglichem DB-Schreibzugriff/DOI-Versand', async () => {
      mockVerifyCaptcha.mockResolvedValueOnce({ ok: false, disabled: false });
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'alice@example.com', domain: 'example.com', captchaToken: 'bad' },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({ success: false, error: 'captcha_failed' });
      // Fail-closed: weder Rate-Limit-Query noch Lead-Insert noch DOI-Mail
      expect(mockQuery).not.toHaveBeenCalled();
      expect(mockDoiEmail).not.toHaveBeenCalled();
    });

    it('reicht das CAPTCHA-Token an verifyCaptcha durch', async () => {
      dbState.rateCounts = { email: 0, domain: 0, ip: 0 };
      await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'alice@example.com', domain: 'example.com', captchaToken: 'tok-123' },
      });
      expect(mockVerifyCaptcha).toHaveBeenCalledWith('tok-123', expect.any(String));
    });

    // --- Aggregierte Velocity-Drossel (VEC-173, F2) -----------------------------
    it('429 velocity_limited bei globalem Spike — kein Lead/keine DOI-Mail', async () => {
      dbState.rateCounts = { email: 0, domain: 0, ip: 0 }; // per-Bezeichner-Limits NICHT erreicht
      dbState.velocityCounts = { global: 200, recipientDomain: 0 }; // VELOCITY.maxGlobal
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'alice@example.com', domain: 'example.com' },
      });
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ success: false, error: 'velocity_limited' });
      const insertCalls = mockQuery.mock.calls.filter((c) => String(c[0]).includes('INSERT INTO webcheck_leads'));
      expect(insertCalls).toHaveLength(0);
      expect(mockDoiEmail).not.toHaveBeenCalled();
    });

    it('429 velocity_limited bei Empfänger-Domain-Spike', async () => {
      dbState.rateCounts = { email: 0, domain: 0, ip: 0 };
      dbState.velocityCounts = { global: 0, recipientDomain: 25 }; // VELOCITY.maxPerRecipientDomain
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/start',
        payload: { email: 'victim@gmail.com', domain: 'example.com' },
      });
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ success: false, error: 'velocity_limited' });
      expect(mockDoiEmail).not.toHaveBeenCalled();
    });
  });

  // --- /api/webcheck/verify -----------------------------------------------------

  describe('POST /api/webcheck/verify', () => {
    it('400 invalid_lead_id für nicht-UUID', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/verify',
        payload: { leadId: 'not-a-uuid' },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ success: false, error: 'invalid_lead_id' });
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it('404 lead_not_found für unbekannte (aber valide) leadId', async () => {
      dbState.lead = null; // 0 rows
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/verify',
        payload: { leadId: VALID_LEAD_ID },
      });
      expect(res.statusCode).toBe(404);
      expect(res.json()).toEqual({ success: false, error: 'lead_not_found' });
    });

    it('idempotent: vorhandene order_id stößt KEINEN zweiten Scan an', async () => {
      dbState.lead = {
        id: VALID_LEAD_ID,
        email: 'alice@example.com',
        domain: 'example.com',
        verification_token: 'tok',
        verified: true,
        order_id: 'existing-order-9',
      };
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/verify',
        payload: { leadId: VALID_LEAD_ID },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({
        success: true,
        data: { verified: true, scanStarted: false, alreadyRequested: true, orderId: 'existing-order-9' },
      });
      // Idempotenz-Invariante: keine Verifikation, kein Order-Insert, kein enqueue
      expect(mockVerifyAll).not.toHaveBeenCalled();
      expect(mockEnqueue).not.toHaveBeenCalled();
      const orderInserts = mockQuery.mock.calls.filter((c) => String(c[0]).includes('INSERT INTO orders'));
      expect(orderInserts).toHaveLength(0);
    });

    it('verify-false: nicht nachgewiesene Domain startet keinen Scan', async () => {
      dbState.lead = {
        id: VALID_LEAD_ID,
        email: 'alice@example.com',
        domain: 'example.com',
        verification_token: 'tok',
        verified: false,
        order_id: null,
      };
      mockVerifyAll.mockResolvedValue({ verified: false });
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/verify',
        payload: { leadId: VALID_LEAD_ID },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ success: true, data: { verified: false, scanStarted: false } });
      expect(mockEnqueue).not.toHaveBeenCalled();
      const orderInserts = mockQuery.mock.calls.filter((c) => String(c[0]).includes('INSERT INTO orders'));
      expect(orderInserts).toHaveLength(0);
    });

    it('429 free_scan_already_used wenn das Domain-Fenster belegt ist', async () => {
      dbState.lead = {
        id: VALID_LEAD_ID,
        email: 'alice@example.com',
        domain: 'example.com',
        verification_token: 'tok',
        verified: false,
        order_id: null,
      };
      dbState.recentFreeScans = 1; // Fenster bereits belegt
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/verify',
        payload: { leadId: VALID_LEAD_ID },
      });
      expect(res.statusCode).toBe(429);
      expect(res.json().error).toBe('free_scan_already_used');
      // Resource-Consumption-Schutz: kein Order-Insert, kein enqueue trotz Verifikation
      expect(mockEnqueue).not.toHaveBeenCalled();
      const orderInserts = mockQuery.mock.calls.filter((c) => String(c[0]).includes('INSERT INTO orders'));
      expect(orderInserts).toHaveLength(0);
    });

    it('Happy-Path: verifizierte Domain legt Order+Target an und enqueued Precheck', async () => {
      dbState.lead = {
        id: VALID_LEAD_ID,
        email: 'alice@example.com',
        domain: 'example.com',
        verification_token: 'tok',
        verified: false,
        order_id: null,
      };
      dbState.recentFreeScans = 0;
      dbState.newOrderId = 'order-77';
      dbState.newTargetId = 'target-77';
      const res = await app.inject({
        method: 'POST',
        url: '/api/webcheck/verify',
        payload: { leadId: VALID_LEAD_ID },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({
        success: true,
        data: { verified: true, scanStarted: true, orderId: 'order-77' },
      });
      // Order wird als limitiertes webcheck-Paket im normalen precheck_running-Gate angelegt
      const orderInsert = mockQuery.mock.calls.find((c) => String(c[0]).includes('INSERT INTO orders'));
      expect(orderInsert).toBeDefined();
      expect(orderInsert![1]).toContain('webcheck');
      expect(String(orderInsert![0])).toContain("'precheck_running'");
      // Scan wird genau einmal mit der frischen Order/Target enqueued
      expect(mockEnqueue).toHaveBeenCalledTimes(1);
      expect(mockEnqueue).toHaveBeenCalledWith({ orderId: 'order-77', targetIds: ['target-77'] });
    });

    // TOCTOU-Regression (VEC-174, F3 aus VEC-169): zwei nebenläufige Verifies für
    // DIESELBE Domain (zwei verschiedene Leads, gleicher Eigentümer) dürfen zusammen
    // GENAU EINEN Free-Scan auslösen. Ohne DB-Guard passieren beide den COUNT==0-Check
    // und legen zwei Orders an; mit per-Domain Advisory-Lock + atomarem Gate gewinnt
    // genau einer (200 scanStarted), der andere wird mit 429 abgewiesen.
    it('nebenläufiger Doppel-Verify derselben Domain stößt genau 1 Free-Scan an', async () => {
      const LEAD_A = '11111111-2222-3333-4444-555555555555';
      const LEAD_B = '66666666-7777-8888-9999-000000000000';
      dbState.leadsById = {
        [LEAD_A]: {
          id: LEAD_A, email: 'alice@example.com', domain: 'example.com',
          verification_token: 'tok-a', verified: false, order_id: null,
        },
        [LEAD_B]: {
          id: LEAD_B, email: 'bob@example.com', domain: 'example.com',
          verification_token: 'tok-b', verified: false, order_id: null,
        },
      };
      dbState.recentFreeScans = 0;

      const [resA, resB] = await Promise.all([
        app.inject({ method: 'POST', url: '/api/webcheck/verify', payload: { leadId: LEAD_A } }),
        app.inject({ method: 'POST', url: '/api/webcheck/verify', payload: { leadId: LEAD_B } }),
      ]);

      const codes = [resA.statusCode, resB.statusCode].sort();
      // Genau eine 200 (Scan gestartet) und eine 429 (Fenster belegt) — keine 2 Scans.
      expect(codes).toEqual([200, 429]);
      const winner = resA.statusCode === 200 ? resA : resB;
      const loser = resA.statusCode === 429 ? resA : resB;
      expect(winner.json().data).toMatchObject({ verified: true, scanStarted: true });
      expect(loser.json().error).toBe('free_scan_already_used');

      // Harter Beweis der Invariante: trotz zweier paralleler Verifies genau EIN
      // Order-Insert und genau EIN enqueue.
      expect(dbState.orderInsertCount).toBe(1);
      expect(mockEnqueue).toHaveBeenCalledTimes(1);
    });
  });

  // --- /api/webcheck/doi/confirm ------------------------------------------------

  describe('GET /api/webcheck/doi/confirm', () => {
    it('400 invalid_token wenn kein Token übergeben wird', async () => {
      const res = await app.inject({ method: 'GET', url: '/api/webcheck/doi/confirm' });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ success: false, error: 'invalid_token' });
    });

    it('confirmed:true bei gültigem, noch ausstehendem Token', async () => {
      dbState.doiUpdatedRows = 1;
      const res = await app.inject({
        method: 'GET',
        url: '/api/webcheck/doi/confirm?token=' + 'a'.repeat(36),
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ success: true, data: { confirmed: true } });
    });

    it('kein Token-Oracle: unbekanntes/bereits-bestätigtes Token liefert dieselbe 200-Form', async () => {
      dbState.doiUpdatedRows = 0; // 0 betroffene Zeilen (unbekannt ODER schon confirmed)
      const res = await app.inject({
        method: 'GET',
        url: '/api/webcheck/doi/confirm?token=' + 'b'.repeat(36),
      });
      // Keine 404/Unterschied, der die Existenz eines Tokens verrät — idempotent + leak-frei
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ success: true, data: { confirmed: false } });
    });
  });
});
