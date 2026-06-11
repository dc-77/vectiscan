/**
 * Unit-Tests für die CRM-Anbindung (VEC-301): Twenty-Mapping, Config-Gating
 * (Trockenmodus), Idempotenz-Upsert und Vertriebs-Notify. Kein Netz/DB — `fetch`
 * wird gemockt. Sichert die DSGVO-/Sicherheits-Invarianten als Regression:
 *  - Ohne CRM_WEBHOOK_URL passiert NICHTS (kein Lead-Leak im Trockenmodus).
 *  - Bei fehlgeschlagenem Lookup wird KEIN Duplikat angelegt.
 */
import {
  buildTwentyPerson,
  loadCrmConfig,
  upsertLeadToCrm,
  notifySales,
} from '../lib/crm.js';

const LEAD = {
  email: 'Max.Muster@ACME.de',
  domain: 'acme.de',
  icpSegment: 'Maschinenbau',
  channel: 'Direkt',
};

describe('buildTwentyPerson', () => {
  it('mappt nur Standard-Twenty-Felder (email normalisiert, domain im Nachnamen)', () => {
    const p = buildTwentyPerson(LEAD) as {
      emails: { primaryEmail: string };
      name: { firstName: string; lastName: string };
      jobTitle?: string;
    };
    expect(p.emails.primaryEmail).toBe('max.muster@acme.de');
    expect(p.name.firstName).toBe('max.muster');
    expect(p.name.lastName).toBe('(acme.de)');
    expect(p.jobTitle).toBe('Maschinenbau');
  });

  it('sendet keine unbekannten Felder (Twenty würde 400 werfen)', () => {
    const p = buildTwentyPerson(LEAD) as Record<string, unknown>;
    expect(Object.keys(p).sort()).toEqual(['emails', 'jobTitle', 'name']);
  });
});

describe('loadCrmConfig', () => {
  it('liest CRM_WEBHOOK_URL/CRM_API_KEY/SALES_NOTIFY_URL aus der Env', () => {
    const cfg = loadCrmConfig({
      CRM_WEBHOOK_URL: 'https://crm.example/rest/people',
      CRM_API_KEY: 'k',
      SALES_NOTIFY_URL: 'https://hook',
    } as NodeJS.ProcessEnv);
    expect(cfg).toEqual({
      webhookUrl: 'https://crm.example/rest/people',
      apiKey: 'k',
      salesNotifyUrl: 'https://hook',
    });
  });
});

describe('upsertLeadToCrm — Trockenmodus', () => {
  it('ohne webhookUrl: No-op, kein fetch', async () => {
    const spy = jest.spyOn(global, 'fetch');
    const r = await upsertLeadToCrm(LEAD, { webhookUrl: null, apiKey: null, salesNotifyUrl: null });
    expect(r).toEqual({ synced: false, reason: 'crm-not-configured' });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

describe('upsertLeadToCrm — Idempotenz', () => {
  const cfg = { webhookUrl: 'https://crm.example/rest/people', apiKey: 'k', salesNotifyUrl: null };

  afterEach(() => jest.restoreAllMocks());

  it('legt an, wenn die Person noch nicht existiert', async () => {
    const calls: string[] = [];
    jest.spyOn(global, 'fetch').mockImplementation((async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url}`);
      if (!init?.method || init.method === 'GET') {
        return { ok: true, status: 200, json: async () => ({ data: { people: [] } }) } as Response;
      }
      return { ok: true, status: 201, json: async () => ({ data: { createPerson: { id: 'p1' } } }) } as Response;
    }) as typeof fetch);

    const r = await upsertLeadToCrm(LEAD, cfg);
    // LEAD hat keine `company` → kein Company-Upsert, companyId bleibt null.
    expect(r).toEqual({ synced: true, action: 'created', status: 201, companyId: null });
    expect(calls.some((c) => c.startsWith('GET'))).toBe(true);
    expect(calls.some((c) => c.startsWith('POST'))).toBe(true);
  });

  it('legt bei Demo-Lead mit Firma eine Company an und verknüpft die Person (VEC-117)', async () => {
    const LEAD_WITH_COMPANY = { ...LEAD, fullName: 'Erika Mustermann', company: 'ACME GmbH' };
    const personBodies: Array<Record<string, unknown>> = [];
    jest.spyOn(global, 'fetch').mockImplementation((async (url: string, init?: RequestInit) => {
      const isCompanies = String(url).includes('/rest/companies');
      if (!init?.method || init.method === 'GET') {
        // Person-Lookup leer; Company-Lookup leer → beide werden angelegt.
        return { ok: true, status: 200, json: async () => ({ data: { people: [], companies: [] } }) } as Response;
      }
      if (isCompanies) {
        return { ok: true, status: 201, json: async () => ({ data: { createCompany: { id: 'c1' } } }) } as Response;
      }
      if (init?.body) personBodies.push(JSON.parse(String(init.body)));
      return { ok: true, status: 201, json: async () => ({ data: { createPerson: { id: 'p1' } } }) } as Response;
    }) as typeof fetch);

    const r = await upsertLeadToCrm(LEAD_WITH_COMPANY, cfg);
    expect(r.synced).toBe(true);
    expect(r.companyId).toBe('c1');
    // Person trägt die verknüpfte companyId und den echten Namen.
    expect(personBodies[0]).toMatchObject({ companyId: 'c1', name: { firstName: 'Erika', lastName: 'Mustermann' } });
  });

  it('legt NICHT an, wenn die Person bereits existiert', async () => {
    const post = jest.fn();
    jest.spyOn(global, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
      if (init?.method === 'POST') post();
      return { ok: true, status: 200, json: async () => ({ data: { people: [{ id: 'p1' }] } }) } as Response;
    }) as typeof fetch);

    const r = await upsertLeadToCrm(LEAD, cfg);
    expect(r.synced).toBe(true);
    expect(r.action).toBe('exists');
    expect(post).not.toHaveBeenCalled();
  });

  it('legt bei fehlgeschlagenem Lookup KEIN Duplikat an (Dedup-Schutz)', async () => {
    const post = jest.fn();
    jest.spyOn(global, 'fetch').mockImplementation((async (_url: string, init?: RequestInit) => {
      if (init?.method === 'POST') post();
      return { ok: false, status: 500, json: async () => ({}) } as Response;
    }) as typeof fetch);

    const r = await upsertLeadToCrm(LEAD, cfg);
    expect(r.synced).toBe(false);
    expect(r.reason).toBe('crm-lookup-failed');
    expect(post).not.toHaveBeenCalled();
  });
});

describe('notifySales', () => {
  afterEach(() => jest.restoreAllMocks());

  it('ohne salesNotifyUrl: No-op', async () => {
    const spy = jest.spyOn(global, 'fetch');
    const r = await notifySales(LEAD, { webhookUrl: null, apiKey: null, salesNotifyUrl: null });
    expect(r).toEqual({ notified: false, reason: 'sales-notify-not-configured' });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('postet an den Webhook, wenn gesetzt', async () => {
    const spy = jest.spyOn(global, 'fetch').mockResolvedValue(
      { ok: true, status: 200, json: async () => ({}) } as Response,
    );
    const r = await notifySales(LEAD, { webhookUrl: null, apiKey: null, salesNotifyUrl: 'https://hook' });
    expect(r.notified).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
