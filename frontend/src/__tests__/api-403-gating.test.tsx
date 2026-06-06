/**
 * VEC-294 — Regression-Gate: 403-Normalisierung und AdminGate
 *
 * Sicherheitsklasse: BOLA-Seitenkanal / Broken Access Control UX
 * Linse: Complete Mediation, Fail Securely, OWASP API5 (Broken
 *        Function-Level Authorization)
 *
 * Schlägt gegen den ALTEN Code fehl, besteht gegen den neuen:
 *  - VOR fix: api.ts gab 403-Body unmodifiziert weiter; `forbidden` war nie gesetzt.
 *  - NACH fix: 403 → `{ success: false, forbidden: true, error: <deutsch/machine> }`.
 *
 * AdminDenied-Smoke: StateView „denied" muss für jeden Admin-Direktlink
 * den richtigen Escape-CTA rendern (kein Dead End).
 */

import * as fs from 'fs';
import * as path from 'path';

// ── Hilfsfunktion: minimales fetch-Mock ─────────────────────────────────────

function mockFetch(status: number, body: object) {
  global.fetch = jest.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    json: () => Promise.resolve(body),
  } as unknown as Response);
}

// ── Importiere eine repräsentative API-Funktion, die handleResponse nutzt ──
// getOrderStatus() → GET /api/orders/:id → handleResponse → ApiResponse.
// login() geht NICHT durch handleResponse (res.json() direkt) — daher kein Test-Kandidat.
import { getOrderStatus } from '@/lib/api';

// ── 403-Normalisierung ───────────────────────────────────────────────────────

describe('VEC-294: api.ts 403-Normalisierung', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('setzt forbidden:true und neutralisiert "Access denied"', async () => {
    mockFetch(403, { error: 'Access denied' });
    const res = await getOrderStatus('test-order-id');

    expect(res.success).toBe(false);
    expect(res.forbidden).toBe(true);
    // Kein roher englischer Backend-String darf beim Customer ankommen.
    expect(res.error).not.toBe('Access denied');
    expect(res.error).not.toBe('Forbidden');
    expect(typeof res.error).toBe('string');
    expect(res.error!.length).toBeGreaterThan(0);
  });

  it('setzt forbidden:true und neutralisiert generisches "Forbidden"', async () => {
    mockFetch(403, { error: 'Forbidden' });
    const res = await getOrderStatus('test-order-id');

    expect(res.success).toBe(false);
    expect(res.forbidden).toBe(true);
    expect(res.error).not.toBe('Forbidden');
  });

  it('leitet Maschinen-Codes unverändert weiter (gezielte Verzweigung)', async () => {
    mockFetch(403, { error: 'subscription_required' });
    const res = await getOrderStatus('test-order-id');

    expect(res.forbidden).toBe(true);
    // Machine-Code bleibt erhalten — Consumer kann darauf branchen.
    expect(res.error).toBe('subscription_required');
  });

  it('normalisiert auch leeren Body (kein JSON)', async () => {
    // json() schlägt fehl → catch() → raw = '' → friendly-Fallback.
    global.fetch = jest.fn().mockResolvedValue({
      status: 403,
      ok: false,
      json: () => Promise.reject(new SyntaxError('no body')),
    } as unknown as Response);

    const res = await getOrderStatus('test-order-id');
    expect(res.forbidden).toBe(true);
    expect(res.error).toBeTruthy();
    expect(res.error).not.toBe('Access denied');
  });

  it('setzt status:403 in der Antwort', async () => {
    mockFetch(403, { error: 'Access denied' });
    const res = await getOrderStatus('test-order-id');
    expect(res.status).toBe(403);
  });

  it('lässt 200-Antworten unberührt (Nicht-Regression)', async () => {
    mockFetch(200, { success: true, data: { token: 'jwt', user: { id: '1', email: 'x@x.de', role: 'customer' } } });
    const res = await getOrderStatus('test-order-id');
    expect(res.success).toBe(true);
    expect(res.forbidden).toBeUndefined();
  });
});

// ── AdminGate: statische Invarianz-Checks ───────────────────────────────────
// Render-Tests fallen im aktuellen jsdom-Setup wegen react-dom/test-utils
// Inkompatibilität aus (pre-existing, nicht VEC-294-spezifisch — betrifft
// auch ds-primitives.test.tsx). Stattdessen statische Quelltext-Analyse:
// verifizieren, dass AdminDenied das richtige StateView-Variant und einen
// /dashboard-Escape-CTA enthält (kein Dead End).

const ADMIN_GATE_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'components', 'ds', 'AdminGate.tsx'),
  'utf8',
);

describe('VEC-294: AdminGate — statische Invarianten', () => {
  it('AdminDenied nutzt StateView variant="denied" (nicht leer/error)', () => {
    expect(ADMIN_GATE_SRC).toContain('variant="denied"');
  });

  it('AdminDenied hat /dashboard als Escape-CTA (kein Dead End)', () => {
    expect(ADMIN_GATE_SRC).toContain('/dashboard');
  });

  it('AdminDenied enthält KEINEN rohen "Access denied"-String', () => {
    // Der Text "Access denied" darf nicht sichtbar gerendert werden.
    expect(ADMIN_GATE_SRC).not.toContain('>Access denied<');
    expect(ADMIN_GATE_SRC).not.toContain('"Access denied"');
  });

  it('useAdminGuard unterscheidet Auth- von Permission-Grenze', () => {
    // Nicht eingeloggt → /login (echte Auth-Grenze, kein StateView).
    expect(ADMIN_GATE_SRC).toContain("router.replace('/login')");
    // Eingeloggt, kein Admin → setState('denied') (StateView).
    expect(ADMIN_GATE_SRC).toContain("setState(isAdmin() ? 'ok' : 'denied')");
    // Stilles router.replace('/dashboard') darf NICHT im ausführbaren Code vorkommen.
    // (Nur Kommentare dürfen es dokumentieren — wir prüfen, dass keine
    //  Nicht-Kommentarzeile den Ausdruck enthält.)
    const execLines = ADMIN_GATE_SRC
      .split('\n')
      .filter(l => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
    const hasDashboardRedirect = execLines.some(l => l.includes("router.replace('/dashboard')"));
    expect(hasDashboardRedirect).toBe(false);
  });

  it('AdminGate exportiert useAdminGuard UND AdminDenied (kanonische Exporte)', () => {
    // Jede Admin-Seite muss genau diese beiden Exporte nutzen können.
    expect(ADMIN_GATE_SRC).toContain('export function useAdminGuard');
    expect(ADMIN_GATE_SRC).toContain('export default function AdminDenied');
  });
});
