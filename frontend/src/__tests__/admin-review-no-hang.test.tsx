/**
 * VEC-349 — Regression-Gate: Admin Target-Review hängt nicht mehr im Spinner
 *
 * Prod-Bug: /admin/review und /admin/review/[orderId] blieben ewig auf
 * „Lade Review-Queue..." / „Lade Review...", weil
 *  (a) handleResponse() ein nicht-JSON-Body (Traefik-502/504-HTML, leerer
 *      500-Body) mit res.json() unbehandelt werfen ließ, und
 *  (b) die load()-Funktionen der Seiten kein try/catch/finally hatten →
 *      setLoading(false) lief nie → endloser Spinner statt Error-State.
 *
 * VOR fix: getReviewQueue() rejectete bei nicht-JSON-Body → Aufrufer hing.
 * NACH fix: getReviewQueue() resolved IMMER zu einer {success,error}-Antwort;
 *           beide Seiten setzen loading in finally zurück.
 */

import * as fs from 'fs';
import * as path from 'path';

import { getReviewQueue } from '@/lib/api';

afterEach(() => {
  jest.restoreAllMocks();
});

describe('VEC-349: handleResponse wirft nie bei nicht-JSON-Body', () => {
  it('500 mit nicht-parsebarem Body → strukturierter Fehler statt throw', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      status: 500,
      ok: false,
      json: () => Promise.reject(new SyntaxError('Unexpected token < in JSON')),
    } as unknown as Response);

    // Darf NICHT rejecten — sonst hängt der Aufrufer (load()).
    const res = await getReviewQueue();
    expect(res.success).toBe(false);
    expect(res.status).toBe(500);
    expect(typeof res.error).toBe('string');
    expect(res.error!.length).toBeGreaterThan(0);
  });

  it('502 (Traefik-HTML-Gateway-Body) → strukturierter Fehler statt throw', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      status: 502,
      ok: false,
      json: () => Promise.reject(new SyntaxError('Unexpected token <')),
    } as unknown as Response);

    const res = await getReviewQueue();
    expect(res.success).toBe(false);
    expect(res.status).toBe(502);
  });

  it('200 mit gültigem Body bleibt unberührt (Nicht-Regression)', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: () => Promise.resolve({ success: true, data: { orders: [], subscriptions: [] } }),
    } as unknown as Response);

    const res = await getReviewQueue();
    expect(res.success).toBe(true);
    expect(res.data).toEqual({ orders: [], subscriptions: [] });
  });
});

// ── Statische Invarianten: beide Review-Seiten resetten loading garantiert ──
// Page-Render scheitert im aktuellen jsdom-Setup (react-dom/test-utils, siehe
// api-403-gating.test.tsx). Stattdessen Quelltext-Analyse: jede load()-Funktion
// MUSS setLoading(false) in einem finally-Block haben, damit kein geworfener
// Fetch den Spinner einfriert.

const LIST_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'app', 'admin', 'review', 'page.tsx'),
  'utf8',
);
const DETAIL_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'app', 'admin', 'review', '[orderId]', 'page.tsx'),
  'utf8',
);

function hasFinallyResetLoading(src: string): boolean {
  // Naive aber ausreichende Heuristik: ein finally-Block, der setLoading(false)
  // enthält. Schützt gegen Reintroduktion des ungeschützten load().
  return /finally\s*\{[\s\S]*?setLoading\(false\)[\s\S]*?\}/.test(src);
}

describe('VEC-349: load() resettet loading im finally (kein Endlos-Spinner)', () => {
  it('Queue-Seite (/admin/review) hat finally → setLoading(false)', () => {
    expect(hasFinallyResetLoading(LIST_SRC)).toBe(true);
  });

  it('Detail-Seite (/admin/review/[orderId]) hat finally → setLoading(false)', () => {
    expect(hasFinallyResetLoading(DETAIL_SRC)).toBe(true);
  });

  it('beide Seiten fangen Fetch-Rejections mit catch ab', () => {
    expect(LIST_SRC).toContain('} catch {');
    expect(DETAIL_SRC).toContain('} catch {');
  });
});
