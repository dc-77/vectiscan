/**
 * A7 (Jul 2026) — der results-Endpoint muss status/skip_reason durchreichen,
 * die Live-Feed-Queries duerfen dagegen unveraendert bleiben: skipped-Zeilen
 * tragen exit_code = -3 und werden von "exit_code >= 0" automatisch
 * herausgefiltert (sonst flutet der Terminal-Stream).
 */
import { readFileSync } from 'fs';
import { join } from 'path';

const ordersSrc = readFileSync(join(__dirname, '..', 'routes', 'orders.ts'), 'utf8');
const wsSrc = readFileSync(join(__dirname, '..', 'routes', 'ws.ts'), 'utf8');

describe('GET /api/orders/:id/results — A7-Spalten', () => {
  it('selektiert status und skip_reason', () => {
    const select = ordersSrc.match(
      /SELECT id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms,[\s\S]{0,120}?FROM scan_results/,
    );
    expect(select).not.toBeNull();
    expect(select![0]).toContain('status');
    expect(select![0]).toContain('skip_reason');
  });

  it('mappt auf camelCase mit null-Fallback fuer Legacy-Zeilen', () => {
    expect(ordersSrc).toMatch(/status:\s*\(row\.status as string \| null\) \?\? null/);
    expect(ordersSrc).toMatch(/skipReason:\s*\(row\.skip_reason as string \| null\) \?\? null/);
  });
});

describe('GET /api/orders/:id/results — 42703-Fallback (Migration 044 fehlt)', () => {
  it('faengt SQLSTATE 42703 (undefined_column) ab', () => {
    expect(ordersSrc).toContain("=== '42703'");
  });

  it('haelt eine Legacy-SELECT-Variante ohne A7-Spalten bereit', () => {
    expect(ordersSrc).toContain('RESULTS_SELECT_LEGACY');
    // Die Legacy-Variante darf status/skip_reason NICHT selektieren.
    const legacy = ordersSrc.match(
      /RESULTS_SELECT_LEGACY\s*=\s*`([\s\S]*?)`/,
    );
    expect(legacy).not.toBeNull();
    expect(legacy![1]).not.toContain('status');
    expect(legacy![1]).not.toContain('skip_reason');
  });

  it('nutzt zuerst die A7-Variante und faellt nur bei 42703 zurueck', () => {
    expect(ordersSrc).toContain('RESULTS_SELECT_A7');
    expect(ordersSrc).toMatch(/resultsQuery = await query\(RESULTS_SELECT_LEGACY/);
  });
});

describe('Live-Feed-Queries bleiben unveraendert', () => {
  it('orders.ts filtert weiterhin auf exit_code >= 0', () => {
    expect(ordersSrc).toContain('AND exit_code >= 0');
  });

  it('ws.ts filtert weiterhin auf exit_code >= 0', () => {
    expect(wsSrc).toContain('exit_code >= 0');
  });

  it('AI-Meta-Zeilen bleiben namentlich ausgeschlossen', () => {
    for (const src of [ordersSrc, wsSrc]) {
      expect(src).toContain("'ai_host_strategy', 'ai_phase2_config', 'ai_host_skip'");
    }
  });
});
