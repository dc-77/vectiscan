/**
 * A7 (Jul 2026) — ToolTrace zeigt den neuen Lauf-Status samt Grund an und
 * faellt fuer Legacy-Zeilen (status === null) auf die exit_code-Logik zurueck.
 */
import { render, screen } from '@testing-library/react';
import ToolTrace, { statusBadge } from '@/components/scan/ToolTrace';
import type { ScanResult } from '@/lib/api';

function row(overrides: Partial<ScanResult>): ScanResult {
  return {
    id: 'r1',
    hostIp: '1.2.3.4',
    phase: 2,
    toolName: 'zap_spider',
    rawOutput: null,
    exitCode: -3,
    durationMs: 0,
    status: 'skipped',
    skipReason: 'zap_daemon_unavailable',
    createdAt: '2026-07-21T10:00:00.000Z',
    ...overrides,
  };
}

describe('statusBadge', () => {
  it('nutzt den A7-Status wenn vorhanden', () => {
    expect(statusBadge({ status: 'skipped', exitCode: -3 }).label).toBe('SKIPPED');
    expect(statusBadge({ status: 'blocked', exitCode: -3 }).label).toBe('BLOCKED');
    expect(statusBadge({ status: 'failed', exitCode: -2 }).label).toBe('FAILED');
    expect(statusBadge({ status: 'timeout', exitCode: -1 }).label).toBe('TIMEOUT');
    expect(statusBadge({ status: 'ok', exitCode: 0 }).label).toBe('OK');
  });

  it('faellt bei Legacy-Zeilen auf die exit_code-Logik zurueck', () => {
    expect(statusBadge({ status: null, exitCode: 0 }).label).toBe('OK');
    expect(statusBadge({ status: null, exitCode: -1 }).label).toBe('TIMEOUT');
    expect(statusBadge({ status: null, exitCode: 1 }).label).toBe('WARN');
    expect(statusBadge({ status: null, exitCode: 7 }).label).toBe('EXIT 7');
    expect(statusBadge({ exitCode: 0 }).label).toBe('OK');
  });

  it('ignoriert unbekannte Status-Werte und nutzt den Fallback', () => {
    expect(statusBadge({ status: 'quantensprung', exitCode: 1 }).label).toBe('WARN');
  });
});

describe('ToolTrace', () => {
  it('zeigt SKIPPED plus Grund fuer einen nicht gelaufenen ZAP', () => {
    render(<ToolTrace scanResults={[row({})]} />);
    expect(screen.getByText('SKIPPED')).toBeInTheDocument();
    expect(screen.getByText('zap_daemon_unavailable')).toBeInTheDocument();
    expect(screen.getByText('zap_spider')).toBeInTheDocument();
  });

  it('zeigt Legacy-Zeilen unveraendert als OK', () => {
    render(
      <ToolTrace
        scanResults={[row({ status: null, skipReason: null, exitCode: 0, toolName: 'httpx' })]}
      />,
    );
    expect(screen.getByText('OK')).toBeInTheDocument();
    expect(screen.queryByText('SKIPPED')).not.toBeInTheDocument();
  });
});
