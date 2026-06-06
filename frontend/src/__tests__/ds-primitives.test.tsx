import { render, screen, fireEvent } from '@testing-library/react';
import { statusMeta, statusLabel } from '@/lib/status';
import { StatusChip, StateView, ConfirmDialog, SkeletonList } from '@/components/ds';

describe('status mapping (H8)', () => {
  it('maps technical codes to customer plain language', () => {
    expect(statusLabel('precheck_running')).toBe('Wird vorbereitet');
    expect(statusLabel('report_complete')).toBe('Bericht fertig');
    expect(statusLabel('pending_target_review')).toBe('Wird geprüft');
    expect(statusLabel('failed')).toBe('Fehlgeschlagen');
  });

  it('treats hyphen/underscore/queue variants consistently', () => {
    expect(statusLabel('scan-pending')).toBe('In Warteschlange');
    expect(statusLabel('scan_pending')).toBe('In Warteschlange');
    expect(statusLabel('PRECHECK_RUNNING')).toBe('Wird vorbereitet');
  });

  it('falls back gracefully for unknown codes', () => {
    expect(statusLabel('some_future_status')).toBe('Unbekannt');
    expect(statusLabel(null)).toBe('Unbekannt');
  });

  it('flags running states as active', () => {
    expect(statusMeta('scan_phase2').active).toBe(true);
    expect(statusMeta('report_complete').active).toBeUndefined();
  });
});

describe('StatusChip', () => {
  it('renders the customer label, never the raw code', () => {
    render(<StatusChip status="precheck_running" />);
    expect(screen.getByText('Wird vorbereitet')).toBeInTheDocument();
    expect(screen.queryByText('precheck_running')).not.toBeInTheDocument();
  });
});

describe('StateView', () => {
  it('renders title, description and an action link (anti-dead-end)', () => {
    render(
      <StateView
        variant="empty"
        title="Noch keine Scans"
        description="Starten Sie Ihren ersten Scan."
        actions={[{ label: 'Neuer Scan', href: '/scan/new' }]}
      />,
    );
    expect(screen.getByText('Noch keine Scans')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Neuer Scan' })).toHaveAttribute('href', '/scan/new');
  });

  it('error variant exposes an alert role', () => {
    render(<StateView variant="error" title="Fehler beim Laden" />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });
});

describe('ConfirmDialog (H7)', () => {
  it('does not render when closed', () => {
    const { container } = render(
      <ConfirmDialog open={false} title="Löschen?" onConfirm={jest.fn()} onCancel={jest.fn()} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('fires onConfirm/onCancel from the dialog buttons', () => {
    const onConfirm = jest.fn();
    const onCancel = jest.fn();
    render(
      <ConfirmDialog open title="Order löschen?" confirmLabel="Löschen" destructive
        onConfirm={onConfirm} onCancel={onCancel} />,
    );
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true');
    fireEvent.click(screen.getByRole('button', { name: 'Löschen' }));
    expect(onConfirm).toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Abbrechen' }));
    expect(onCancel).toHaveBeenCalled();
  });
});

describe('SkeletonList (H9)', () => {
  it('exposes a loading status region', () => {
    render(<SkeletonList rows={2} />);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});
