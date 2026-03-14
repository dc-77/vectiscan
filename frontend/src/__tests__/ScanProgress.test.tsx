import { render, screen, fireEvent } from '@testing-library/react';
import ScanProgress from '@/components/ScanProgress';
import { ScanStatus } from '@/lib/api';

const baseScan: ScanStatus = {
  id: '123',
  domain: 'example.com',
  status: 'dns_recon',
  package: 'professional',
  estimatedDuration: '~45 Minuten',
  progress: {
    phase: 'phase0',
    currentTool: null,
    currentHost: null,
    hostsTotal: 0,
    hostsCompleted: 0,
    discoveredHosts: [],
  },
  startedAt: '2026-03-12T14:30:00Z',
  finishedAt: null,
  error: null,
  hasReport: false,
};

describe('ScanProgress', () => {
  it('should show domain and phase badge', () => {
    render(<ScanProgress scan={baseScan} />);
    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByText('DNS-Reconnaissance')).toBeInTheDocument();
  });

  it('should show current tool when scanning', () => {
    const scan: ScanStatus = {
      ...baseScan,
      status: 'scan_phase2',
      progress: {
        ...baseScan.progress,
        currentTool: 'nikto',
        currentHost: '1.2.3.4',
        hostsTotal: 3,
        hostsCompleted: 1,
      },
    };
    render(<ScanProgress scan={scan} />);
    expect(screen.getByText('nikto')).toBeInTheDocument();
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument();
    expect(screen.getByText('1 / 3')).toBeInTheDocument();
  });

  it('should show report generating status', () => {
    const scan: ScanStatus = {
      ...baseScan,
      status: 'report_generating',
    };
    render(<ScanProgress scan={scan} />);
    expect(screen.getByText('Report wird generiert')).toBeInTheDocument();
  });

  it('should show estimated remaining time when hosts are being scanned', () => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const scan: ScanStatus = {
      ...baseScan,
      status: 'scan_phase2',
      startedAt: fiveMinutesAgo,
      progress: {
        ...baseScan.progress,
        hostsTotal: 4,
        hostsCompleted: 2,
        currentTool: 'nmap',
      },
    };
    render(<ScanProgress scan={scan} />);
    const estimate = screen.getByTestId('time-estimate');
    expect(estimate).toBeInTheDocument();
    expect(estimate.textContent).toContain('Geschätzte Restzeit');
  });

  it('should not show estimated time when no hosts completed', () => {
    const scan: ScanStatus = {
      ...baseScan,
      status: 'scan_phase1',
      progress: {
        ...baseScan.progress,
        hostsTotal: 3,
        hostsCompleted: 0,
      },
    };
    render(<ScanProgress scan={scan} />);
    expect(screen.queryByTestId('time-estimate')).not.toBeInTheDocument();
  });

  it('should show cancel button when onCancel is provided', () => {
    const onCancel = jest.fn();
    render(<ScanProgress scan={baseScan} onCancel={onCancel} />);
    const btn = screen.getByText('Scan abbrechen');
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('should show cancelling state', () => {
    render(<ScanProgress scan={baseScan} onCancel={() => {}} cancelling={true} />);
    expect(screen.getByText('Wird abgebrochen...')).toBeInTheDocument();
  });

  it('should not show cancel button when onCancel is not provided', () => {
    render(<ScanProgress scan={baseScan} />);
    expect(screen.queryByText('Scan abbrechen')).not.toBeInTheDocument();
  });

  it('should use smooth transition on progress bar', () => {
    const scan: ScanStatus = {
      ...baseScan,
      status: 'scan_phase2',
      progress: {
        ...baseScan.progress,
        hostsTotal: 4,
        hostsCompleted: 2,
      },
    };
    const { container } = render(<ScanProgress scan={scan} />);
    const bar = container.querySelector('.bg-blue-500.rounded-full');
    expect(bar?.className).toContain('duration-1000');
    expect(bar?.className).toContain('ease-in-out');
  });
});
