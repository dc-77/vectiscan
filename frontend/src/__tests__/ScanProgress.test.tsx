import { render, screen, fireEvent } from '@testing-library/react';
import ScanProgress from '@/components/ScanProgress';
import { OrderStatus } from '@/lib/api';

const baseScan: OrderStatus = {
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
    toolOutput: null,
    lastCompletedTool: null,
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
    expect(screen.getByText('DNS Recon')).toBeInTheDocument();
  });

  it('should show progress bar during active phases even without hosts', () => {
    render(<ScanProgress scan={baseScan} />);
    // dns_recon for perimeter: midpoint of [8, 15] = 12%
    expect(screen.getByText(/12%/)).toBeInTheDocument();
  });

  it('should interpolate host progress in scan_phase2', () => {
    const scan: OrderStatus = {
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
    // scan_phase2 perimeter: [30, 75], 1/3 hosts = 30 + (75-30) * 0.333 = 45%
    expect(screen.getByText(/1\/3 hosts/)).toBeInTheDocument();
    expect(screen.getByText(/45%/)).toBeInTheDocument();
  });

  it('should show report generating status with progress', () => {
    const scan: OrderStatus = {
      ...baseScan,
      status: 'report_generating',
    };
    render(<ScanProgress scan={scan} />);
    expect(screen.getByText('Generating Report')).toBeInTheDocument();
    // Midpoint of [90, 95] = 93%
    expect(screen.getByText(/93%/)).toBeInTheDocument();
  });

  it('should show ETA only during host-based phases', () => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const scan: OrderStatus = {
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
    expect(screen.getByText(/ETA:/)).toBeInTheDocument();
  });

  it('should not show ETA during non-host phases', () => {
    render(<ScanProgress scan={baseScan} />);
    expect(screen.queryByText(/ETA:/)).not.toBeInTheDocument();
  });

  it('should not show ETA when no hosts completed', () => {
    const scan: OrderStatus = {
      ...baseScan,
      status: 'scan_phase1',
      progress: {
        ...baseScan.progress,
        hostsTotal: 3,
        hostsCompleted: 0,
      },
    };
    render(<ScanProgress scan={scan} />);
    expect(screen.queryByText(/ETA:/)).not.toBeInTheDocument();
  });

  it('should show cancel button when onCancel is provided', () => {
    const onCancel = jest.fn();
    render(<ScanProgress scan={baseScan} onCancel={onCancel} />);
    const btn = screen.getByText('Cancel scan');
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('should show cancelling state', () => {
    render(<ScanProgress scan={baseScan} onCancel={() => {}} cancelling={true} />);
    expect(screen.getByText('Cancelling...')).toBeInTheDocument();
  });

  it('should not show cancel button when onCancel is not provided', () => {
    render(<ScanProgress scan={baseScan} />);
    expect(screen.queryByText('Cancel scan')).not.toBeInTheDocument();
  });

  it('should use different progress ranges for webcheck vs perimeter', () => {
    const webcheckScan: OrderStatus = {
      ...baseScan,
      package: 'webcheck',
      status: 'dns_recon',
    };
    const { unmount } = render(<ScanProgress scan={webcheckScan} />);
    // dns_recon for webcheck: midpoint of [0, 10] = 5%
    expect(screen.getByText(/5%/)).toBeInTheDocument();
    unmount();

    // Perimeter dns_recon: midpoint of [8, 15] = 12%
    render(<ScanProgress scan={baseScan} />);
    expect(screen.getByText(/12%/)).toBeInTheDocument();
  });

  it('should not show progress bar for completed scans', () => {
    const scan: OrderStatus = {
      ...baseScan,
      status: 'report_complete',
    };
    const { container } = render(<ScanProgress scan={scan} />);
    expect(container.querySelector('.bg-gray-700')).not.toBeInTheDocument();
  });

  it('should use smooth transition on progress bar', () => {
    const scan: OrderStatus = {
      ...baseScan,
      status: 'scan_phase2',
      progress: {
        ...baseScan.progress,
        hostsTotal: 4,
        hostsCompleted: 2,
      },
    };
    const { container } = render(<ScanProgress scan={scan} />);
    const bar = container.querySelector('.animate-energyFlow');
    expect(bar).toBeInTheDocument();
    expect(bar?.getAttribute('style')).toContain('transition: width 1s ease-out');
  });
});
