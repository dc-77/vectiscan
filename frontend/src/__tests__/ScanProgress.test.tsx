import { render, screen } from '@testing-library/react';
import ScanProgress from '@/components/ScanProgress';
import { ScanStatus } from '@/lib/api';

const baseScan: ScanStatus = {
  id: '123',
  domain: 'example.com',
  status: 'dns_recon',
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
});
