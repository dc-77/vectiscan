import { render, screen, fireEvent } from '@testing-library/react';
import ReportDownload from '@/components/ReportDownload';

jest.mock('@/lib/api', () => ({
  getReportDownloadUrl: jest.fn((id: string) => `http://localhost:4000/api/scans/${id}/report`),
}));

describe('ReportDownload', () => {
  it('should show download button', () => {
    render(<ReportDownload scanId="123" domain="example.com" />);
    expect(screen.getByText('PDF herunterladen')).toBeInTheDocument();
  });

  it('should show filename with domain', () => {
    render(<ReportDownload scanId="123" domain="example.com" />);
    expect(screen.getByText(/vectiscan-example\.com/)).toBeInTheDocument();
  });

  it('should link to report download URL', () => {
    render(<ReportDownload scanId="123" domain="example.com" />);
    const link = screen.getByText('PDF herunterladen');
    expect(link.closest('a')).toHaveAttribute('href', 'http://localhost:4000/api/scans/123/report');
  });

  it('should show new scan button when onNewScan is provided', () => {
    const onNewScan = jest.fn();
    render(<ReportDownload scanId="123" domain="example.com" onNewScan={onNewScan} />);
    const btn = screen.getByText('Neuen Scan starten');
    fireEvent.click(btn);
    expect(onNewScan).toHaveBeenCalledTimes(1);
  });

  it('should not show new scan button when onNewScan is not provided', () => {
    render(<ReportDownload scanId="123" domain="example.com" />);
    expect(screen.queryByText('Neuen Scan starten')).not.toBeInTheDocument();
  });
});
