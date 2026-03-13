import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import ReportDownload from '@/components/ReportDownload';

// Mock the API module
jest.mock('@/lib/api', () => ({
  getScanReport: jest.fn(),
}));

import { getScanReport } from '@/lib/api';
const mockGetScanReport = getScanReport as jest.MockedFunction<typeof getScanReport>;

const mockReportData = {
  success: true as const,
  data: {
    downloadUrl: 'http://minio:9000/test.pdf?signed=1',
    fileName: 'vectiscan-example.com-2026-03-12.pdf',
    fileSize: 245760,
  },
};

describe('ReportDownload', () => {
  it('should show download button when report is available', async () => {
    mockGetScanReport.mockResolvedValueOnce(mockReportData);

    render(<ReportDownload scanId="123" />);

    await waitFor(() => {
      expect(screen.getByText('PDF herunterladen')).toBeInTheDocument();
    });
    expect(screen.getByText(/vectiscan-example.com/)).toBeInTheDocument();
    expect(screen.getByText(/240 KB/)).toBeInTheDocument();
  });

  it('should show loading state initially', () => {
    mockGetScanReport.mockReturnValueOnce(new Promise(() => {})); // never resolves
    render(<ReportDownload scanId="123" />);
    expect(screen.getByText('Report wird geladen...')).toBeInTheDocument();
  });

  it('should show new scan button when onNewScan is provided', async () => {
    mockGetScanReport.mockResolvedValueOnce(mockReportData);
    const onNewScan = jest.fn();

    render(<ReportDownload scanId="123" onNewScan={onNewScan} />);

    await waitFor(() => {
      expect(screen.getByText('Neuen Scan starten')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Neuen Scan starten'));
    expect(onNewScan).toHaveBeenCalledTimes(1);
  });

  it('should not show new scan button when onNewScan is not provided', async () => {
    mockGetScanReport.mockResolvedValueOnce(mockReportData);

    render(<ReportDownload scanId="123" />);

    await waitFor(() => {
      expect(screen.getByText('PDF herunterladen')).toBeInTheDocument();
    });
    expect(screen.queryByText('Neuen Scan starten')).not.toBeInTheDocument();
  });
});
