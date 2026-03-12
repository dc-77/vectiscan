import { render, screen, waitFor } from '@testing-library/react';
import ReportDownload from '@/components/ReportDownload';

// Mock the API module
jest.mock('@/lib/api', () => ({
  getScanReport: jest.fn(),
}));

import { getScanReport } from '@/lib/api';
const mockGetScanReport = getScanReport as jest.MockedFunction<typeof getScanReport>;

describe('ReportDownload', () => {
  it('should show download button when report is available', async () => {
    mockGetScanReport.mockResolvedValueOnce({
      success: true,
      data: {
        downloadUrl: 'http://minio:9000/test.pdf?signed=1',
        fileName: 'vectiscan-example.com-2026-03-12.pdf',
        fileSize: 245760,
      },
    });

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
});
