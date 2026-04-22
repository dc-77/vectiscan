import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';

// Mock next/navigation
const mockPush = jest.fn();
jest.mock('next/navigation', () => ({
  useParams: () => ({ orderId: 'test-order-id' }),
  useRouter: () => ({ push: mockPush }),
}));

// Mock API
const mockGetVerificationStatus = jest.fn();
const mockCheckVerification = jest.fn();
const mockManualVerify = jest.fn();
jest.mock('@/lib/api', () => ({
  getVerificationStatus: (...args: unknown[]) => mockGetVerificationStatus(...args),
  checkVerification: (...args: unknown[]) => mockCheckVerification(...args),
  manualVerify: (...args: unknown[]) => mockManualVerify(...args),
}));

import VerifyPage from '@/app/verify/[orderId]/page';

const MOCK_STATUS = {
  success: true,
  data: {
    verified: false,
    method: null,
    token: 'vectiscan-verify-abc123def456',
    domain: 'example.com',
  },
};

describe('VerifyPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    mockGetVerificationStatus.mockResolvedValue(MOCK_STATUS);
    mockCheckVerification.mockResolvedValue({ success: true, data: { verified: false } });
    mockManualVerify.mockResolvedValue({ success: true, data: { verified: true, method: 'manual' } });
    Object.assign(navigator, {
      clipboard: { writeText: jest.fn().mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should render domain and tabs', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    expect(screen.getByText('Domain verifizieren')).toBeInTheDocument();
    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByTestId('tab-dns_txt')).toBeInTheDocument();
    expect(screen.getByTestId('tab-file')).toBeInTheDocument();
    expect(screen.getByTestId('tab-meta_tag')).toBeInTheDocument();
  });

  it('should show DNS tab content by default', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    expect(screen.getByTestId('tab-content-dns_txt')).toBeInTheDocument();
    // Inhalt enthaelt den zu erstellenden TXT-Record
    expect(screen.getByTestId('tab-content-dns_txt').textContent).toMatch(/TXT-Record/);
  });

  it('should switch between tabs', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    // Switch to file tab
    fireEvent.click(screen.getByTestId('tab-file'));
    expect(screen.getByTestId('tab-content-file')).toBeInTheDocument();

    // Switch to meta tag tab
    fireEvent.click(screen.getByTestId('tab-meta_tag'));
    expect(screen.getByTestId('tab-content-meta_tag')).toBeInTheDocument();

    // Switch back to DNS
    fireEvent.click(screen.getByTestId('tab-dns_txt'));
    expect(screen.getByTestId('tab-content-dns_txt')).toBeInTheDocument();
  });

  it('should copy DNS record to clipboard', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    fireEvent.click(screen.getByTestId('copy-dns'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      '_vectiscan-verify.example.com TXT "vectiscan-verify-abc123def456"',
    );
  });

  it('should copy token to clipboard in file tab', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    fireEvent.click(screen.getByTestId('tab-file'));
    fireEvent.click(screen.getByTestId('copy-file'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('vectiscan-verify-abc123def456');
  });

  it('should copy meta tag to clipboard', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    fireEvent.click(screen.getByTestId('tab-meta_tag'));
    fireEvent.click(screen.getByTestId('copy-meta'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      '<meta name="vectiscan-verify" content="vectiscan-verify-abc123def456">',
    );
  });

  it('should call checkVerification on button click', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('check-button'));
    });

    expect(mockCheckVerification).toHaveBeenCalledWith('test-order-id');
  });

  it('should show error on verification failure', async () => {
    mockCheckVerification.mockResolvedValueOnce({ success: true, data: { verified: false } });

    await act(async () => {
      render(<VerifyPage />);
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('check-button'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('error-message')).toBeInTheDocument();
    });
  });

  it('should show verified banner on success', async () => {
    mockCheckVerification.mockResolvedValueOnce({
      success: true,
      data: { verified: true, method: 'dns_txt' },
    });

    await act(async () => {
      render(<VerifyPage />);
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('check-button'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('verified-banner')).toBeInTheDocument();
      expect(screen.getByText(/Verifiziert!/)).toBeInTheDocument();
    });
  });

  it('should show verified state when already verified on load', async () => {
    mockGetVerificationStatus.mockResolvedValueOnce({
      success: true,
      data: { verified: true, method: 'file', token: 'tok', domain: 'example.com' },
    });

    await act(async () => {
      render(<VerifyPage />);
    });

    expect(screen.getByTestId('verified-banner')).toBeInTheDocument();
  });

  it('should have manual verify button', async () => {
    await act(async () => {
      render(<VerifyPage />);
    });

    expect(screen.getByTestId('manual-verify-button')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByTestId('manual-verify-button'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('verified-banner')).toBeInTheDocument();
    });
  });
});
