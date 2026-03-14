import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Home from '@/app/page';
import * as api from '@/lib/api';

// Mock the API module
jest.mock('@/lib/api', () => ({
  createScan: jest.fn(),
  getScanStatus: jest.fn(),
  cancelScan: jest.fn(),
  verifyPassword: jest.fn(),
  getReportDownloadUrl: jest.fn(),
  getScanReport: jest.fn(),
}));

const mockCreateScan = api.createScan as jest.MockedFunction<typeof api.createScan>;

describe('Page submit with package', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Simulate authenticated state
    sessionStorage.setItem('vectiscan_auth', 'true');
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it('should submit with default professional package', async () => {
    mockCreateScan.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'professional', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateScan).toHaveBeenCalledWith('example.com', 'professional');
    });
  });

  it('should submit with selected basic package', async () => {
    mockCreateScan.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'basic', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    // Select basic package
    const basicCard = screen.getByTestId('package-basic');
    fireEvent.click(basicCard);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateScan).toHaveBeenCalledWith('example.com', 'basic');
    });
  });

  it('should submit with selected nis2 package', async () => {
    mockCreateScan.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'nis2', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    // Select NIS2 package
    const nis2Card = screen.getByTestId('package-nis2');
    fireEvent.click(nis2Card);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateScan).toHaveBeenCalledWith('example.com', 'nis2');
    });
  });

  it('should show package selector with 3 cards', () => {
    render(<Home />);
    expect(screen.getByTestId('package-selector')).toBeInTheDocument();
    expect(screen.getByTestId('package-basic')).toBeInTheDocument();
    expect(screen.getByTestId('package-professional')).toBeInTheDocument();
    expect(screen.getByTestId('package-nis2')).toBeInTheDocument();
  });
});
