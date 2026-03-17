import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Home from '@/app/page';
import * as api from '@/lib/api';

// Mock the API module
jest.mock('@/lib/api', () => ({
  createOrder: jest.fn(),
  getOrderStatus: jest.fn(),
  cancelOrder: jest.fn(),
  getReportDownloadUrl: jest.fn(),
  getOrderReport: jest.fn(),
  login: jest.fn(),
  register: jest.fn(),
  listOrders: jest.fn(),
}));

// Mock the auth module
jest.mock('@/lib/auth', () => ({
  isLoggedIn: jest.fn().mockReturnValue(true),
  getToken: jest.fn().mockReturnValue('mock-token'),
  setToken: jest.fn(),
  clearToken: jest.fn(),
  getUser: jest.fn().mockReturnValue({ id: '1', email: 'test@test.com', role: 'customer' }),
  isAdmin: jest.fn().mockReturnValue(false),
}));

const mockCreateOrder = api.createOrder as jest.MockedFunction<typeof api.createOrder>;

describe('Page submit with package', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should submit with default perimeter package', async () => {
    mockCreateOrder.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'perimeter', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateOrder).toHaveBeenCalledWith('example.com', 'perimeter');
    });
  });

  it('should submit with selected webcheck package', async () => {
    mockCreateOrder.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'webcheck', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    // Select webcheck package
    const webcheckCard = screen.getByTestId('package-webcheck');
    fireEvent.click(webcheckCard);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateOrder).toHaveBeenCalledWith('example.com', 'webcheck');
    });
  });

  it('should submit with selected compliance package', async () => {
    mockCreateOrder.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'compliance', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    // Select compliance package
    const compCard = screen.getByTestId('package-compliance');
    fireEvent.click(compCard);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateOrder).toHaveBeenCalledWith('example.com', 'compliance');
    });
  });

  it('should show package selector with 5 cards', () => {
    render(<Home />);
    expect(screen.getByTestId('package-selector')).toBeInTheDocument();
    expect(screen.getByTestId('package-webcheck')).toBeInTheDocument();
    expect(screen.getByTestId('package-perimeter')).toBeInTheDocument();
    expect(screen.getByTestId('package-compliance')).toBeInTheDocument();
    expect(screen.getByTestId('package-supplychain')).toBeInTheDocument();
    expect(screen.getByTestId('package-insurance')).toBeInTheDocument();
  });
});
