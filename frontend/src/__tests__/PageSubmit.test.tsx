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

  it('should submit with default professional package', async () => {
    mockCreateOrder.mockResolvedValueOnce({
      success: true,
      data: { id: 'test-id', domain: 'example.com', status: 'created', package: 'professional', createdAt: new Date().toISOString() },
    });

    render(<Home />);

    const input = screen.getByPlaceholderText('beispiel.de');
    fireEvent.change(input, { target: { value: 'example.com' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockCreateOrder).toHaveBeenCalledWith('example.com', 'professional');
    });
  });

  it('should submit with selected basic package', async () => {
    mockCreateOrder.mockResolvedValueOnce({
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
      expect(mockCreateOrder).toHaveBeenCalledWith('example.com', 'basic');
    });
  });

  it('should submit with selected nis2 package', async () => {
    mockCreateOrder.mockResolvedValueOnce({
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
      expect(mockCreateOrder).toHaveBeenCalledWith('example.com', 'nis2');
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
