import { render, screen, fireEvent } from '@testing-library/react';
import ScanError from '@/components/ScanError';

describe('ScanError', () => {
  it('should show generic error message for non-timeout errors', () => {
    render(<ScanError error="Something went wrong" onRetry={() => {}} />);
    expect(screen.getByText('Scan fehlgeschlagen')).toBeInTheDocument();
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('should show timeout-specific heading for timeout errors', () => {
    render(<ScanError error="Scan-Timeout: Das Basic-Paket hat das Zeitlimit überschritten." onRetry={() => {}} />);
    expect(screen.getByText('Scan-Zeitlimit erreicht')).toBeInTheDocument();
    expect(screen.getByText(/Versuchen Sie es erneut/)).toBeInTheDocument();
  });

  it('should call onRetry when button clicked', () => {
    const onRetry = jest.fn();
    render(<ScanError error="Error" onRetry={onRetry} />);
    fireEvent.click(screen.getByText('Neuen Scan starten'));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('should handle null error gracefully', () => {
    render(<ScanError error={null} onRetry={() => {}} />);
    expect(screen.getByText('Scan fehlgeschlagen')).toBeInTheDocument();
  });
});
