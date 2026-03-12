import { render, screen, fireEvent } from '@testing-library/react';
import ScanError from '@/components/ScanError';

describe('ScanError', () => {
  it('should show error message', () => {
    render(<ScanError error="Timeout exceeded" onRetry={() => {}} />);
    expect(screen.getByText('Scan fehlgeschlagen')).toBeInTheDocument();
    expect(screen.getByText('Timeout exceeded')).toBeInTheDocument();
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
