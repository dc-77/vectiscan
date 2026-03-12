import { render, screen } from '@testing-library/react';
import VectiScanLogo from '@/components/VectiScanLogo';

describe('VectiScanLogo', () => {
  it('should render the logo text', () => {
    render(<VectiScanLogo />);
    expect(screen.getByText('Vecti')).toBeInTheDocument();
    expect(screen.getByText('Scan')).toBeInTheDocument();
  });

  it('should render the subtitle', () => {
    render(<VectiScanLogo />);
    expect(screen.getByText('Security Scanner')).toBeInTheDocument();
  });

  it('should contain an SVG element', () => {
    const { container } = render(<VectiScanLogo />);
    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
  });

  it('should apply custom className', () => {
    const { container } = render(<VectiScanLogo className="mb-4" />);
    const wrapper = container.firstElementChild;
    expect(wrapper?.className).toContain('mb-4');
  });

  it('should have aria-hidden on SVG', () => {
    const { container } = render(<VectiScanLogo />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
  });
});
