import { render, screen } from '@testing-library/react';
import VectiScanLogo from '@/components/VectiScanLogo';

describe('VectiScanLogo', () => {
  it('should render the logo text', () => {
    render(<VectiScanLogo />);
    expect(screen.getByText('vecti')).toBeInTheDocument();
    expect(screen.getByText('scan')).toBeInTheDocument();
  });

  it('should render shield with aria-hidden', () => {
    const { container } = render(<VectiScanLogo />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
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
