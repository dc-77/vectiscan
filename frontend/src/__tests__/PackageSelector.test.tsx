import { render, screen, fireEvent } from '@testing-library/react';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';

describe('PackageSelector', () => {
  const defaultProps = {
    selected: 'perimeter' as ScanPackage,
    onSelect: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render 5 package cards', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('package-webcheck')).toBeInTheDocument();
    expect(screen.getByTestId('package-perimeter')).toBeInTheDocument();
    expect(screen.getByTestId('package-compliance')).toBeInTheDocument();
    expect(screen.getByTestId('package-supplychain')).toBeInTheDocument();
    expect(screen.getByTestId('package-insurance')).toBeInTheDocument();
  });

  it('should default to perimeter selected', () => {
    render(<PackageSelector {...defaultProps} />);
    const periCard = screen.getByTestId('package-perimeter');
    expect(periCard.style.borderColor.toLowerCase()).toBe('#38bdf8');
  });

  it('should call onSelect with webcheck when webcheck card is clicked', () => {
    const onSelect = jest.fn();
    render(<PackageSelector selected="perimeter" onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('package-webcheck'));
    expect(onSelect).toHaveBeenCalledWith('webcheck');
  });

  it('should call onSelect with compliance when compliance card is clicked', () => {
    const onSelect = jest.fn();
    render(<PackageSelector selected="perimeter" onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('package-compliance'));
    expect(onSelect).toHaveBeenCalledWith('compliance');
  });

  it('should show gold border on compliance card when selected', () => {
    render(<PackageSelector selected="compliance" onSelect={jest.fn()} />);
    const compCard = screen.getByTestId('package-compliance');
    expect(compCard.style.borderColor.toLowerCase()).toBe('#eab308');
  });

  it('should show non-selected border on unselected cards', () => {
    render(<PackageSelector selected="webcheck" onSelect={jest.fn()} />);
    const periCard = screen.getByTestId('package-perimeter');
    // Unselected cards use a dim version of their accent (color + 30% alpha suffix).
    expect(periCard.style.borderColor.toLowerCase()).toMatch(/^#[0-9a-f]{6}30$/);
  });

  it('should show "Empfohlen" badge on perimeter card', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('badge-perimeter')).toHaveTextContent('Empfohlen');
  });

  it('should show "NIS2" badge on compliance card', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('badge-compliance')).toHaveTextContent('NIS2');
  });

  it('should show duration badges', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByText('~15–20 Min')).toBeInTheDocument();
    expect(screen.getByText('~60–90 Min')).toBeInTheDocument();
  });
});
