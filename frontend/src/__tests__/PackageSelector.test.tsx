import { render, screen, fireEvent } from '@testing-library/react';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';

// Der Wizard zeigt nur im Kunden-Frontend gelistete Pakete (listed-Flag im
// kanonischen Katalog, SSoT). Aktuell sind das Perimeter-Scan + Cyberversicherung;
// WebCheck/Compliance/SupplyChain bleiben im Katalog, werden hier aber ausgeblendet.
describe('PackageSelector', () => {
  const defaultProps = {
    selected: 'perimeter' as ScanPackage,
    onSelect: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render only listed package cards (perimeter, insurance)', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('package-perimeter')).toBeInTheDocument();
    expect(screen.getByTestId('package-insurance')).toBeInTheDocument();
    // Nicht gelistete Pakete sind im Kunden-Wizard ausgeblendet.
    expect(screen.queryByTestId('package-webcheck')).not.toBeInTheDocument();
    expect(screen.queryByTestId('package-compliance')).not.toBeInTheDocument();
    expect(screen.queryByTestId('package-supplychain')).not.toBeInTheDocument();
  });

  it('should default to perimeter selected', () => {
    render(<PackageSelector {...defaultProps} />);
    const periCard = screen.getByTestId('package-perimeter');
    expect(periCard.style.borderColor.toLowerCase()).toBe('#38bdf8');
  });

  it('should call onSelect with insurance when insurance card is clicked', () => {
    const onSelect = jest.fn();
    render(<PackageSelector selected="perimeter" onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('package-insurance'));
    expect(onSelect).toHaveBeenCalledWith('insurance');
  });

  it('should show accent border on insurance card when selected', () => {
    render(<PackageSelector selected="insurance" onSelect={jest.fn()} />);
    const insCard = screen.getByTestId('package-insurance');
    expect(insCard.style.borderColor.toLowerCase()).toBe('#34d399');
  });

  it('should show non-selected border on unselected cards', () => {
    render(<PackageSelector selected="insurance" onSelect={jest.fn()} />);
    const periCard = screen.getByTestId('package-perimeter');
    // Unselected cards use a dim version of their accent (color + 30% alpha suffix).
    expect(periCard.style.borderColor.toLowerCase()).toMatch(/^#[0-9a-f]{6}30$/);
  });

  it('should show "Empfohlen" badge on perimeter card', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('badge-perimeter')).toHaveTextContent('Empfohlen');
  });

  it('should show "Versicherung" badge on insurance card', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('badge-insurance')).toHaveTextContent('Versicherung');
  });

  it('should show the duration badge for the recommended package', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByText('~60–90 Min')).toBeInTheDocument();
    // WebCheck (free) ist nicht mehr gelistet — dessen Dauer-Badge entfaellt.
    expect(screen.queryByText('~15–20 Min')).not.toBeInTheDocument();
  });
});
