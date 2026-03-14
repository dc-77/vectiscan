import { render, screen, fireEvent } from '@testing-library/react';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';

describe('PackageSelector', () => {
  const defaultProps = {
    selected: 'professional' as ScanPackage,
    onSelect: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render 3 package cards', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('package-basic')).toBeInTheDocument();
    expect(screen.getByTestId('package-professional')).toBeInTheDocument();
    expect(screen.getByTestId('package-nis2')).toBeInTheDocument();
  });

  it('should default to professional selected', () => {
    render(<PackageSelector {...defaultProps} />);
    const proCard = screen.getByTestId('package-professional');
    // Selected card has cyan border
    expect(proCard.style.borderColor.toLowerCase()).toBe('#38bdf8');
  });

  it('should call onSelect with basic when basic card is clicked', () => {
    const onSelect = jest.fn();
    render(<PackageSelector selected="professional" onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('package-basic'));
    expect(onSelect).toHaveBeenCalledWith('basic');
  });

  it('should call onSelect with nis2 when NIS2 card is clicked', () => {
    const onSelect = jest.fn();
    render(<PackageSelector selected="professional" onSelect={onSelect} />);
    fireEvent.click(screen.getByTestId('package-nis2'));
    expect(onSelect).toHaveBeenCalledWith('nis2');
  });

  it('should show gold border on NIS2 card when selected', () => {
    render(<PackageSelector selected="nis2" onSelect={jest.fn()} />);
    const nis2Card = screen.getByTestId('package-nis2');
    expect(nis2Card.style.borderColor.toLowerCase()).toBe('#eab308');
  });

  it('should show non-selected border on unselected cards', () => {
    render(<PackageSelector selected="basic" onSelect={jest.fn()} />);
    const proCard = screen.getByTestId('package-professional');
    expect(proCard.style.borderColor).toBe('#334155');
  });

  it('should show "Empfohlen" badge on professional card', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('badge-professional')).toHaveTextContent('Empfohlen');
  });

  it('should show "NIS2-konform" badge on NIS2 card', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByTestId('badge-nis2')).toHaveTextContent('NIS2-konform');
  });

  it('should show correct features for basic (included items)', () => {
    render(<PackageSelector selected="basic" onSelect={jest.fn()} />);
    // Basic has Port-Scan ✓ but not Vulnerability-Scan
    const basicCard = screen.getByTestId('package-basic');
    const checkmarks = basicCard.querySelectorAll('[aria-label="included"]');
    const dashes = basicCard.querySelectorAll('[aria-label="not included"]');
    // 5 included features + some not included
    expect(checkmarks.length).toBe(5);
    expect(dashes.length).toBe(8); // 8 features not included in basic (excluding Max. Hosts which shows "3")
  });

  it('should show correct features for professional (included items)', () => {
    render(<PackageSelector selected="professional" onSelect={jest.fn()} />);
    const proCard = screen.getByTestId('package-professional');
    const checkmarks = proCard.querySelectorAll('[aria-label="included"]');
    const dashes = proCard.querySelectorAll('[aria-label="not included"]');
    expect(checkmarks.length).toBe(10);
    expect(dashes.length).toBe(3); // NIS2-specific features
  });

  it('should show duration badges', () => {
    render(<PackageSelector {...defaultProps} />);
    expect(screen.getByText('~10 Min')).toBeInTheDocument();
    expect(screen.getAllByText('~45 Min').length).toBe(2);
  });
});
