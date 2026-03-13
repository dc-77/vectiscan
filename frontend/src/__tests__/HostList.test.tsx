import { render, screen } from '@testing-library/react';
import HostList from '@/components/HostList';

describe('HostList', () => {
  it('should render nothing when hosts array is empty', () => {
    const { container } = render(<HostList hosts={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it('should render a single host', () => {
    const hosts = [
      { ip: '1.2.3.4', fqdns: ['example.com'], status: 'completed' },
    ];
    render(<HostList hosts={hosts} />);
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument();
    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByText('✅')).toBeInTheDocument();
  });

  it('should render multiple hosts with different statuses', () => {
    const hosts = [
      { ip: '1.2.3.4', fqdns: ['a.com'], status: 'completed' },
      { ip: '5.6.7.8', fqdns: ['b.com', 'www.b.com'], status: 'scanning' },
      { ip: '9.10.11.12', fqdns: [], status: 'pending' },
    ];
    render(<HostList hosts={hosts} />);
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument();
    expect(screen.getByText('5.6.7.8')).toBeInTheDocument();
    expect(screen.getByText('9.10.11.12')).toBeInTheDocument();
    expect(screen.getByText('✅')).toBeInTheDocument();
    expect(screen.getByText('🔄')).toBeInTheDocument();
    expect(screen.getByText('⏳')).toBeInTheDocument();
    expect(screen.getByText(/Entdeckte Hosts \(3\)/)).toBeInTheDocument();
  });
});
