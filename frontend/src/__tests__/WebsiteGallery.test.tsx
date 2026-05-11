import { render, screen } from '@testing-library/react';

import { WebsiteGallery } from '@/components/scan/WebsiteGallery';
import type { DiscoveredHost, TechProfile } from '@/lib/api';

const MOCK_TECH: Record<string, TechProfile> = {
  '18.65.0.55': {
    ip: '18.65.0.55',
    fqdns: ['heuel.com'],
    cms: 'WordPress',
    cms_version: '6.4',
    tech_rows: [
      { name: 'WordPress', version: '6.4', category: 'cms', status: 'current', is_mega_cve: false, vuln_name: '', confidence: null, source: 'cms' },
      { name: 'Apache',    version: '2.4', category: 'server', status: 'current', is_mega_cve: false, vuln_name: '', confidence: null, source: 'nmap' },
    ],
  },
};

const MOCK_HOSTS: DiscoveredHost[] = [{
  ip: '18.65.0.55',
  fqdns: ['heuel.com'],
  vhosts: [
    {
      fqdn: 'heuel.com',
      status: 200,
      title: 'Heuel - Home',
      is_primary: true,
      screenshot_minio_key: 'order-abc/18.65.0.55__heuel.com.png',
      site_summary: {
        description: 'WordPress 6.4 auf Apache - Marketing-Webseite.',
        classification: 'web_content',
        is_real_content: true,
        confidence: 0.95,
      },
    },
    {
      fqdn: 'panel.heuel.com',
      status: 200,
      title: 'Plesk Onyx Login',
      is_primary: true,
      site_summary: {
        description: 'Plesk-Verwaltungspanel (Login-Seite)',
        classification: 'control_panel',
        is_real_content: true,
        confidence: 1.0,
      },
    },
  ],
  vhost_skipped: [
    {
      fqdn: 'old.heuel.com',
      reason: 'parking',
      status: 200,
      title: 'Sponsored Listings',
      site_summary: {
        description: 'Parking-Page - Domain ist nicht aktiv im Einsatz',
        classification: 'parking',
        is_real_content: false,
        confidence: 1.0,
      },
    },
  ],
}];

describe('WebsiteGallery', () => {
  it('renders empty state when no hosts have vhosts', () => {
    render(
      <WebsiteGallery discoveredHosts={[]} techProfilesByIp={{}} orderId="ord-empty" />,
    );
    expect(screen.getByText('Keine Webseiten erkannt')).toBeInTheDocument();
  });

  it('default-filter "Echte Sites" zeigt web_content + control_panel', () => {
    render(
      <WebsiteGallery
        discoveredHosts={MOCK_HOSTS}
        techProfilesByIp={MOCK_TECH}
        orderId="ord-1"
      />,
    );
    // Default-Filter: real (= is_real_content true). Sollte 2/3 zeigen.
    expect(screen.getByText('heuel.com')).toBeInTheDocument();
    expect(screen.getByText('panel.heuel.com')).toBeInTheDocument();
    expect(screen.queryByText('old.heuel.com')).not.toBeInTheDocument();
  });

  it('zeigt Description aus site_summary', () => {
    render(
      <WebsiteGallery
        discoveredHosts={MOCK_HOSTS}
        techProfilesByIp={MOCK_TECH}
        orderId="ord-1"
      />,
    );
    expect(screen.getByText(/WordPress 6.4 auf Apache - Marketing-Webseite/)).toBeInTheDocument();
    expect(screen.getByText(/Plesk-Verwaltungspanel/)).toBeInTheDocument();
  });

  it('zeigt Sprung-Link zum Host', () => {
    render(
      <WebsiteGallery
        discoveredHosts={MOCK_HOSTS}
        techProfilesByIp={MOCK_TECH}
        orderId="ord-1"
      />,
    );
    // Beide Cards (real) zeigen "→ Host 18.65.0.55".
    const hostLinks = screen.getAllByText(/→ Host 18\.65\.0\.55/);
    expect(hostLinks).toHaveLength(2);
  });

  it('zeigt Pillen mit korrekten Counts', () => {
    render(
      <WebsiteGallery
        discoveredHosts={MOCK_HOSTS}
        techProfilesByIp={MOCK_TECH}
        orderId="ord-1"
      />,
    );
    // "Echte Sites" Count = 2 (heuel.com + panel.heuel.com)
    // "Panels" Count = 1 (panel.heuel.com)
    // "Skipped" Count = 1 (old.heuel.com / parking)
    // "Alle" Count = 3
    expect(screen.getByText(/Echte Sites/).closest('button')).toHaveTextContent('2');
    expect(screen.getByText(/Panels/).closest('button')).toHaveTextContent('1');
    expect(screen.getByText(/Skipped/).closest('button')).toHaveTextContent('1');
    expect(screen.getByText(/Alle/).closest('button')).toHaveTextContent('3');
  });
});
