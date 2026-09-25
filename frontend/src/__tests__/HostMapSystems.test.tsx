import { render, screen } from '@testing-library/react';

import HostMap, { systemMembers } from '@/components/scan/HostMap';
import type { TechProfile } from '@/lib/api';

// S6b-1 Nachtrag 3 (spec/09 Q16): Junkerwerk 31d67a02. Die IPv6-Adresse von
// 188.40.3.130 (gleiches rDNS) ist vom Pruefstand aus nicht erreichbar. Sie bekommt
// keine eigene Hostkarte, sondern steht in der Karte des Systems mit dem Grund.

const TECH: Record<string, TechProfile> = {
  '188.40.3.130': {
    ip: '188.40.3.130',
    fqdns: ['junkerwerk.de'],
    cms: null,
    cms_version: null,
    server: null,
    waf: null,
    open_ports: [21, 22, 80, 443],
    tech_rows: [],
    additional_ips: [
      { ip: '2a01:4f8:d0a:3124::2', note: 'über IPv6 vom Prüfstand aus nicht erreichbar' },
    ],
  },
};

const AI_HOSTS = [
  { ip: '188.40.3.130', action: 'scan' as const },
  { ip: '2a01:4f8:d0a:3124::2', action: 'scan' as const },
  { ip: '217.243.248.28', action: 'scan' as const },
];

describe('HostMap: ein System, eine Karte', () => {
  it('ordnet die IPv6-Adresse ihrer Leitadresse zu', () => {
    expect(systemMembers(AI_HOSTS, TECH)).toEqual({ '2a01:4f8:d0a:3124::2': '188.40.3.130' });
  });

  it('zeigt die IPv6-Adresse nur als zweite Adresse in der Karte des Systems', () => {
    const { container } = render(
      <HostMap aiHosts={AI_HOSTS} discoveredHosts={[]} techProfilesByIp={TECH} />,
    );
    expect(screen.getByText('Hosts (2)')).toBeInTheDocument();
    const karte = container.querySelector('#host-188\\.40\\.3\\.130');
    expect(karte).not.toBeNull();
    expect(karte?.textContent).toContain('2a01:4f8:d0a:3124::2');
    expect(karte?.textContent).toContain('über IPv6 vom Prüfstand aus nicht erreichbar');
    // Keine eigene Karte: der Anker der IPv6-Adresse liegt in der Karte des Systems.
    const anker = container.querySelector('[id="host-2a01:4f8:d0a:3124::2"]');
    expect(anker).not.toBeNull();
    expect(karte?.contains(anker as Node)).toBe(true);
  });

  it('laesst eine Adresse stehen, wenn die Leitadresse keine Karte hat', () => {
    expect(systemMembers([{ ip: '2a01:4f8:d0a:3124::2', action: 'scan' }], TECH)).toEqual({});
  });
});
