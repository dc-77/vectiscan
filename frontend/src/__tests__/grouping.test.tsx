import { groupOrders, findGroupByKey } from '@/lib/grouping';
import type { OrderListItem, Subscription } from '@/lib/api';

const baseOrder: OrderListItem = {
  id: 'o-1',
  domain: 'example.com',
  email: 'c@example.com',
  package: 'perimeter',
  status: 'report_complete',
  hasReport: true,
  error: null,
  hostsTotal: 3,
  hostsCompleted: 3,
  currentTool: null,
  currentHost: null,
  startedAt: '2026-04-01T10:00:00Z',
  finishedAt: '2026-04-01T11:00:00Z',
  createdAt: '2026-04-01T09:55:00Z',
  overallRisk: 'MEDIUM',
  severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 2, LOW: 1, INFO: 4 },
  businessImpactScore: 5.5,
  subscriptionId: null,
  isRescan: false,
  targetCount: null,
};

const baseSub: Subscription = {
  id: 'sub-1',
  customerEmail: 'c@example.com',
  package: 'perimeter',
  status: 'active',
  scanInterval: 'monthly',
  maxDomains: 30,
  maxRescans: 3,
  rescansUsed: 0,
  reportEmails: ['c@example.com'],
  startedAt: '2026-01-01T00:00:00Z',
  expiresAt: '2027-01-01T00:00:00Z',
  lastScanAt: '2026-04-01T11:00:00Z',
  createdAt: '2026-01-01T00:00:00Z',
  targets: [
    { id: 'sd-1', raw_input: 'example.com', canonical: 'example.com', target_type: 'fqdn_root', discovery_policy: 'enumerate', exclusions: [], status: 'approved' },
    { id: 'sd-2', raw_input: 'shop.example.com', canonical: 'shop.example.com', target_type: 'fqdn_specific', discovery_policy: 'scoped', exclusions: [], status: 'approved' },
  ],
};

describe('groupOrders', () => {
  it('groups orders with subscriptionId under the matching subscription', () => {
    const orders: OrderListItem[] = [
      { ...baseOrder, id: 'o-1', subscriptionId: 'sub-1' },
      { ...baseOrder, id: 'o-2', domain: 'shop.example.com', subscriptionId: 'sub-1' },
    ];
    const groups = groupOrders(orders, [baseSub]);
    const subGroup = groups.find(g => g.kind === 'subscription' && g.key === 'sub:sub-1');
    expect(subGroup).toBeDefined();
    expect(subGroup!.orders).toHaveLength(2);
    expect(subGroup!.aggregates.totalScans).toBe(2);
  });

  it('falls back to per-domain grouping when subscriptionId is null', () => {
    const orders: OrderListItem[] = [
      { ...baseOrder, id: 'o-1', domain: 'foo.com', subscriptionId: null },
      { ...baseOrder, id: 'o-2', domain: 'foo.com', subscriptionId: null },
      { ...baseOrder, id: 'o-3', domain: 'bar.com', subscriptionId: null },
    ];
    const groups = groupOrders(orders, []);
    expect(groups).toHaveLength(2);
    const fooGroup = groups.find(g => g.domain === 'foo.com');
    expect(fooGroup).toBeDefined();
    expect(fooGroup!.kind).toBe('domain');
    expect(fooGroup!.orders).toHaveLength(2);
    expect(groups.find(g => g.domain === 'bar.com')!.orders).toHaveLength(1);
  });

  it('treats orders with subscriptionId pointing to an unknown subscription as domain-only', () => {
    const orders: OrderListItem[] = [
      { ...baseOrder, id: 'o-1', subscriptionId: 'sub-deleted' },
    ];
    const groups = groupOrders(orders, []);
    expect(groups).toHaveLength(1);
    expect(groups[0].kind).toBe('domain');
    expect(groups[0].domain).toBe('example.com');
  });

  it('emits an empty subscription group when no orders are linked yet', () => {
    const groups = groupOrders([], [baseSub]);
    expect(groups).toHaveLength(1);
    expect(groups[0].kind).toBe('subscription');
    expect(groups[0].orders).toHaveLength(0);
    expect(groups[0].domains).toEqual(['example.com', 'shop.example.com']);
  });

  it('aggregates severity counts and picks the highest risk', () => {
    const orders: OrderListItem[] = [
      { ...baseOrder, id: 'o-1', overallRisk: 'LOW', severityCounts: { LOW: 1 } },
      { ...baseOrder, id: 'o-2', overallRisk: 'HIGH', severityCounts: { HIGH: 1, MEDIUM: 2 } },
    ];
    const groups = groupOrders(orders, []);
    expect(groups[0].aggregates.latestRisk).toBe('HIGH');
    expect(groups[0].aggregates.severityCounts.HIGH).toBe(1);
    expect(groups[0].aggregates.severityCounts.MEDIUM).toBe(2);
    expect(groups[0].aggregates.severityCounts.LOW).toBe(1);
  });

  it('counts active/done/failed correctly', () => {
    const orders: OrderListItem[] = [
      { ...baseOrder, id: 'o-1', status: 'report_complete' },
      { ...baseOrder, id: 'o-2', status: 'scanning' },
      { ...baseOrder, id: 'o-3', status: 'failed' },
      { ...baseOrder, id: 'o-4', status: 'cancelled' },
    ];
    const groups = groupOrders(orders, []);
    const agg = groups[0].aggregates;
    expect(agg.doneScans).toBe(1);
    expect(agg.activeScans).toBe(1);
    expect(agg.failedScans).toBe(2);
  });

  it('findGroupByKey resolves both sub: and dom: keys', () => {
    const orders: OrderListItem[] = [
      { ...baseOrder, id: 'o-1', subscriptionId: 'sub-1' },
      { ...baseOrder, id: 'o-2', domain: 'lonely.com', subscriptionId: null },
    ];
    const groups = groupOrders(orders, [baseSub]);
    expect(findGroupByKey(groups, 'sub:sub-1')).not.toBeNull();
    expect(findGroupByKey(groups, 'dom:lonely.com')).not.toBeNull();
    expect(findGroupByKey(groups, 'sub:does-not-exist')).toBeNull();
  });
});
