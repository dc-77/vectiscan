import type { OrderListItem, Subscription } from './api';

export type OrderGroupKind = 'subscription' | 'domain';

export interface OrderGroupAggregates {
  totalScans: number;
  activeScans: number;
  failedScans: number;
  doneScans: number;
  latestRisk: string | null;
  severityCounts: Record<string, number>;
  lastScanAt: string | null;
  latestStatus: string | null;
}

export interface OrderGroup {
  kind: OrderGroupKind;
  key: string;                 // group route param: "sub:<uuid>" or "dom:<domain>"
  title: string;
  subtitle: string;
  subscription?: Subscription;
  domain?: string;
  domains: string[];           // all domains touched by this group's orders (or sub.domains)
  orders: OrderListItem[];
  aggregates: OrderGroupAggregates;
}

const ACTIVE_STATUSES = new Set([
  'verification_pending', 'verified', 'created', 'queued',
  'scanning', 'passive_intel', 'dns_recon',
  'scan_phase1', 'scan_phase2', 'scan_phase3', 'scan_complete',
  'pending_review', 'approved', 'report_generating',
]);
const DONE_STATUSES = new Set(['report_complete', 'delivered']);
const FAILED_STATUSES = new Set(['failed', 'cancelled', 'rejected']);

const RISK_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const RANK_TO_RISK = ['LOW', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const PACKAGE_LABELS: Record<string, string> = {
  webcheck: 'WebCheck',
  perimeter: 'Perimeter',
  compliance: 'Compliance',
  supplychain: 'SupplyChain',
  insurance: 'Insurance',
  tlscompliance: 'TLS-Audit',
};

function packageLabel(pkg: string | undefined): string {
  if (!pkg) return '–';
  return PACKAGE_LABELS[pkg.toLowerCase()] ?? pkg;
}

function aggregate(orders: OrderListItem[]): OrderGroupAggregates {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  let activeScans = 0, failedScans = 0, doneScans = 0;
  let lastScanAt: string | null = null;
  let latestStatus: string | null = null;
  let latestRiskRank = -1;
  let latestSortDate = 0;

  for (const o of orders) {
    if (ACTIVE_STATUSES.has(o.status)) activeScans++;
    else if (FAILED_STATUSES.has(o.status)) failedScans++;
    else if (DONE_STATUSES.has(o.status)) doneScans++;

    const dateRef = o.finishedAt || o.startedAt || o.createdAt;
    const ts = dateRef ? new Date(dateRef).getTime() : 0;
    if (ts > latestSortDate) {
      latestSortDate = ts;
      lastScanAt = dateRef || null;
      latestStatus = o.status;
    }

    if (o.severityCounts) {
      for (const [k, v] of Object.entries(o.severityCounts)) {
        const key = k.toUpperCase() as keyof typeof counts;
        if (key in counts) counts[key] += Number(v) || 0;
      }
    }
    if (o.overallRisk) {
      const rank = RISK_RANK[o.overallRisk.toUpperCase()] ?? -1;
      if (rank > latestRiskRank) latestRiskRank = rank;
    }
  }

  let latestRisk: string | null = null;
  if (latestRiskRank >= 0) {
    latestRisk = RANK_TO_RISK[latestRiskRank];
  } else if (counts.CRITICAL > 0) latestRisk = 'CRITICAL';
  else if (counts.HIGH > 0) latestRisk = 'HIGH';
  else if (counts.MEDIUM > 0) latestRisk = 'MEDIUM';
  else if (counts.LOW > 0) latestRisk = 'LOW';

  return {
    totalScans: orders.length,
    activeScans,
    failedScans,
    doneScans,
    latestRisk,
    severityCounts: counts,
    lastScanAt,
    latestStatus,
  };
}

/**
 * Group orders into "subscription" and "domain" buckets.
 *
 * - Orders with `subscriptionId` set → grouped by that subscription.
 * - Orders without `subscriptionId` → grouped by domain.
 * - Subscriptions without any orders are still emitted (empty group).
 *
 * The returned list is sorted: groups with the most recent activity first;
 * empty subscriptions land at the end.
 */
export function groupOrders(
  orders: OrderListItem[],
  subscriptions: Subscription[],
): OrderGroup[] {
  const subById = new Map(subscriptions.map(s => [s.id, s]));
  const subOrders = new Map<string, OrderListItem[]>();
  const domainOrders = new Map<string, OrderListItem[]>();

  for (const order of orders) {
    if (order.subscriptionId && subById.has(order.subscriptionId)) {
      const list = subOrders.get(order.subscriptionId) ?? [];
      list.push(order);
      subOrders.set(order.subscriptionId, list);
    } else {
      const list = domainOrders.get(order.domain) ?? [];
      list.push(order);
      domainOrders.set(order.domain, list);
    }
  }

  const groups: OrderGroup[] = [];

  // Subscription groups (incl. empty ones so the user sees their abo on the dashboard)
  for (const sub of subscriptions) {
    const orderList = subOrders.get(sub.id) ?? [];
    const subTargets = (sub.targets ?? []).map(t => t.canonical || t.raw_input);
    const allDomains = Array.from(new Set([...subTargets, ...orderList.map(o => o.domain)])).sort();
    groups.push({
      kind: 'subscription',
      key: `sub:${sub.id}`,
      title: `${packageLabel(sub.package)}-Abo`,
      subtitle: subTargets.length === 1
        ? subTargets[0]
        : `${subTargets.length} Ziele`,
      subscription: sub,
      domains: allDomains,
      orders: orderList,
      aggregates: aggregate(orderList),
    });
  }

  // Domain groups (one per unique domain among unlinked orders)
  for (const [domain, orderList] of domainOrders) {
    groups.push({
      kind: 'domain',
      key: `dom:${encodeURIComponent(domain)}`,
      title: domain,
      subtitle: orderList.length === 1 ? '1 Einzelscan' : `${orderList.length} Einzelscans`,
      domain,
      domains: [domain],
      orders: orderList,
      aggregates: aggregate(orderList),
    });
  }

  // Sort: groups with recent activity first; empty groups last
  groups.sort((a, b) => {
    const aTs = a.aggregates.lastScanAt ? new Date(a.aggregates.lastScanAt).getTime() : 0;
    const bTs = b.aggregates.lastScanAt ? new Date(b.aggregates.lastScanAt).getTime() : 0;
    if (aTs !== bTs) return bTs - aTs;
    // Tie-breaker: subscriptions before domain-only when both are empty
    if (a.kind !== b.kind) return a.kind === 'subscription' ? -1 : 1;
    return a.title.localeCompare(b.title);
  });

  return groups;
}

/**
 * Resolve a route-param `groupKey` (e.g. "sub:abc-123" or "dom:example.com")
 * to its OrderGroup, or null if none matches.
 */
export function findGroupByKey(groups: OrderGroup[], groupKey: string): OrderGroup | null {
  return groups.find(g => g.key === groupKey) ?? null;
}
