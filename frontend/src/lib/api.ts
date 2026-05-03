import { getToken, clearToken, AuthResponse } from './auth';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export interface OrderData {
  id: string;
  domain: string;
  status: string;
  package: string;
  createdAt: string;
  alreadyVerified?: boolean;
}

export interface HostInfo {
  ip: string;
  fqdns: string[];
  status: string;
}

export interface OrderProgress {
  phase: string | null;
  currentTool: string | null;
  currentHost: string | null;
  hostsTotal: number;
  hostsCompleted: number;
  discoveredHosts: HostInfo[];
  toolOutput: string | null;
  lastCompletedTool: string | null;
}

export interface OrderStatus {
  id: string;
  domain: string;
  status: string;
  package: string;
  estimatedDuration: string;
  progress: OrderProgress;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  hasReport: boolean;
  passiveIntelSummary?: Record<string, unknown> | null;
  correlationData?: unknown[] | null;
  businessImpactScore?: number | null;
}

export interface ReportData {
  downloadUrl: string;
  fileName: string;
  fileSize: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function handleResponse<T>(res: Response): Promise<ApiResponse<T>> {
  if (res.status === 401) {
    clearToken();
    if (typeof window !== 'undefined') {
      window.location.href = '/login';
    }
    return { success: false, error: 'Sitzung abgelaufen. Bitte erneut anmelden.' };
  }
  return res.json();
}

// --- Auth ---

export async function login(email: string, password: string): Promise<ApiResponse<AuthResponse>> {
  const res = await fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return res.json();
}

export async function register(email: string, password: string, companyName?: string): Promise<ApiResponse<AuthResponse>> {
  const res = await fetch(`${API_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, companyName: companyName || undefined }),
  });
  return res.json();
}

// --- Orders ---

export type TargetType = 'fqdn_root' | 'fqdn_specific' | 'ipv4' | 'cidr';
export type DiscoveryPolicy = 'enumerate' | 'scoped' | 'ip_only';

export interface TargetEntry {
  raw_input: string;
  exclusions: string[];
}

export interface TargetValidation {
  raw_input: string;
  valid: boolean;
  canonical?: string;
  target_type?: TargetType;
  policy_default?: DiscoveryPolicy;
  expanded_count_estimate?: number;
  warnings: string[];
  error?: string;
}

export interface TargetBatchValidation {
  targets: TargetValidation[];
  errors: string[];
}

export interface OrderTargetStub {
  id: string;
  raw_input: string;
  canonical: string;
  target_type: TargetType;
  discovery_policy: DiscoveryPolicy;
  status: string;
}

export interface OrderWithTargets {
  id: string;
  status: string;
  package: string;
  targetCount: number;
  targets: OrderTargetStub[];
}

export async function validateTargets(targets: TargetEntry[]): Promise<ApiResponse<TargetBatchValidation>> {
  const res = await fetch(`${API_URL}/api/orders/validate-targets`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ targets }),
  });
  return handleResponse(res);
}

export async function createOrder(targets: TargetEntry[], pkg: string = 'perimeter'): Promise<ApiResponse<OrderWithTargets>> {
  const res = await fetch(`${API_URL}/api/orders`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ package: pkg, targets }),
  });
  return handleResponse(res);
}

export async function getOrderStatus(id: string): Promise<ApiResponse<OrderStatus>> {
  const res = await fetch(`${API_URL}/api/orders/${id}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export interface OrderEvents {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  aiStrategy: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  aiConfigs: Record<string, any>;
  toolOutputs: Array<{ tool: string; host: string; summary: string; ts: string }>;
  discoveredHosts: HostInfo[];
  error: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  aiDebug?: Record<string, any>;
  falsePositives?: {
    count: number;
    by_reason: Record<string, number>;
    details: Array<{
      tool: string;
      title: string;
      severity: string;
      reason: string;
      host: string;
      cve?: string;
    }>;
  } | null;
  costs?: {
    total_usd: number;
    breakdown: Array<{
      step: string;
      model: string;
      tokens: number;
      cost_usd: number;
    }>;
  } | null;
}

export async function getOrderEvents(id: string): Promise<ApiResponse<OrderEvents>> {
  const res = await fetch(`${API_URL}/api/orders/${id}/events`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export function getReportDownloadUrl(id: string, version?: number): string {
  const token = getToken();
  const url = `${API_URL}/api/orders/${id}/report${token ? `?token=${token}` : ''}`;
  return version ? `${url}&version=${version}` : url;
}

export async function getOrderReport(id: string): Promise<ApiResponse<ReportData>> {
  const res = await fetch(`${API_URL}/api/orders/${id}/report`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function cancelOrder(id: string): Promise<ApiResponse<null>> {
  const token = getToken();
  const res = await fetch(`${API_URL}/api/orders/${id}`, {
    method: 'DELETE',
    headers: token ? { 'Authorization': `Bearer ${token}` } : {},
  });
  return handleResponse(res);
}

// --- Verification ---

export interface VerificationStatus {
  verified: boolean;
  method: string | null;
  token: string;
  domain: string;
}

export interface VerificationCheckResult {
  verified: boolean;
  method?: string;
}

export async function getVerificationStatus(orderId: string): Promise<ApiResponse<VerificationStatus>> {
  const res = await fetch(`${API_URL}/api/verify/status/${orderId}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function checkVerification(orderId: string): Promise<ApiResponse<VerificationCheckResult>> {
  const res = await fetch(`${API_URL}/api/verify/check`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ orderId }),
  });
  return handleResponse(res);
}

export interface OrderListItem {
  id: string;
  domain: string;
  email: string;
  package: string;
  status: string;
  hasReport: boolean;
  error: string | null;
  hostsTotal: number;
  hostsCompleted: number;
  currentTool: string | null;
  currentHost: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  overallRisk: string | null;
  severityCounts: Record<string, number> | null;
  businessImpactScore: number | null;
  subscriptionId: string | null;
  isRescan: boolean;
  targetCount: number | null;
  // Multi-Target-UX: bei N>1 listet das Frontend die Domains direkt
  // (statt nur "multi-target (N)" anzuzeigen).
  targets?: Array<{ canonical: string }> | null;
}

// --- Findings ---

export interface Finding {
  id: string;
  title: string;
  severity: string;
  cvss_score: string;
  cvss_vector: string;
  cwe: string;
  affected: string;
  description: string;
  evidence: string;
  impact: string;
  recommendation: string;
  nis2_ref?: string;
  iso27001_ref?: string;
  confidence?: number;
  epss?: number;
  epss_percentile?: number;
  in_cisa_kev?: boolean;
  exploit_available?: boolean;
  business_impact?: number;
  // Q2/2026 Determinismus
  policy_id?: string;
  severity_provenance?: {
    policy_id?: string;
    policy_decision?: string;
    policy_version?: string;
    rationale?: string;
    rule_references?: string[];
  };
  business_impact_score?: number;
  affected_hosts?: string[];
  // Threat-Intel (durchgereicht aus correlation_data.enrichment im /findings-Endpoint)
  threat_intel?: {
    cisa_kev?: { cveID?: string; knownRansomwareCampaignUse?: string } | null;
    epss?: { epss?: number; percentile?: number } | null;
    nvd?: { cvss_score?: number; cwe?: string } | null;
    exploitdb?: Array<{ id: string }> | null;
  } | null;
}

export interface PositiveFinding {
  title: string;
  description: string;
}

export interface Recommendation {
  timeframe: string;
  action: string;
  finding_refs: string[];
  effort: string;
}

export interface FindingsData {
  overall_risk: string;
  overall_description: string;
  severity_counts: Record<string, number>;
  findings: Finding[];
  positive_findings: PositiveFinding[];
  recommendations: Recommendation[];
  package: string;
  nis2_compliance_summary?: Record<string, string> | null;
  excluded_finding_ids?: string[];
  exclusions?: Array<{
    finding_id: string;
    reason: string;
    created_at: string;
  }>;
  // Q2/2026 Audit-Felder (Migration 016/018, durchgereicht im /findings-Endpoint)
  policy_version?: string | null;
  policy_id_distinct?: string[];
  audit_severity_counts?: Record<string, number> | null;
  business_impact_score?: number | null;
}

export async function listOrders(): Promise<ApiResponse<{ orders: OrderListItem[] }>> {
  const res = await fetch(`${API_URL}/api/orders`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Dashboard Summary ---

export interface DashboardSummary {
  domains: number;
  totalScans: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  overallRisk: string;
  topFindings: Array<{ domain: string; title: string; severity: string; cvss: number; orderId: string }>;
}

export async function getDashboardSummary(
  filter?: { subscriptionId?: string; domain?: string; orderId?: string },
): Promise<ApiResponse<DashboardSummary>> {
  const qs = new URLSearchParams();
  if (filter?.subscriptionId) qs.set('subscriptionId', filter.subscriptionId);
  if (filter?.domain) qs.set('domain', filter.domain);
  if (filter?.orderId) qs.set('orderId', filter.orderId);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  const res = await fetch(`${API_URL}/api/orders/dashboard-summary${suffix}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Scan Diff ---

export interface ScanDiff {
  current: { orderId: string; domain: string; date: string; findingsCount: number };
  previous: { orderId: string; domain: string; date: string; findingsCount: number };
  newFindings: Array<{ title: string; severity: string; cvss_score: string }>;
  resolvedFindings: Array<{ title: string; severity: string; cvss_score: string }>;
  unchangedCount: number;
  summary: string;
}

export async function getScanDiff(orderId: string, compareId: string): Promise<ApiResponse<ScanDiff>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/diff?compare=${compareId}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Password Reset ---

export async function forgotPassword(email: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  return res.json();
}

export async function resetPassword(token: string, password: string): Promise<ApiResponse<AuthResponse>> {
  const res = await fetch(`${API_URL}/api/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, password }),
  });
  return res.json();
}

// --- Admin ---

export async function getFindings(orderId: string): Promise<ApiResponse<FindingsData>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/findings`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function deleteOrderPermanent(id: string): Promise<ApiResponse<null>> {
  const token = getToken();
  const res = await fetch(`${API_URL}/api/orders/${id}?permanent=true`, {
    method: 'DELETE',
    headers: token ? { 'Authorization': `Bearer ${token}` } : {},
  });
  return handleResponse(res);
}

// --- Profile ---

export async function changePassword(currentPassword: string, newPassword: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/auth/password`, {
    method: 'PUT',
    headers: authHeaders(),
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  return handleResponse(res);
}

// --- Subscriptions ---

export interface SubscriptionTarget {
  id: string;
  raw_input: string;
  canonical: string;
  target_type: TargetType;
  discovery_policy: DiscoveryPolicy;
  exclusions: string[];
  status: string;
}

export interface Subscription {
  id: string;
  customerEmail: string;
  package: string;
  status: string;
  scanInterval: string;
  maxDomains: number;
  maxHosts?: number;
  maxCidrPrefix?: number;
  maxRescans: number;
  rescansUsed: number;
  reportEmails: string[];
  startedAt: string;
  expiresAt: string;
  lastScanAt: string | null;
  createdAt: string;
  targets: SubscriptionTarget[];
}

// PR-Posture: aggregierter Sicherheits-Status ueber alle Scans der Subscription
export interface SubscriptionPosture {
  subscriptionId: string;
  lastScanOrderId: string | null;
  lastAggregatedAt: string | null;
  severityCounts: {
    open?: { CRITICAL?: number; HIGH?: number; MEDIUM?: number; LOW?: number; INFO?: number };
    total_open?: number;
    resolved_total?: number;
    regressed_total?: number;
    accepted_total?: number;
  };
  postureScore: number | null;
  trendDirection: 'improving' | 'stable' | 'degrading' | 'unknown';
  updatedAt: string | null;
}

export interface ConsolidatedFinding {
  id: string;
  hostIp: string;
  findingType: string;
  portOrPath: string;
  status: 'open' | 'resolved' | 'regressed' | 'risk_accepted';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvssScore: number | null;
  title: string;
  description: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  riskAcceptedAt: string | null;
  riskAcceptedReason: string | null;
  metadata: Record<string, unknown>;
}

export interface PostureHistoryPoint {
  id: string;
  triggeringOrderId: string | null;
  snapshotAt: string;
  postureScore: number;
  severityCounts: Record<string, unknown>;
  newFindings: number;
  resolvedFindings: number;
  regressedFindings: number;
}

export async function getSubscriptionPosture(
  subscriptionId: string,
): Promise<ApiResponse<SubscriptionPosture>> {
  const res = await fetch(`${API_URL}/api/subscriptions/${subscriptionId}/posture`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function getSubscriptionFindings(
  subscriptionId: string,
  filter?: { status?: string; severity?: string },
): Promise<ApiResponse<{ findings: ConsolidatedFinding[] }>> {
  const qs = new URLSearchParams();
  if (filter?.status) qs.set('status', filter.status);
  if (filter?.severity) qs.set('severity', filter.severity);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  const res = await fetch(`${API_URL}/api/subscriptions/${subscriptionId}/findings${suffix}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function acceptFindingRisk(
  subscriptionId: string, findingId: string, reason: string,
): Promise<ApiResponse<{ id: string; status: string }>> {
  const res = await fetch(
    `${API_URL}/api/subscriptions/${subscriptionId}/findings/${findingId}/accept-risk`,
    { method: 'POST', headers: authHeaders(), body: JSON.stringify({ reason }) },
  );
  return handleResponse(res);
}

export async function reopenFinding(
  subscriptionId: string, findingId: string,
): Promise<ApiResponse<{ id: string; status: string }>> {
  const res = await fetch(
    `${API_URL}/api/subscriptions/${subscriptionId}/findings/${findingId}/reopen`,
    { method: 'POST', headers: authHeaders() },
  );
  return handleResponse(res);
}

export async function getPostureHistory(
  subscriptionId: string, limit = 50,
): Promise<ApiResponse<{ history: PostureHistoryPoint[] }>> {
  const res = await fetch(
    `${API_URL}/api/subscriptions/${subscriptionId}/posture-history?limit=${limit}`,
    { headers: authHeaders() },
  );
  return handleResponse(res);
}

export async function generateStatusReport(
  subscriptionId: string,
): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(
    `${API_URL}/api/subscriptions/${subscriptionId}/status-report/generate`,
    { method: 'POST', headers: authHeaders() },
  );
  return handleResponse(res);
}

export async function createSubscription(data: {
  package: string; targets: TargetEntry[]; scanInterval: string; reportEmails: string[];
}): Promise<ApiResponse<{ id: string; message: string }>> {
  const res = await fetch(`${API_URL}/api/subscriptions`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse(res);
}

export async function listSubscriptions(): Promise<ApiResponse<{ subscriptions: Subscription[] }>> {
  const res = await fetch(`${API_URL}/api/subscriptions`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function addSubscriptionTarget(subscriptionId: string, entry: TargetEntry): Promise<ApiResponse<SubscriptionTarget>> {
  const res = await fetch(`${API_URL}/api/subscriptions/${subscriptionId}/targets`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(entry),
  });
  return handleResponse(res);
}

export async function removeSubscriptionTarget(subscriptionId: string, targetId: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/subscriptions/${subscriptionId}/targets/${targetId}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function requestRescan(subscriptionId: string, targetId?: string): Promise<ApiResponse<{ orderId: string; message: string }>> {
  const res = await fetch(`${API_URL}/api/subscriptions/${subscriptionId}/rescan`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(targetId ? { targetId } : {}),
  });
  return handleResponse(res);
}

export interface PendingDomain {
  id: string;
  domain: string;
  subscriptionId: string;
  package: string;
  customerEmail: string;
  createdAt: string;
}

export async function getPendingDomains(): Promise<ApiResponse<{ domains: PendingDomain[] }>> {
  const res = await fetch(`${API_URL}/api/admin/pending-domains`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function approveDomain(domainId: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/admin/subscription-domains/${domainId}/approve`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function rejectDomain(domainId: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/admin/subscription-domains/${domainId}/reject`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Verified Domains ---

export interface VerifiedDomain {
  domain: string;
  verification_method: string;
  verified_at: string;
  expires_at: string;
}

export async function getVerifiedDomains(): Promise<ApiResponse<{ domains: VerifiedDomain[] }>> {
  const res = await fetch(`${API_URL}/api/auth/verified-domains`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Admin: Users ---

export interface AdminUser {
  id: string;
  email: string;
  role: string;
  customerId: string | null;
  orderCount: number;
  createdAt: string;
}

export async function listUsers(): Promise<ApiResponse<{ users: AdminUser[] }>> {
  const res = await fetch(`${API_URL}/api/admin/users`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function changeUserRole(userId: string, role: string): Promise<ApiResponse<{ id: string; email: string; role: string }>> {
  const res = await fetch(`${API_URL}/api/admin/users/${userId}/role`, {
    method: 'PUT',
    headers: authHeaders(),
    body: JSON.stringify({ role }),
  });
  return handleResponse(res);
}

export async function deleteUser(userId: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/admin/users/${userId}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Scan Schedules ---

export interface ScanSchedule {
  id: string;
  domain: string;
  package: string;
  scheduleType: 'weekly' | 'monthly' | 'quarterly' | 'once';
  scheduleLabel: string;
  scheduledAt: string | null;
  enabled: boolean;
  lastScanAt: string | null;
  nextScanAt: string;
  lastOrderId: string | null;
  createdAt: string;
}

export async function listSchedules(): Promise<ApiResponse<{ schedules: ScanSchedule[] }>> {
  const res = await fetch(`${API_URL}/api/schedules`, { headers: authHeaders() });
  return handleResponse(res);
}

export async function createSchedule(data: {
  domain: string; package: string; scheduleType: string; scheduledAt?: string;
}): Promise<ApiResponse<{ id: string }>> {
  const res = await fetch(`${API_URL}/api/schedules`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse(res);
}

export async function updateSchedule(id: string, data: Record<string, unknown>): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/schedules/${id}`, {
    method: 'PUT',
    headers: authHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse(res);
}

export async function deleteSchedule(id: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/schedules/${id}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export interface AdminStats {
  users: { total: number; admins: number };
  orders: { total: number; today: number; byStatus: Record<string, number> };
}

export async function getAdminStats(): Promise<ApiResponse<AdminStats>> {
  const res = await fetch(`${API_URL}/api/admin/stats`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export interface AiCostsData {
  total_cost_usd: number;
  cost_by_model: Record<string, {count: number; total_usd: number}>;
  cost_by_package: Record<string, {count: number; total_usd: number}>;
  recent_reports: Array<{orderId: string; domain: string; package: string; cost_usd: number; model: string; createdAt: string}>;
}

export async function getAiCosts(): Promise<ApiResponse<AiCostsData>> {
  const res = await fetch(`${API_URL}/api/admin/ai-costs`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Admin: Review Workflow ---

export interface PendingReview {
  id: string;
  domain: string;
  package: string;
  status: string;
  customerEmail: string;
  createdAt: string;
  scanFinishedAt: string;
  businessImpactScore: number | null;
  severityCounts: Record<string, number> | null;
}

export async function getPendingReviews(): Promise<ApiResponse<{ reviews: PendingReview[] }>> {
  const res = await fetch(`${API_URL}/api/admin/pending-reviews`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function approveOrder(orderId: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/admin/orders/${orderId}/approve`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function rejectOrder(orderId: string, reason: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/admin/orders/${orderId}/reject`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ reason }),
  });
  return handleResponse(res);
}

export async function manualVerify(orderId: string): Promise<ApiResponse<VerificationCheckResult>> {
  const res = await fetch(`${API_URL}/api/verify/manual`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ orderId }),
  });
  return handleResponse(res);
}

export interface ScanResult {
  id: string;
  hostIp: string | null;
  phase: number;
  toolName: string;
  rawOutput: string | null;
  exitCode: number;
  durationMs: number;
  createdAt: string;
}

export async function getScanResults(orderId: string): Promise<ApiResponse<{ results: ScanResult[] }>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/results`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Finding Exclusions ---

export async function excludeFinding(orderId: string, findingId: string, reason: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/findings/${findingId}/exclude`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ reason }),
  });
  return handleResponse(res);
}

export async function unexcludeFinding(orderId: string, findingId: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/findings/${findingId}/exclude`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function regenerateReport(orderId: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/regenerate-report`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Report Versions ---

export interface ReportVersion {
  version: number;
  createdAt: string;
  findingsCount: number;
  excludedCount: number;
  excludedFindings: string[];
  fileSizeBytes: number;
  isCurrent: boolean;
}

export interface ReportVersionsData {
  versions: ReportVersion[];
}

export async function getReportVersions(orderId: string): Promise<ApiResponse<ReportVersionsData>> {
  const res = await fetch(`${API_URL}/api/orders/${orderId}/report-versions`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

// --- Admin: Multi-Target Review ---

export type TargetDiscoveryPolicy = 'enumerate' | 'scoped' | 'ip_only';

export interface ReviewCustomer {
  email: string;
  companyName: string | null;
}

export interface ReviewQueueOrder {
  type: 'order';
  id: string;
  displayName: string;
  package: string;
  targetCount: number | null;
  liveHostsCount: number | null;
  pendingTargets: number;
  customer: ReviewCustomer;
  createdAt: string;
}

export interface ReviewQueueSubscription {
  type: 'subscription';
  id: string;
  package: string;
  scanInterval: string;
  pendingTargets: number;
  customer: ReviewCustomer;
  createdAt: string;
}

export interface ReviewQueue {
  orders: ReviewQueueOrder[];
  subscriptions: ReviewQueueSubscription[];
}

export async function getReviewQueue(): Promise<ApiResponse<ReviewQueue>> {
  const res = await fetch(`${API_URL}/api/admin/review/queue`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export interface ScanTargetHost {
  scan_target_id: string;
  ip: string;
  fqdns: string[] | null;
  is_live: boolean;
  ports_hint: number[] | null;
  http_status: number | null;
  http_title: string | null;
  http_final_url: string | null;
  reverse_dns: string | null;
  cloud_provider: string | null;
  parking_page: boolean | null;
  source: string;
}

export interface ScanTargetDetail {
  id: string;
  raw_input: string;
  canonical: string | null;
  target_type: string;
  discovery_policy: TargetDiscoveryPolicy | string;
  exclusions: string[] | null;
  status: string;
  review_notes: string | null;
  approved_by: string | null;
  approved_at: string | null;
  hosts: ScanTargetHost[];
}

export interface ScanAuthorization {
  id: string;
  document_type: string;
  minio_path: string;
  original_filename: string;
  file_size_bytes: number;
  uploaded_by: string | null;
  notes: string | null;
  valid_until: string | null;
  created_at: string;
}

export interface ReviewDetail {
  type: 'order' | 'subscription';
  id: string;
  targets: ScanTargetDetail[];
  authorizations: ScanAuthorization[];
}

export async function getReviewDetail(
  type: 'order' | 'subscription',
  id: string,
): Promise<ApiResponse<ReviewDetail>> {
  const res = await fetch(`${API_URL}/api/admin/review/${type}/${id}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export interface TargetUpdatePayload {
  discoveryPolicy?: TargetDiscoveryPolicy;
  exclusions?: string[];
}

export async function updateTarget(
  targetId: string,
  payload: TargetUpdatePayload,
): Promise<ApiResponse<{ id: string; discovery_policy: string; exclusions: string[] }>> {
  const res = await fetch(`${API_URL}/api/admin/targets/${targetId}`, {
    method: 'PUT',
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });
  return handleResponse(res);
}

export interface TargetApprovePayload extends TargetUpdatePayload {
  notes?: string;
}

export async function approveTarget(
  targetId: string,
  payload: TargetApprovePayload,
): Promise<ApiResponse<{ id: string; status: string }>> {
  const res = await fetch(`${API_URL}/api/admin/targets/${targetId}/approve`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(payload || {}),
  });
  return handleResponse(res);
}

export async function rejectTarget(
  targetId: string,
  reason: string,
): Promise<ApiResponse<{ id: string; status: string }>> {
  const res = await fetch(`${API_URL}/api/admin/targets/${targetId}/reject`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ reason }),
  });
  return handleResponse(res);
}

export async function restartPrecheck(
  targetId: string,
): Promise<ApiResponse<{ targetId: string; status: string }>> {
  const res = await fetch(`${API_URL}/api/admin/targets/${targetId}/restart-precheck`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export async function releaseOrder(
  orderId: string,
): Promise<ApiResponse<{ orderId: string; approvedCount: number }>> {
  const res = await fetch(`${API_URL}/api/admin/orders/${orderId}/release`, {
    method: 'POST',
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export interface AuthorizationUploadOptions {
  documentType: string;
  notes?: string;
  validUntil?: string;
}

export async function uploadAuthorization(
  type: 'order' | 'subscription',
  id: string,
  file: File,
  options: AuthorizationUploadOptions,
): Promise<ApiResponse<{ id: string; minio_path: string; filename: string }>> {
  const token = getToken();
  const form = new FormData();
  form.append('document_type', options.documentType);
  if (options.notes) form.append('notes', options.notes);
  if (options.validUntil) form.append('valid_until', options.validUntil);
  form.append('file', file, file.name);

  const path = type === 'order'
    ? `/api/admin/orders/${id}/authorizations`
    : `/api/admin/subscriptions/${id}/authorizations`;

  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers,
    body: form,
  });
  return handleResponse(res);
}

export async function deleteAuthorization(authId: string): Promise<ApiResponse<{ message: string }>> {
  const res = await fetch(`${API_URL}/api/admin/authorizations/${authId}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return handleResponse(res);
}
