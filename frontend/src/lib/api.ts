import { getToken, clearToken, AuthResponse } from './auth';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export interface OrderData {
  id: string;
  domain: string;
  status: string;
  package: string;
  createdAt: string;
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

export async function register(email: string, password: string): Promise<ApiResponse<AuthResponse>> {
  const res = await fetch(`${API_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return res.json();
}

// --- Orders ---

export async function createOrder(domain: string, pkg: string = 'professional'): Promise<ApiResponse<OrderData>> {
  const res = await fetch(`${API_URL}/api/orders`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ domain, package: pkg }),
  });
  return handleResponse(res);
}

export async function getOrderStatus(id: string): Promise<ApiResponse<OrderStatus>> {
  const res = await fetch(`${API_URL}/api/orders/${id}`, {
    headers: authHeaders(),
  });
  return handleResponse(res);
}

export function getReportDownloadUrl(id: string): string {
  const token = getToken();
  return `${API_URL}/api/orders/${id}/report${token ? `?token=${token}` : ''}`;
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
}

export async function listOrders(): Promise<ApiResponse<{ orders: OrderListItem[] }>> {
  const res = await fetch(`${API_URL}/api/orders`, {
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
