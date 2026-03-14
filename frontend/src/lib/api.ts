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

export async function createOrder(email: string, domain: string, pkg: string = 'professional'): Promise<ApiResponse<OrderData>> {
  const res = await fetch(`${API_URL}/api/orders`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, domain, package: pkg }),
  });
  return res.json();
}

export async function getOrderStatus(id: string): Promise<ApiResponse<OrderStatus>> {
  const res = await fetch(`${API_URL}/api/orders/${id}`);
  return res.json();
}

export function getReportDownloadUrl(id: string): string {
  return `${API_URL}/api/orders/${id}/report`;
}

export async function getOrderReport(id: string): Promise<ApiResponse<ReportData>> {
  const res = await fetch(`${API_URL}/api/orders/${id}/report`);
  return res.json();
}

export async function cancelOrder(id: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/orders/${id}`, { method: 'DELETE' });
  return res.json();
}

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
  const res = await fetch(`${API_URL}/api/verify/status/${orderId}`);
  return res.json();
}

export async function checkVerification(orderId: string): Promise<ApiResponse<VerificationCheckResult>> {
  const res = await fetch(`${API_URL}/api/verify/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ orderId }),
  });
  return res.json();
}

export async function verifyPassword(password: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  return res.json();
}
