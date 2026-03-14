const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export interface ScanData {
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

export interface ScanProgress {
  phase: string | null;
  currentTool: string | null;
  currentHost: string | null;
  hostsTotal: number;
  hostsCompleted: number;
  discoveredHosts: HostInfo[];
}

export interface ScanStatus {
  id: string;
  domain: string;
  status: string;
  package: string;
  estimatedDuration: string;
  progress: ScanProgress;
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

export async function createScan(domain: string, pkg: string = 'professional'): Promise<ApiResponse<ScanData>> {
  const res = await fetch(`${API_URL}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, package: pkg }),
  });
  return res.json();
}

export async function getScanStatus(id: string): Promise<ApiResponse<ScanStatus>> {
  const res = await fetch(`${API_URL}/api/scans/${id}`);
  return res.json();
}

export function getReportDownloadUrl(id: string): string {
  return `${API_URL}/api/scans/${id}/report`;
}

export async function getScanReport(id: string): Promise<ApiResponse<ReportData>> {
  const res = await fetch(`${API_URL}/api/scans/${id}/report`);
  return res.json();
}

export async function cancelScan(id: string): Promise<ApiResponse<null>> {
  const res = await fetch(`${API_URL}/api/scans/${id}`, { method: 'DELETE' });
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
