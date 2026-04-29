import type { LogListResult, RequestLog, DashboardData, AccountData, ModelMapping, BootstrapResponse } from '../types';

function getToken(): string {
  return localStorage.getItem('admin_token') || '';
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['X-Admin-Token'] = token;

  const res = await fetch(path, { ...init, headers: { ...headers, ...init?.headers } });
  if (res.status === 401) throw new Error('unauthorized');
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: { message: res.statusText } }));
    throw new Error(err.error?.message || `HTTP ${res.status}`);
  }
  return res.json();
}

// Dashboard
export const getDashboard = (range: string) =>
  request<DashboardData>(`/admin/dashboard?range=${range}`);

// Logs
export const getLogs = (params: Record<string, string>) => {
  const qs = new URLSearchParams(params).toString();
  return request<LogListResult>(`/admin/logs?${qs}`);
};
export const getLog = (id: string) => request<RequestLog>(`/admin/logs/${id}`);
export const replayLog = (id: string, body?: unknown) =>
  request<RequestLog>(`/admin/logs/${id}/replay`, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
export const cleanupLogs = () => request<{ deleted: number }>('/admin/logs/cleanup', { method: 'POST' });

// Account
export const getAccount = () => request<AccountData>('/admin/account');
export const refreshAccount = () => request<{ credential: unknown }>('/admin/account/refresh', { method: 'POST' });
export const startBootstrap = () => request<BootstrapResponse>('/admin/account/bootstrap', { method: 'POST' });
export const getBootstrapStatus = (id: string) => request<BootstrapResponse>(`/admin/account/bootstrap/status?id=${encodeURIComponent(id)}`);

// Mappings
export const getMappings = () => request<ModelMapping[]>('/admin/mappings');
export const createMapping = (m: Partial<ModelMapping>) =>
  request<ModelMapping>('/admin/mappings', { method: 'POST', body: JSON.stringify(m) });
export const updateMapping = (id: number, m: Partial<ModelMapping>) =>
  request<ModelMapping>(`/admin/mappings/${id}`, { method: 'PUT', body: JSON.stringify(m) });
export const deleteMapping = (id: number) =>
  request<{ status: string }>(`/admin/mappings/${id}`, { method: 'DELETE' });
export const testMapping = (model: string) =>
  request<{ matched: boolean; rule_name?: string; rule_id?: number; target: string; input_model: string }>(
    '/admin/mappings/test', { method: 'POST', body: JSON.stringify({ model }) }
  );

// Settings
export const getSettings = () => request<Record<string, string>>('/admin/settings');
export const updateSettings = (s: Record<string, string>) =>
  request<{ status: string }>('/admin/settings', { method: 'PUT', body: JSON.stringify(s) });

// Validation
export const validateToken = async (): Promise<boolean> => {
  try {
    await request('/admin/status');
    return true;
  } catch {
    return false;
  }
};
