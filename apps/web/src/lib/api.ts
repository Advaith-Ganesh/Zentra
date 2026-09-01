/**
 * The single typed API client.
 *
 * Every network call in the application goes through `request()`. Components
 * never call `fetch` directly, so authentication, error shaping, timeouts and
 * retries live in exactly one place.
 */

import type {
  Alert,
  ApiErrorBody,
  ApiKey,
  AuthResponse,
  Benchmark,
  Billing,
  Dashboard,
  Finding,
  FindingHistoryEntry,
  FindingStatus,
  Me,
  Member,
  Organization,
  PublicScanResult,
  Report,
  ScanDetail,
  Scan,
  Vendor,
  VendorList,
  VendorScore,
} from './types';

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

const TOKEN_KEY = 'zentra.access_token';
const ORG_KEY = 'zentra.organization_id';
const DEFAULT_TIMEOUT_MS = 20_000;

/** A structured API failure. Always carries the code the backend returned. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;
  readonly requestId?: string;

  constructor(
    status: number,
    code: string,
    message: string,
    details?: Record<string, unknown>,
    requestId?: string,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }

  get isAuthError(): boolean {
    return this.status === 401;
  }

  get isEntitlementError(): boolean {
    return this.status === 402;
  }

  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

// --------------------------------------------------------------------- session
export const session = {
  getToken(): string | null {
    if (typeof window === 'undefined') return null;
    try {
      return window.localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  setToken(token: string): void {
    try {
      window.localStorage.setItem(TOKEN_KEY, token);
    } catch {
      /* storage unavailable (private mode); the session lives in memory only */
    }
  },
  getOrganizationId(): string | null {
    if (typeof window === 'undefined') return null;
    try {
      return window.localStorage.getItem(ORG_KEY);
    } catch {
      return null;
    }
  },
  setOrganizationId(id: string): void {
    try {
      window.localStorage.setItem(ORG_KEY, id);
    } catch {
      /* ignore */
    }
  },
  clear(): void {
    try {
      window.localStorage.removeItem(TOKEN_KEY);
      window.localStorage.removeItem(ORG_KEY);
    } catch {
      /* ignore */
    }
  },
};

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  /** Omit the Authorization header (public endpoints). */
  anonymous?: boolean;
  timeoutMs?: number;
  /** Retry idempotent GETs on a transient network/5xx failure. */
  retries?: number;
  signal?: AbortSignal;
  raw?: boolean;
}

async function parseError(response: Response): Promise<ApiError> {
  let code = `HTTP_${response.status}`;
  let message = 'The request could not be completed.';
  let details: Record<string, unknown> | undefined;
  let requestId: string | undefined = response.headers.get('x-request-id') ?? undefined;
  try {
    const body = (await response.json()) as ApiErrorBody;
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      details = body.error.details;
      requestId = body.error.request_id ?? requestId;
    }
  } catch {
    /* a non-JSON error body (proxy error page); keep the defaults */
  }
  return new ApiError(response.status, code, message, details, requestId);
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const {
    method = 'GET',
    body,
    anonymous = false,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = method === 'GET' ? 1 : 0,
    signal,
  } = options;

  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (!anonymous) {
    const token = session.getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const organizationId = session.getOrganizationId();
    if (organizationId) headers['X-Zentra-Organization'] = organizationId;
  }

  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const onAbort = () => controller.abort();
    signal?.addEventListener('abort', onAbort);

    try {
      const response = await fetch(`${API_URL}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        credentials: 'omit',
        mode: 'cors',
      });

      if (response.ok) {
        if (options.raw) return response as unknown as T;
        if (response.status === 204) return undefined as T;
        const text = await response.text();
        return (text ? JSON.parse(text) : undefined) as T;
      }

      const error = await parseError(response);
      // Only retry transient server-side conditions on a safe method.
      if (response.status >= 500 && attempt < retries) {
        lastError = error;
        continue;
      }
      throw error;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      lastError = error;
      if (attempt >= retries) {
        if ((error as Error)?.name === 'AbortError') {
          throw new ApiError(
            408,
            'REQUEST_TIMEOUT',
            'The request timed out. Please check your connection and try again.',
          );
        }
        throw new ApiError(
          0,
          'NETWORK_ERROR',
          'Zentra could not reach the API. Please check your connection and try again.',
        );
      }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }
  throw lastError instanceof ApiError
    ? lastError
    : new ApiError(0, 'NETWORK_ERROR', 'The request failed.');
}

// ------------------------------------------------------------------ endpoints
export const api = {
  auth: {
    signUp: (input: {
      email: string;
      password: string;
      full_name?: string;
      organization_name: string;
      industry?: string;
      company_size?: string;
    }) =>
      request<AuthResponse>('/api/v1/auth/signup', {
        method: 'POST',
        body: input,
        anonymous: true,
      }),
    signIn: (input: { email: string; password: string }) =>
      request<AuthResponse>('/api/v1/auth/signin', {
        method: 'POST',
        body: input,
        anonymous: true,
      }),
    signOut: () => request<void>('/api/v1/auth/signout', { method: 'POST' }),
    requestPasswordReset: (email: string) =>
      request<{ message: string }>('/api/v1/auth/password-reset', {
        method: 'POST',
        body: { email },
        anonymous: true,
      }),
    acceptInvite: (token: string) =>
      request<{ organization_id: string; role: string; message: string }>(
        '/api/v1/auth/accept-invite',
        { method: 'POST', body: { token } },
      ),
  },

  me: () => request<Me>('/api/v1/me'),
  dashboard: () => request<Dashboard>('/api/v1/dashboard'),

  organization: {
    get: () => request<Organization>('/api/v1/organization'),
    update: (input: Record<string, unknown>) =>
      request<Organization>('/api/v1/organization', { method: 'PATCH', body: input }),
    members: () => request<Member[]>('/api/v1/organization/members'),
    invite: (input: { email: string; role: string }) =>
      request<{ invitation_id: string; message: string }>(
        '/api/v1/organization/members/invite',
        { method: 'POST', body: input },
      ),
    removeMember: (memberId: string) =>
      request<void>(`/api/v1/organization/members/${memberId}`, { method: 'DELETE' }),
  },

  vendors: {
    list: (params: Record<string, string | number | string[] | undefined> = {}) => {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === '') continue;
        if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
        else search.set(key, String(value));
      }
      const query = search.toString();
      return request<VendorList>(`/api/v1/vendors${query ? `?${query}` : ''}`);
    },
    get: (id: string) => request<Vendor>(`/api/v1/vendors/${id}`),
    create: (input: {
      name: string;
      domain: string;
      description?: string;
      category?: string;
      criticality?: string;
      owner_label?: string;
    }) => request<Vendor>('/api/v1/vendors', { method: 'POST', body: input }),
    update: (id: string, input: Record<string, unknown>) =>
      request<Vendor>(`/api/v1/vendors/${id}`, { method: 'PATCH', body: input }),
    archive: (id: string) =>
      request<Vendor>(`/api/v1/vendors/${id}/archive`, { method: 'POST' }),
    remove: (id: string) => request<void>(`/api/v1/vendors/${id}`, { method: 'DELETE' }),
    score: (id: string) => request<VendorScore>(`/api/v1/vendors/${id}/score`),
    scans: (id: string) => request<Scan[]>(`/api/v1/vendors/${id}/scans`),
    findings: (id: string) => request<Finding[]>(`/api/v1/vendors/${id}/findings`),
    scan: (id: string) =>
      request<Scan>(`/api/v1/vendors/${id}/scan`, { method: 'POST', body: {} }),
  },

  scans: {
    get: (id: string) => request<ScanDetail>(`/api/v1/scans/${id}`),
  },

  findings: {
    list: (params: { status?: string[]; severity?: string[] } = {}) => {
      const search = new URLSearchParams();
      params.status?.forEach((s) => search.append('status', s));
      params.severity?.forEach((s) => search.append('severity', s));
      const query = search.toString();
      return request<Finding[]>(`/api/v1/findings${query ? `?${query}` : ''}`);
    },
    update: (
      id: string,
      input: { status?: FindingStatus; note?: string; assigned_to?: string; unassign?: boolean },
    ) => request<Finding>(`/api/v1/findings/${id}`, { method: 'PATCH', body: input }),
    history: (id: string) =>
      request<FindingHistoryEntry[]>(`/api/v1/findings/${id}/history`),
  },

  alerts: {
    list: (limit = 50) => request<Alert[]>(`/api/v1/alerts?limit=${limit}`),
    acknowledge: (id: string) =>
      request<Alert>(`/api/v1/alerts/${id}/acknowledge`, { method: 'POST' }),
  },

  reports: {
    list: () => request<Report[]>('/api/v1/reports'),
    create: (input: { title?: string; vendor_ids?: string[]; kind?: string } = {}) =>
      request<Report>('/api/v1/reports', { method: 'POST', body: input }),
    get: (id: string) => request<Report>(`/api/v1/reports/${id}`),
    downloadUrl: (id: string) => `${API_URL}/api/v1/reports/${id}/download`,
    /** Fetches the PDF with the session token attached and returns a blob URL. */
    async download(id: string): Promise<Blob> {
      const token = session.getToken();
      const organizationId = session.getOrganizationId();
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      if (organizationId) headers['X-Zentra-Organization'] = organizationId;
      const response = await fetch(`${API_URL}/api/v1/reports/${id}/download`, { headers });
      if (!response.ok) throw await parseError(response);
      return response.blob();
    },
  },

  billing: {
    get: () => request<Billing>('/api/v1/billing'),
    checkout: (input: { plan?: string; product?: string }) =>
      request<{ checkout_url: string; session_id: string }>('/api/v1/billing/checkout', {
        method: 'POST',
        body: input,
      }),
    portal: () =>
      request<{ portal_url: string }>('/api/v1/billing/portal', { method: 'POST' }),
  },

  apiKeys: {
    list: () => request<ApiKey[]>('/api/v1/api-keys'),
    create: (input: { name: string; scopes?: string[]; expires_in_days?: number }) =>
      request<{ api_key: ApiKey; secret: string }>('/api/v1/api-keys', {
        method: 'POST',
        body: input,
      }),
    revoke: (id: string) => request<ApiKey>(`/api/v1/api-keys/${id}`, { method: 'DELETE' }),
  },

  integrations: {
    list: () =>
      request<{ id: string; provider: string; display_name: string | null; status: string }[]>(
        '/api/v1/integrations',
      ),
    connectTeams: (webhookUrl: string) =>
      request('/api/v1/integrations/teams', {
        method: 'POST',
        body: { webhook_url: webhookUrl },
      }),
    disconnectTeams: () =>
      request<void>('/api/v1/integrations/teams', { method: 'DELETE' }),
  },

  benchmark: () => request<Benchmark>('/api/v1/benchmark'),

  publicScan: (domain: string) =>
    request<PublicScanResult>('/api/v1/public/scan', {
      method: 'POST',
      body: { domain },
      anonymous: true,
      // A free scan runs several live checks; give it room.
      timeoutMs: 95_000,
      retries: 0,
    }),
};
