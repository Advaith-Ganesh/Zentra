import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, request, session } from '@/lib/api';

function mockFetch(response: Partial<Response> & { jsonBody?: unknown }) {
  const body = JSON.stringify(response.jsonBody ?? {});
  return vi.fn().mockResolvedValue({
    ok: response.ok ?? true,
    status: response.status ?? 200,
    headers: new Headers(response.headers ?? {}),
    text: async () => body,
    json: async () => JSON.parse(body),
  } as unknown as Response);
}

afterEach(() => {
  vi.unstubAllGlobals();
  session.clear();
});

describe('session storage', () => {
  it('stores and clears the access token', () => {
    session.setToken('token-123');
    expect(session.getToken()).toBe('token-123');
    session.clear();
    expect(session.getToken()).toBeNull();
  });

  it('survives storage being unavailable', () => {
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('denied');
    });
    expect(() => session.getToken()).not.toThrow();
    expect(session.getToken()).toBeNull();
    spy.mockRestore();
  });
});

describe('request', () => {
  it('attaches the bearer token and organization header', async () => {
    session.setToken('token-abc');
    session.setOrganizationId('org-1');
    const fetchMock = mockFetch({ jsonBody: { ok: true } });
    vi.stubGlobal('fetch', fetchMock);

    await request('/api/v1/me');

    const [, init] = fetchMock.mock.calls[0]!;
    expect(init.headers.Authorization).toBe('Bearer token-abc');
    expect(init.headers['X-Zentra-Organization']).toBe('org-1');
  });

  it('omits credentials on anonymous requests', async () => {
    session.setToken('token-abc');
    const fetchMock = mockFetch({ jsonBody: {} });
    vi.stubGlobal('fetch', fetchMock);

    await request('/api/v1/public/scan', { method: 'POST', body: {}, anonymous: true });

    const [, init] = fetchMock.mock.calls[0]!;
    expect(init.headers.Authorization).toBeUndefined();
  });

  it('turns an error envelope into a typed ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ok: false,
        status: 404,
        jsonBody: {
          error: { code: 'VENDOR_NOT_FOUND', message: 'Vendor could not be found.', request_id: 'r1' },
        },
      }),
    );

    await expect(request('/api/v1/vendors/x')).rejects.toMatchObject({
      status: 404,
      code: 'VENDOR_NOT_FOUND',
      message: 'Vendor could not be found.',
      requestId: 'r1',
    });
  });

  it('classifies auth, entitlement and rate-limit errors', () => {
    expect(new ApiError(401, 'X', 'x').isAuthError).toBe(true);
    expect(new ApiError(402, 'X', 'x').isEntitlementError).toBe(true);
    expect(new ApiError(429, 'X', 'x').isRateLimited).toBe(true);
    expect(new ApiError(500, 'X', 'x').isAuthError).toBe(false);
  });

  it('reports a network failure as a friendly error rather than throwing raw', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(request('/api/v1/me', { retries: 0 })).rejects.toMatchObject({
      code: 'NETWORK_ERROR',
    });
  });

  it('retries a GET once on a 5xx, then surfaces the error', async () => {
    const fetchMock = mockFetch({
      ok: false,
      status: 503,
      jsonBody: { error: { code: 'SERVICE_UNAVAILABLE', message: 'down' } },
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(request('/api/v1/me')).rejects.toMatchObject({ status: 503 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry a mutation', async () => {
    const fetchMock = mockFetch({
      ok: false,
      status: 500,
      jsonBody: { error: { code: 'INTERNAL_ERROR', message: 'boom' } },
    });
    vi.stubGlobal('fetch', fetchMock);
    await expect(request('/api/v1/vendors', { method: 'POST', body: {} })).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('handles a 204 with no body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 204,
        headers: new Headers(),
        text: async () => '',
      } as unknown as Response),
    );
    await expect(request('/api/v1/vendors/x', { method: 'DELETE' })).resolves.toBeUndefined();
  });
});

describe('endpoint helpers', () => {
  it('builds vendor list query strings without empty values', async () => {
    const fetchMock = mockFetch({ jsonBody: { items: [], total: 0, limit: 50, offset: 0 } });
    vi.stubGlobal('fetch', fetchMock);

    await api.vendors.list({ search: 'stripe', status: 'active', risk_level: ['high'], sort: undefined });

    const [url] = fetchMock.mock.calls[0]!;
    expect(url).toContain('search=stripe');
    expect(url).toContain('status=active');
    expect(url).toContain('risk_level=high');
    expect(url).not.toContain('sort=');
  });
});
