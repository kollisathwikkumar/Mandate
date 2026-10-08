import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ApiFailure, request } from '../src/api/client';

afterEach(() => vi.unstubAllGlobals());

describe('same-origin API client', () => {
  it('attaches the scoped bearer token and a fresh idempotency key to writes', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ id: 'agent-1' }), { status: 201, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const response = await request('/api/v1/orgs/org-1/agents', z.object({ id: z.string() }), {
      token: 'session-token', method: 'POST', body: { id: 'agent-1' }, idempotency: true,
    });
    const init = fetchMock.mock.calls[0]?.[1];
    const headers = new Headers(init?.headers);
    expect(response).toEqual({ id: 'agent-1' });
    expect(headers.get('Authorization')).toBe('Bearer session-token');
    expect(headers.get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/);
    expect(headers.get('Content-Type')).toBe('application/json');
  });

  it('does not parse a body for the API’s 204 response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 204 })));
    await expect(request('/api/v1/resource', z.object({}), { token: 'session-token', method: 'DELETE' })).resolves.toEqual({});
  });

  it('preserves typed backend error code and request id', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'FORBIDDEN', message: 'Role required', requestId: 'req-42' } }), { status: 403 })));
    await expect(request('/api/v1/resource', z.object({ id: z.string() }), { token: 'session-token' })).rejects.toMatchObject<ApiFailure>({
      name: 'ApiFailure', status: 403, code: 'FORBIDDEN', requestId: 'req-42', message: 'Role required',
    });
  });
});
