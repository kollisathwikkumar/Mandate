import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

vi.mock('../src/auth/AuthProvider', () => ({ useAuth: () => ({ accessToken: 'session', user: { access_token: 'session', profile: {} }, loading: false }) }));
vi.mock('../src/app/VisualStage', () => ({ VisualStage: () => null }));

import { App } from '../src/app/App';

let host: HTMLDivElement;
let root: Root;
let approvalReads: number;
let failFirstRead: boolean;

beforeEach(() => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} });
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  approvalReads = 0;
  failFirstRead = false;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === '/api/v1/me') return new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'approver' }, organizations: [{ organizationId: 'tenant', role: 'APPROVER' }] }));
    if (path === '/health/ready') return new Response('{"status":"ready"}');
    if (path.endsWith('/actions?state=HELD&limit=100')) {
      approvalReads += 1;
      if (failFirstRead && approvalReads === 1) return new Response('{"error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Approval read unavailable","requestId":"request-1"}}', { status: 503 });
      return new Response(JSON.stringify({ actions: approvalReads === 1 ? [] : [{ actionId: 'held-1', policyId: 'policy-1', policyRevision: 1, actionHash: `0x${'a'.repeat(64)}`, state: 'HELD', verdict: 'REQUIRE_APPROVAL', reason: 'APPROVAL_REQUIRED', action: { agentId: 'agent-1', recipient: '0xrecipient', amount: '1000' }, createdAt: '2026-10-08T00:00:00.000Z', updatedAt: '2026-10-08T00:00:00.000Z' }] }));
    }
    return new Response('Not found', { status: 404 });
  }));
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it('refreshes an empty approvals list to show a newly held authoritative action', async () => {
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/approvals']}><App /></MemoryRouter>); });
  expect(host.textContent).toContain('No held actions');
  const refresh = Array.from(host.querySelectorAll('button')).find((button) => button.textContent?.includes('Refresh approvals'));
  expect(refresh).toBeDefined();
  await act(async () => { refresh?.click(); });
  expect(approvalReads).toBe(2);
  expect(host.textContent).toContain('held-1');
  expect(host.textContent).not.toContain('No held actions');
});

it('retries a failed approvals read without claiming there are no held actions', async () => {
  failFirstRead = true;
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/approvals']}><App /></MemoryRouter>); });
  expect(host.textContent).toContain('Approval read unavailable');
  expect(host.textContent).not.toContain('No held actions');
  const retry = Array.from(host.querySelectorAll('button')).find((button) => button.textContent?.includes('Retry approvals'));
  expect(retry).toBeDefined();
  await act(async () => { retry?.click(); });
  expect(approvalReads).toBe(2);
  expect(host.textContent).toContain('held-1');
});
