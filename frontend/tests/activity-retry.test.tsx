import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

vi.mock('../src/auth/AuthProvider', () => ({ useAuth: () => ({ accessToken: 'session', user: { access_token: 'session', profile: {} }, loading: false }) }));
vi.mock('../src/app/VisualStage', () => ({ VisualStage: () => null }));

import { App } from '../src/app/App';

let host: HTMLDivElement;
let root: Root;
let auditReads: number;
let receiptReads: number;

beforeEach(() => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} });
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  auditReads = 0;
  receiptReads = 0;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === '/api/v1/me') return new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'tenant', role: 'OWNER' }] }));
    if (path === '/health/ready') return new Response('{"status":"ready"}');
    if (path.endsWith('/audit-events?limit=100')) {
      auditReads += 1;
      if (auditReads === 1) return new Response('{"error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Audit read unavailable","requestId":"request-1"}}', { status: 503 });
      return new Response(JSON.stringify({ events: [{ sequence: '1', eventType: 'ACTION_BLOCKED', actorType: 'AGENT', actorId: 'agent-1', subjectType: 'ACTION', subjectId: 'denied-1', correlationId: 'request-1', payload: {}, previousHash: null, eventHash: 'hash-1', createdAt: '2026-10-08T00:00:00.000Z' }] }));
    }
    if (path.endsWith('/receipts?limit=100')) {
      receiptReads += 1;
      return new Response(JSON.stringify({ receipts: receiptReads === 1 ? [] : [{ id: 'receipt-1', actionId: 'allowed-1', chainId: 10143, transactionHash: `0x${'a'.repeat(64)}`, blockNumber: '10', blockHash: `0x${'b'.repeat(64)}`, status: 'FINAL', observedAt: '2026-10-08T00:00:10.000Z' }] }));
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

it('retries a failed activity read and shows the new authoritative audit event', async () => {
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/activity']}><App /></MemoryRouter>); });
  expect(host.textContent).toContain('Audit read unavailable');
  expect(host.textContent).not.toContain('No audit events');
  const retry = Array.from(host.querySelectorAll('button')).find((button) => button.textContent?.includes('Retry activity'));
  expect(retry).toBeDefined();
  await act(async () => { retry?.click(); });
  expect(auditReads).toBe(2);
  expect(receiptReads).toBe(2);
  expect(host.textContent).toContain('ACTION_BLOCKED');
  expect(host.textContent).toContain('denied-1');
  expect(host.textContent).toContain('allowed-1');
  expect(host.textContent).toContain('FINAL');
});

it('retries an action detail read and shows the reconciled state returned by the API', async () => {
  let detailReads = 0;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === '/api/v1/me') return new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'tenant', role: 'OWNER' }] }));
    if (path === '/health/ready') return new Response('{"status":"ready"}');
    if (path.endsWith('/actions/allowed-1')) {
      detailReads += 1;
      if (detailReads === 1) return new Response('{"error":{"code":"DEPENDENCY_UNAVAILABLE","message":"Action read unavailable","requestId":"request-2"}}', { status: 503 });
      return new Response(JSON.stringify({ actionId: 'allowed-1', policyId: 'policy-1', policyRevision: 1, actionHash: '0xabc', state: 'RECONCILED', verdict: 'ALLOW', reason: 'POLICY_PASS', action: {}, createdAt: '2026-10-08T00:00:00.000Z', updatedAt: '2026-10-08T00:00:10.000Z', reservation: null, events: [] }));
    }
    return new Response('Not found', { status: 404 });
  }));
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/activity/allowed-1']}><App /></MemoryRouter>); });
  expect(host.textContent).toContain('Action read unavailable');
  const retry = Array.from(host.querySelectorAll('button')).find((button) => button.textContent?.includes('Retry action'));
  expect(retry).toBeDefined();
  await act(async () => { retry?.click(); });
  expect(detailReads).toBe(2);
  expect(host.textContent).toContain('RECONCILED');
  expect(host.textContent).toContain('POLICY_PASS');
});
