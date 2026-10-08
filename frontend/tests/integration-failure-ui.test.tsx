import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
vi.mock('../src/auth/AuthProvider', () => ({ useAuth: () => ({ accessToken: 'session', user: { access_token: 'session', profile: {} }, loading: false }) }));
vi.mock('../src/app/VisualStage', () => ({ VisualStage: () => null }));
import { App } from '../src/app/App';
let host: HTMLDivElement;
let root: Root;
beforeEach(() => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} });
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement('div'); document.body.append(host); root = createRoot(host);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path === '/api/v1/me') return new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'viewer' }, organizations: [{ organizationId: 'tenant', role: 'VIEWER' }] }));
    if (path === '/health/ready') return new Response('{"status":"ready"}');
    return new Response('{"error":{"code":"FORBIDDEN","message":"Organization administrator access required","requestId":"request-1"}}', { status: 403 });
  }));
});
afterEach(() => { act(() => root.unmount()); host.remove(); localStorage.clear(); vi.unstubAllGlobals(); });
it('shows integration authorization failure rather than a fabricated empty result', async () => {
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/settings/integrations']}><App /></MemoryRouter>); });
  expect(host.textContent).toContain('Organization administrator access required');
  expect(host.textContent).not.toContain('No webhooks');
});
it('does not claim there are no held actions when the API read failed', async () => {
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/approvals']}><App /></MemoryRouter>); });
  expect(host.textContent).toContain('Organization administrator access required');
  expect(host.textContent).not.toContain('No held actions');
});
