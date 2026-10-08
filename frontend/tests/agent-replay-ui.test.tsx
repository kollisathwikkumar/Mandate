import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

vi.mock('../src/auth/AuthProvider', () => ({ useAuth: () => ({ accessToken: 'session', user: { access_token: 'session', profile: {} }, loading: false }) }));
vi.mock('../src/app/VisualStage', () => ({ VisualStage: () => null }));
import { App } from '../src/app/App';

const host = document.createElement('div');
const root = createRoot(host);
afterEach(() => { act(() => root.unmount()); host.remove(); localStorage.clear(); sessionStorage.clear(); vi.unstubAllGlobals(); });

it('renders a secretless registration replay as an explicit recovery state', async () => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} });
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  document.body.append(host);
  localStorage.setItem('mandate.organizationId', 'tenant');
  let submittedKey: string | null = null;
  const agent = { id: 'agent-1', displayName: 'Treasury', status: 'ACTIVE', keyVersion: 1, createdAt: '2026-10-08T00:00:00.000Z' };
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const path = String(input);
    if (path === '/api/v1/me') return new Response(JSON.stringify({ principal: { type: 'HUMAN', subject: 'owner' }, organizations: [{ organizationId: 'tenant', role: 'OWNER' }] }));
    if (path === '/health/ready') return new Response('{"status":"ready"}');
    if (path === '/api/v1/orgs/tenant/agents' && options?.method === 'POST') {
      submittedKey = new Headers(options.headers).get('Idempotency-Key');
      return new Response(JSON.stringify({ agent, replayed: true }), { status: 200 });
    }
    if (path === '/api/v1/orgs/tenant/agents') return new Response(JSON.stringify({ agents: [] }));
    return new Response('{"error":{"code":"RESOURCE_NOT_FOUND","message":"Not found","requestId":"test"}}', { status: 404 });
  }));
  await act(async () => { root.render(<MemoryRouter initialEntries={['/app/agents']}><App /></MemoryRouter>); });
  await act(async () => { Array.from(host.querySelectorAll('button')).find((button) => button.textContent?.includes('Register agent'))?.click(); });
  const dialog = host.querySelector('[role="dialog"]');
  expect(dialog).not.toBeNull();
  const id = dialog?.querySelector<HTMLInputElement>('input[placeholder="treasury-agent"]');
  const name = dialog?.querySelector<HTMLInputElement>('input[placeholder="Treasury agent"]');
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  await act(async () => {
    setValue?.call(id, 'agent-1'); id?.dispatchEvent(new Event('input', { bubbles: true }));
    setValue?.call(name, 'Treasury'); name?.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => { dialog?.querySelector('form')?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
  expect(dialog?.textContent).toContain('one-time credential cannot be shown after a replay');
  expect(dialog?.textContent).not.toContain('Agent registration failed');
  expect(host.textContent).not.toContain('agent-secret');
  expect(submittedKey).toBeTruthy();
  expect(sessionStorage.getItem('mandate.agentRegistration/tenant/owner/agent-1')).toBeNull();
});
