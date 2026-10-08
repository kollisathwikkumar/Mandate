import { act, useState } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

const auth = vi.hoisted(() => ({ accessToken: 'test-session-token' }));
vi.mock('../src/auth/AuthProvider', () => ({ useAuth: () => ({ accessToken: auth.accessToken }) }));
const { useApi } = await import('../src/app/App');

const TenantResponse = z.object({ tenant: z.string() });
let host: HTMLDivElement;
let root: Root;
let resolveSecond: ((response: Response) => void) | undefined;

function TenantProbe() {
  const [path, setPath] = useState('/api/v1/orgs/tenant-a/agents');
  const result = useApi(path, TenantResponse);
  return <><button onClick={() => setPath('/api/v1/orgs/tenant-b/agents')}>Switch organization</button><output>{result.data?.tenant ?? (result.loading ? 'loading' : 'empty')}</output></>;
}

beforeEach(() => {
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  resolveSecond = undefined;
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    if (String(input).includes('tenant-a')) return Promise.resolve(new Response(JSON.stringify({ tenant: 'tenant A data' }), { status: 200 }));
    return new Promise<Response>((resolve) => { resolveSecond = resolve; });
  }));
});

afterEach(() => {
  act(() => root.unmount());
  host.remove();
  vi.unstubAllGlobals();
});

describe('tenant-scoped API state', () => {
  it('clears the previous organization payload while the newly scoped request loads', async () => {
    await act(async () => {
      root.render(<TenantProbe />);
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(host.querySelector('output')?.textContent).toBe('tenant A data');
    const switchButton = host.querySelector('button');
    expect(switchButton).not.toBeNull();
    act(() => switchButton?.click());
    expect(host.querySelector('output')?.textContent).toBe('loading');
    await act(async () => {
      resolveSecond?.(new Response(JSON.stringify({ tenant: 'tenant B data' }), { status: 200 }));
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(host.querySelector('output')?.textContent).toBe('tenant B data');
  });
});

it('ignores an old tenant response even when transport completes after cancellation', async () => {
  let resolveFirst: ((response: Response) => void) | undefined;
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    if (String(input).includes('tenant-a')) return new Promise<Response>((resolve) => { resolveFirst = resolve; });
    return Promise.resolve(new Response(JSON.stringify({ tenant: 'tenant B data' }), { status: 200 }));
  }));
  await act(async () => { root.render(<TenantProbe />); });
  await act(async () => { host.querySelector('button')?.click(); });
  expect(host.querySelector('output')?.textContent).toBe('tenant B data');
  await act(async () => { resolveFirst?.(new Response(JSON.stringify({ tenant: 'tenant A data' }), { status: 200 })); });
  expect(host.querySelector('output')?.textContent).toBe('tenant B data');
});
