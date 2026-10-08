import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { User } from 'oidc-client-ts';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const manager = vi.hoisted(() => ({
  getUser: vi.fn(), signinRedirectCallback: vi.fn(), signinRedirect: vi.fn(), signoutRedirect: vi.fn(),
  events: { addUserLoaded: vi.fn(), addUserUnloaded: vi.fn(), addAccessTokenExpired: vi.fn(), removeUserLoaded: vi.fn(), removeUserUnloaded: vi.fn(), removeAccessTokenExpired: vi.fn() },
}));
vi.mock('../src/auth/identity', () => ({ identityConfigured: true, identityManager: manager }));
import { AuthProvider, useAuth } from '../src/auth/AuthProvider';
let host: HTMLDivElement;
let root: Root;
function Probe() {
  const auth = useAuth();
  return <><output>{auth.accessToken ?? 'signed-out'}</output><p>{auth.error}</p><button onClick={() => void auth.signIn()}>Sign in</button><aside>{auth.returnTo}</aside></>;
}
beforeEach(() => {
  vi.clearAllMocks();
  window.history.replaceState({}, '', '/login?returnTo=%2Fapp%2Fpolicies%2Fp-1%2Fedit');
  manager.getUser.mockResolvedValue(new User({ access_token: 'token', token_type: 'Bearer', expires_at: Math.floor(Date.now() / 1000) + 300, profile: { sub: 'user', iss: 'https://id.test', aud: 'app', exp: 9999999999, iat: 1 } }));
  host = document.createElement('div'); document.body.append(host); root = createRoot(host);
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(() => { act(() => root.unmount()); host.remove(); });
it('removes the token immediately when the identity manager reports expiry', async () => {
  await act(async () => { root.render(<AuthProvider><Probe /></AuthProvider>); });
  expect(host.querySelector('output')?.textContent).toBe('token');
  const callback: (() => void) | undefined = manager.events.addAccessTokenExpired.mock.calls[0]?.[0];
  expect(callback).toBeTypeOf('function');
  act(() => callback?.());
  expect(host.querySelector('output')?.textContent).toBe('signed-out');
});
it('binds the validated deep link to OIDC state and renders redirect-start failures', async () => {
  manager.signinRedirect.mockRejectedValue(new Error('provider internal detail'));
  await act(async () => { root.render(<AuthProvider><Probe /></AuthProvider>); });
  await act(async () => { host.querySelector('button')?.click(); });
  expect(manager.signinRedirect).toHaveBeenCalledWith({ state: { returnTo: '/app/policies/p-1/edit' } });
  expect(host.querySelector('p')?.textContent).toBe('Sign-in could not start. Please try again.');
});
it('restores the validated destination from the completed OIDC callback', async () => {
  window.history.replaceState({}, '', '/login/callback?code=test&state=test');
  manager.signinRedirectCallback.mockResolvedValue(new User({ access_token: 'callback-token', token_type: 'Bearer', userState: { returnTo: '/app/activity/action-1' }, profile: { sub: 'user', iss: 'https://id.test', aud: 'app', exp: 9999999999, iat: 1 } }));
  await act(async () => { root.render(<AuthProvider><Probe /></AuthProvider>); });
  expect(host.querySelector('aside')?.textContent).toBe('/app/activity/action-1');
  expect(host.querySelector('output')?.textContent).toBe('callback-token');
});
