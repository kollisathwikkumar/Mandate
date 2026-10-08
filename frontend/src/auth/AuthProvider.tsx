import { createContext, useCallback, useContext, useEffect, useMemo, useState, type PropsWithChildren } from 'react';
import { z } from 'zod';
import { safeReturnTo } from './returnTo';
import type { User } from 'oidc-client-ts';
import { identityConfigured, identityManager } from './identity';
import { createAsyncOnce } from './asyncOnce';

interface AuthValue {
  readonly configured: boolean;
  readonly user: User | null;
  readonly loading: boolean;
  readonly signIn: () => Promise<void>;
  readonly signOut: () => Promise<void>;
  readonly accessToken: string | null;
  readonly returnTo: string;
  readonly error: string | null;
}
const AuthContext = createContext<AuthValue | null>(null);
const processRedirectCallbackOnce = createAsyncOnce<User>();

export function AuthProvider({ children }: PropsWithChildren) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [returnTo, setReturnTo] = useState('/app/overview');
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const manager = identityManager;
    if (manager === null) { setLoading(false); return; }
    let alive = true;
    const callback = window.location.pathname === '/login/callback';
    const load = callback ? processRedirectCallbackOnce(() => manager.signinRedirectCallback()).then((signedIn) => {
      const state = z.object({ returnTo: z.string() }).safeParse(signedIn.state);
      if (alive) setReturnTo(safeReturnTo(state.success ? state.data.returnTo : undefined));
      return signedIn;
    }) : manager.getUser();
    void load.then((current) => { if (alive) setUser(current?.expired ? null : current); }).catch(() => { if (alive) { setUser(null); setError('Sign-in did not complete. Please try again.'); } }).finally(() => { if (alive) setLoading(false); });
    const onLoaded = (next: User) => { setUser(next.expired ? null : next); setError(null); };
    const onUnloaded = () => setUser(null);
    manager.events.addUserLoaded(onLoaded);
    manager.events.addUserUnloaded(onUnloaded);
    manager.events.addAccessTokenExpired(onUnloaded);
    return () => { alive = false; manager.events.removeUserLoaded(onLoaded); manager.events.removeUserUnloaded(onUnloaded); manager.events.removeAccessTokenExpired(onUnloaded); };
  }, []);
  const signIn = useCallback(async () => {
    setError(null);
    const target = safeReturnTo(new URLSearchParams(window.location.search).get('returnTo'));
    try { if (identityManager !== null) await identityManager.signinRedirect({ state: { returnTo: target } }); }
    catch { setError('Sign-in could not start. Please try again.'); }
  }, []);
  const signOut = useCallback(async () => {
    try { if (identityManager !== null) await identityManager.signoutRedirect(); }
    catch { setError('Sign-out did not complete. Please try again.'); }
  }, []);
  const value = useMemo<AuthValue>(() => ({ configured: identityConfigured, user, loading, signIn, signOut, accessToken: user?.access_token ?? null, returnTo, error }), [user, loading, signIn, signOut, returnTo, error]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (value === null) throw new Error('useAuth must be inside AuthProvider');
  return value;
}
