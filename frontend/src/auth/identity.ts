import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const authority = import.meta.env.VITE_OIDC_AUTHORITY?.trim() ?? '';
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID?.trim() ?? '';
export const identityConfigured = authority.length > 0 && clientId.length > 0;

export const identityManager = identityConfigured ? new UserManager({
  authority,
  client_id: clientId,
  redirect_uri: `${window.location.origin}/login/callback`,
  post_logout_redirect_uri: `${window.location.origin}/`,
  response_type: 'code',
  scope: import.meta.env.VITE_OIDC_SCOPE?.trim() || 'openid profile email',
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  automaticSilentRenew: true,
  loadUserInfo: false,
}) : null;
