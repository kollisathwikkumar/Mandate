# Mandate Console

The console is a React/Vite client for the API contract in `../backend/API_HANDOFF.md`.

## Local development

1. Start the local API and PostgreSQL stack from `../backend` with `docker compose up -d`.
2. Copy `.env.example` to `.env.local` and fill in the public OIDC authority and client ID for a local identity-provider client. Register `http://127.0.0.1:5173/login/callback` as its redirect URI and `http://127.0.0.1:5173/` as its post-logout redirect URI. Keep `.env.local` uncommitted; `VITE_*` settings are public client configuration, never secrets.
3. Run `npm install` and `npm run dev` from this directory.

The Vite development server proxies `/api` and `/health` to `http://127.0.0.1:3000` by default. Set `VITE_API_PROXY_TARGET` when running against a different local API instance. Protected routes require a valid human OIDC session accepted by the API. The website's `/login` is the sign-in entry point: its button redirects to the configured identity provider, then the provider returns to `/login/callback`; Mandate does not have a separate local username/password login. For local end-to-end checks, use a disposable identity-provider test account rather than a personal account. If no provider is configured, the sign-in page explains which public settings are missing; no fake login or token bypass is provided.

## Authenticated local verification gate

Configure the API separately in `../backend/.env.local` before testing signed-in flows:

- `MANDATE_JWT_ISSUER` must exactly match the token issuer (`iss`) and the OIDC discovery issuer used by `VITE_OIDC_AUTHORITY`.
- `MANDATE_JWT_JWKS_URL` must expose the provider's signing keys and be reachable from the API runtime.
- `MANDATE_JWT_AUDIENCE` must match an accepted audience (`aud`) on the provider's RS256 access token. The API requires `exp` and `sub` claims.
- Register the same redirect URI shown above for the OIDC client and enable authorization-code flow with PKCE.
- Register the post-logout redirect URI shown above with the provider as well; otherwise provider logout may reject the return to the website.

After configuring those values, verify browser sign-in, organization onboarding/membership selection, then the relevant page actions against the local API and PostgreSQL. A public-page or unauthenticated route smoke test does not count as verification of protected page data or mutations.

## Verification

- `npm run typecheck`
- `npm test -- --reporter=dot`
- `npm run test:models:coverage` (100% statement, branch, function, and line thresholds for overview metric/path models)
- `npm run build`
- `npm run verify:api-contract` (requires the local API on `127.0.0.1:3000`; checks UI-used path/method availability against the running OpenAPI document)

The frontend makes no AWS deployment or provisioning changes. Model-provider keys are submitted to the organization-scoped backend credential API; they are not stored in frontend configuration or local storage.

After completing website SSO in an isolated local Chrome session, the Playwright CLI can run `run-code --filename scripts/verify-overview-browser.js`. This audit verifies dashboard navigation, mobile layout/navigation, reduced motion, receipt loading/error recovery, and real-API restoration. It never injects authentication tokens. Its intentionally intercepted outage is a frontend resilience test, not evidence that the backend itself failed.
