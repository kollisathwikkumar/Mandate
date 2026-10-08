# Frontend security review

**Scope:** OIDC browser session handling, tenant-scoped API requests, provider credentials, agent credentials, invitation tokens, account verification, and webhook management in this local frontend implementation.

## Findings

| Area | Status | Evidence / boundary |
|---|---|---|
| Authentication | PASS (client flow) | OIDC authorization-code flow with PKCE; session state stored in `sessionStorage`; protected routes redirect to sign-in. The public sign-in page collects no credentials and explicitly identifies any following password prompt as belonging to the configured identity provider. API remains responsible for validating bearer tokens. |
| Authorization / tenant isolation | PASS (client sends explicit scope) | Organization ID is explicit in organization routes. Scoped payloads are cleared while a request for a newly selected organization is loading; a regression test covers the transition. The backend is authoritative for membership and role enforcement; hiding a UI control is not an authorization boundary. |
| One-time secrets | PASS | Agent tokens, invitation tokens, and webhook signing secrets are held in component memory and shown in an explicit one-time dialog. They are not written to local/session storage or logs. Copying requires a user click; closing the dialog clears component state. |
| Model-provider keys | PASS (client handling) | Password input is cleared after successful submission; request goes to the same-origin organization-scoped backend endpoint. Backend secret adapter owns encryption/storage and provider authorization. |
| Input / output handling | PASS | API response payloads are parsed with Zod contracts; user-visible text is rendered by React rather than inserted as HTML. IDs, email, event types, and account addresses have client-side constraints plus server validation. |
| Webhook destination | PASS (client + backend validation observed locally) | The UI requires HTTPS; an authenticated `https://localhost` form submission was rejected by the backend validator and created no endpoint. Backend URL and DNS checks remain authoritative for unsafe destinations. |
| State-changing requests | PASS (client path) | Organization/agent/account/policy/invitation/webhook writes include fresh idempotency keys where required by the API contract. Approval actions use the exact action identifier/hash and backend decision endpoint. |
| Policy activation / revocation | PASS (flow separation) | The UI prepares a Safe owner-signature plan, displays the exact backend plan, and never signs or broadcasts. Finalization accepts transaction hashes only after external owner execution; the API independently validates receipts and chain finality before updating policy/grant state. |
| Credential lifecycle | PASS (REST API/PostgreSQL suite; browser mutation journey partial) | The full 24-test API/PostgreSQL integration suite covers provider write, replace, stubbed connectivity test, disable, delete, and empty-list behavior using fake secret storage; it makes no AWS or real provider call. The browser's positive key-save flow and real provider connectivity remain untested. Webhooks support pause/enable, deliveries, rotation, cleanup retry, and confirmed deletion; retries preserve the original idempotency key when backend cleanup is pending, but delivery is not exercised end to end here. |
| Dependency audit | PASS | `npm audit --omit=dev` reported zero vulnerabilities at review time. |
| Security headers / production hosting | OPEN | Final CSP, HSTS, framing, caching, and origin policy depend on the eventual production hosting configuration; this local Vite review does not qualify those controls. |
| Authenticated browser journey | PASS (local OIDC pages; mutation coverage partial) | A local Keycloak authorization-code + PKCE session loaded all 14 protected route templates against the local API/PostgreSQL; policy draft/revision and read-only preflight were exercised in the local backend flow. Safe mutation coverage for every control remains ongoing. No test-only auth bypass was added. |

## OWASP-focused review

- **A01 Broken access control:** client route guard is UX-only; API role and tenant checks remain authoritative.
- **A02 Cryptographic failures / sensitive data exposure:** no secret persistence in browser storage; OIDC tokens use session storage. TLS and backend secret-store configuration remain deployment gates.
- **A03 Injection:** React escaping is used; no `innerHTML` sink was added. API payloads are schema parsed.
- **A04 Insecure design:** preflight is represented as read-only, distinct from execution-boundary enforcement.
- **A04 Insecure design:** policy activation/revocation is a two-stage owner-signature workflow. The browser does not treat a prepared plan or pasted hash as authorization; backend finality verification is required.
- **A05 Security misconfiguration:** production headers and allowed origins remain host/deployment verification items.
- **A06 Vulnerable components:** production dependency audit passed with zero findings.
- **A07 Authentication failures:** a local Keycloak authorization-code + PKCE sign-in/callback completed and protected routes loaded successfully. Third-party identity-provider configuration and deployment callback/origin settings remain deployment gates.
- **A08 Software/data integrity:** Zod validates responses and mutation results; idempotency is supplied on relevant writes.
- **A09 Logging/monitoring:** frontend avoids logging credential payloads; backend audit and operational alerting remain authoritative.
- **A10 SSRF:** client-side HTTPS parsing is only an early check; backend webhook URL/destination validation is the security boundary.

**Review status:** client-side controls reviewed; local authenticated route coverage is established, while some mutation journeys remain open. Production hosting and live-chain qualification remain separate gates.

See [`VERIFICATION.md`](./VERIFICATION.md) for the latest route, responsive, API-readiness, and local build evidence.

Dashboard display-state follow-up: no authentication or API authorization rules were weakened. Independent request states prevent missing/failed data from being represented as an authoritative zero; active prerequisites and receipt evidence remain explicitly distinct from execution permission. A fresh integrated local Chrome SSO and logout/guard check passed. The receipt outage used in the browser audit is an explicit test interception, removed before returning to the real API. Temporary test credentials were not printed or included in artifacts.

Sign-in copy re-review — 2026-10-07: the change is explanatory UI copy only. The OIDC authority, client settings, credential handling, token storage, redirect/callback, and API authorization behavior are unchanged. Browser checks confirm `/login` has no username/password input and that **Continue with SSO** navigates to the configured local identity provider. No user credentials were entered or recorded during this copy review.

## Policy-draft reference preflight — 2026-10-07

The policy editor now validates draft references against the same organization-scoped, Zod-validated agent/account responses already used by the console. It only blocks obviously unavailable or inactive references in the UI; the backend still independently enforces role, tenant, account-agent linkage, adapter state, payload schema, and idempotency. The preflight sends no policy mutation when required active resources are absent. No authorization bypass, local token injection, secret handling, or new browser persistence was introduced. Authenticated Chrome verification observed a disabled submit button and zero policy POST requests with one active agent and no active account.

## Account verification action — 2026-10-07

The UI action now appears for supported `PAUSED`/`ACTIVE` accounts only while `verifiedAt` is null. This condition is presentation logic, not authorization: the verification endpoint still enforces the organization-scoped principal and backend chain verifier. A browser request against the local fixture reached the backend and returned HTTP 503 because no chain RPC/Safe singleton config is present; the UI preserved the unverified state. No chain transaction, auth bypass, or assertion of on-chain verification occurred. Positive chain verification remains open pending an isolated local Anvil/Safe enrollment fixture.

## Account verification positive-path recheck — 2026-10-07

This supersedes the earlier note that the positive path was still open. In the main compose configuration, the account verification request correctly returned HTTP 503 without an RPC/Safe singleton configuration and preserved the unverified state. The positive path was subsequently completed against a disposable local Anvil/Safe fixture: the authenticated UI registered an account (201), invoked verification (200), and rendered the backend-confirmed `ACTIVE`/verified state. No live chain, auth bypass, or fund transfer was involved. Production RPC configuration remains a separate gate.
