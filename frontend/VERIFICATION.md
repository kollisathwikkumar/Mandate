# Frontend local verification

Last run: 2026-10-07. This record describes local checks only; it is not a staging or production qualification.

## Build and dependency checks

Run from `frontend/`:

| Command | Result |
|---|---|
| `npm run typecheck` | PASS |
| `npm test -- --reporter=dot` | PASS — 8 test files, 21 tests, including tenant-switch isolation, activity-link subject-type coverage, and organization-picker behavior |
| `npm run build` | PASS — Vite production build completed; largest emitted JavaScript chunk was 454.11 kB (130.45 kB gzip) |
| `npm audit --omit=dev` | PASS — 0 vulnerabilities |
| `npm run verify:api-contract` | PASS — 38/38 frontend API methods are present in the running local OpenAPI 3.1 document |

After the workspace-picker interaction fix, the current frontend checks were rerun: **8 test files / 21 tests passed**, typecheck passed, production build passed, API contract check passed at 38/38, and `npm audit --omit=dev` reported 0 vulnerabilities.

The activity audit table originally linked every audit `subjectId` to the action-detail route. A local OIDC-backed browser check showed policy and agent subjects then returned `RESOURCE_NOT_FOUND` from the action endpoint. The row renderer now links only `ACTION` subjects; non-action audit rows remain visible and are not sent to an unrelated action endpoint. `frontend/tests/activity-link.test.ts` verifies ACTION encoding and rejects AGENT, POLICY, ORGANIZATION, and ACCOUNT subjects.

The route checker was also pointed at an unused loopback port and exited **1** with `Could not reach local API…`, confirming it fails closed when the contract source is unavailable.

## Browser and backend checks

- Chrome production-preview smoke test: **20/20 route templates passed**. The six public routes rendered their expected page headings. The 14 protected routes redirected to `/login` as expected without an authenticated session; this verifies the route guard, not the protected pages' authenticated data flows.
- Public-route mobile audit at **390 × 844**: all six pages had no horizontal document overflow and every button/link had an accessible text name or ARIA label.
- Production-preview browser console: **0 errors** during route checks.
- The animated 3D background changed between screenshots captured 0.9 seconds apart.
- Developer page visual QA: 3D canvas was present on desktop, screenshots differed across a 0.9-second interval, and the code panel rendered with no console errors.
- Developer page mobile check at **390 × 844**: no horizontal overflow and all visible buttons retained accessible names.
- `GET http://127.0.0.1:3000/health/ready`: **200**, `{"status":"ready","dependencies":{"postgres":"ready"}}`.
- `GET http://127.0.0.1:4173/health/ready` through the frontend proxy: **200**, same ready response.
- Unauthenticated `GET http://127.0.0.1:3000/api/v1/me`: **401 `UNAUTHENTICATED`**, confirming the API authentication boundary is active.
- `verify:api-contract` checks path/method availability only; it does not claim authenticated payloads or business state transitions work end to end.

## Authenticated local OIDC checks — 2026-10-07

Using the local Keycloak test realm and local PostgreSQL/API, a fresh authorization-code + PKCE sign-in completed successfully. Browser-verified authenticated pages loaded tenant-scoped backend data for Overview, Activity, Team, Accounts, and Integrations settings. The test organization showed its OWNER member, one registered agent, one DRAFT policy at revision 2, four audit events, no receipt evidence, no pending invitations, and empty provider/webhook lists. An earlier authenticated flow created the organization, registered the agent, created and revised the draft policy, and ran backend preflight; the result was `BLOCK POLICY_INACTIVE` with the expected policy hash and no transaction submission.

The test account row in local PostgreSQL was seeded only as a local fixture and is **not** on-chain verification. No live RPC transaction, browser-submitted provider key, invitation email, webhook delivery, or cloud deployment was performed. Fake provider keys are exercised only by the isolated API/PostgreSQL integration test. The local OIDC compose overlay and ignored local env files are development-only.

An additional authenticated Chrome smoke pass traversed all **14 protected route templates** with a live local session. Each settled at its expected page state: overview; agents list/detail; policies list/create/detail/edit/preflight; approvals; activity list/detail; team; accounts; integrations settings. The synthetic nonexistent action route correctly rendered the backend's `RESOURCE_NOT_FOUND` state. The `edit` and data-heavy settings routes were rechecked after organization/API loading settled. All **six public routes** also passed local heading smoke checks; the earlier production-preview route smoke passed all 20 templates.

Fresh authenticated Chrome pass on 2026-10-07 revisited all **14 protected route templates**. Each rendered its expected screen; the deliberately nonexistent action detail displayed the backend's “The requested resource was not found” error. The local API readiness endpoint returned HTTP 200 with PostgreSQL ready. On the single-membership fixture, the workspace picker now reports disabled to accessibility tools and omits the misleading dropdown indicator; its switching eligibility is covered by unit tests for zero, one, and multiple memberships.

Authenticated integrations form check: an `http://127.0.0.1` webhook destination was rejected by the UI's HTTPS precheck; an `https://localhost` destination passed that precheck but was rejected by the backend destination validator. The integrations page continued to show “No webhooks,” confirming no endpoint was created. The browser was returned to the Overview page after the check.

Overview visual update: the authenticated dashboard now shares the public site's subdued violet grid and includes the existing reduced-motion-aware 3D background at low opacity, behind the API data. The organization name now ellipsizes on one line. Chrome visual QA after this change showed the 3D wireframe shapes behind the overview content; screenshots 0.9 seconds apart differed in **50,106 bytes**, confirming visible motion. Typecheck, all 21 frontend tests, and production build passed after the change.

REST API/PostgreSQL integration: `docker compose --profile tests run --rm integration npm run test:integration -- --reporter=dot apps/api/test/api.integration.test.ts` — **PASS, 24/24 tests** against the isolated `mandate_test` PostgreSQL service. Provider-key lifecycle assertions use an in-memory fake secret store and provider tester, so they verify write/replace/test/disable/delete without AWS or an external model request. The browser's successful key-save path remains unverified end to end because the running API uses its AWS Secrets Manager adapter rather than a local secret-store emulator.

Visual checks on the local overview and developer pages confirmed the dark/violet grid, motion-based reveal composition, and canvas background. Two overview screenshots 0.9 seconds apart differed in 85,372 bytes, confirming visible animation. The developer example explicitly says the SDK import path is not yet published.

The Team page's invite form was submitted once using a reserved `mandate.invalid` test address. The UI returned the one-time token and explicitly reported that automated email delivery is not configured; the token dialog was closed without copying or storing the token. The pending invitation remains in the local test database so far. Revocation is not included in this pass.

## Remaining verification gates

- Authenticated page data and several policy/agent workflows have now been checked against local API/PostgreSQL, but not every control has received an authenticated end-to-end action/state verification. Continue page-by-page and exercise each safe mutation against local state.
- Production hosting headers/origin policy, deployment secrets, live-chain qualification, and staging behavior remain separate deployment gates.
- Production identity-provider configuration remains open. This frontend and API use OIDC; local browser verification uses the loopback Keycloak test realm. Production issuer, client, callback, and accepted API audience must be selected and verified together.

## Fresh local checks — 2026-10-07

From `frontend/`, `npm run typecheck && npm test -- --reporter=dot && npm run build && npm run verify:api-contract` completed with exit status **0**. TypeScript passed; Vitest passed **8 files / 21 tests**; Vite production build succeeded (largest application chunk 454.11 kB / 130.45 kB gzip); the live local OpenAPI contract check passed **38/38** operations. The API contract check verifies path/method presence only, not authenticated business-state transitions.

The Team page's invitation-revoke backend path was rechecked against the isolated PostgreSQL integration service with `docker compose --profile tests run --rm integration npm run test:integration -- --reporter=dot apps/api/test/api.integration.test.ts -t "lists and revokes organization invitations idempotently"`: **1 passed / 23 skipped**, exit status **0**. It verifies invitation list, idempotent revoke/replay, revoked-token rejection, and exactly one audit plus outbox event. The React Team handler sends `DELETE` with an idempotency key and refetches the invitation list; a fresh authenticated browser click/state check for that control remains open.

Integrated sign-in browser check: from the Mandate website's `/login`, the **Continue with SSO** action completed OIDC authorization-code + PKCE through the local test issuer, returned to `/app/overview`, and fetched authenticated `GET /api/v1/me` with HTTP **200**. A one-use local test identity (created with a random temporary password and complete profile fields) had no memberships, so the expected “Create your first workspace” state rendered. The identity and temporary password files were removed after the check; no personal account or password was used. Screenshot: `frontend/output/playwright/integrated-oidc-success.png`.

Integrated sign-in regression check: the OIDC callback is now memoized for the lifetime of the browser document so React Strict Mode cannot exchange a one-time authorization code twice. The automated browser started at the Mandate `/login`, used the SSO redirect and local test identity, reached `/app/overview`, received HTTP **200** from the token endpoint and authenticated `GET /api/v1/me`, and recorded **zero** browser console/page errors. Screenshot: `frontend/output/playwright/integrated-oidc-fixed.png`. The test identity is ephemeral and separate from any personal account; no user password was needed or used.

Auth callback regression tests: **2 passed** (one in-flight operation is shared across repeated effects; a rejected exchange is not retried with the consumed authorization code). Frontend verification after the fix: `npm run typecheck` passed, `npm run build` passed, and `npm test -- --reporter=dot` passed (**9 files, 23 tests**).

The local login route initially requested a missing favicon. A branded violet-on-black SVG favicon is now linked from `index.html`; a post-change Chromium browser check returned `/login` with **zero 404 resources and zero console errors**, and `/favicon.svg` returned HTTP **200**. `git diff --check` passed, and the project docs contain no references to the unrelated hosted site.

## Authorization-path dashboard — 2026-10-07

The authenticated Overview now includes a live, four-stage authorization-path visualization backed by the organization-scoped Agents, Policies, Accounts, and Receipts API resources. The model counts only active agents, active policies, active accounts with a verification record, and FINAL receipts in the latest five. It explicitly distinguishes readiness from authorization: an active policy count is not blanket permission, account/policy matching still applies, and receipts are evidence rather than grants. Each stage links to its existing console section. When any of these requests is loading or errors, the path shows a loading/error state instead of presenting missing data as zero.

The pure path model was introduced test-first: the first focused run failed to resolve the not-yet-implemented model (exit **1**); after implementation, `npm test -- --reporter=dot tests/authorization-path-model.test.ts` passed **3/3 tests**. Cases cover mixed statuses, no active policy, no verified supported account, and non-final receipts.

Fresh checks from `frontend/` after this change: `npm test -- --reporter=dot` — **PASS, 11 files / 28 tests**; `npm run typecheck` — **PASS**; `npm run build` — **PASS** (Vite production bundle built); `npm run verify:api-contract` — **PASS, 38/38 route/method operations**; `npm audit --omit=dev --audit-level=high` — **PASS, 0 vulnerabilities**; `git diff --check` — **PASS**. The local Vite server returned HTTP **200**, the local API readiness endpoint returned HTTP **200**, and the local OIDC issuer responded with HTTP **302**. These checks establish local build and unit/model behavior; they do not replace a fresh authenticated browser visual check of this newest dashboard panel or staging/production qualification.

## Dashboard state and integrated Chrome audit — 2026-10-07

The latest Chrome audit completed the website's **Continue with SSO → local test identity provider → OIDC callback → authenticated Overview** flow again. The token exchange and authenticated `/api/v1/me`, Agents, Accounts, Policies, Alerts, and Receipts resources returned HTTP **200**. No personal password was requested or used. React StrictMode aborted obsolete duplicate reads; successful replacement reads returned 200. A third-party `THREE.Clock` deprecation warning remains; the audit recorded zero browser page errors.

Two actual UI defects were corrected:

- The topbar avatar called OIDC logout while its accessible name said “User account.” It now says **Sign out**, including its tooltip. Before the change the browser assertion failed with `Topbar sign-out action is mislabeled: User account` (exit 1). After the change the browser audit passed, and clicking it completed OIDC logout; opening a protected route then returned to the website sign-in page.
- Metrics previously used only the Agents/Policies loading flags for all four resources and could display a fabricated zero for pending/failed receipt or alert requests. The typed metric model independently handles each resource: pending/not-yet-requested → `—`, failed → `Unavailable`, successful empty list → `0`. Receipt and alert list limits are explicitly labeled **Latest 5 records**; the unsupported “Open signals” interpretation was replaced with **Recent signals**. The cards now link to their actual console sections.

`scripts/verify-overview-browser.js` passed **17/17 checks** in an isolated real Chrome session, including all four authorization-path node links, the linked metric cards, one shared 3D canvas, no horizontal document overflow at **390 × 844**, mobile navigation open/close, reduced-motion immediate visibility, and receipt pending/error/recovery behavior. The loading/outage checks deliberately intercept only the receipt request; after the interception is removed the card recovers from the real local API. The separate OIDC logout/protected-route check also passed. Desktop and mobile screenshots were reopened and visually inspected:

- `output/playwright/overview-authorization-path-desktop.png`
- `output/playwright/overview-authorization-path-mobile.png`

Fresh current checks: typecheck **PASS**; all **12 test files / 36 tests PASS**; `npm run test:models:coverage` **PASS, 11 model tests, 100% statements/branches/functions/lines across both models**; production build **PASS**; API route/method contract **38/38 PASS**; production dependency audit **0 vulnerabilities**; `git diff --check` **PASS**. These are local results. The earlier 28-test entry remains historical rather than the latest total.

The exact App.tsx baseline hash, modified copy, diff, commands, and tested copy-only rollback are recorded in `output/verification/overview-state/VERIFICATION.txt`. The live source and `MODIFIED_FILE.tsx` remain modified; rollback was exercised only on a separate copy. Remaining work still includes positive/negative mutation journeys for every applicable control and external-adapter qualification; this dashboard audit does not claim those gates are complete.

## Reference, motion, sign-in, and current local re-verification — 2026-10-07

Opened the requested StringTune landing page, its Skill Hub, and the **Reveal on scroll** skill in Chrome. The Skill Hub's concrete movement vocabulary includes reveal, parallax, progress, lerp/glide, cursor/magnetic response, spotlight, and sequenced entrances. Opened the requested Monad Metropolis campaign page in Chrome and used its dark, high-contrast, dimensional/grid direction only as a visual reference. Mandate keeps original content and its restrained violet accent rather than copying either reference. These choices are recorded in `DESIGN_DECISIONS.md`.

Chrome visual QA: the Mandate home page was scrolled in viewport-sized increments before capturing the full-page image, confirming its reveal sections actually appear during normal scrolling. `/login` displays the website's **Continue with SSO** entry point and animated 3D background; it does not collect a Mandate-local password. The local identity-provider credential prompt appears only after that SSO redirect. The authenticated Chrome session reached `/app/overview`; its API readiness badge was **Ready**, backend-derived counts rendered (1 agent, 0 policies, 0 recent receipts, 4 recent signals), the authorization path linked to the relevant sections, and the browser reported **0 page errors**. The separate end-to-end OIDC evidence above records the redirect, callback, token exchange, and authenticated API requests using an ephemeral test identity—not a personal account/password.

Reopened and visually inspected these current screenshots:

- `output/playwright/mandate-home-scrolled.png`
- `output/playwright/mandate-signin-entry.png`
- `output/playwright/mandate-overview-current.png`

Latest fresh frontend commands from `frontend/`: `npm run typecheck` **PASS**; `npm test -- --reporter=dot` **PASS, 13 files / 43 tests**; `npm run build` **PASS**; `npm run verify:api-contract` **PASS, 38/38 route/method operations**. API-contract verification itself states that it proves route/method presence only; authenticated request/state-transition coverage remains a separate integration gate. Backend mutation coverage and staging/production qualification remain ongoing.

## Policy-draft prerequisite preflight — 2026-10-07

An authenticated submit using the template's example addresses reached the backend and returned `404 RESOURCE_NOT_FOUND` with a generic organization-resource message. The same Chrome session's API data showed **1 active agent and 0 active accounts**; the template referenced neither a registered agent nor a linked account. That response was safe, but it was confusing and the editor made an impossible submission look available.

The draft editor now reads organization-scoped agents and accounts before enabling submission, explains the live prerequisite counts, links to the relevant setup sections, and validates the selected active agent plus active account/address/chain/adapter against those API lists before sending a draft request. The backend remains authoritative and still validates the submitted policy. On the current local fixture, a fresh authenticated browser check confirmed the CTA is disabled, both setup links are present, **0 policy POSTs** were sent, and there were **0 browser page errors**. Screenshot: `output/playwright/policy-draft-prerequisites.png`; browser check: `scripts/verify-policy-prerequisites-browser.js`.

TDD validation: the six focused reference checks pass; the new helper has **100% statements, branches, functions, and lines**. Fresh frontend verification: `npm run typecheck` **PASS**; full Vitest suite **PASS, 14 files / 49 tests**; production build **PASS**; API method contract **38/38 PASS**; `git diff --check` **PASS**. The policy-create positive path still requires a real active account and a policy body using this organization's registered resources; no account or on-chain state was fabricated to claim that mutation succeeded.

## Integrated website sign-in and logout re-verification — 2026-10-07

The test started from the Mandate website at `/login` and clicked **Continue with SSO**; it did not compare or use another Mandate-branded website. The browser was redirected to the configured local OIDC provider with `response_type=code` and `code_challenge_method=S256`, returned through `/login/callback`, and reached `/app/overview`. The authenticated `GET /api/v1/me` returned **HTTP 200**; with zero memberships, the expected **Create your first workspace** state appeared. API readiness was `{"status":"ready","dependencies":{"postgres":"ready"}}`; the OIDC discovery endpoint returned **200**. No personal login or password was used. The website's sign-in copy now explains that the identity provider opens next, returns to Mandate, and handles its own password.

This pass also found a local provider configuration gap: logout initially returned **HTTP 400 `Invalid redirect uri`** because the OIDC client did not allow the app's post-logout redirect. Registering `http://127.0.0.1:5173/` as the client's post-logout redirect fixed the complete flow: sign-out returned to `/`, and opening `/app/overview` while signed out redirected to `/login`. The browser recorded **0 page errors** throughout the successful sign-in and logout flow (one existing non-fatal Three.js deprecation warning). The local test identity was ephemeral and removed after verification. `README.md` now documents both required redirect URIs and clarifies that the website login button redirects to the configured identity provider.

## Authenticated organization and resource workflows — 2026-10-07

A fresh local OIDC test identity completed the website sign-in flow and used the real UI against the local API/PostgreSQL. **Create organization** created `org_c2237219-87e1-456d-91f1-ecf7c9d70ff6`; the Overview switched from the no-membership onboarding state to live organization data. **Register agent** created `e2e-treasury-agent`; the organization-scoped agent GET returned **200** and included that agent. **Register account** created `e2e-treasury-account` at a syntactically valid test address; the organization-scoped account GET returned **200** and showed the expected `PAUSED` status with `verifiedAt: null`. This is only a local registration fixture; no chain verification or transaction was performed. The live backend-driven overview was captured and reopened at `output/playwright/local-e2e-overview.png`.

The Team form created a pending invitation for the reserved `mandate.invalid` test address. Its one-time token dialog was closed without copying the token. **Revoke** then changed that invitation to `REVOKED`; the UI showed its success notice and the row's updated backend state. No email delivery was configured or sent. The synthetic organization, agent, paused/unverified account, and revoked invitation remain in the local development database for continued UI checks; no real account or chain state was touched.

Chrome exposed an actual frontend validation bug during agent creation: the ID input's hyphen-containing character class was invalid under the browser's Unicode Sets (`v`) regular-expression semantics, producing a console error. Agent and account IDs now share `RESOURCE_ID_PATTERN`, which keeps the hyphen outside the character class. A seven-case `v`-flag regression test covers accepted and rejected IDs; the real browser accepted `test-id.with_hyphen-2` via native `checkValidity()`. A fresh browser snapshot after the fix had **0 page errors** (one non-fatal Three.js deprecation warning).

Fresh checks after the fix: `npm run typecheck` **PASS**; full Vitest suite **15 files / 56 tests PASS**; `npm run build` **PASS**; API route/method contract **38/38 PASS**; `git diff --check` **PASS**. The optional `VITE_API_PROXY_TARGET` was exercised with a temporary local stub: the second Vite server returned `{"probe":"proxy-target-override"}` through `/health/ready`, while the normal server continued to return the API's PostgreSQL-ready response. Both temporary probe processes were stopped after the check.

## Account on-chain verification action — 2026-10-07

The authenticated Accounts page hid **Verify on-chain** for new account registrations because the backend correctly creates them in `PAUSED` state while the button was limited to `ACTIVE` accounts. The page now exposes verification only for `PAUSED` or `ACTIVE` accounts with `verifiedAt: null`; `UNSUPPORTED` and already-verified accounts remain ineligible in the UI. The backend continues to own authorization and verification.

TDD: the focused test first failed to resolve the not-yet-created helper (expected RED), then `npm test -- --reporter=dot tests/account-verification-action.test.ts` passed **5/5** cases, including paused/unverified and unsupported/already-verified states. Authenticated Chrome rendered **Verify on-chain** for the local API's paused fixture. Clicking it reached the organization-scoped API and returned **HTTP 503 Service Unavailable** because the local compose environment has no `MANDATE_EVM_RPC_URLS`/trusted Safe singleton configured; the UI showed the verification failure, and the account remained `PAUSED` / **Not verified**. This is a confirmed fail-closed backend boundary, not a successful chain verification. No chain transaction was sent and no live-chain result is claimed. Configure an isolated local Anvil RPC plus the corresponding Safe singleton/enrollment fixture before verifying the positive chain path.

Fresh frontend checks after the change: typecheck **PASS**; Vitest **16 files / 61 tests PASS**; production build **PASS**; OpenAPI operation contract **38/38 PASS**; `git diff --check` **PASS**. Local API readiness returned HTTP **200** with PostgreSQL ready. Authenticated Chrome had zero page errors before the intentional API 503; its non-fatal Three.js deprecation warning remains.

The underlying enrollment verifier also passed its real local-chain positive path: from `backend/`, `npm run test:contracts -- --reporter=dot packages/chain/test/safe-enforcement.integration.test.ts -t "verifies the registered Safe"` — **1 passed / 13 skipped**, exit **0**. This deploys Safe/guard/module contracts to disposable Anvil, verifies the fully enrolled Safe, and rejects an unregistered address. It proves the verifier implementation against Anvil; the running compose API still lacks a chain RPC/Safe singleton fixture, so the full positive browser-to-API chain workflow remains open. The helper's focused coverage check passed **100% statements / branches / functions / lines**. Screenshot reopened and visually inspected: `output/playwright/accounts-verification-action.png`.

## Full website-to-local-chain verification — 2026-10-07

Closed the positive-path gap above using an isolated PostgreSQL database, a disposable local Anvil chain (chain ID 10143), and a separately configured local API instance. The logged-in website's Accounts page registered `anvil-account` against the deployed Safe proxy (**POST 201**), then **Verify on-chain** completed the actual organization-scoped API call (**POST 200**). A follow-up account read returned **200**; the row changed from `PAUSED` / `Not verified` to `ACTIVE` with a verification timestamp, and the UI showed `On-chain protection verified for anvil-account.` No funds were transferred and no live chain was used.

This full path exposed the verifier bug: JSON-RPC returned a valid odd-length quantity `0x9` for the block number, but the backend treated it as an invalid byte string and returned `409`. The new canonical quantity parser accepts `0x9` and rejects malformed `0x09` as an RPC dependency error. The regression test was observed failing before the code change and passing afterward. Backend full suite: **46 files passed / 10 skipped; 310 passed / 51 skipped**; backend typecheck and build passed; focused real-Anvil enrollment test passed **1/1**. The full workflow and security boundary are documented in `../backend/VERIFICATION.txt` and `../backend/SECURITY_REVIEW.md`.

Reopened and visually inspected `output/playwright/accounts-anvil-e2e-verified.png`. All disposable services were stopped/removed afterward; the normal local frontend at `127.0.0.1:5173` again proxies to the main API at `127.0.0.1:3000`, API/PostgreSQL readiness returned HTTP **200**, and the automated test session was signed out. Production RPC configuration, external integrations, and deployment remain separate verification gates.

## Chain-aware receipt explorer links — 2026-10-07

The Overview previously sent every transaction hash to Monad's main explorer, even though the app's default/test fixture chain is Monad Testnet (`chainId: 10143`). `receiptExplorerUrl` now maps `10143` to `https://testnet.monadexplorer.com/tx/` and URL-encodes the hash as one path segment; unknown chain IDs display a plain hash instead of a misleading external link. Reference network metadata: [Chainlist 10143](https://chainlist.org/chain/10143) and [Monad Testnet explorer](https://testnet.monadexplorer.com/).

TDD: `tests/receipt-explorer.test.ts` first failed because the helper did not exist, then passed **3/3** checks (correct testnet explorer, no incorrect fallback for unsupported chains, and path-segment encoding). The final recheck passed: full Vitest **17 files / 64 tests**, typecheck, production build, frontend API contract **38/38**, helper coverage **100% statements / branches / functions / lines**, and `git diff --check`.

## Public-page browser / motion audit — 2026-10-07

Added reusable Chrome audit `scripts/verify-public-pages-browser.js`. The real browser passed **53 checks** across `/`, `/how-it-works`, `/security`, `/integrations`, `/developers`, and `/login`: public navigation and CTAs route correctly; website SSO initiates OIDC authorization-code + PKCE with the Mandate callback; the developer copy button writes the SDK snippet and its API-contract link opens the live local OpenAPI document; each page renders one shared animated 3D canvas, reveals all scroll-triggered content, and has no horizontal overflow at **390px**. The high-intent primary CTA has a reversible magnetic pointer response; reduced motion disables both it and the animated scroll bar, then uses the static 3D fallback. **Zero browser page errors.** Desktop and mobile screenshots were saved under `../output/playwright/public-*-desktop.png` and `public-*-mobile.png`. The home screenshot was reopened after all reveals were activated; the login and developer desktop screenshots were reopened and visually inspected as well.

## String Tune Skill Hub magnetic action — 2026-10-07

Applied the Skill Hub's `MAGNETIC` interaction only to high-intent public actions (Open console, home primary CTA, developer CTA, and Continue with SSO), not high-frequency console controls. Movement is mouse-only, capped at **4px**, recenters on pointer leave, and is disabled by `prefers-reduced-motion`/coarse pointers. `getMagneticOffset` was covered with a TDD red/green cycle and achieved **100% statements, branches, functions, and lines**. The live Chrome audit confirmed pointer attraction, recentering, and reduced-motion suppression.

Fresh full frontend checks: **18 test files / 67 tests PASS**, typecheck, production build, OpenAPI route/method check **38/38**, magnetic helper coverage **100%**, and `git diff --check`.

## Sign-in credential prompt clarity — 2026-10-07

A fresh browser check confirmed the username/password prompt is served by `http://127.0.0.1:8080` on the **Mandate Local Test Identity Provider** after the website's **Continue with SSO** redirect. The Mandate `/login` page itself contains no username/password fields. Its sign-in copy now explicitly says the next credential prompt belongs to the configured identity provider, not Mandate, and that Mandate has no separate local password. No user credentials were entered in this check. The browser regression audit first failed on the missing explanation (exit **1**), then passed **56 checks** after the copy update; the audited website initiated OIDC authorization-code + PKCE and the browser confirmed the test identity provider page. This specific fresh run stopped at the provider sign-in screen; the completed callback/token exchange and authenticated API evidence remains in the earlier integrated OIDC verification section above.

Fresh checks after this copy-only auth UX change: `npm run typecheck` **PASS**; Vitest **18 files / 67 tests PASS**; `npm run build` **PASS**; `npm run verify:api-contract` **38/38 PASS**; `node --check scripts/verify-public-pages-browser.js` **PASS**. The API contract check covers routes/methods, not auth state transitions.
