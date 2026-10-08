# Backend API handoff for frontend development

## Contract source and stability

- `GET /api/v1/openapi.json` is the published OpenAPI 3.1 contract; `apps/api/src/openapi.ts` is its source.
- API routes remain under `/api/v1`. Do not change a request, response, status code, or error contract incompatibly in place; introduce a versioned route or an announced deprecation.
- `apps/api/test/api-contract.test.ts` compares the registered Fastify method/path set with the OpenAPI operations and checks `operationId` uniqueness. Run it after adding or changing a route.
- The API currently exposes 48 registered operations (including health and OpenAPI endpoints). The contract-parity check prevents undocumented or stale paths/methods.
- The Node SDK is a convenient client but returns generic JSON values for business responses. Frontend consumers should use the published OpenAPI schemas or validate response data at their own boundary.

## Browser integration requirements

- Authenticate with an OIDC bearer token for a human user. Use `/api/v1/me` to discover the identity and memberships; bind each request to the selected organization. Never place model-provider keys, webhook signing secrets, agent credentials, or AWS credentials in browser code.
- Send `Idempotency-Key` for state-changing endpoints that require it. Invitation acceptance is replay-safe by its one-time token. Handle `204 No Content` without attempting to parse a JSON body.
- `GET /api/v1/orgs/{orgId}/actions` supports state-filtered, bounded action summaries; human members are organization-scoped, while agent principals see only their own action intents.
- `GET /api/v1/orgs/{orgId}/policies/{policyId}/revisions/{revision}` returns the tenant-scoped immutable canonical revision body for detail and revision editing.
- Handle typed `{ error: { code, message, requestId } }` failures. Preserve idempotency keys only for retries of the same user intent. Respect `429 RATE_LIMITED` and `Retry-After`.
- Cross-origin browser access is controlled by `MANDATE_CORS_ALLOWED_ORIGINS`, a comma-separated exact origin allowlist. Values must be HTTPS origins (HTTP loopback is accepted for local development); wildcard and `null` origins are rejected. The API supports preflight only for its standard methods and `Authorization`, `Content-Type`, and `Idempotency-Key` headers; it does not enable cookie credentials. Leave it unset for same-origin deployments. Configure the exact staging/production console origins before browser integration.
- If the API is behind a reverse proxy, configure `MANDATE_TRUSTED_PROXY_CIDRS` with only the actual proxy CIDRs. The default ignores forwarded-IP headers; this is intentional to avoid trusting arbitrary client-supplied forwarding headers.

## Staging handoff checklist

1. Configure the staging API URL, OIDC issuer/JWKS/audience, exact `MANDATE_CORS_ALLOWED_ORIGINS` if cross-origin, and selected test-chain RPC/settings.
2. Use staging-only credentials and an isolated PostgreSQL database. Apply migrations through the migration job; confirm readiness before frontend testing.
3. Verify login/token audience, organization selection, allowed/denied action journeys, API error display, rate-limit handling, and invitation/retry flows from the browser.
4. Keep frontend work against staging. Production deployment remains a separate gate after end-to-end regression, monitoring, backup/restore, rollback, and required live-service checks.

## Known backend/deployment gaps

- The local frontend lives in `../frontend`, proxies `/api` and `/health` to local port 3000, and uses OIDC authorization-code + PKCE. Configure its public `VITE_OIDC_*` values before testing protected browser flows.
- No AWS production infrastructure-as-code or production deploy pipeline is present; local Compose is not a production topology.
- Live AWS Secrets Manager, SES, and S3 Object Lock/IAM behavior still needs environment-level verification.
- Identity-provider tenant/user provisioning and the login/passkey UX are external integration work; the API validates issued OIDC JWTs.
- Monad/testnet deployment, long-run stateful contract/failover qualification, and independent review remain outside the local API contract test.
- Quote/oracle valuation and arbitrary contract calls are not part of the current supported action surface; the current Safe path is deliberately bounded to its documented native/ERC-20 transfer subset.

## Security review: browser-origin handling

- The API applies an exact configured origin allowlist; wildcard, `null`, non-HTTPS public origins, malformed entries, and duplicate entries are rejected.
- Preflight is limited to supported HTTP methods and the three browser request headers the API needs. No cookie credentials are enabled; bearer authentication and tenant authorization remain mandatory. CORS is browser access control, not API authorization.
- Unlisted browser origins are rejected before protected route handling; no origin value is reflected unless it exactly matches the validated allowlist. Staging and production should use separately configured origin lists.
- No new runtime dependency was added. The production dependency audit completed with zero reported vulnerabilities.

## Local verification commands

```sh
npm run typecheck
npm test -- --reporter=dot
npm run build
npm audit --omit=dev
docker compose --profile tests run --build --rm integration
```

After staging is deployed and its TLS URL, browser origin, and staging OIDC token are available, run the read-only deployment smoke suite with `MANDATE_STAGING_API_URL`, `MANDATE_STAGING_ORIGIN`, and `MANDATE_STAGING_TOKEN` set in the shell, then `npm run smoke:staging`. It checks liveness, PostgreSQL readiness, the published OpenAPI 3.1 document, exact CORS preflight behavior, and authenticated `/api/v1/me`; it never prints the bearer token.
