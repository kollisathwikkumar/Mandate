# Mandate — production backend architecture and product map

**Status:** architecture proposal, not implemented code.  
**Design goal:** bounded, accountable AI-agent actions, with enforcement at the resource that can actually execute the action.  
**Inspiration:** AgentLedger's documented `quote → evaluate → reserve → sign → settle → reconcile` payment flow. Mandate generalizes the policy lifecycle for a tightly bounded set of smart-account actions; it does not copy AgentLedger's implementation or claim its feature coverage.

## 1. Product definition

Mandate is an authorization control plane. A human or organization defines what a named agent may do, approves a versioned policy, and connects it to an enforcement adapter. Before an agent action executes, the system checks the actor and action against that policy. Allowed actions are executed through the adapter; denied actions are stopped; exceptional actions wait for a human. The system records attributable decisions and final execution outcomes.

**Mandate is not:** the agent/model, an owner-key custodian, a guarantee that an agent's intent is benign, a generic on-chain identity registry, or a log viewer that learns of violations only after execution.

### First customer/problem hypothesis

DAO/protocol treasury operators need AI agents to perform recurring, bounded actions without sharing owner keys or manually approving every routine operation. The buyer, exact workflow, and willingness to adopt a new control plane remain validation questions.

### Hard invariant

> Every action Mandate calls “enforced” must pass through the policy check at the action's actual execution boundary. If a supported wallet/tool has a bypass path, Mandate must either close it or clearly mark that path unsupported.

The off-chain policy engine provides fast explanation and preflight. The smart-account module, wallet-provider policy, or target API authorization is the final enforcement point. The control plane must never imply that a green UI result alone prevents an alternate signer or direct contract call.

## 2. System context

```text
 Human / Org Admin ─────────────── Web Console
       │                              │ OIDC session + WebAuthn/wallet confirmation
       │                              ▼
 Agent ── SDK / CLI / MCP ──► Mandate API (modular monolith)
                                  │
              ┌───────────────────┼──────────────────┐
              ▼                   ▼                  ▼
        Policy Engine       Approval Service    Execution Coordinator
              │                   │                  │
              └───────────────────┼──────────────────┘
                                  ▼
                 Enforcement Adapter / Wallet Policy
                                  │
                                  ▼
                 Smart Account on Monad / EVM
                                  │
               Chain Indexer ◄───┘ ───► Receipt Reconciler
                      │                       │
                      └──────── Postgres ─────┘
                            │
                     Outbox → Worker
                       │      │      │
                       ▼      ▼      ▼
                   Alerts  Webhooks  Audit export
```

MCP, REST, SDK, and CLI are different entry points to the same application services and policy evaluator. They must not implement separate authorization rules.

## 3. Deployable backend shape

Start with a **TypeScript modular monolith** in one repository and separate process entry points, not a fleet of microservices. This keeps policy decisions, approvals, and budget reservations transactionally consistent while preserving the ability to scale workers independently.

```text
apps/
  api/                 REST API + auth/session middleware
  worker/              outbox dispatch, alerts, webhook delivery, reconciliation
  chain-indexer/        finalized logs, reorg tracking, cursor persistence
  mcp-server/          thin MCP facade over shared application services
packages/
  domain/              typed entities, value objects, state transitions
  policy/              canonical schema, compiler, deterministic evaluator
  application/         use cases; sole orchestration layer
  ports/               repository, signer, wallet, chain, clock, queue interfaces
  adapters/            Postgres, EVM/Monad, wallet provider, notifications
  contracts/           ABI, deployment metadata, generated types
  api-contracts/       OpenAPI schemas, MCP tool schemas, shared error codes
  observability/        OpenTelemetry setup, redaction, correlation IDs
contracts/
  src/                  narrow supported account module / policy enforcer
  test/                 unit, invariant, fuzz, integration tests
```

### Runtime components

1. **API process:** stateless HTTP endpoints; tenant/authentication checks; schema validation; delegates to application services.
2. **Worker process:** durable outbox consumer for notifications, encrypted invitation-email jobs, webhook retries, chain reconciliation, and audit anchors. Invitation delivery is at-least-once; it never silently retries a transaction with a new nonce.
3. **Indexer process:** consumes contract events; stores block/hash cursor; handles confirmations and reorg rollback; never treats unfinalized observations as final.
4. **MCP process:** publishes narrow typed tools such as `mandate_policy_get`, `mandate_action_simulate`, `mandate_action_request`, and `mandate_receipt_get`. MCP calls use the same identity, tenant, authorization, and service layer as REST.
5. **Chain adapter:** Monad/EVM JSON-RPC interface, transaction simulation, fee estimation, submission, receipt polling, and failover. RPC availability is not an authority decision.

## 4. Data and infrastructure boundaries

- **PostgreSQL:** authoritative off-chain records and transactional state: organizations, memberships, agent identities, policies, policy revisions, approvals, action requests, reservations, execution attempts, receipts, webhook jobs, and indexer cursors.
- **Postgres transactions:** use row locks or serializable transactions for off-chain reservation changes. Create the decision, reservation, and outbox event atomically.
- **On-chain account/module:** authoritative enforcement state for supported smart-account operations: enabled/revoked policy epoch, nonce/replay state, and counters/limits where the rule must be enforced on-chain.
- **Redis:** optional cache, rate limiting, and transient coordination only. Redis is never the sole source of truth for a budget, revocation, approval, or execution state.
- **Outbox + worker queue:** write an outbox row in the same DB transaction as a state change; publish/consume idempotently. Queue redelivery must not duplicate an approval, reservation, or transaction.
- **Object storage:** optional encrypted evidence attachments or exports; store content hashes and retention metadata in Postgres. No secrets or raw prompts in public chain data.
- **Secrets:** KMS/secret manager for service integration credentials; owner keys remain in user wallets/accounts. Never put private keys, seed phrases, or raw signing credentials in logs or Mandate's general database.

## 5. Domain model and classification

| Entity | Purpose | Owner / boundary |
|---|---|---|
| Organization | Tenant and policy boundary | Organization |
| Member + Role | Human identity, role, and approval authority | Organization/IdP |
| Agent | Registered actor and lifecycle state | Organization; rotateable agent key reference |
| Account | Smart account/wallet resource an agent may act through | Wallet/account owner |
| Policy | Stable logical policy identity | Organization + account |
| PolicyRevision | Immutable canonical rules, schema version, hash, signer, validity | Owner-approved; never edit in place |
| Grant | Enforcement artifact binding revision to adapter/account/agent | Wallet/account adapter |
| ActionRequest | Agent's exact proposed operation and idempotency key | Agent principal |
| Decision | Allow/block/hold with matched policy and reason codes | Policy engine; append-only |
| Approval | Human decision bound to one exact action hash + expiry | Authorized member |
| Reservation | Atomic temporary budget allocation for one action | DB for hosted coordination; account module for chain-enforced caps |
| Execution | Submission lifecycle, tx hash, receipt, retries | Execution adapter |
| AuditEvent | Attributable state transition and integrity metadata | Append-only application event |
| Receipt | Final verified execution or denial evidence | Chain receipt + indexed projection |

Do not overload an “agent” record with human identity, signing keys, wallet/account, and policy. Those are different principals/resources and should have explicit foreign keys and authorization checks.

## 6. Policy contract and evaluation

### Canonical typed policy

Start with a versioned, typed JSON schema/AST—not arbitrary scripts and not model-generated rules. A policy revision includes:

- organization, owner/account, exact agent public key and key version;
- chain ID, account/module, adapter type, and policy revision hash;
- permitted action category, target contract, function selector, and typed parameter constraints;
- token/asset, recipient allowlist, per-action limit, cumulative limit/window, and action count if applicable;
- validity interval, nonce/epoch, approval thresholds, and revocation reference;
- explicit unsupported/unknown behavior (`DENY`).

The UI summary is rendered from the exact canonical revision bytes/hash that are signed and enforced. Normalization rules (address casing, integer units, selectors, array ordering, decimals, and time units) are shared by UI, API, SDK, contracts, and tests.

### Deterministic decision sequence

1. Authenticate the caller and resolve tenant, member/agent, account, and adapter identity.
2. Verify the action signature/credential, request nonce, idempotency key, chain/domain, and policy revision.
3. Validate the action schema and derive the exact call target, selector, asset, recipient, value, and fee.
4. Check policy status/revision, expiry, revocation epoch, adapter support, and all allow/deny constraints.
5. Check cumulative limits and active reservations atomically; verify external price/balance data only through configured adapters.
6. Return `BLOCK` for any failed or unmeasurable mandatory condition; return `HOLD` if explicit human approval applies; otherwise `ALLOW` with a short-lived, action-bound authorization artifact.
7. Revalidate at the execution adapter. A preflight allow is not a promise that later execution will succeed.

Collect stable reason codes (e.g. `AGENT_UNKNOWN`, `POLICY_EXPIRED`, `TARGET_DENIED`, `LIMIT_EXCEEDED`, `APPROVAL_REQUIRED`, `NONCE_REPLAYED`, `ADAPTER_UNSUPPORTED`); avoid leaking another tenant's policy details in error messages.

### No model in the authority path

An LLM may propose an action or explain a policy in plain language, but it cannot create, broaden, approve, or interpret authority. Any natural-language draft is converted into typed fields, shown for human review, then canonicalized and signed. The evaluator and enforcer are deterministic.

## 7. Execution lifecycle (AgentLedger-inspired, stronger state separation)

```text
RECEIVED → VALIDATED → QUOTED → EVALUATED
                              ├─ BLOCKED
                              ├─ HELD → APPROVED | DENIED | EXPIRED
                              └─ ALLOWED → RESERVED → AUTHORIZED
                                                   → SUBMITTED
                                                   → CONFIRMED | REVERTED | DROPPED
                                                   → RECONCILED
```

- Every transition has a unique event ID, actor, timestamp, correlation ID, policy revision hash, and reason code.
- `AUTHORIZED` is bound to the exact chain/account/target/call data/value/nonce and a short expiry; it cannot be edited into a different transaction.
- Approval signs/approves the exact action hash, not a vague “approve agent” toggle.
- Reservations have lease expiry, reconciliation, and release rules. A worker crash must not leak the whole budget or make it spendable twice.
- On-chain counters/revocation state protect against parallel submissions and service bypass. Off-chain DB locks alone do not protect a directly callable smart account.
- Chain reorgs move an action from tentative to pending/reorged state; the UI never reports “settled” until its configured finality condition is met.
- A proven post-finality reorg changes the action, attempt, and receipt to `REORGED`, restores an active reservation hold, and pauses the affected account. An organization `OWNER` may record one idempotent `CONSUMED` or `RELEASED` disposition with a reason and optional evidence hash; the immutable resolution preserves both old and canonical block hashes. Resolution never rewrites chain facts, resumes the account, or retries execution. Account verification is a separate step and is rejected until every deep-reorg reservation for the account has an explicit owner disposition.

## 8. API / MCP contract

All REST routes are versioned under `/api/v1`. Every state-changing request requires a tenant context, authenticated principal, idempotency key, and explicit target. Use generated OpenAPI types and shared runtime validation.

```text
GET    /api/v1/me
GET    /api/v1/orgs/{orgId}/agents
POST   /api/v1/orgs/{orgId}/agents
GET    /api/v1/orgs/{orgId}/policies
POST   /api/v1/orgs/{orgId}/policies                 # creates draft
POST   /api/v1/orgs/{orgId}/policies/{id}/revisions  # immutable new revision
POST   /api/v1/orgs/{orgId}/policies/{id}/simulate
POST   /api/v1/orgs/{orgId}/policies/{id}/activate   # owner approval/signature required
POST   /api/v1/orgs/{orgId}/policies/{id}/revoke
POST   /api/v1/orgs/{orgId}/actions                  # submit action intent
POST   /api/v1/orgs/{orgId}/actions/{id}/approval    # approve/deny exact action hash
POST   /api/v1/orgs/{orgId}/actions/{id}/reorg-resolution # owner-only deep-reorg reservation disposition
GET    /api/v1/orgs/{orgId}/actions/{id}
GET    /api/v1/orgs/{orgId}/receipts
GET    /api/v1/orgs/{orgId}/audit-events
GET    /api/v1/orgs/{orgId}/audit-exports              # owner/admin-only Ed25519-signed bounded export
```

MCP tools are thin, typed wrappers over the same commands/queries, with an explicit `orgId` and principal context injected by auth—not freely chosen by the model. Default tools are read-only (`get`, `list`, `simulate`). `activate`, `approve`, `execute`, and `revoke` are separately permissioned and require user confirmation/signature where applicable. Never expose “execute arbitrary calldata” as a general MCP tool.

## 9. Security / failure behavior

- **AuthN:** enterprise OIDC/passkeys for humans; cryptographic agent credentials or scoped short-lived tokens for agent calls. Wallet signatures prove control of an account, not company role by themselves.
- **AuthZ:** tenant and role checks at every application use case, not only route middleware. Approver cannot silently approve own policy when separation-of-duties is enabled.
- **Replay/concurrency:** domain-separated signatures, monotonic nonce/epoch, short expiry, atomic reservations, on-chain spent-state/counters.
- **Fail closed:** policy service timeout, stale policy, unknown field, unsupported adapter, bad quote, stale mandatory oracle, or unclear chain state blocks/holds; never auto-allow.
- **Revocation:** owner action increments on-chain epoch/revocation state for supported accounts; backend cache is invalidated but cannot be relied on as the only gate.
- **Operator recovery:** owner can disable adapter/module through the supported account's owner path; deep-reorg reservation disposition is explicit, append-only, and owner-only, while paused accounts require separate supported verification before resuming. Document pause/unpause behavior and protect against a broken guard bricking the account.
- **Audit integrity:** append-only event sequence with hash links, independent periodic anchoring, signed exports, and clear distinction between tamper evidence and proof that source facts are truthful/complete. Signed exports use a pinned Ed25519 public-key fingerprint; exports are bounded and the API returns 503 if the signing secret is not configured. The worker writes canonical Ed25519-signed, domain-separated checkpoints to S3 Object Lock with compliance retention, conditional create, version IDs, and a per-organization checkpoint chain recorded in PostgreSQL. The S3 bucket must be separately administered and configured with versioning/Object Lock; the deployment provisions it and grants the worker narrowly scoped access. Live-cloud qualification remains a deployment requirement.
- **Privacy:** minimize chain-visible data; avoid hashes of low-entropy personal fields as “privacy”; encrypt sensitive off-chain data; tenant-scoped access and retention/deletion.
- **Abuse controls:** rate limits, request size caps, quote freshness, webhook signing, SSRF protection for any user-supplied URL, and redacted structured logs.
- **Supply chain:** pinned dependencies, reproducible contract builds, code review, invariant/fuzz tests, external audit and incident playbook before real funds.

## 10. Page classification and connection plan

Pages are grouped by job. The frontend must call backend APIs under the corresponding domain module; no page owns a separate policy engine.

| Route | Classification / page job | Primary backend reads/writes | Next valid path |
|---|---|---|---|
| `/` | Public product overview | None | `/how-it-works` or `/signup` |
| `/how-it-works` | Explain policy → enforcement → receipt | None | `/security` or `/signup` |
| `/security` | Threat model, custody, enforcement boundaries | Versioned public security content | `/developers` or `/signup` |
| `/integrations` | Supported adapter/capability matrix | Public adapter registry | Adapter docs; never imply unsupported adapter |
| `/developers` | SDK, API, MCP, CLI docs | OpenAPI/schema/docs release | Quickstart or console |
| `/login` | Authentication | Auth provider | Allowlisted local `returnTo`, else `/app/overview` |
| `/app/overview` | Tenant operational dashboard | Agents, active policy counts, pending approvals, alerts | Agent/policy/approval/activity detail |
| `/app/agents` | Agent registry | Agent list | `/app/agents/{agentId}` |
| `/app/agents/{agentId}` | Agent detail/key lifecycle | Agent + policies + activity | Policy detail, rotate key, revoke grants |
| `/app/policies` | Policy registry | Policy list/revisions/status | `/app/policies/new` or `/app/policies/{policyId}` |
| `/app/policies/new` | Draft typed policy | Create draft | `/app/policies/{policyId}/edit` |
| `/app/policies/{policyId}` | Immutable revision overview | Revision + grant + lifecycle | `/edit`, `/simulate`, `/revoke`, `/activity` |
| `/app/policies/{policyId}/edit` | Create next revision, never mutate active revision | Create draft revision | Back to policy review |
| `/app/policies/{policyId}/simulate` | Read-only intent/policy preflight | Simulate action | Policy detail; never submits tx |
| `/app/approvals` | Human queue | Held action requests | Exact action review then approve/deny |
| `/app/activity` | Cross-tenant authorized audit feed | Decisions, executions, receipts | Action/receipt detail |
| `/app/activity/{actionId}` | One action's event timeline | Action + receipt + matched policy | Policy/agent detail |
| `/app/settings/team` | Members/roles | Membership CRUD | Team settings |
| `/app/settings/accounts` | Linked wallet/smart accounts | Account adapter state | Account detail / integration docs |
| `/app/settings/integrations` | Provider/network integrations | Adapter status; secrets via secure setup flow | Integration details |

### Page shell and domain ownership

- Public shell: product nav, public docs, footer. No private tenant data.
- Authenticated shell: organization picker, role-aware nav, environment/network indicator, consistent alert center.
- `overview` composes read APIs; it does not become a second source of policy/agent data.
- Policy wizard, detail, simulation, and revocation all use the Policy application module. Detail screens show exact policy version/hash and adapter capability.
- Approvals use the Approval module and bind every button to an immutable action hash; approving does not directly send altered calldata.
- Activity is a projection over audit events and chain receipts; click-through opens the canonical action detail route.

## 11. Routing and redirection rules (prevent overlap/misroutes)

1. Maintain one typed route manifest with route ID, path, auth requirement, role requirement, data loader, and allowed parent shell. Generate navigation and route tests from it.
2. Reserve `/api/v1/*`, `/mcp/*`, `/auth/*`, and `/health/*` for backend endpoints. The web router never swallows these namespaces with its SPA fallback.
3. Route specificity is explicit: `/app/policies/new` and `/app/policies/{id}/edit` resolve before generic policy detail. Validate `{id}` as the expected opaque ID; malformed IDs get a 404, not a fallback to another page.
4. Only `/app/*` requires login. A protected deep link redirects to `/login?returnTo=<encoded-local-path>`; accept only a same-origin relative path beginning `/app/`. Reject absolute URLs, protocol-relative URLs, and encoded traversal.
5. After sign-in, return to a still-authorized route; otherwise send to `/app/overview` with an access message. Do not send every authorization error to overview, which hides the real 403.
6. Unknown paths return a real not-found page. They do not silently redirect to `/` or `/app/overview`.
7. Legacy paths receive individually declared permanent redirects (for example `/dashboard` → `/app/overview`); no broad catch-all aliases.
8. A missing entity is 404; an existing entity in another tenant is 404 to avoid leaking existence; a known resource without role access is 403 within the authorized tenant.
9. After create/update/revoke actions, redirect to the canonical resource route and show state from the backend response. Do not infer success from a button click or optimistic browser state.
10. Use POST/Redirect/GET for browser form mutations; preserve idempotency keys across a retry, not across a new user intention.

### Route test matrix

- Public pages load with no session; app pages redirect to login with a safe local `returnTo`.
- Auth callback preserves a valid deep link and rejects absolute/external redirect URLs.
- Static routes (`new`, `settings`, `activity`) never parse as IDs.
- Every dynamic detail route tests valid, malformed, missing, cross-tenant, and insufficient-role cases.
- Direct refresh/deep links and trailing-slash normalization resolve to one canonical route.
- API/MCP paths never return the frontend HTML shell; unknown API paths return typed JSON 404.
- Mutation success redirects to its canonical detail; failure preserves form input and shows the backend reason.

## 12. Build order and architecture decisions

### Phase A — validate and freeze scope

Confirm one treasury workflow, supported smart-account adapter on Monad, policy fields that are truly enforceable, required human approvers, and customer deployment expectations. Keep one adapter and a bounded action set.

### Phase B — core domain before UI

Write canonical schemas, state machines, reason codes, threat model, and contract invariants. Test canonicalization and policy decisions before building pages.

### Phase C — enforcement slice

Implement one account adapter, owner grant/revoke, exact action binding, nonces, expiry, counters, and deny cases. Prove bypass attempts fail. Don't call an escrow demo a reusable smart-account adapter.

### Phase D — application services / adapters

Build policy, approval, execution, receipt, and audit modules behind ports. Add Postgres transaction/outbox behavior and deterministic idempotency tests.

### Phase E — interfaces

Expose the same services through REST, SDK, MCP, and CLI. Build console pages from the route table; no parallel business logic in frontend or MCP.

### Phase F — production qualification

Run contract fuzz/invariant suites, adapter conformance tests, concurrency/replay/reorg/failover drills, independent review, and a monitored test deployment. Mainnet real-fund support is a later explicit release gate.

### Initial ADRs

- **ADR-001:** Modular monolith + separate worker/indexer processes; avoid premature service fragmentation.
- **ADR-002:** Postgres is authoritative for organization/policy workflow; chain/account is authoritative for on-chain execution constraints.
- **ADR-003:** No private-key custody by Mandate; provider/account adapter owns signing enforcement.
- **ADR-004:** Typed policy AST with versioned deterministic evaluator; no user-authored executable policy.
- **ADR-005:** REST/SDK/MCP/CLI all call the same application services and decision engine.
- **ADR-006:** Unknown policy terms, stale required inputs, and unsupported adapters deny by default.
- **ADR-007:** One explicit Monad smart-account adapter first; portability is earned through tested adapters.

## 13. Inspiration research / architecture references

- AgentLedger documents quote → evaluate → record/reserve → sign → settle/reconcile; it says a failed required measurement blocks and its agent signing permission is constrained by Privy as a second boundary. [AgentLedger docs](https://useagentledger.xyz/docs/)
- AgentLedger's public preview labels its data synthetic; its public ledger describes company-owned agent activity. Its docs state that a hash chain alone cannot prove removal before the first fetched entry. Treat these as transparent design notes, not independent verification. [Preview](https://useagentledger.xyz/demo/) · [Ledger](https://useagentledger.xyz/ledger/)
- ERC-7715 defines wallet permission requests; ERC-7710 defines delegation redemption/validation. Treat as integration standards, not Mandate-owned replacements. [ERC-7715](https://eips.ethereum.org/EIPS/eip-7715) · [ERC-7710](https://eips.ethereum.org/EIPS/eip-7710)
- Safe documents agent spending limits and warns modules are security-critical. [Safe agent spending limits](https://docs.safe.global/home/ai-agent-quickstarts/agent-with-spending-limit) · [Safe modules](https://docs.safe.global/advanced/smart-account-modules)
- Privy documents wallet policies for transfers, recipients, contracts, and calldata. [Privy policies](https://docs.privy.io/security/wallet-infrastructure/policy-and-controls)
- Monad developer setup and network details. [Monad Developer Portal](https://developers.monad.xyz/)

## 14. Open questions (do not hard-code assumptions)

- Which specific DAO/treasury action is frequent and valuable enough to justify Mandate?
- Which supported Monad smart-account framework will provide the execution hook/module boundary?
- Does the chosen adapter enforce the exact target, selector, parameters, value, nonce, and aggregate budget atomically?
- What details can be public on-chain, and what belongs in encrypted organization data?
- Who can issue, amend, approve, revoke, and recover policies in an organization?
- How is an action treated during RPC outage, chain reorg, delayed finality, or lost indexer cursor?
- What evidence and deployment model would a real treasury operator require before production use?
