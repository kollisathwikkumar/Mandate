import { z } from 'zod';
import { AccountCreateSchema, AgentCreateSchema, AgentCreatedResponseSchema, AgentSummarySchema, ApiErrorSchema } from '../../../packages/api-contracts/src/schemas.js';
import { ActionIntentSchema, PolicyRevisionSchema } from '../../../packages/policy/src/schema.js';
import { POLICY_REASON_CODES } from '../../../packages/domain/src/reason-code.js';
import { ACTION_STATES } from '../../../packages/domain/src/action-state.js';
import { WEBHOOK_EVENT_TYPES } from '../../../packages/ports/src/webhook.js';

const agentListResponseSchema = z.object({ agents: z.array(AgentSummarySchema) }).strict();
const accountSummarySchema = z.object({
  id: z.string(), chainId: z.number().int().positive().safe(), address: z.string().regex(/^0x[0-9a-f]{40}$/),
  adapter: z.literal('evm-smart-account'), status: z.enum(['PAUSED', 'ACTIVE', 'UNSUPPORTED']), createdAt: z.string().datetime(),
  guardAddress: z.string().regex(/^0x[0-9a-f]{40}$/).nullable(),
  moduleAddress: z.string().regex(/^0x[0-9a-f]{40}$/).nullable(),
  verifiedAt: z.string().datetime().nullable(),
}).strict();
const accountListResponseSchema = z.object({ accounts: z.array(accountSummarySchema) }).strict();
const accountCreateResponseSchema = z.object({ account: accountSummarySchema }).strict();
const accountReplayResponseSchema = accountCreateResponseSchema.extend({ replayed: z.literal(true) }).strict();
const accountVerificationResponseSchema = z.union([accountCreateResponseSchema, accountReplayResponseSchema]);
const humanProfileSchema = z.object({
  principal: z.object({ type: z.literal('HUMAN'), subject: z.string() }).strict(),
  organizations: z.array(z.object({ organizationId: z.string(), role: z.string() }).strict()),
}).strict();
const agentReplaySchema = z.object({ agent: AgentSummarySchema.extend({ status: z.literal('ACTIVE') }), replayed: z.literal(true) }).strict();
const policyWriteSchema = z.object({
  policyId: z.string(),
  revision: z.number().int().positive(),
  state: z.literal('DRAFT'),
  revisionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
}).strict();
const policyReplaySchema = policyWriteSchema.extend({ replayed: z.literal(true) }).strict();
const policyActivationPlanSchema = z.object({
  planId: z.string().uuid(),
  state: z.literal('AWAITING_SAFE_OWNER_SIGNATURES'),
  plan: z.record(z.string(), z.json()),
  replayed: z.literal(true).optional(),
}).strict();
const policyFinalizationResponseSchema = z.object({
  planId: z.string().uuid(),
  policyId: z.string(),
  policyRevision: z.number().int().positive(),
  revisionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  policyState: z.literal('ACTIVE'),
  grantState: z.literal('ACTIVE'),
  finalized: z.record(z.string(), z.json()),
  replayed: z.literal(true).optional(),
}).strict();
const policyRevocationPlanSchema = z.object({
  planId: z.string().uuid(), state: z.literal('AWAITING_SAFE_OWNER_SIGNATURES'),
  plan: z.record(z.string(), z.json()), replayed: z.literal(true).optional(),
}).strict();
const policyRevocationFinalizationResponseSchema = z.object({
  planId: z.string().uuid(), policyId: z.string(), policyRevision: z.number().int().positive(),
  revisionHash: z.string().regex(/^0x[0-9a-f]{64}$/), previousPolicyEpoch: z.string(), policyEpoch: z.string(),
  policyState: z.literal('REVOKED'), grantState: z.literal('REVOKED'), finalized: z.record(z.string(), z.json()),
  replayed: z.literal(true).optional(),
}).strict();
const policySimulationSchema = z.object({
  verdict: z.enum(['ALLOW', 'HOLD', 'BLOCK']),
  reason: z.enum(POLICY_REASON_CODES),
  policyRevisionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
}).strict();
const policyListSchema = z.object({
  policies: z.array(z.object({
    id: z.string(), accountId: z.string(), currentRevision: z.number().int().positive(),
    state: z.enum(['DRAFT', 'ACTIVE', 'REVOKED', 'EXPIRED']), revisionHash: z.string(), createdAt: z.string().datetime(),
  }).strict()),
}).strict();
const actionSubmissionSchema = z.object({
  actionId: z.string(), state: z.enum(['BLOCKED', 'HELD', 'RESERVED']),
  verdict: z.enum(['BLOCK', 'HOLD', 'ALLOW']), reason: z.enum(POLICY_REASON_CODES),
  policyRevisionHash: z.string().regex(/^0x[0-9a-f]{64}$/), reservationExpiresAt: z.string().datetime().nullable(),
}).strict();
const actionAuthorizationResponseSchema = z.object({
  actionId: z.string(), state: z.literal('AUTHORIZED'), authorization: z.record(z.string(), z.json()),
  replayed: z.literal(true).optional(),
}).strict();
const actionExecutionResponseSchema = z.object({
  actionId: z.string(), state: z.literal('SUBMITTED'), transactionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  replayed: z.literal(true).optional(),
}).strict();
const actionReplaySchema = actionSubmissionSchema.extend({ replayed: z.literal(true) }).strict();
const actionApprovalSchema = z.object({
  actionId: z.string(), state: z.enum(['RESERVED', 'DENIED', 'EXPIRED']), verdict: z.enum(['ALLOW', 'BLOCK']),
  reason: z.enum(['HUMAN_APPROVED', 'APPROVAL_DENIED', 'ACTION_EXPIRED']), actionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
}).strict();
const actionApprovalReplaySchema = actionApprovalSchema.extend({ replayed: z.literal(true) }).strict();
const actionDeepReorgResolutionSchema = z.object({
  actionId: z.string(), actionState: z.literal('REORGED'), reservationState: z.enum(['CONSUMED', 'RELEASED']),
  disposition: z.enum(['CONSUMED', 'RELEASED']), reason: z.string(), evidenceHash: z.string().regex(/^0x[0-9a-f]{64}$/).nullable(),
  actorSubject: z.string(), resolvedAt: z.string().datetime(),
  incident: z.object({ blockNumber: z.number().int().nonnegative(), previousBlockHash: z.string().regex(/^0x[0-9a-f]{64}$/), canonicalBlockHash: z.string().regex(/^0x[0-9a-f]{64}$/) }).strict(),
  replayed: z.literal(true).optional(),
}).strict();
const auditEventSchema = z.object({
  sequence: z.string(), eventType: z.string(), actorType: z.string(), actorId: z.string(), subjectType: z.string(),
  subjectId: z.string(), correlationId: z.string(), payload: z.record(z.string(), z.json()),
  previousHash: z.string().nullable(), eventHash: z.string(), createdAt: z.string().datetime(),
}).strict();
const signedAuditExportSchema = z.object({
  payload: z.object({
    schemaVersion: z.literal(1), organizationId: z.string(), exportedAt: z.string().datetime(),
    fromSequence: z.string().nullable(), throughSequence: z.string().nullable(), events: z.array(auditEventSchema),
    integrityNotice: z.literal('Signatures and hash links provide tamper evidence, not proof of source truth or completeness.'),
  }).strict(),
  canonicalPayload: z.string(), algorithm: z.literal('Ed25519'), keyId: z.string(), publicKeyPem: z.string(),
  keyFingerprint: z.string().regex(/^[0-9a-f]{64}$/), signature: z.string(),
}).strict();
const actionDetailSchema = z.object({
  actionId: z.string(), policyId: z.string(), policyRevision: z.number().int().positive(), actionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  state: z.enum(ACTION_STATES), verdict: z.enum(['ALLOW', 'BLOCK', 'HOLD']).nullable(), reason: z.enum(POLICY_REASON_CODES).nullable(),
  action: ActionIntentSchema, createdAt: z.string().datetime(), updatedAt: z.string().datetime(),
  reservation: z.object({ state: z.enum(['ACTIVE', 'CONSUMED', 'RELEASED', 'EXPIRED']), amount: z.string(), leaseExpiresAt: z.string().datetime() }).strict().nullable(),
  events: z.array(auditEventSchema),
}).strict();
const actionListItemSchema = actionDetailSchema.omit({ reservation: true, events: true }).strict();
const actionListSchema = z.object({ actions: z.array(actionListItemSchema) }).strict();
const receiptSchema = z.object({
  id: z.string(), actionId: z.string(), chainId: z.number().int().positive(), transactionHash: z.string(),
  blockNumber: z.string(), blockHash: z.string(), status: z.enum(['TENTATIVE', 'FINAL', 'REORGED']),
  receipt: z.record(z.string(), z.json()), observedAt: z.string().datetime(),
}).strict();
const alertSchema = z.object({
  id: z.string(), eventType: z.string(), title: z.string(), aggregateId: z.string(), createdAt: z.string().datetime(),
}).strict();
const organizationMemberSchema = z.object({ subject: z.string(), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']), createdAt: z.string().datetime() }).strict();
const organizationMemberListSchema = z.object({ members: z.array(organizationMemberSchema) }).strict();
const organizationMemberWriteSchema = z.object({ member: organizationMemberSchema, replayed: z.literal(true).optional() }).strict();
const organizationInvitationSchema = z.object({
  id: z.string().uuid(), organizationId: z.string(), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']),
  state: z.enum(['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED']), expiresAt: z.string().datetime(), createdAt: z.string().datetime(),
}).strict();
const organizationInvitationCreateResponseSchema = z.object({ invitation: organizationInvitationSchema, invitationToken: z.string().optional(), shownOnce: z.literal(true).optional(), emailDeliveryQueued: z.literal(true).optional(), replayed: z.literal(true).optional() }).strict();
const organizationInvitationListSchema = z.object({ invitations: z.array(organizationInvitationSchema) }).strict();
const organizationInvitationAcceptResponseSchema = z.object({ organizationId: z.string(), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']), accepted: z.literal(true), replayed: z.literal(true).optional() }).strict();
const organizationCreatedSchema = z.object({ organization: z.object({ organizationId: z.string(), displayName: z.string(), role: z.literal('OWNER'), createdAt: z.string().datetime() }).strict(), replayed: z.literal(true).optional() }).strict();
const webhookEndpointSchema = z.object({
  id: z.string().uuid(), url: z.string(), eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)), enabled: z.boolean(),
  createdAt: z.string().datetime(), updatedAt: z.string().datetime(),
}).strict();
const webhookEndpointListSchema = z.object({ endpoints: z.array(webhookEndpointSchema) }).strict();
const webhookCreateSchema = z.object({ url: z.string().min(1).max(2048), eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1).max(30) }).strict();
const webhookCreatedSchema = z.object({ endpoint: webhookEndpointSchema, signingSecret: z.string(), shownOnce: z.literal(true) }).strict();
const webhookReplaySchema = z.object({ endpoint: webhookEndpointSchema, replayed: z.literal(true) }).strict();
const webhookDeliverySchema = z.object({
  id: z.string().uuid(), endpointId: z.string().uuid(), eventType: z.string(), status: z.enum(['PENDING', 'DELIVERED', 'FAILED']),
  attempts: z.number().int().nonnegative(), availableAt: z.string().datetime(), deliveredAt: z.string().datetime().nullable(), lastErrorCode: z.string().nullable(),
}).strict();
const webhookDeliveryListSchema = z.object({ deliveries: z.array(webhookDeliverySchema) }).strict();
const agentProfileSchema = z.object({
  principal: z.object({ type: z.literal('AGENT'), organizationId: z.string(), agentId: z.string(), keyVersion: z.number().int() }).strict(),
}).strict();

const ref = (name: string): { readonly $ref: string } => ({ $ref: `#/components/schemas/${name}` });
const jsonContent = <T extends object>(schema: T) => ({ 'application/json': { schema } });

export const openApiDocument = {
  openapi: '3.1.0',
  info: { title: 'Mandate API', version: '1.0.0', description: 'Tenant-scoped agent identity and policy-control API. Except for health probes and the OpenAPI document, /api/v1 requests are limited to 120 per source IP per 60-second window by default. Exhaustion returns 429 RATE_LIMITED and RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, and Retry-After headers.' },
  paths: {
    '/health/live': { get: { operationId: 'getLiveness', responses: { '200': { description: 'Process is live' } } } },
    '/health/ready': { get: { operationId: 'getReadiness', responses: { '200': { description: 'Dependencies are ready' }, '503': { description: 'A required dependency is unavailable' } } } },
    '/api/v1/openapi.json': { get: { operationId: 'getOpenApiDocument', responses: { '200': { description: 'OpenAPI 3.1 specification' } } } },
    '/api/v1/me': {
      get: {
        operationId: 'getCurrentPrincipal',
        security: [{ bearerAuth: [] }],
        responses: {
          '200': { description: 'Authenticated human or agent principal', content: jsonContent(z.toJSONSchema(z.union([humanProfileSchema, agentProfileSchema]))) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs': {
      post: {
        operationId: 'createOrganization', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } }],
        requestBody: { required: true, content: jsonContent({ type: 'object', properties: { displayName: { type: 'string', minLength: 1, maxLength: 160 } }, required: ['displayName'], additionalProperties: false }) },
        responses: {
          '201': { description: 'Organization created with the authenticated human as initial owner', content: jsonContent(ref('OrganizationCreated')) },
          '200': { description: 'Idempotent replay of organization creation', content: jsonContent(ref('OrganizationCreated')) },
          '400': { description: 'Invalid name or missing idempotency key', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'A human principal is required', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Idempotency key conflict', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/accounts': {
      get: {
        operationId: 'listOrganizationAccounts', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Tenant-scoped account records and enforcement status', content: jsonContent(ref('AccountList')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant is not visible to this principal', content: jsonContent(ref('ApiError')) },
        },
      },
      post: {
        operationId: 'registerOrganizationAccount', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(ref('AccountCreate')) },
        responses: {
          '201': { description: 'Account registered paused pending on-chain verification', content: jsonContent(ref('AccountCreated')) },
          '200': { description: 'Idempotent replay', content: jsonContent(ref('AccountReplay')) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Owner or administrator role required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant is not visible to this principal', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Account or idempotency conflict', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/accounts/{accountId}/verify': {
      post: {
        operationId: 'verifyOrganizationAccountEnrollment', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'accountId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        responses: {
          '200': { description: 'On-chain Safe guard/module enrollment verified', content: jsonContent(ref('AccountVerificationResult')) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Owner or administrator role required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Account or tenant was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Registered account is not correctly enrolled on-chain', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Configured chain RPC is unavailable', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/agents': {
      get: {
        operationId: 'listOrganizationAgents',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Agents visible in this tenant', content: jsonContent(ref('AgentList')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant is not visible to this principal', content: jsonContent(ref('ApiError')) },
        },
      },
      post: {
        operationId: 'registerOrganizationAgent',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(ref('AgentCreate')) },
        responses: {
          '201': { description: 'Agent registered; credential is returned once', content: jsonContent(ref('AgentCreated')) },
          '200': { description: 'Idempotent replay; credential is not repeated', content: jsonContent(ref('AgentReplay')) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Principal cannot register agents', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant is not visible to this principal', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Resource or idempotency conflict', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies': {
      get: {
        operationId: 'listOrganizationPolicies',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          '200': { description: 'Tenant-scoped policy summaries', content: jsonContent(ref('PolicyList')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant is not visible to this principal', content: jsonContent(ref('ApiError')) },
        },
      },
      post: {
        operationId: 'createPolicyDraft',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(ref('PolicyRevision')) },
        responses: {
          '201': { description: 'Revision-1 draft created', content: jsonContent(ref('PolicyWrite')) },
          '200': { description: 'Idempotent replay', content: jsonContent(ref('PolicyReplay')) },
          '400': { description: 'Invalid policy contract', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Owner or administrator role required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Account, agent, or tenant was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Policy or idempotency conflict', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/revisions': {
      post: {
        operationId: 'createImmutablePolicyRevision',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(ref('PolicyRevision')) },
        responses: {
          '201': { description: 'New immutable draft revision created', content: jsonContent(ref('PolicyWrite')) },
          '200': { description: 'Idempotent replay', content: jsonContent(ref('PolicyReplay')) },
          '400': { description: 'Invalid policy contract', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Owner or administrator role required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Policy or tenant was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Revision number, policy, or idempotency conflict', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/revisions/{revision}': {
      get: {
        operationId: 'getImmutablePolicyRevision', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'revision', in: 'path', required: true, schema: { type: 'integer', minimum: 1 } },
        ],
        responses: {
          '200': { description: 'Tenant-scoped canonical policy revision body', content: jsonContent(ref('PolicyRevision')) },
          '400': { description: 'Invalid revision identifier', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Policy revision or tenant was not found', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/activate': {
      post: {
        operationId: 'preparePolicyActivation',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        responses: {
          '201': { description: 'Persisted Safe owner-signature plan; no policy grant becomes active until a finalized Safe transaction is verified', content: jsonContent(policyActivationPlanSchema) },
          '200': { description: 'Idempotent replay of the same Safe owner-signature plan', content: jsonContent(policyActivationPlanSchema) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Organization owner required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Policy or organization was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Policy, enrollment, chain epoch, or idempotency conflict', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Configured chain RPC is unavailable', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/activate/finalize': {
      post: {
        operationId: 'finalizePolicyActivation',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(z.toJSONSchema(z.object({
          planId: z.string().uuid(), transactionHashes: z.array(z.string().regex(/^0x[0-9a-fA-F]{64}$/)).min(1).max(32),
        }).strict())) },
        responses: {
          '200': { description: 'Owner Safe execution receipts are final and the policy/grant are atomically ACTIVE', content: jsonContent(policyFinalizationResponseSchema) },
          '400': { description: 'Invalid request or transaction hashes', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Organization owner required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Activation plan or organization was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Receipt is unsuccessful, not final, mismatched, or the policy state changed', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Configured chain finality verification is unavailable', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/revoke': {
      post: {
        operationId: 'preparePolicyRevocation', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        responses: {
          '201': { description: 'Persisted Safe owner-signature revocation plan; the policy remains active until finalized', content: jsonContent(policyRevocationPlanSchema) },
          '200': { description: 'Idempotent replay of the same revocation plan', content: jsonContent(policyRevocationPlanSchema) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Organization owner required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Policy or organization was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Policy, enrollment, chain epoch, or idempotency conflict', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Configured chain RPC is unavailable', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/revoke/finalize': {
      post: {
        operationId: 'finalizePolicyRevocation', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(z.toJSONSchema(z.object({
          planId: z.string().uuid(), transactionHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
        }).strict())) },
        responses: {
          '200': { description: 'Finalized Safe revocation receipt; policy and grant atomically transition to REVOKED', content: jsonContent(policyRevocationFinalizationResponseSchema) },
          '400': { description: 'Invalid request or transaction hash', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Organization owner required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Revocation plan or organization was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Receipt is unsuccessful, not final, mismatched, or policy state changed', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Configured chain finality verification is unavailable', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/policies/{policyId}/simulate': {
      post: {
        operationId: 'simulatePolicyAction',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'policyId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        requestBody: { required: true, content: jsonContent(ref('ActionIntent')) },
        responses: {
          '200': { description: 'Deterministic preflight only; this operation creates no action or reservation', content: jsonContent(ref('PolicySimulation')) },
          '400': { description: 'Invalid action request', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Human principal required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant, policy, or account is not visible', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/actions': {
      get: {
        operationId: 'listOrganizationActions', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'state', in: 'query', required: false, schema: { type: 'string', enum: ACTION_STATES } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100, default: 50 } },
        ],
        responses: {
          '200': { description: 'Tenant-scoped action summaries; agent principals see only their own actions', content: jsonContent(actionListSchema) },
          '400': { description: 'Invalid list filters', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Organization is not visible to this principal', content: jsonContent(ref('ApiError')) },
        },
      },
      post: {
        operationId: 'requestAgentAction',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(ref('ActionIntent')) },
        responses: {
          '201': { description: 'Action evaluated; a bounded reservation is created for ALLOW/HOLD, with no transaction submitted', content: jsonContent(ref('ActionSubmission')) },
          '200': { description: 'Idempotent replay', content: jsonContent(ref('ActionReplay')) },
          '400': { description: 'Invalid action request', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Agent credential does not match the action', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant or policy was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Action or idempotency conflict', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/actions/{actionId}/approval': {
      post: {
        operationId: 'decideHeldAction',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'actionId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(z.toJSONSchema(z.object({ outcome: z.enum(['APPROVED', 'DENIED']), actionHash: z.string().regex(/^0x[0-9a-f]{64}$/) }).strict())) },
        responses: {
          '201': { description: 'Exact held action approved or denied', content: jsonContent(ref('ActionApproval')) },
          '200': { description: 'Idempotent replay', content: jsonContent(ref('ActionApprovalReplay')) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Approver role required; policy author cannot approve their own policy action', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Tenant or action was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Action is no longer pending or hash does not match', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/actions/{actionId}/reorg-resolution': {
      post: {
        operationId: 'resolveDeepReorgReservation', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'actionId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(z.toJSONSchema(z.object({
          disposition: z.enum(['CONSUMED', 'RELEASED']), reason: z.string().trim().min(1).max(1000),
          evidenceHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
        }).strict())) },
        responses: {
          '201': { description: 'Owner records a durable reservation disposition; the action, attempt, receipt, and paused account remain REORGED/PAUSED', content: jsonContent(z.toJSONSchema(actionDeepReorgResolutionSchema)) },
          '200': { description: 'Idempotent replay of the same resolution', content: jsonContent(z.toJSONSchema(actionDeepReorgResolutionSchema)) },
          '400': { description: 'Invalid resolution request', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Organization OWNER role required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Organization or action was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Action is not an unresolved deep reorg or the idempotency key conflicts', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/actions/{actionId}/authorize': {
      post: {
        operationId: 'authorizeReservedAgentAction', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'actionId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        responses: {
          '201': { description: 'Exact action-bound agent EIP-712 authorization prepared and persisted; no chain transaction is submitted', content: jsonContent(ref('ActionAuthorization')) },
          '200': { description: 'Idempotent replay of the same authorization', content: jsonContent(ref('ActionAuthorization')) },
          '400': { description: 'Invalid request', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'An agent credential matching the action is required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Action or tenant was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Action, active grant, reservation, policy epoch, or idempotency conflict', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Configured chain RPC is unavailable', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/actions/{actionId}/execute': {
      post: {
        operationId: 'executeAuthorizedAgentAction', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'actionId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(z.object({
          signature: z.string().regex(/^0x(?:[0-9a-fA-F]{2}){65}$/), rawTransaction: z.string().max(262146).regex(/^0x(?:[0-9a-fA-F]{2})+$/),
        }).strict()) },
        responses: {
          '201': { description: 'Caller-signed transaction broadcast and submission state atomically recorded; Mandate never signs it', content: jsonContent(ref('ActionExecution')) },
          '200': { description: 'Idempotent replay of the same transaction; a pending transaction is rebroadcast byte-for-byte', content: jsonContent(ref('ActionExecution')) },
          '400': { description: 'Invalid agent signature or signed transaction', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'An agent credential matching the action is required', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Action or tenant was not found', content: jsonContent(ref('ApiError')) },
          '409': { description: 'Authorization is stale or the action/idempotency key is bound to another transaction', content: jsonContent(ref('ApiError')) },
          '503': { description: 'RPC unavailable; retry the same signed bytes and idempotency key', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/actions/{actionId}': {
      get: {
        operationId: 'getOrganizationAction',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'actionId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: {
          '200': { description: 'Tenant-scoped action detail and audit timeline', content: jsonContent(ref('ActionDetail')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '404': { description: 'Action is not visible to this principal', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/audit-events': {
      get: {
        operationId: 'listOrganizationAuditEvents', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100, default: 50 } },
          { name: 'beforeSequence', in: 'query', required: false, schema: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' } },
        ],
        responses: { '200': { description: 'Tenant-scoped audit events in descending sequence order', content: jsonContent(z.toJSONSchema(z.object({ events: z.array(auditEventSchema) }).strict())) }, '400': { description: 'Invalid pagination', content: jsonContent(ref('ApiError')) } },
      },
    },
    '/api/v1/orgs/{orgId}/audit-exports': {
      get: {
        operationId: 'createSignedOrganizationAuditExport', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 10000, default: 1000 } },
          { name: 'beforeSequence', in: 'query', required: false, schema: { type: 'string', pattern: '^[1-9][0-9]{0,18}$' } },
        ],
        responses: {
          '200': { description: 'OWNER/ADMIN-only Ed25519-signed tamper-evident audit export; signature does not prove source truth or completeness', content: jsonContent(z.toJSONSchema(signedAuditExportSchema)) },
          '400': { description: 'Invalid export pagination', content: jsonContent(ref('ApiError')) },
          '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) },
          '403': { description: 'Owner or administrator role required', content: jsonContent(ref('ApiError')) },
          '503': { description: 'Audit signing key is not configured', content: jsonContent(ref('ApiError')) },
        },
      },
    },
    '/api/v1/orgs/{orgId}/receipts': {
      get: {
        operationId: 'listOrganizationReceipts', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100, default: 50 } },
          { name: 'actionId', in: 'query', required: false, schema: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' } },
        ],
        responses: { '200': { description: 'Tenant-scoped indexed chain receipts', content: jsonContent(z.toJSONSchema(z.object({ receipts: z.array(receiptSchema) }).strict())) }, '400': { description: 'Invalid pagination', content: jsonContent(ref('ApiError')) } },
      },
    },
    '/api/v1/orgs/{orgId}/alerts': {
      get: {
        operationId: 'listOrganizationAlerts', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100, default: 50 } },
        ],
        responses: { '200': { description: 'Tenant-scoped materialized alert notifications', content: jsonContent(z.toJSONSchema(z.object({ alerts: z.array(alertSchema) }).strict())) }, '400': { description: 'Invalid pagination', content: jsonContent(ref('ApiError')) } },
      },
    },
    '/api/v1/orgs/{orgId}/members': {
      get: {
        operationId: 'listOrganizationMembers', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Tenant members and roles', content: jsonContent(ref('OrganizationMemberList')) }, '404': { description: 'Tenant is not visible to this principal', content: jsonContent(ref('ApiError')) } },
      },
    },
    '/api/v1/orgs/{orgId}/invitations': {
      get: {
        operationId: 'listOrganizationInvitations', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Tenant invitation metadata; no email or token is returned', content: jsonContent(ref('OrganizationInvitationList')) }, '403': { description: 'Organization administrator required' }, '404': { description: 'Organization not found' } },
      },
      post: {
        operationId: 'createOrganizationInvitation', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } }],
        requestBody: { required: true, content: jsonContent({ type: 'object', properties: { email: { type: 'string', format: 'email', maxLength: 254 }, role: { type: 'string', enum: ['OWNER', 'ADMIN', 'APPROVER', 'VIEWER'] } }, required: ['email', 'role'], additionalProperties: false }) },
        responses: { '201': { description: 'Invitation created; token is shown once, and emailDeliveryQueued is true when automated delivery is configured', content: jsonContent(ref('OrganizationInvitationCreateResponse')) }, '200': { description: 'Invitation replay; secret token is not repeated', content: jsonContent(ref('OrganizationInvitationCreateResponse')) }, '403': { description: 'Organization administrator required; only owners may invite an owner' }, '409': { description: 'Idempotency key conflict' } },
      },
    },
    '/api/v1/orgs/{orgId}/invitations/{invitationId}': {
      delete: {
        operationId: 'revokeOrganizationInvitation', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'invitationId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }, { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } }],
        responses: { '204': { description: 'Pending invitation revoked or request replayed' }, '403': { description: 'Organization administrator required' }, '404': { description: 'Invitation not found' }, '409': { description: 'Invitation already accepted, expired, or revoked; or idempotency conflict' } },
      },
    },
    '/api/v1/invitations/accept': {
      post: {
        operationId: 'acceptOrganizationInvitation', security: [{ bearerAuth: [] }],
        requestBody: { required: true, content: jsonContent({ type: 'object', properties: { token: { type: 'string', minLength: 40, maxLength: 128 } }, required: ['token'], additionalProperties: false }) },
        responses: { '200': { description: 'Invitation accepted or idempotently replayed for the same verified identity', content: jsonContent(ref('OrganizationInvitationAcceptResponse')) }, '401': { description: 'Missing or invalid bearer credential', content: jsonContent(ref('ApiError')) }, '403': { description: 'Verified human email claim required', content: jsonContent(ref('ApiError')) }, '404': { description: 'Invitation does not match the authenticated verified email', content: jsonContent(ref('ApiError')) }, '409': { description: 'Invitation is expired, closed, or identity is already a member', content: jsonContent(ref('ApiError')) } },
      },
    },
    '/api/v1/orgs/{orgId}/members/{subject}': {
      put: {
        operationId: 'setOrganizationMemberRole', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'subject', in: 'path', required: true, schema: { type: 'string', minLength: 1, maxLength: 255 } }, { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } }],
        requestBody: { required: true, content: jsonContent({ type: 'object', properties: { role: { type: 'string', enum: ['OWNER', 'ADMIN', 'APPROVER', 'VIEWER'] } }, required: ['role'], additionalProperties: false }) },
        responses: { '201': { description: 'Member added', content: jsonContent(ref('OrganizationMemberWrite')) }, '200': { description: 'Member role updated or idempotently replayed', content: jsonContent(ref('OrganizationMemberWrite')) }, '403': { description: 'Administrator required; only an owner can grant owner role' }, '409': { description: 'Idempotency conflict or last-owner invariant' } },
      },
      delete: {
        operationId: 'removeOrganizationMember', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'subject', in: 'path', required: true, schema: { type: 'string', minLength: 1, maxLength: 255 } }, { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } }],
        responses: { '204': { description: 'Membership removed' }, '403': { description: 'Administrator required; only an owner can remove an owner' }, '409': { description: 'Idempotency conflict or last-owner invariant' } },
      },
    },
    '/api/v1/orgs/{orgId}/webhooks': {
      get: {
        operationId: 'listWebhookEndpoints', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Organization webhook endpoints; signing secrets are never returned', content: jsonContent(ref('WebhookEndpointList')) }, '403': { description: 'Organization administrator role required' }, '404': { description: 'Organization not found' } },
      },
      post: {
        operationId: 'createWebhookEndpoint', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent(ref('WebhookCreate')) },
        responses: {
          '201': { description: 'Endpoint created; signingSecret is returned once', content: jsonContent(ref('WebhookCreated')) },
          '200': { description: 'Idempotent replay; signing secret is not repeated', content: jsonContent(ref('WebhookReplay')) },
          '400': { description: 'Invalid or non-public HTTPS destination' }, '403': { description: 'Organization administrator role required' }, '409': { description: 'Idempotency conflict' },
        },
      },
    },
    '/api/v1/orgs/{orgId}/webhooks/{endpointId}': {
      patch: {
        operationId: 'setWebhookEndpointEnabled', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'endpointId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        requestBody: { required: true, content: jsonContent({ type: 'object', properties: { enabled: { type: 'boolean' } }, required: ['enabled'], additionalProperties: false }) },
        responses: { '200': { description: 'Endpoint updated' }, '403': { description: 'Organization administrator role required' }, '404': { description: 'Endpoint not found' }, '409': { description: 'Idempotency conflict' } },
      },
      delete: {
        operationId: 'deleteWebhookEndpoint', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'endpointId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        responses: { '204': { description: 'Endpoint disabled, removed from lists, and signing secret deleted' }, '403': { description: 'Organization administrator role required' }, '404': { description: 'Endpoint not found' }, '503': { description: 'Secret cleanup pending; retry with the same idempotency key' } },
      },
    },
    '/api/v1/orgs/{orgId}/webhooks/{endpointId}/rotate-secret': {
      post: {
        operationId: 'rotateWebhookSigningSecret', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'endpointId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
          { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } },
        ],
        responses: { '200': { description: 'New signingSecret returned once; cleanupPending indicates old secret deletion needs retry' }, '403': { description: 'Organization administrator role required' }, '404': { description: 'Endpoint not found' }, '409': { description: 'Idempotency conflict or prior cleanup pending' } },
      },
    },
    '/api/v1/orgs/{orgId}/webhooks/{endpointId}/deliveries': {
      get: {
        operationId: 'listWebhookDeliveries', security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'orgId', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'endpointId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
          { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100, default: 25 } },
        ],
        responses: { '200': { description: 'Latest delivery attempts and coarse outcomes', content: jsonContent(ref('WebhookDeliveryList')) }, '403': { description: 'Organization administrator role required' }, '404': { description: 'Endpoint not found' } },
      },
    },
    '/api/v1/orgs/{orgId}/integrations/model-providers': {
      get: {
        operationId: 'listModelProviderIntegrations', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Masked organization model-provider credential metadata', content: jsonContent({ type: 'object', properties: { credentials: { type: 'array', items: { $ref: '#/components/schemas/ModelProviderCredential' } } }, required: ['credentials'], additionalProperties: false }) } },
      },
    },
    '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}': {
      put: {
        operationId: 'setModelProviderCredential', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'provider', in: 'path', required: true, schema: { type: 'string', enum: ['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER'] } }, { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string', minLength: 1, maxLength: 200 } }],
        requestBody: { required: true, content: jsonContent({ type: 'object', properties: { apiKey: { type: 'string', minLength: 16, maxLength: 4096, writeOnly: true } }, required: ['apiKey'], additionalProperties: false }) },
        responses: { '201': { description: 'Credential stored; only masked metadata returned' } },
      },
      delete: {
        operationId: 'deleteModelProviderCredential', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'provider', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '204': { description: 'Credential disabled and removed' } },
      },
    },
    '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}/test': {
      post: {
        operationId: 'testModelProviderCredential', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'provider', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Provider API-key connection test result; no inference request is made' } },
      },
    },
    '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}/disable': {
      post: {
        operationId: 'disableModelProviderCredential', security: [{ bearerAuth: [] }],
        parameters: [{ name: 'orgId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'provider', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Credential disabled; secret retained for later re-enable or deletion' } },
      },
    },
  },
  components: {
    securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT or Mandate agent token' } },
    schemas: {
      AgentCreate: z.toJSONSchema(AgentCreateSchema),
      AccountCreate: z.toJSONSchema(AccountCreateSchema, { io: 'input' }),
      Account: z.toJSONSchema(accountSummarySchema),
      AccountCreated: z.toJSONSchema(accountCreateResponseSchema),
      AccountReplay: z.toJSONSchema(accountReplayResponseSchema),
      AccountVerificationResult: z.toJSONSchema(accountVerificationResponseSchema),
      AccountList: z.toJSONSchema(accountListResponseSchema),
      Agent: z.toJSONSchema(AgentSummarySchema),
      AgentCreated: z.toJSONSchema(AgentCreatedResponseSchema),
      AgentList: z.toJSONSchema(agentListResponseSchema),
      AgentReplay: z.toJSONSchema(agentReplaySchema),
      PolicyRevision: z.toJSONSchema(PolicyRevisionSchema, { io: 'input' }),
      PolicyWrite: z.toJSONSchema(policyWriteSchema),
      PolicyReplay: z.toJSONSchema(policyReplaySchema),
      PolicyList: z.toJSONSchema(policyListSchema),
      PolicySimulation: z.toJSONSchema(policySimulationSchema),
      ActionIntent: z.toJSONSchema(ActionIntentSchema, { io: 'input' }),
      ActionSubmission: z.toJSONSchema(actionSubmissionSchema),
      ActionReplay: z.toJSONSchema(actionReplaySchema),
      ActionAuthorization: z.toJSONSchema(actionAuthorizationResponseSchema),
      ActionExecution: z.toJSONSchema(actionExecutionResponseSchema),
      ActionApproval: z.toJSONSchema(actionApprovalSchema),
      ActionApprovalReplay: z.toJSONSchema(actionApprovalReplaySchema),
      ActionDeepReorgResolution: z.toJSONSchema(actionDeepReorgResolutionSchema),
      ActionDetail: z.toJSONSchema(actionDetailSchema, { io: 'input' }),
      ActionList: z.toJSONSchema(actionListSchema, { io: 'input' }),
      AuditEvent: z.toJSONSchema(auditEventSchema),
      Receipt: z.toJSONSchema(receiptSchema),
      Alert: z.toJSONSchema(alertSchema),
      ModelProviderCredential: { type: 'object', properties: { provider: { type: 'string' }, maskedSuffix: { type: 'string' }, state: { type: 'string' }, createdAt: { type: 'string', format: 'date-time' }, rotatedAt: { type: ['string', 'null'], format: 'date-time' }, verifiedAt: { type: ['string', 'null'], format: 'date-time' }, disabledAt: { type: ['string', 'null'], format: 'date-time' } }, required: ['provider', 'maskedSuffix', 'state', 'createdAt', 'rotatedAt', 'verifiedAt', 'disabledAt'], additionalProperties: false },
      OrganizationMember: z.toJSONSchema(organizationMemberSchema),
      OrganizationMemberList: z.toJSONSchema(organizationMemberListSchema),
      OrganizationMemberWrite: z.toJSONSchema(organizationMemberWriteSchema),
      OrganizationInvitationCreateResponse: z.toJSONSchema(organizationInvitationCreateResponseSchema),
      OrganizationInvitationList: z.toJSONSchema(organizationInvitationListSchema),
      OrganizationInvitationAcceptResponse: z.toJSONSchema(organizationInvitationAcceptResponseSchema),
      OrganizationCreated: z.toJSONSchema(organizationCreatedSchema),
      WebhookEndpoint: z.toJSONSchema(webhookEndpointSchema),
      WebhookEndpointList: z.toJSONSchema(webhookEndpointListSchema),
      WebhookCreate: z.toJSONSchema(webhookCreateSchema, { io: 'input' }),
      WebhookCreated: z.toJSONSchema(webhookCreatedSchema),
      WebhookReplay: z.toJSONSchema(webhookReplaySchema),
      WebhookDelivery: z.toJSONSchema(webhookDeliverySchema),
      WebhookDeliveryList: z.toJSONSchema(webhookDeliveryListSchema),
      HumanProfile: z.toJSONSchema(humanProfileSchema),
      AgentProfile: z.toJSONSchema(agentProfileSchema),
      ApiError: z.toJSONSchema(ApiErrorSchema),
    },
  },
} as const;
