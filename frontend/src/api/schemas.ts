import { z } from 'zod';

const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const dateTime = z.string();
export const HumanProfileSchema = z.object({
  principal: z.object({ type: z.literal('HUMAN'), subject: z.string() }),
  organizations: z.array(z.object({ organizationId: z.string(), role: z.string() })),
});
export const AgentListSchema = z.object({ agents: z.array(z.object({ id: z.string(), displayName: z.string(), status: z.enum(['ACTIVE', 'REVOKED']), keyVersion: z.number(), createdAt: dateTime })) });
export const AgentCreatedSchema = z.object({ agent: z.object({ id: z.string(), displayName: z.string(), status: z.literal('ACTIVE'), keyVersion: z.number(), createdAt: dateTime }), credential: z.object({ token: z.string(), shownOnce: z.literal(true) }) });
export const AgentReplaySchema = z.object({ agent: AgentCreatedSchema.shape.agent, replayed: z.literal(true) }).strict();
export const AccountListSchema = z.object({ accounts: z.array(z.object({ id: z.string(), chainId: z.number(), address, adapter: z.literal('evm-smart-account'), status: z.enum(['PAUSED', 'ACTIVE', 'UNSUPPORTED']), createdAt: dateTime, guardAddress: address.nullable(), moduleAddress: address.nullable(), verifiedAt: dateTime.nullable() })) });
export const AccountResultSchema = z.object({ account: AccountListSchema.shape.accounts.element });
export const PolicyListSchema = z.object({ policies: z.array(z.object({ id: z.string(), accountId: z.string(), currentRevision: z.number(), state: z.enum(['DRAFT', 'ACTIVE', 'REVOKED', 'EXPIRED']), revisionHash: z.string(), createdAt: dateTime })) });
export const PolicyRevisionSchema = z.object({
  schemaVersion: z.literal(1), policyId: z.string(), revision: z.number().int().positive(), organizationId: z.string(),
  owner: address, account: address, agentId: z.string(), agentAddress: address, agentKeyVersion: z.number().int().positive(),
  chainId: z.number().int().positive(), adapter: z.literal('evm-smart-account'), target: address,
  selectors: z.array(z.string().regex(/^0x[0-9a-f]{8}$/)).min(1), asset: address, recipients: z.array(address).min(1),
  limits: z.object({ perAction: z.string(), cumulative: z.string(), windowSeconds: z.number().int().positive(), approvalThreshold: z.string().optional(), maxActions: z.number().int().positive().optional() }).strict(),
  validAfter: z.number().int().nonnegative(), expiresAt: z.number().int().nonnegative(), nonceEpoch: z.number().int().nonnegative(),
}).strict().refine((policy) => policy.expiresAt > policy.validAfter, { message: 'Expiry must be later than start time.' });
export const PolicySignaturePlanSchema = z.object({ planId: z.string().uuid(), state: z.literal('AWAITING_SAFE_OWNER_SIGNATURES'), plan: z.record(z.string(), z.json()), replayed: z.literal(true).optional() });
export const PolicyActivationFinalizedSchema = z.object({ planId: z.string().uuid(), policyId: z.string(), policyRevision: z.number().int().positive(), revisionHash: z.string().regex(/^0x[0-9a-f]{64}$/), policyState: z.literal('ACTIVE'), grantState: z.literal('ACTIVE'), finalized: z.record(z.string(), z.json()), replayed: z.literal(true).optional() });
export const PolicyRevocationFinalizedSchema = z.object({ planId: z.string().uuid(), policyId: z.string(), policyRevision: z.number().int().positive(), revisionHash: z.string().regex(/^0x[0-9a-f]{64}$/), previousPolicyEpoch: z.string(), policyEpoch: z.string(), policyState: z.literal('REVOKED'), grantState: z.literal('REVOKED'), finalized: z.record(z.string(), z.json()), replayed: z.literal(true).optional() });
export const AuditEventsSchema = z.object({ events: z.array(z.object({ sequence: z.string(), eventType: z.string(), actorType: z.string(), actorId: z.string(), subjectType: z.string(), subjectId: z.string(), correlationId: z.string(), payload: z.record(z.string(), z.json()), previousHash: z.string().nullable(), eventHash: z.string(), createdAt: dateTime })) });
export const ReceiptsSchema = z.object({ receipts: z.array(z.object({ id: z.string(), actionId: z.string(), chainId: z.number(), transactionHash: z.string(), blockNumber: z.string(), blockHash: z.string(), status: z.enum(['TENTATIVE', 'FINAL', 'REORGED']), observedAt: dateTime })) });
export const AlertsSchema = z.object({ alerts: z.array(z.object({ id: z.string(), eventType: z.string(), title: z.string(), aggregateId: z.string(), createdAt: dateTime })) });
export const MembersSchema = z.object({ members: z.array(z.object({ subject: z.string(), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']), createdAt: dateTime })) });
export const InvitationsSchema = z.object({ invitations: z.array(z.object({ id: z.string(), organizationId: z.string(), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']), state: z.enum(['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED']), expiresAt: dateTime, createdAt: dateTime })) });
export const InvitationCreatedSchema = z.object({ invitation: z.object({ id: z.string(), organizationId: z.string(), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']), state: z.enum(['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED']), expiresAt: dateTime, createdAt: dateTime }), invitationToken: z.string().optional(), shownOnce: z.literal(true).optional(), emailDeliveryQueued: z.literal(true).optional(), replayed: z.literal(true).optional() });
export const ProvidersSchema = z.object({ credentials: z.array(z.object({ provider: z.string(), state: z.string(), maskedSuffix: z.string(), createdAt: dateTime, rotatedAt: dateTime.nullable(), verifiedAt: dateTime.nullable(), disabledAt: dateTime.nullable() })) });
export const ProviderTestSchema = z.object({ ok: z.boolean(), reason: z.string().nullable(), credential: z.object({ provider: z.string(), maskedSuffix: z.string(), state: z.string(), verifiedAt: dateTime.nullable() }).nullable() });
export const WebhooksSchema = z.object({ endpoints: z.array(z.object({ id: z.string(), url: z.string(), eventTypes: z.array(z.string()), enabled: z.boolean(), createdAt: dateTime, updatedAt: dateTime })) });
export const WebhookCreatedSchema = z.object({ endpoint: WebhooksSchema.shape.endpoints.element, signingSecret: z.string(), shownOnce: z.literal(true) });
export const WebhookReplaySchema = z.object({ endpoint: WebhooksSchema.shape.endpoints.element, replayed: z.literal(true) });
export const WebhookRotatedSchema = z.object({ endpointId: z.string(), signingSecret: z.string(), shownOnce: z.literal(true), cleanupPending: z.boolean().optional() });
export const WebhookRotationReplaySchema = z.object({ endpointId: z.string(), replayed: z.literal(true) });
export const WebhookDeliveriesSchema = z.object({ deliveries: z.array(z.object({ id: z.string(), endpointId: z.string(), eventType: z.string(), status: z.enum(['PENDING', 'DELIVERED', 'FAILED']), attempts: z.number().int().nonnegative(), availableAt: dateTime, deliveredAt: dateTime.nullable(), lastErrorCode: z.string().nullable() })) });
export const ActionSchema = z.object({ actionId: z.string(), policyId: z.string(), policyRevision: z.number(), actionHash: z.string(), state: z.string(), verdict: z.string().nullable(), reason: z.string().nullable(), action: z.record(z.string(), z.json()), createdAt: dateTime, updatedAt: dateTime, reservation: z.record(z.string(), z.json()).nullable(), events: z.array(z.record(z.string(), z.json())) });
export const ActionListSchema = z.object({ actions: z.array(z.object({ actionId: z.string(), policyId: z.string(), policyRevision: z.number(), actionHash: z.string(), state: z.string(), verdict: z.string().nullable(), reason: z.string().nullable(), action: z.record(z.string(), z.json()), createdAt: dateTime, updatedAt: dateTime })) });
export const ApiErrorSchema = z.object({ error: z.object({ code: z.string(), message: z.string(), requestId: z.string() }) });

export type HumanProfile = z.infer<typeof HumanProfileSchema>;
export type AgentList = z.infer<typeof AgentListSchema>;
export type AccountList = z.infer<typeof AccountListSchema>;
export type PolicyList = z.infer<typeof PolicyListSchema>;
export type PolicyRevision = z.infer<typeof PolicyRevisionSchema>;
export type AuditEvents = z.infer<typeof AuditEventsSchema>;
export type Receipts = z.infer<typeof ReceiptsSchema>;
export type Alerts = z.infer<typeof AlertsSchema>;
export type Members = z.infer<typeof MembersSchema>;
export type Invitations = z.infer<typeof InvitationsSchema>;
export type Providers = z.infer<typeof ProvidersSchema>;
export type Webhooks = z.infer<typeof WebhooksSchema>;
export type WebhookDeliveries = z.infer<typeof WebhookDeliveriesSchema>;
export type ActionDetail = z.infer<typeof ActionSchema>;
export type ActionList = z.infer<typeof ActionListSchema>;
