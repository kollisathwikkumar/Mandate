import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AccountCreateSchema } from '../../../packages/api-contracts/src/schemas.js';
import { ActionIntentSchema, PolicyRevisionSchema, type ActionIntent, type PolicyRevision } from '../../../packages/policy/src/schema.js';
import type { JsonValue } from '../../../packages/sdk/src/client.js';
import { WEBHOOK_EVENT_TYPES, type WebhookEventType } from '../../../packages/ports/src/webhook.js';

const MODEL_PROVIDERS = ['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER'] as const;
export type CliModelProvider = (typeof MODEL_PROVIDERS)[number];

export interface CliApi {
  listAgents(): Promise<JsonValue>;
  createAgent(agent: { readonly id: string; readonly displayName: string }, idempotencyKey: string): Promise<JsonValue>;
  listPolicies(): Promise<JsonValue>;
  simulateAction(action: ActionIntent): Promise<JsonValue>;
  requestAction(action: ActionIntent): Promise<JsonValue>;
  getAction(actionId: string): Promise<JsonValue | null>;
  getReceipts(limit?: number): Promise<JsonValue>;
  getAuditEvents(limit?: number): Promise<JsonValue>;
  getAlerts(limit?: number): Promise<JsonValue>;
  listModelProviderCredentials(): Promise<JsonValue>;
  setModelProviderCredential(provider: CliModelProvider, apiKey: string, idempotencyKey: string): Promise<JsonValue>;
  deleteModelProviderCredential(provider: CliModelProvider): Promise<JsonValue>;
  testModelProviderCredential(provider: CliModelProvider): Promise<JsonValue>;
  disableModelProviderCredential(provider: CliModelProvider): Promise<JsonValue>;
  createOrganization(displayName: string, idempotencyKey: string): Promise<JsonValue>;
  acceptInvitation(token: string): Promise<JsonValue>;
  createPolicyDraft(revision: PolicyRevision, idempotencyKey: string): Promise<JsonValue>;
  createPolicyRevision(policyId: string, revision: PolicyRevision, idempotencyKey: string): Promise<JsonValue>;
  approveAction(actionId: string, outcome: 'APPROVED' | 'DENIED', actionHash: string, idempotencyKey: string): Promise<JsonValue>;
  getSignedAuditExport(limit?: number, beforeSequence?: string): Promise<JsonValue>;
  listAccounts(): Promise<JsonValue>;
  registerAccount(account: z.input<typeof AccountCreateSchema>, idempotencyKey: string): Promise<JsonValue>;
  verifyAccount(accountId: string, idempotencyKey: string): Promise<JsonValue>;
  listMembers(): Promise<JsonValue>;
  setMemberRole(subject: string, role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER', idempotencyKey: string): Promise<JsonValue>;
  removeMember(subject: string, idempotencyKey: string): Promise<JsonValue>;
  listInvitations(): Promise<JsonValue>;
  createInvitation(email: string, role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER', idempotencyKey: string): Promise<JsonValue>;
  revokeInvitation(invitationId: string, idempotencyKey: string): Promise<JsonValue>;
  preparePolicyActivation(policyId: string, idempotencyKey: string): Promise<JsonValue>;
  finalizePolicyActivation(policyId: string, planId: string, transactionHashes: readonly string[], idempotencyKey: string): Promise<JsonValue>;
  preparePolicyRevocation(policyId: string, idempotencyKey: string): Promise<JsonValue>;
  finalizePolicyRevocation(policyId: string, planId: string, transactionHash: string, idempotencyKey: string): Promise<JsonValue>;
  authorizeAction(actionId: string, idempotencyKey: string): Promise<JsonValue>;
  executeAction(actionId: string, signature: string, rawTransaction: string, idempotencyKey: string): Promise<JsonValue>;
  resolveDeepReorg(actionId: string, disposition: 'CONSUMED' | 'RELEASED', reason: string, idempotencyKey: string, evidenceHash?: string): Promise<JsonValue>;
  listWebhookEndpoints(): Promise<JsonValue>;
  createWebhookEndpoint(url: string, eventTypes: readonly WebhookEventType[], idempotencyKey: string): Promise<JsonValue>;
  setWebhookEndpointEnabled(endpointId: string, enabled: boolean, idempotencyKey: string): Promise<JsonValue>;
  deleteWebhookEndpoint(endpointId: string, idempotencyKey: string): Promise<JsonValue>;
  rotateWebhookSigningSecret(endpointId: string, idempotencyKey: string): Promise<JsonValue>;
  listWebhookDeliveries(endpointId: string, limit?: number): Promise<JsonValue>;
}

export type CliCommand =
  | { readonly kind: 'help' }
  | { readonly kind: 'agents-list' }
  | { readonly kind: 'agents-create'; readonly id: string; readonly displayName: string }
  | { readonly kind: 'policies-list' }
  | { readonly kind: 'action-get'; readonly actionId: string }
  | { readonly kind: 'action-simulate'; readonly input: string }
  | { readonly kind: 'action-request'; readonly input: string }
  | { readonly kind: 'receipts-list' }
  | { readonly kind: 'audit-list' }
  | { readonly kind: 'alerts-list' }
  | { readonly kind: 'model-providers-list' }
  | { readonly kind: 'model-provider-set'; readonly provider: CliModelProvider; readonly keyInput: string }
  | { readonly kind: 'model-provider-delete'; readonly provider: CliModelProvider }
  | { readonly kind: 'model-provider-test'; readonly provider: CliModelProvider }
  | { readonly kind: 'model-provider-disable'; readonly provider: CliModelProvider }
  | { readonly kind: 'organization-create'; readonly displayName: string }
  | { readonly kind: 'invitation-accept'; readonly tokenInput: string }
  | { readonly kind: 'policy-create'; readonly input: string }
  | { readonly kind: 'policy-revise'; readonly policyId: string; readonly input: string }
  | { readonly kind: 'action-approve'; readonly actionId: string; readonly outcome: 'APPROVED' | 'DENIED'; readonly actionHash: string }
  | { readonly kind: 'action-authorize'; readonly actionId: string }
  | { readonly kind: 'action-execute'; readonly actionId: string; readonly signatureInput: string; readonly transactionInput: string }
  | { readonly kind: 'action-resolve-reorg'; readonly actionId: string; readonly input: string }
  | { readonly kind: 'audit-export'; readonly limit: number; readonly beforeSequence?: string }
  | { readonly kind: 'account-list' }
  | { readonly kind: 'account-register'; readonly input: string }
  | { readonly kind: 'account-verify'; readonly accountId: string }
  | { readonly kind: 'member-list' }
  | { readonly kind: 'member-set-role'; readonly subject: string; readonly role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER' }
  | { readonly kind: 'member-remove'; readonly subject: string }
  | { readonly kind: 'invitation-list' }
  | { readonly kind: 'invitation-create'; readonly email: string; readonly role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER' }
  | { readonly kind: 'invitation-revoke'; readonly invitationId: string }
  | { readonly kind: 'policy-activate'; readonly policyId: string }
  | { readonly kind: 'policy-activate-finalize'; readonly policyId: string; readonly input: string }
  | { readonly kind: 'policy-revoke'; readonly policyId: string }
  | { readonly kind: 'policy-revoke-finalize'; readonly policyId: string; readonly input: string }
  | { readonly kind: 'webhook-list' }
  | { readonly kind: 'webhook-create'; readonly input: string }
  | { readonly kind: 'webhook-enable'; readonly endpointId: string; readonly enabled: boolean }
  | { readonly kind: 'webhook-delete'; readonly endpointId: string }
  | { readonly kind: 'webhook-rotate-secret'; readonly endpointId: string }
  | { readonly kind: 'webhook-deliveries'; readonly endpointId: string; readonly limit: number };

export const CLI_USAGE = `Mandate CLI
  mandate agents list
  mandate agents create <agent-id> <display-name>
  mandate policies list
  mandate policies create <@revision-json|->
  mandate policies revise <policy-id> <@revision-json|->
  mandate policies activate <policy-id>
  mandate policies activate-finalize <policy-id> <@finalize-json|->
  mandate policies revoke <policy-id>
  mandate policies revoke-finalize <policy-id> <@finalize-json|->
  mandate actions get <action-id>
  mandate actions simulate <@json-file|->
  mandate actions request <@json-file|->
  mandate actions approve <action-id> <APPROVED|DENIED> <action-hash>
  mandate actions authorize <action-id>
  mandate actions execute <action-id> <@signature-file|-> <@raw-transaction-file|->
  mandate actions resolve-reorg <action-id> <@json-file|->
  mandate accounts list
  mandate accounts register <@account-json|->
  mandate accounts verify <account-id>
  mandate members list
  mandate members set-role <subject> <OWNER|ADMIN|APPROVER|VIEWER>
  mandate members remove <subject>
  mandate invitations list
  mandate invitations create <email> <OWNER|ADMIN|APPROVER|VIEWER>
  mandate invitations revoke <invitation-id>
  mandate receipts list
  mandate audit list
  mandate audit export [limit] [before-sequence]
  mandate alerts list
  mandate webhooks list
  mandate webhooks create <@webhook-json|->
  mandate webhooks enable <endpoint-id>
  mandate webhooks disable <endpoint-id>
  mandate webhooks delete <endpoint-id>
  mandate webhooks rotate-secret <endpoint-id>
  mandate webhooks deliveries <endpoint-id> [limit]
  mandate model-providers list
  mandate model-providers set <DEEPSEEK|OPENAI|ANTHROPIC|OTHER> <@key-file|->
  mandate model-providers test <DEEPSEEK|OPENAI|ANTHROPIC|OTHER>
  mandate model-providers disable <DEEPSEEK|OPENAI|ANTHROPIC|OTHER>
  mandate model-providers delete <DEEPSEEK|OPENAI|ANTHROPIC|OTHER>
  mandate organizations create <display-name>
  mandate invitations accept <@token-file|->

Configure MANDATE_API_URL and MANDATE_API_TOKEN. Set MANDATE_ORGANIZATION_ID when the identity has multiple organizations.
Provider keys are read from a file or stdin so they do not appear in command history.`;

export function parseCliCommand(args: readonly string[]): CliCommand {
  if (args.length === 0 || args[0] === 'help' || args[0] === '--help' || args[0] === '-h') return { kind: 'help' };
  const [resource, verb, first, second] = args;
  if (resource === 'agents' && verb === 'list' && args.length === 2) return { kind: 'agents-list' };
  if (resource === 'agents' && verb === 'create' && args.length === 4 && first !== undefined && second !== undefined) {
    return { kind: 'agents-create', id: first, displayName: second };
  }
  if (resource === 'policies' && verb === 'list' && args.length === 2) return { kind: 'policies-list' };
  if (resource === 'policies' && verb === 'create' && args.length === 3 && first !== undefined) return { kind: 'policy-create', input: jsonReference(first) };
  if (resource === 'policies' && verb === 'revise' && args.length === 4 && first !== undefined && second !== undefined) {
    return { kind: 'policy-revise', policyId: first, input: jsonReference(second) };
  }
  if (resource === 'policies' && verb === 'activate' && args.length === 3 && first !== undefined) return { kind: 'policy-activate', policyId: first };
  if (resource === 'policies' && verb === 'activate-finalize' && args.length === 4 && first !== undefined && second !== undefined) {
    return { kind: 'policy-activate-finalize', policyId: first, input: jsonReference(second) };
  }
  if (resource === 'policies' && verb === 'revoke' && args.length === 3 && first !== undefined) return { kind: 'policy-revoke', policyId: first };
  if (resource === 'policies' && verb === 'revoke-finalize' && args.length === 4 && first !== undefined && second !== undefined) {
    return { kind: 'policy-revoke-finalize', policyId: first, input: jsonReference(second) };
  }
  if (resource === 'actions' && verb === 'get' && args.length === 3 && first !== undefined) return { kind: 'action-get', actionId: first };
  if (resource === 'actions' && verb === 'simulate' && args.length === 3 && first !== undefined) return { kind: 'action-simulate', input: first };
  if (resource === 'actions' && verb === 'request' && args.length === 3 && first !== undefined) return { kind: 'action-request', input: first };
  if (resource === 'actions' && verb === 'approve' && args.length === 5 && first !== undefined && second !== undefined && args[4] !== undefined) {
    const outcome = z.enum(['APPROVED', 'DENIED']).parse(second);
    const actionHash = z.string().regex(/^0x[0-9a-f]{64}$/).parse(args[4]);
    return { kind: 'action-approve', actionId: first, outcome, actionHash };
  }
  if (resource === 'actions' && verb === 'authorize' && args.length === 3 && first !== undefined) return { kind: 'action-authorize', actionId: first };
  if (resource === 'actions' && verb === 'execute' && args.length === 5 && first !== undefined && second !== undefined && args[4] !== undefined) {
    return { kind: 'action-execute', actionId: first, signatureInput: secretReference(second), transactionInput: secretReference(args[4]) };
  }
  if (resource === 'actions' && verb === 'resolve-reorg' && args.length === 4 && first !== undefined && second !== undefined) {
    return { kind: 'action-resolve-reorg', actionId: first, input: jsonReference(second) };
  }
  if (resource === 'accounts' && verb === 'list' && args.length === 2) return { kind: 'account-list' };
  if (resource === 'accounts' && verb === 'register' && args.length === 3 && first !== undefined) return { kind: 'account-register', input: jsonReference(first) };
  if (resource === 'accounts' && verb === 'verify' && args.length === 3 && first !== undefined) return { kind: 'account-verify', accountId: first };
  if (resource === 'members' && verb === 'list' && args.length === 2) return { kind: 'member-list' };
  if (resource === 'members' && verb === 'set-role' && args.length === 4 && first !== undefined && second !== undefined) {
    return { kind: 'member-set-role', subject: first, role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']).parse(second) };
  }
  if (resource === 'members' && verb === 'remove' && args.length === 3 && first !== undefined) return { kind: 'member-remove', subject: first };
  if (resource === 'receipts' && verb === 'list' && args.length === 2) return { kind: 'receipts-list' };
  if (resource === 'audit' && verb === 'list' && args.length === 2) return { kind: 'audit-list' };
  if (resource === 'audit' && verb === 'export' && args.length <= 4) {
    const limit = args[2] === undefined ? 1_000 : positiveInteger(args[2], 10_000, 'audit export limit');
    const beforeSequence = args[3] === undefined ? undefined : z.string().regex(/^[1-9][0-9]{0,18}$/).parse(args[3]);
    return { kind: 'audit-export', limit, ...(beforeSequence === undefined ? {} : { beforeSequence }) };
  }
  if (resource === 'alerts' && verb === 'list' && args.length === 2) return { kind: 'alerts-list' };
  if (resource === 'webhooks' && verb === 'list' && args.length === 2) return { kind: 'webhook-list' };
  if (resource === 'webhooks' && verb === 'create' && args.length === 3 && first !== undefined) return { kind: 'webhook-create', input: jsonReference(first) };
  if (resource === 'webhooks' && (verb === 'enable' || verb === 'disable') && args.length === 3 && first !== undefined) {
    return { kind: 'webhook-enable', endpointId: first, enabled: verb === 'enable' };
  }
  if (resource === 'webhooks' && verb === 'delete' && args.length === 3 && first !== undefined) return { kind: 'webhook-delete', endpointId: first };
  if (resource === 'webhooks' && verb === 'rotate-secret' && args.length === 3 && first !== undefined) return { kind: 'webhook-rotate-secret', endpointId: first };
  if (resource === 'webhooks' && verb === 'deliveries' && args.length >= 3 && args.length <= 4 && first !== undefined) {
    return { kind: 'webhook-deliveries', endpointId: first, limit: args[3] === undefined ? 25 : positiveInteger(args[3], 100, 'delivery limit') };
  }
  if (resource === 'organizations' && verb === 'create' && args.length >= 3) {
    const displayName = args.slice(2).join(' ').trim();
    if (displayName.length < 1 || displayName.length > 160) throw new Error('Organization name must contain 1 to 160 characters');
    return { kind: 'organization-create', displayName };
  }
  if (resource === 'invitations' && verb === 'accept' && args.length === 3 && first !== undefined) {
    if (first !== '-' && !/^@[^\s]+$/.test(first)) throw new Error('Use @file or - to read the invitation token; do not pass it as a literal command-line argument');
    return { kind: 'invitation-accept', tokenInput: first };
  }
  if (resource === 'invitations' && verb === 'list' && args.length === 2) return { kind: 'invitation-list' };
  if (resource === 'invitations' && verb === 'create' && args.length === 4 && first !== undefined && second !== undefined) {
    const email = z.string().trim().email().max(254).parse(first);
    return { kind: 'invitation-create', email, role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']).parse(second) };
  }
  if (resource === 'invitations' && verb === 'revoke' && args.length === 3 && first !== undefined) return { kind: 'invitation-revoke', invitationId: z.string().uuid().parse(first) };
  if (resource === 'model-providers' && verb === 'list' && args.length === 2) return { kind: 'model-providers-list' };
  if (resource === 'model-providers' && ['set', 'test', 'disable', 'delete'].includes(verb ?? '')) {
    const provider = z.enum(MODEL_PROVIDERS).safeParse(first);
    if (!provider.success) throw new Error(`Invalid model provider. Expected one of ${MODEL_PROVIDERS.join(', ')}`);
    if (verb === 'set' && args.length === 4 && second !== undefined) {
      if (second !== '-' && !/^@[^\s]+$/.test(second)) throw new Error('Use @file or - to read a provider key; do not pass a literal key on the command line');
      return { kind: 'model-provider-set', provider: provider.data, keyInput: second };
    }
    if (args.length === 3 && verb === 'test') return { kind: 'model-provider-test', provider: provider.data };
    if (args.length === 3 && verb === 'disable') return { kind: 'model-provider-disable', provider: provider.data };
    if (args.length === 3 && verb === 'delete') return { kind: 'model-provider-delete', provider: provider.data };
  }
  throw new Error(`Invalid Mandate CLI command.\n${CLI_USAGE}`);
}

function jsonReference(value: string): string {
  if (value !== '-' && !/^@[^\u0000\s]+$/.test(value)) throw new Error('Use @file or - to read JSON input');
  return value;
}

function secretReference(value: string): string {
  if (value !== '-' && !/^@[^\u0000\s]+$/.test(value)) throw new Error('Use @file or - to read sensitive input; do not pass it as a literal command-line argument');
  return value;
}

function positiveInteger(value: string, maximum: number, label: string): number {
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${label} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) throw new Error(`${label} must be between 1 and ${maximum}`);
  return parsed;
}

export function parseActionInput(value: JsonValue): ActionIntent {
  return ActionIntentSchema.parse(value);
}

export async function executeCliCommand(
  command: CliCommand,
  api: CliApi,
  readAction: (reference: string) => Promise<ActionIntent>,
  readSecret: (reference: string) => Promise<string> = async () => { throw new Error('Provider-key input reader is not configured'); },
  readJson: (reference: string) => Promise<JsonValue> = async () => { throw new Error('JSON input reader is not configured'); },
): Promise<JsonValue | null> {
  switch (command.kind) {
    case 'help': return { usage: CLI_USAGE };
    case 'agents-list': return api.listAgents();
    case 'agents-create': return api.createAgent({ id: command.id, displayName: command.displayName }, randomUUID());
    case 'policies-list': return api.listPolicies();
    case 'action-get': return api.getAction(command.actionId);
    case 'action-simulate': return api.simulateAction(await readAction(command.input));
    case 'action-request': return api.requestAction(await readAction(command.input));
    case 'receipts-list': return api.getReceipts();
    case 'audit-list': return api.getAuditEvents();
    case 'alerts-list': return api.getAlerts();
    case 'model-providers-list': return api.listModelProviderCredentials();
    case 'model-provider-set': {
      const apiKey = (await readSecret(command.keyInput)).trim();
      if (apiKey.length < 16 || apiKey.length > 4096) throw new Error('Provider key must contain 16 to 4096 characters');
      return api.setModelProviderCredential(command.provider, apiKey, randomUUID());
    }
    case 'model-provider-delete': return api.deleteModelProviderCredential(command.provider);
    case 'model-provider-test': return api.testModelProviderCredential(command.provider);
    case 'model-provider-disable': return api.disableModelProviderCredential(command.provider);
    case 'organization-create': return api.createOrganization(command.displayName, randomUUID());
    case 'invitation-accept': {
      const token = (await readSecret(command.tokenInput)).trim();
      if (!/^[A-Za-z0-9_-]{40,128}$/.test(token)) throw new Error('Invitation token input is invalid');
      return api.acceptInvitation(token);
    }
    case 'policy-create': return api.createPolicyDraft(PolicyRevisionSchema.parse(await readJson(command.input)), randomUUID());
    case 'policy-revise': return api.createPolicyRevision(command.policyId, PolicyRevisionSchema.parse(await readJson(command.input)), randomUUID());
    case 'action-approve': return api.approveAction(command.actionId, command.outcome, command.actionHash, randomUUID());
    case 'action-authorize': return api.authorizeAction(command.actionId, randomUUID());
    case 'action-execute': {
      const signature = (await readSecret(command.signatureInput)).trim();
      const rawTransaction = (await readSecret(command.transactionInput)).trim();
      return api.executeAction(command.actionId, signature, rawTransaction, randomUUID());
    }
    case 'action-resolve-reorg': {
      const body = z.object({
        disposition: z.enum(['CONSUMED', 'RELEASED']), reason: z.string().min(1).max(1000),
        evidenceHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
      }).strict().parse(await readJson(command.input));
      return api.resolveDeepReorg(command.actionId, body.disposition, body.reason, randomUUID(), body.evidenceHash);
    }
    case 'audit-export': return api.getSignedAuditExport(command.limit, command.beforeSequence);
    case 'account-list': return api.listAccounts();
    case 'account-register': return api.registerAccount(AccountCreateSchema.parse(await readJson(command.input)), randomUUID());
    case 'account-verify': return api.verifyAccount(command.accountId, randomUUID());
    case 'member-list': return api.listMembers();
    case 'member-set-role': return api.setMemberRole(command.subject, command.role, randomUUID());
    case 'member-remove': return api.removeMember(command.subject, randomUUID());
    case 'invitation-list': return api.listInvitations();
    case 'invitation-create': return api.createInvitation(command.email, command.role, randomUUID());
    case 'invitation-revoke': return api.revokeInvitation(command.invitationId, randomUUID());
    case 'policy-activate': return api.preparePolicyActivation(command.policyId, randomUUID());
    case 'policy-activate-finalize': {
      const body = z.object({ planId: z.string().uuid(), transactionHashes: z.array(z.string().regex(/^0x[0-9a-fA-F]{64}$/)).min(1).max(32) }).strict().parse(await readJson(command.input));
      return api.finalizePolicyActivation(command.policyId, body.planId, body.transactionHashes, randomUUID());
    }
    case 'policy-revoke': return api.preparePolicyRevocation(command.policyId, randomUUID());
    case 'policy-revoke-finalize': {
      const body = z.object({ planId: z.string().uuid(), transactionHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }).strict().parse(await readJson(command.input));
      return api.finalizePolicyRevocation(command.policyId, body.planId, body.transactionHash, randomUUID());
    }
    case 'webhook-list': return api.listWebhookEndpoints();
    case 'webhook-create': {
      const body = z.object({ url: z.string().min(1).max(2048), eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1).max(30) }).strict().parse(await readJson(command.input));
      return api.createWebhookEndpoint(body.url, body.eventTypes, randomUUID());
    }
    case 'webhook-enable': return api.setWebhookEndpointEnabled(command.endpointId, command.enabled, randomUUID());
    case 'webhook-delete': return api.deleteWebhookEndpoint(command.endpointId, randomUUID());
    case 'webhook-rotate-secret': return api.rotateWebhookSigningSecret(command.endpointId, randomUUID());
    case 'webhook-deliveries': return api.listWebhookDeliveries(command.endpointId, command.limit);
  }
}
