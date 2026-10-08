import { z } from 'zod';
import { API_ERROR_CODES, AccountCreateSchema, AgentCreateSchema, ApiErrorSchema } from '../../api-contracts/src/schemas.js';
import { ActionIntentSchema, PolicyRevisionSchema, type ActionIntent, type PolicyRevision } from '../../policy/src/schema.js';
import { WEBHOOK_EVENT_TYPES } from '../../ports/src/webhook.js';

export const JsonValueSchema = z.json();
export type JsonValue = z.infer<typeof JsonValueSchema>;

const OrganizationIdSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);
const HumanIdentitySchema = z.object({
  principal: z.object({ type: z.literal('HUMAN'), subject: z.string().min(1) }).strict(),
  organizations: z.array(z.object({ organizationId: OrganizationIdSchema, role: z.string() }).strict()).optional(),
}).strict();
const AgentIdentitySchema = z.object({
  principal: z.object({ type: z.literal('AGENT'), organizationId: OrganizationIdSchema, agentId: z.string().min(1), keyVersion: z.number().int().positive() }).strict(),
}).strict();

export interface MandateClientContext {
  readonly organizationId: string | null;
  readonly principalType: 'HUMAN' | 'AGENT';
}

export interface MandateClientOptions {
  readonly apiUrl: string;
  readonly token: string;
  readonly organizationId?: string | null;
  readonly timeoutMs?: number;
  readonly fetcher?: typeof fetch;
}

export class MandateApiError extends Error {
  constructor(
    message: string,
    readonly code: (typeof API_ERROR_CODES)[number] | `HTTP_${number}` | 'INVALID_RESPONSE',
    readonly statusCode: number,
    readonly requestId: string | null,
    readonly retryAfterSeconds: number | null,
  ) {
    super(message);
    this.name = 'MandateApiError';
  }
}

function parseApiUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('MANDATE_API_URL must be an absolute URL'); }
  const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);
  if (url.username || url.password || url.search || url.hash
    || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopbackHosts.has(url.hostname)))) {
    throw new Error('MANDATE_API_URL must be HTTPS (HTTP only for loopback development) without credentials, query, or fragment');
  }
  return url;
}

function resolveContext(identityValue: JsonValue, organizationId: string | null | undefined): MandateClientContext {
  const agentIdentity = AgentIdentitySchema.safeParse(identityValue);
  if (agentIdentity.success) {
    const resolvedOrganization = agentIdentity.data.principal.organizationId;
    if (organizationId !== undefined && organizationId !== null && OrganizationIdSchema.parse(organizationId) !== resolvedOrganization) {
      throw new Error('MANDATE_ORGANIZATION_ID does not match the authenticated agent organization');
    }
    return { organizationId: resolvedOrganization, principalType: 'AGENT' };
  }
  const identity = HumanIdentitySchema.parse(identityValue);
  const organizations = identity.organizations ?? [];
  if (organizationId !== undefined && organizationId !== null) {
    const selected = OrganizationIdSchema.parse(organizationId);
    if (!organizations.some((organization) => organization.organizationId === selected)) {
      throw new Error('MANDATE_ORGANIZATION_ID is not present in the authenticated identity');
    }
    return { organizationId: selected, principalType: 'HUMAN' };
  }
  if (organizations.length === 0) return { organizationId: null, principalType: 'HUMAN' };
  if (organizations.length > 1) throw new Error('MANDATE_ORGANIZATION_ID is required when identity has multiple organizations');
  const resolvedOrganization = organizations[0]?.organizationId;
  if (resolvedOrganization === undefined) throw new Error('MANDATE_API_INVALID_IDENTITY');
  return { organizationId: resolvedOrganization, principalType: 'HUMAN' };
}

export class MandateClient {
  public readonly context: MandateClientContext;

  private constructor(
    private readonly apiUrl: URL,
    private readonly token: string,
    context: MandateClientContext,
    private readonly fetcher: typeof fetch,
    private readonly timeoutMs: number,
  ) {
    this.context = context;
  }

  public static async connect(options: MandateClientOptions): Promise<MandateClient> {
    const apiUrl = parseApiUrl(options.apiUrl);
    if (!/^[A-Za-z0-9._~-]{16,4096}$/.test(options.token)) throw new Error('MANDATE_API_TOKEN is invalid');
    const timeoutMs = options.timeoutMs ?? 8_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) throw new Error('MANDATE_API_TIMEOUT_MS must be between 100 and 120000');
    const fetcher = options.fetcher ?? fetch;
    const pending = new MandateClient(apiUrl, options.token, { organizationId: 'pending', principalType: 'HUMAN' }, fetcher, timeoutMs);
    const identity = await pending.requestJson('/api/v1/me', { method: 'GET' });
    const context = resolveContext(identity, options.organizationId);
    return new MandateClient(apiUrl, options.token, context, fetcher, timeoutMs);
  }

  private async requestJson(path: string, init: RequestInit): Promise<JsonValue> {
    const url = new URL(path, this.apiUrl.origin);
    const headers = new Headers(init.headers);
    headers.set('authorization', `Bearer ${this.token}`);
    headers.set('accept', 'application/json');
    if (init.body !== undefined && init.body !== null) headers.set('content-type', 'application/json');
    let response: Response;
    try {
      response = await this.fetcher(url, { ...init, headers, signal: AbortSignal.timeout(this.timeoutMs) });
    } catch {
      throw new MandateApiError('Mandate API request failed', 'HTTP_0', 0, null, null);
    }
    const responseText = await response.text();
    if (response.status === 204) return null;
    let parsed: ReturnType<typeof JsonValueSchema.safeParse>;
    try { parsed = JsonValueSchema.safeParse(JSON.parse(responseText || 'null')); }
    catch { throw new MandateApiError('Mandate API returned an invalid JSON response', 'INVALID_RESPONSE', response.status, null, null); }
    if (!parsed.success) throw new MandateApiError('Mandate API returned an invalid JSON response', 'INVALID_RESPONSE', response.status, null, null);
    if (!response.ok) {
      const apiError = ApiErrorSchema.safeParse(parsed.data);
      const retryAfterHeader = response.headers.get('retry-after');
      const retryAfterSeconds = retryAfterHeader !== null && /^[1-9][0-9]*$/.test(retryAfterHeader) ? Number(retryAfterHeader) : null;
      if (apiError.success) {
        throw new MandateApiError(apiError.data.error.message, apiError.data.error.code, response.status, apiError.data.error.requestId, retryAfterSeconds);
      }
      throw new MandateApiError('Mandate API request failed', `HTTP_${response.status}`, response.status, null, retryAfterSeconds);
    }
    return parsed.data;
  }

  private organizationPath(path: string): string {
    if (this.context.organizationId === null) throw new Error('Select an organization before making organization-scoped requests');
    return `/api/v1/orgs/${encodeURIComponent(this.context.organizationId)}${path}`;
  }

  private requireHuman(): void {
    if (this.context.principalType !== 'HUMAN') throw new Error('This operation requires a human principal');
  }

  private async getJson(path: string): Promise<JsonValue> {
    return this.requestJson(path, { method: 'GET' });
  }

  private async postJson<T>(path: string, body: T, idempotencyKey?: string): Promise<JsonValue> {
    const headers = new Headers();
    if (idempotencyKey !== undefined) {
      if (idempotencyKey.trim() === '' || idempotencyKey.length > 200) throw new Error('Idempotency-Key must contain 1 to 200 characters');
      headers.set('idempotency-key', idempotencyKey);
    }
    return this.requestJson(path, { method: 'POST', headers, body: JSON.stringify(body) });
  }

  private async writeJson<T>(method: 'PUT' | 'PATCH', path: string, body: T, idempotencyKey?: string): Promise<JsonValue> {
    const headers = new Headers();
    if (idempotencyKey !== undefined) {
      if (idempotencyKey.trim() === '' || idempotencyKey.length > 200) throw new Error('Idempotency-Key must contain 1 to 200 characters');
      headers.set('idempotency-key', idempotencyKey);
    }
    return this.requestJson(path, { method, headers, body: JSON.stringify(body) });
  }

  private async deleteJson(path: string, idempotencyKey?: string): Promise<JsonValue> {
    const headers = new Headers();
    if (idempotencyKey !== undefined) {
      if (idempotencyKey.trim() === '' || idempotencyKey.length > 200) throw new Error('Idempotency-Key must contain 1 to 200 characters');
      headers.set('idempotency-key', idempotencyKey);
    }
    return this.requestJson(path, { method: 'DELETE', headers });
  }

  public async createOrganization(displayName: string, idempotencyKey: string): Promise<JsonValue> {
    this.requireHuman();
    // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
    const body = z.object({ displayName: z.string().trim().min(1).max(160).refine((value) => !/[\u0000-\u001f\u007f]/.test(value)) }).strict().parse({ displayName });
    return this.postJson('/api/v1/orgs', body, idempotencyKey);
  }

  public async acceptInvitation(token: string): Promise<JsonValue> {
    this.requireHuman();
    const body = z.object({ token: z.string().min(40).max(128).regex(/^[A-Za-z0-9_-]+$/) }).strict().parse({ token });
    return this.postJson('/api/v1/invitations/accept', body);
  }

  public async selectOrganization(organizationId: string): Promise<MandateClient> {
    const selected = OrganizationIdSchema.parse(organizationId);
    const identity = await this.getJson('/api/v1/me');
    const context = resolveContext(identity, selected);
    return new MandateClient(this.apiUrl, this.token, context, this.fetcher, this.timeoutMs);
  }

  public async listAgents(): Promise<JsonValue> { return this.getJson(this.organizationPath('/agents')); }
  public async createAgent(agent: z.infer<typeof AgentCreateSchema>, idempotencyKey: string): Promise<JsonValue> {
    return this.postJson(this.organizationPath('/agents'), AgentCreateSchema.parse(agent), idempotencyKey);
  }
  public async listPolicies(): Promise<JsonValue> { return this.getJson(this.organizationPath('/policies')); }
  public async createPolicyDraft(revision: PolicyRevision, idempotencyKey: string): Promise<JsonValue> {
    const parsed = PolicyRevisionSchema.parse(revision);
    if (parsed.organizationId !== this.context.organizationId) throw new Error('Policy revision organization does not match the authenticated SDK context');
    return this.postJson(this.organizationPath('/policies'), parsed, idempotencyKey);
  }
  public async createPolicyRevision(policyId: string, revision: PolicyRevision, idempotencyKey: string): Promise<JsonValue> {
    const parsed = PolicyRevisionSchema.parse(revision);
    if (parsed.organizationId !== this.context.organizationId) throw new Error('Policy revision organization does not match the authenticated SDK context');
    return this.postJson(this.organizationPath(`/policies/${encodeURIComponent(policyId)}/revisions`), parsed, idempotencyKey);
  }
  public async simulateAction(action: ActionIntent): Promise<JsonValue> {
    const parsed = ActionIntentSchema.parse(action);
    if (parsed.organizationId !== this.context.organizationId) throw new Error('Action organization does not match the authenticated SDK context');
    return this.postJson(this.organizationPath(`/policies/${encodeURIComponent(parsed.policyId)}/simulate`), parsed);
  }
  public async requestAction(action: ActionIntent): Promise<JsonValue> {
    const parsed = ActionIntentSchema.parse(action);
    if (parsed.organizationId !== this.context.organizationId) throw new Error('Action organization does not match the authenticated SDK context');
    return this.postJson(this.organizationPath('/actions'), parsed, parsed.idempotencyKey);
  }
  public async getAction(actionId: string): Promise<JsonValue | null> {
    try { return await this.getJson(this.organizationPath(`/actions/${encodeURIComponent(actionId)}`)); }
    catch (error) { if (error instanceof MandateApiError && error.code === 'RESOURCE_NOT_FOUND') return null; throw error; }
  }
  public async approveAction(actionId: string, outcome: 'APPROVED' | 'DENIED', actionHash: string, idempotencyKey: string): Promise<JsonValue> {
    const body = z.object({ outcome: z.enum(['APPROVED', 'DENIED']), actionHash: z.string().regex(/^0x[0-9a-f]{64}$/) }).strict().parse({ outcome, actionHash });
    return this.postJson(this.organizationPath(`/actions/${encodeURIComponent(actionId)}/approval`), body, idempotencyKey);
  }
  public async getReceipts(limit = 100): Promise<JsonValue> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('limit must be between 1 and 100');
    return this.getJson(this.organizationPath(`/receipts?limit=${limit}`));
  }
  public async getAuditEvents(limit = 100, beforeSequence?: string): Promise<JsonValue> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('limit must be between 1 and 100');
    const cursor = beforeSequence === undefined ? '' : `&beforeSequence=${encodeURIComponent(z.string().regex(/^[1-9][0-9]{0,18}$/).parse(beforeSequence))}`;
    return this.getJson(this.organizationPath(`/audit-events?limit=${limit}${cursor}`));
  }
  public async getSignedAuditExport(limit = 1_000, beforeSequence?: string): Promise<JsonValue> {
    this.requireHuman();
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error('limit must be between 1 and 10000');
    const cursor = beforeSequence === undefined ? '' : `&beforeSequence=${encodeURIComponent(z.string().regex(/^[1-9][0-9]{0,18}$/).parse(beforeSequence))}`;
    return this.getJson(this.organizationPath(`/audit-exports?limit=${limit}${cursor}`));
  }
  public async getAlerts(limit = 100): Promise<JsonValue> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('limit must be between 1 and 100');
    return this.getJson(this.organizationPath(`/alerts?limit=${limit}`));
  }

  public async listAccounts(): Promise<JsonValue> { return this.getJson(this.organizationPath('/accounts')); }
  public async registerAccount(account: z.input<typeof AccountCreateSchema>, idempotencyKey: string): Promise<JsonValue> {
    return this.postJson(this.organizationPath('/accounts'), AccountCreateSchema.parse(account), idempotencyKey);
  }
  public async verifyAccount(accountId: string, idempotencyKey: string): Promise<JsonValue> {
    return this.postJson(this.organizationPath(`/accounts/${encodeURIComponent(OrganizationIdSchema.parse(accountId))}/verify`), {}, idempotencyKey);
  }

  public async listMembers(): Promise<JsonValue> { this.requireHuman(); return this.getJson(this.organizationPath('/members')); }
  public async setMemberRole(subject: string, role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER', idempotencyKey: string): Promise<JsonValue> {
    this.requireHuman();
    const memberSubject = z.string().min(1).max(255).parse(subject);
    const body = z.object({ role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']) }).strict().parse({ role });
    return this.writeJson('PUT', this.organizationPath(`/members/${encodeURIComponent(memberSubject)}`), body, idempotencyKey);
  }
  public async removeMember(subject: string, idempotencyKey: string): Promise<JsonValue> {
    this.requireHuman();
    const memberSubject = z.string().min(1).max(255).parse(subject);
    return this.deleteJson(this.organizationPath(`/members/${encodeURIComponent(memberSubject)}`), idempotencyKey);
  }
  public async listInvitations(): Promise<JsonValue> { this.requireHuman(); return this.getJson(this.organizationPath('/invitations')); }
  public async createInvitation(email: string, role: 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER', idempotencyKey: string): Promise<JsonValue> {
    this.requireHuman();
    const body = z.object({ email: z.string().trim().email().max(254), role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']) }).strict().parse({ email, role });
    return this.postJson(this.organizationPath('/invitations'), body, idempotencyKey);
  }
  public async revokeInvitation(invitationId: string, idempotencyKey: string): Promise<JsonValue> {
    this.requireHuman();
    const id = z.string().uuid().parse(invitationId);
    return this.deleteJson(this.organizationPath(`/invitations/${encodeURIComponent(id)}`), idempotencyKey);
  }

  public async preparePolicyActivation(policyId: string, idempotencyKey: string): Promise<JsonValue> {
    return this.postJson(this.organizationPath(`/policies/${encodeURIComponent(policyId)}/activate`), {}, idempotencyKey);
  }
  public async finalizePolicyActivation(policyId: string, planId: string, transactionHashes: readonly string[], idempotencyKey: string): Promise<JsonValue> {
    const body = z.object({ planId: z.string().uuid(), transactionHashes: z.array(z.string().regex(/^0x[0-9a-fA-F]{64}$/)).min(1).max(32) }).strict().parse({ planId, transactionHashes });
    return this.postJson(this.organizationPath(`/policies/${encodeURIComponent(policyId)}/activate/finalize`), body, idempotencyKey);
  }
  public async preparePolicyRevocation(policyId: string, idempotencyKey: string): Promise<JsonValue> {
    return this.postJson(this.organizationPath(`/policies/${encodeURIComponent(policyId)}/revoke`), {}, idempotencyKey);
  }
  public async finalizePolicyRevocation(policyId: string, planId: string, transactionHash: string, idempotencyKey: string): Promise<JsonValue> {
    const body = z.object({ planId: z.string().uuid(), transactionHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }).strict().parse({ planId, transactionHash });
    return this.postJson(this.organizationPath(`/policies/${encodeURIComponent(policyId)}/revoke/finalize`), body, idempotencyKey);
  }

  public async authorizeAction(actionId: string, idempotencyKey: string): Promise<JsonValue> {
    return this.postJson(this.organizationPath(`/actions/${encodeURIComponent(actionId)}/authorize`), {}, idempotencyKey);
  }
  public async executeAction(actionId: string, signature: string, rawTransaction: string, idempotencyKey: string): Promise<JsonValue> {
    const body = z.object({ signature: z.string().regex(/^0x(?:[0-9a-fA-F]{2}){65}$/), rawTransaction: z.string().max(262146).regex(/^0x(?:[0-9a-fA-F]{2})+$/) }).strict().parse({ signature, rawTransaction });
    return this.postJson(this.organizationPath(`/actions/${encodeURIComponent(actionId)}/execute`), body, idempotencyKey);
  }
  public async resolveDeepReorg(
    actionId: string,
    disposition: 'CONSUMED' | 'RELEASED',
    reason: string,
    idempotencyKey: string,
    evidenceHash?: string,
  ): Promise<JsonValue> {
    this.requireHuman();
    const body = z.object({
      disposition: z.enum(['CONSUMED', 'RELEASED']),
      // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
      reason: z.string().trim().min(1).max(1000).refine((value) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)),
      evidenceHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).transform((value) => value.toLowerCase()).optional(),
    }).strict().parse({ disposition, reason, ...(evidenceHash === undefined ? {} : { evidenceHash }) });
    return this.postJson(this.organizationPath(`/actions/${encodeURIComponent(OrganizationIdSchema.parse(actionId))}/reorg-resolution`), body, idempotencyKey);
  }

  public async listWebhookEndpoints(): Promise<JsonValue> { return this.getJson(this.organizationPath('/webhooks')); }
  public async createWebhookEndpoint(url: string, eventTypes: readonly (typeof WEBHOOK_EVENT_TYPES)[number][], idempotencyKey: string): Promise<JsonValue> {
    const body = z.object({ url: z.string().min(1).max(2048), eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1).max(30) }).strict().parse({ url, eventTypes });
    return this.postJson(this.organizationPath('/webhooks'), body, idempotencyKey);
  }
  public async setWebhookEndpointEnabled(endpointId: string, enabled: boolean, idempotencyKey: string): Promise<JsonValue> {
    const id = z.string().uuid().parse(endpointId);
    return this.writeJson('PATCH', this.organizationPath(`/webhooks/${encodeURIComponent(id)}`), z.object({ enabled: z.boolean() }).strict().parse({ enabled }), idempotencyKey);
  }
  public async deleteWebhookEndpoint(endpointId: string, idempotencyKey: string): Promise<JsonValue> {
    const id = z.string().uuid().parse(endpointId);
    return this.deleteJson(this.organizationPath(`/webhooks/${encodeURIComponent(id)}`), idempotencyKey);
  }
  public async rotateWebhookSigningSecret(endpointId: string, idempotencyKey: string): Promise<JsonValue> {
    const id = z.string().uuid().parse(endpointId);
    return this.postJson(this.organizationPath(`/webhooks/${encodeURIComponent(id)}/rotate-secret`), {}, idempotencyKey);
  }
  public async listWebhookDeliveries(endpointId: string, limit = 25): Promise<JsonValue> {
    const id = z.string().uuid().parse(endpointId);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('limit must be between 1 and 100');
    return this.getJson(this.organizationPath(`/webhooks/${encodeURIComponent(id)}/deliveries?limit=${limit}`));
  }

  public async listModelProviderCredentials(): Promise<JsonValue> {
    return this.getJson(this.organizationPath('/integrations/model-providers'));
  }
  public async setModelProviderCredential(provider: 'DEEPSEEK' | 'OPENAI' | 'ANTHROPIC' | 'OTHER', apiKey: string, idempotencyKey: string): Promise<JsonValue> {
    const parsedProvider = z.enum(['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER']).parse(provider);
    const body = z.object({ apiKey: z.string().min(16).max(4096) }).strict().parse({ apiKey });
    return this.writeJson('PUT', this.organizationPath(`/integrations/model-providers/${parsedProvider}`), body, idempotencyKey);
  }
  public async deleteModelProviderCredential(provider: 'DEEPSEEK' | 'OPENAI' | 'ANTHROPIC' | 'OTHER'): Promise<JsonValue> {
    const parsedProvider = z.enum(['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER']).parse(provider);
    return this.deleteJson(this.organizationPath(`/integrations/model-providers/${parsedProvider}`));
  }
  public async testModelProviderCredential(provider: 'DEEPSEEK' | 'OPENAI' | 'ANTHROPIC' | 'OTHER'): Promise<JsonValue> {
    const parsedProvider = z.enum(['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER']).parse(provider);
    return this.postJson(this.organizationPath(`/integrations/model-providers/${parsedProvider}/test`), {});
  }
  public async disableModelProviderCredential(provider: 'DEEPSEEK' | 'OPENAI' | 'ANTHROPIC' | 'OTHER'): Promise<JsonValue> {
    const parsedProvider = z.enum(['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER']).parse(provider);
    return this.postJson(this.organizationPath(`/integrations/model-providers/${parsedProvider}/disable`), {});
  }
}
