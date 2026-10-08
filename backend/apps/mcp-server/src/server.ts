import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { ApiErrorSchema } from '../../../packages/api-contracts/src/schemas.js';
import { ActionIntentSchema, type ActionIntent } from '../../../packages/policy/src/schema.js';

const JsonValueSchema = z.json();
type JsonValue = z.infer<typeof JsonValueSchema>;
const OrganizationIdSchema = z.string().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/);
const actionInputSchema = ActionIntentSchema.omit({ organizationId: true }).strict();
const emptyInputSchema = z.object({}).strict();
const identifierInputSchema = z.object({ id: z.string().trim().min(1).max(128) }).strict();
const policyIdInputSchema = z.object({ policyId: z.string().trim().min(1).max(128) }).strict();

export interface AuthenticatedMcpIdentity {
  readonly principal:
    | { readonly type: 'HUMAN'; readonly subject: string }
    | { readonly type: 'AGENT'; readonly organizationId: string; readonly agentId: string; readonly keyVersion: number };
  readonly organizations?: readonly { readonly organizationId: string; readonly role: string }[];
}
export interface McpOrganizationContext {
  readonly organizationId: string;
  readonly principalType: 'HUMAN' | 'AGENT';
}
export interface MandateMcpApi {
  readonly context: McpOrganizationContext;
  listPolicies(): Promise<JsonValue>;
  getPolicy(policyId: string): Promise<JsonValue | null>;
  simulateAction(action: ActionIntent): Promise<JsonValue>;
  requestAction(action: ActionIntent): Promise<JsonValue>;
  getAction(actionId: string): Promise<JsonValue | null>;
  getReceipt(actionId: string): Promise<JsonValue | null>;
}

export function resolveOrganizationContext(identity: AuthenticatedMcpIdentity, configuredOrganizationId: string | null): McpOrganizationContext {
  if (identity.principal.type === 'AGENT') {
    const organizationId = OrganizationIdSchema.parse(identity.principal.organizationId);
    if (configuredOrganizationId !== null && OrganizationIdSchema.parse(configuredOrganizationId) !== organizationId) {
      throw new Error('MANDATE_ORGANIZATION_ID does not match the authenticated agent organization');
    }
    return { organizationId, principalType: 'AGENT' };
  }
  const organizations = identity.organizations ?? [];
  if (configuredOrganizationId !== null) {
    const selected = OrganizationIdSchema.parse(configuredOrganizationId);
    if (!organizations.some((organization) => organization.organizationId === selected)) {
      throw new Error('MANDATE_ORGANIZATION_ID is not present in the authenticated identity');
    }
    return { organizationId: selected, principalType: 'HUMAN' };
  }
  if (organizations.length !== 1) throw new Error('MANDATE_ORGANIZATION_ID is required when the authenticated identity has zero or multiple organizations');
  const organizationId = OrganizationIdSchema.parse(organizations[0]?.organizationId);
  return { organizationId, principalType: 'HUMAN' };
}

const serialize = (value: JsonValue): { content: [{ type: 'text'; text: string }] } => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const errorResult = (error: Error): { content: [{ type: 'text'; text: string }]; isError: true } => ({ content: [{ type: 'text', text: error.message }] , isError: true });

export function createMandateMcpServer(api: MandateMcpApi): McpServer {
  const server = new McpServer({ name: 'mandate', version: '1.0.0' });
  server.registerTool('mandate_policy_list', {
    title: 'List Mandate policies', description: 'List policies for the authenticated human organization context.',
    inputSchema: emptyInputSchema, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async () => api.context.principalType === 'HUMAN' ? serialize(await api.listPolicies()) : errorResult(new Error('HUMAN_PRINCIPAL_REQUIRED')));
  server.registerTool('mandate_policy_get', {
    title: 'Get a Mandate policy', description: 'Get one policy from the authenticated human organization context.',
    inputSchema: policyIdInputSchema, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async ({ policyId }) => {
    if (api.context.principalType !== 'HUMAN') return errorResult(new Error('HUMAN_PRINCIPAL_REQUIRED'));
    const policy = await api.getPolicy(policyId);
    return policy === null ? errorResult(new Error('RESOURCE_NOT_FOUND')) : serialize(policy);
  });
  server.registerTool('mandate_action_simulate', {
    title: 'Simulate a Mandate action', description: 'Human-only deterministic policy preflight; this tool does not reserve budget or submit a transaction.',
    inputSchema: actionInputSchema, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async (input) => {
    if (api.context.principalType !== 'HUMAN') return errorResult(new Error('HUMAN_PRINCIPAL_REQUIRED'));
    const action = ActionIntentSchema.parse({ ...input, organizationId: api.context.organizationId });
    return serialize(await api.simulateAction(action));
  });
  server.registerTool('mandate_action_request', {
    title: 'Request a Mandate action', description: 'Submit a tenant-bound action request. The authenticated agent principal and policy engine control access and decision.',
    inputSchema: actionInputSchema, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => {
    if (api.context.principalType !== 'AGENT') return errorResult(new Error('AGENT_PRINCIPAL_REQUIRED'));
    const action = ActionIntentSchema.parse({ ...input, organizationId: api.context.organizationId });
    return serialize(await api.requestAction(action));
  });
  server.registerTool('mandate_action_get', {
    title: 'Get a Mandate action', description: 'Read an action and its lifecycle from the authenticated organization context.',
    inputSchema: identifierInputSchema, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async ({ id }) => {
    const action = await api.getAction(id);
    return action === null ? errorResult(new Error('RESOURCE_NOT_FOUND')) : serialize(action);
  });
  server.registerTool('mandate_receipt_get', {
    title: 'Get a Mandate receipt', description: 'Read receipt evidence for an action in the authenticated organization context.',
    inputSchema: identifierInputSchema, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async ({ id }) => {
    const receipt = await api.getReceipt(id);
    return receipt === null ? errorResult(new Error('RESOURCE_NOT_FOUND')) : serialize(receipt);
  });
  return server;
}

function parseIdentity(value: JsonValue): AuthenticatedMcpIdentity {
  const schema = z.object({
    principal: z.discriminatedUnion('type', [
      z.object({ type: z.literal('HUMAN'), subject: z.string().min(1) }).strict(),
      z.object({ type: z.literal('AGENT'), organizationId: OrganizationIdSchema, agentId: z.string(), keyVersion: z.number().int().positive() }).strict(),
    ]),
    organizations: z.array(z.object({ organizationId: OrganizationIdSchema, role: z.string() }).strict()).optional(),
  }).strict();
  const parsed = schema.parse(value);
  return { principal: parsed.principal, ...(parsed.organizations === undefined ? {} : { organizations: parsed.organizations }) };
}

export class MandateRestMcpClient implements MandateMcpApi {
  public readonly context: McpOrganizationContext;
  private constructor(private readonly apiUrl: URL, private readonly token: string, context: McpOrganizationContext, private readonly fetcher: typeof fetch) {
    this.context = context;
  }

  public static async connect(apiUrlValue: string, token: string, configuredOrganizationId: string | null, fetcher: typeof fetch = fetch): Promise<MandateRestMcpClient> {
    const apiUrl = new URL(apiUrlValue);
    const localHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);
    if (apiUrl.username || apiUrl.password || apiUrl.search || apiUrl.hash || (apiUrl.protocol !== 'https:' && !(apiUrl.protocol === 'http:' && localHosts.has(apiUrl.hostname)))) {
      throw new Error('MANDATE_API_URL must be HTTPS (HTTP only for loopback development) without credentials, query, or fragment');
    }
    if (!/^[A-Za-z0-9._~-]{16,4096}$/.test(token)) throw new Error('MANDATE_API_TOKEN is invalid');
    const client = new MandateRestMcpClient(apiUrl, token, { organizationId: 'pending', principalType: 'HUMAN' }, fetcher);
    const identity = parseIdentity(await client.getJson('/api/v1/me'));
    const context = resolveOrganizationContext(identity, configuredOrganizationId);
    return new MandateRestMcpClient(apiUrl, token, context, fetcher);
  }

  private async getJson(path: string): Promise<JsonValue> { return this.requestJson(path, { method: 'GET' }); }

  private async requestJson(path: string, init: RequestInit): Promise<JsonValue> {
    const url = new URL(path, this.apiUrl);
    const response = await this.fetcher(url, {
      ...init,
      headers: { authorization: `Bearer ${this.token}`, accept: 'application/json', ...(init.body === undefined ? {} : { 'content-type': 'application/json' }), ...init.headers },
      signal: AbortSignal.timeout(8_000),
    });
    const bodyText = await response.text();
    const parsed = JsonValueSchema.parse(JSON.parse(bodyText));
    if (!response.ok) {
      const error = ApiErrorSchema.safeParse(parsed);
      const code = error.success ? error.data.error.code : `HTTP_${response.status}`;
      throw new Error(`MANDATE_API_${code}`);
    }
    return parsed;
  }

  private organizationPath(path: string): string { return `/api/v1/orgs/${encodeURIComponent(this.context.organizationId)}${path}`; }
  public async listPolicies(): Promise<JsonValue> { return this.getJson(this.organizationPath('/policies')); }
  public async getPolicy(policyId: string): Promise<JsonValue | null> {
    const list = z.object({ policies: z.array(JsonValueSchema) }).safeParse(await this.listPolicies());
    if (!list.success) throw new Error('MANDATE_API_INVALID_POLICY_LIST');
    return list.data.policies.find((policy) => z.object({ id: z.string() }).safeParse(policy).success && z.object({ id: z.string() }).parse(policy).id === policyId) ?? null;
  }
  public async simulateAction(action: ActionIntent): Promise<JsonValue> {
    return this.requestJson(this.organizationPath(`/policies/${encodeURIComponent(action.policyId)}/simulate`), { method: 'POST', body: JSON.stringify(action) });
  }
  public async requestAction(action: ActionIntent): Promise<JsonValue> {
    return this.requestJson(this.organizationPath('/actions'), { method: 'POST', headers: { 'idempotency-key': action.idempotencyKey }, body: JSON.stringify(action) });
  }
  public async getAction(actionId: string): Promise<JsonValue | null> {
    try { return await this.getJson(this.organizationPath(`/actions/${encodeURIComponent(actionId)}`)); }
    catch (error: unknown) { if (error instanceof Error && error.message === 'MANDATE_API_RESOURCE_NOT_FOUND') return null; throw error; }
  }
  public async getReceipt(actionId: string): Promise<JsonValue | null> {
    const result = z.object({ receipts: z.array(JsonValueSchema) }).safeParse(await this.getJson(this.organizationPath(`/receipts?limit=1&actionId=${encodeURIComponent(actionId)}`)));
    if (!result.success) throw new Error('MANDATE_API_INVALID_RECEIPT_LIST');
    return result.data.receipts.find((receipt) => z.object({ actionId: z.string() }).safeParse(receipt).success && z.object({ actionId: z.string() }).parse(receipt).actionId === actionId) ?? null;
  }
}

export interface McpServerEnvironment {
  readonly apiUrl: string;
  readonly token: string;
  readonly organizationId: string | null;
}

export function parseMcpServerEnvironment(environment: NodeJS.ProcessEnv): McpServerEnvironment {
  const apiUrl = z.string().url().parse(environment.MANDATE_API_URL);
  const token = z.string().min(16).max(4096).parse(environment.MANDATE_API_TOKEN);
  const organizationId = environment.MANDATE_ORGANIZATION_ID === undefined ? null : OrganizationIdSchema.parse(environment.MANDATE_ORGANIZATION_ID);
  return { apiUrl, token, organizationId };
}

export async function startMcpServerFromEnvironment(environment: NodeJS.ProcessEnv = process.env): Promise<void> {
  const configuration = parseMcpServerEnvironment(environment);
  const client = await MandateRestMcpClient.connect(configuration.apiUrl, configuration.token, configuration.organizationId);
  const handle = serveStdio(() => createMandateMcpServer(client));
  process.once('SIGINT', () => { void handle.close(); });
  process.once('SIGTERM', () => { void handle.close(); });
}
