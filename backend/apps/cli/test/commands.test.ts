import { describe, expect, it } from 'vitest';
import { executeCliCommand, parseActionInput, parseCliCommand, type CliApi } from '../src/commands.js';

const actionValue = {
  actionId: 'action-1', idempotencyKey: 'request-1', policyId: 'policy-1', policyRevision: 1,
  policyRevisionHash: `0x${'a'.repeat(64)}`, organizationId: 'org-1', account: `0x${'1'.repeat(40)}`,
  agentId: 'agent-1', agentKeyVersion: 1, chainId: 10143, target: `0x${'2'.repeat(40)}`,
  selector: '0x12345678', asset: `0x${'3'.repeat(40)}`, recipient: `0x${'4'.repeat(40)}`,
  amount: '1', nonce: 0, nonceEpoch: 0, expiresAt: 1_900_000_000,
};

const baseApi: CliApi = {
  async listAgents() { return null; }, async createAgent() { return null; }, async listPolicies() { return null; },
  async simulateAction() { return null; }, async requestAction() { return null; }, async getAction() { return null; },
  async getReceipts() { return null; }, async getAuditEvents() { return null; }, async getAlerts() { return null; },
  async listModelProviderCredentials() { return null; }, async setModelProviderCredential() { return null; },
  async deleteModelProviderCredential() { return null; }, async testModelProviderCredential() { return null; },
  async disableModelProviderCredential() { return null; }, async createOrganization() { return null; }, async acceptInvitation() { return null; },
  async createPolicyDraft() { return null; }, async createPolicyRevision() { return null; }, async approveAction() { return null; },
  async getSignedAuditExport() { return null; }, async listAccounts() { return null; }, async registerAccount() { return null; },
  async verifyAccount() { return null; }, async listMembers() { return null; }, async setMemberRole() { return null; },
  async removeMember() { return null; }, async listInvitations() { return null; }, async createInvitation() { return null; },
  async revokeInvitation() { return null; }, async preparePolicyActivation() { return null; }, async finalizePolicyActivation() { return null; },
  async preparePolicyRevocation() { return null; }, async finalizePolicyRevocation() { return null; }, async authorizeAction() { return null; },
  async executeAction() { return null; }, async resolveDeepReorg() { return null; }, async listWebhookEndpoints() { return null; },
  async createWebhookEndpoint() { return null; }, async setWebhookEndpointEnabled() { return null; }, async deleteWebhookEndpoint() { return null; },
  async rotateWebhookSigningSecret() { return null; }, async listWebhookDeliveries() { return null; },
};

describe('Mandate CLI command layer', () => {
  it('parses only explicit supported command shapes', () => {
    expect(parseCliCommand(['actions', 'simulate', '@action.json'])).toEqual({ kind: 'action-simulate', input: '@action.json' });
    expect(() => parseCliCommand(['actions', 'delete', 'action-1'])).toThrow('Invalid Mandate CLI command');
  });

  it('parses the remaining backend SDK command families without ad-hoc shell payloads', () => {
    expect(parseCliCommand(['accounts', 'register', '@account.json'])).toEqual({ kind: 'account-register', input: '@account.json' });
    expect(parseCliCommand(['members', 'set-role', 'alice@example.com', 'APPROVER'])).toEqual({
      kind: 'member-set-role', subject: 'alice@example.com', role: 'APPROVER',
    });
    expect(parseCliCommand(['invitations', 'create', 'alice@example.com', 'VIEWER'])).toEqual({
      kind: 'invitation-create', email: 'alice@example.com', role: 'VIEWER',
    });
    expect(parseCliCommand(['webhooks', 'create', '@webhook.json'])).toEqual({ kind: 'webhook-create', input: '@webhook.json' });
    expect(parseCliCommand(['actions', 'execute', 'action-1', '@sig.txt', '@raw-tx.txt'])).toEqual({
      kind: 'action-execute', actionId: 'action-1', signatureInput: '@sig.txt', transactionInput: '@raw-tx.txt',
    });
    expect(parseCliCommand(['audit', 'export', '250', '175'])).toEqual({ kind: 'audit-export', limit: 250, beforeSequence: '175' });
    expect(() => parseCliCommand(['actions', 'execute', 'action-1', '0xsignature', '@raw.txt'])).toThrow('sensitive input');
    expect(() => parseCliCommand(['webhooks', 'deliveries', 'endpoint-1', '101'])).toThrow('between 1 and 100');
  });

  it('validates JSON inputs and dispatches CLI commands through SDK operations', async () => {
    const calls: string[] = [];
    const api: CliApi = {
      ...baseApi,
      async createPolicyDraft(revision, idempotencyKey) { calls.push(`policy:${revision.policyId}:${idempotencyKey}`); return { created: true }; },
      async registerAccount(account, idempotencyKey) { calls.push(`account:${account.id}:${idempotencyKey}`); return { registered: true }; },
      async createWebhookEndpoint(url, eventTypes, idempotencyKey) { calls.push(`webhook:${url}:${eventTypes[0]}:${idempotencyKey}`); return { created: true }; },
      async executeAction(actionId, signature, rawTransaction, idempotencyKey) {
        calls.push(`execute:${actionId}:${signature}:${rawTransaction}:${idempotencyKey}`); return { submitted: true };
      },
      async getSignedAuditExport(limit, beforeSequence) { calls.push(`export:${limit}:${beforeSequence}`); return { events: [] }; },
    };
    const policy = {
      schemaVersion: 1, policyId: 'policy-1', revision: 1, organizationId: 'org-1',
      owner: `0x${'1'.repeat(40)}`, account: `0x${'2'.repeat(40)}`, agentId: 'agent-1',
      agentAddress: `0x${'3'.repeat(40)}`, agentKeyVersion: 1, chainId: 10143, adapter: 'evm-smart-account',
      target: `0x${'4'.repeat(40)}`, selectors: ['0x12345678'], asset: `0x${'5'.repeat(40)}`,
      recipients: [`0x${'6'.repeat(40)}`], limits: { perAction: '1', cumulative: '10', windowSeconds: 60 },
      validAfter: 1_700_000_000, expiresAt: 1_800_000_000, nonceEpoch: 0,
    };
    const inputs: Record<string, object> = {
      '@policy.json': policy,
      '@account.json': { id: 'account-1', chainId: 10143, address: `0x${'7'.repeat(40)}`, adapter: 'evm-smart-account' },
      '@webhook.json': { url: 'https://hooks.example.com/mandate', eventTypes: ['ACTION_RESERVED'] },
    };
    const readJson = async (reference: string) => inputs[reference] as import('../../../packages/sdk/src/client.js').JsonValue;
    const readSecret = async (reference: string) => reference === '@signature' ? `0x${'ab'.repeat(65)}` : `0x${'cd'.repeat(32)}`;
    for (const args of [
      ['policies', 'create', '@policy.json'],
      ['accounts', 'register', '@account.json'],
      ['webhooks', 'create', '@webhook.json'],
      ['actions', 'execute', 'action-1', '@signature', '@transaction'],
      ['audit', 'export', '250', '175'],
    ]) {
      await executeCliCommand(parseCliCommand(args), api, async () => parseActionInput(actionValue), readSecret, readJson);
    }
    expect(calls.map((call) => call.split(':').slice(0, 3).join(':'))).toEqual([
      expect.stringMatching(/^policy:policy-1:/),
      expect.stringMatching(/^account:account-1:/),
      expect.stringMatching(/^webhook:https:/),
      expect.stringMatching(/^execute:action-1:/),
      'export:250:175',
    ]);
    expect(calls[3]).toContain(`:${`0x${'ab'.repeat(65)}`}:0x${'cd'.repeat(32)}:`);
  });

  it('parses model-provider key commands using file or stdin references, not literal keys', () => {
    expect(parseCliCommand(['model-providers', 'set', 'DEEPSEEK', '@key.txt'])).toEqual({
      kind: 'model-provider-set', provider: 'DEEPSEEK', keyInput: '@key.txt',
    });
    expect(parseCliCommand(['model-providers', 'test', 'OPENAI'])).toEqual({ kind: 'model-provider-test', provider: 'OPENAI' });
    expect(() => parseCliCommand(['model-providers', 'set', 'DEEPSEEK', 'sk-literal-secret'])).toThrow('Use @file or -');
  });

  it('dispatches model-provider key input without returning or logging the raw key', async () => {
    const observed: string[] = [];
    const api: CliApi = {
      ...baseApi,
      async listAgents() { return { agents: [] }; },
      async createAgent() { return { created: true }; },
      async listPolicies() { return { policies: [] }; },
      async simulateAction() { return { verdict: 'ALLOW' }; },
      async requestAction() { return { state: 'RESERVED' }; },
      async getAction() { return null; },
      async getReceipts() { return { receipts: [] }; },
      async getAuditEvents() { return { events: [] }; },
      async getAlerts() { return { alerts: [] }; },
      async listModelProviderCredentials() { return { credentials: [] }; },
      async setModelProviderCredential(provider, key) { observed.push(`${provider}:${key}`); return { provider, maskedSuffix: '4321' }; },
      async deleteModelProviderCredential(provider) { return { provider }; },
      async testModelProviderCredential(provider) { return { provider }; },
      async disableModelProviderCredential(provider) { return { provider }; },
      async createOrganization(name) { return { organizationId: name }; },
      async acceptInvitation() { return { accepted: true }; },
    };
    const rawKey = 'provider-secret-material-4321';
    const result = await executeCliCommand(parseCliCommand(['model-providers', 'set', 'DEEPSEEK', '@key.txt']), api, async () => parseActionInput(actionValue), async () => rawKey);
    expect(observed).toEqual([`DEEPSEEK:${rawKey}`]);
    expect(result).toEqual({ provider: 'DEEPSEEK', maskedSuffix: '4321' });
    expect(JSON.stringify(result)).not.toContain(rawKey);
  });

  it('supports zero-organization onboarding and authenticated invitation acceptance', async () => {
    expect(parseCliCommand(['organizations', 'create', 'Treasury Ops'])).toEqual({
      kind: 'organization-create', displayName: 'Treasury Ops',
    });
    expect(parseCliCommand(['invitations', 'accept', '@invite.txt'])).toEqual({
      kind: 'invitation-accept', tokenInput: '@invite.txt',
    });
    const calls: string[] = [];
    const api: CliApi = {
      ...baseApi,
      async listAgents() { return { agents: [] }; }, async createAgent() { return { created: true }; },
      async listPolicies() { return { policies: [] }; }, async simulateAction() { return { verdict: 'ALLOW' }; },
      async requestAction() { return { state: 'RESERVED' }; }, async getAction() { return null; },
      async getReceipts() { return { receipts: [] }; }, async getAuditEvents() { return { events: [] }; },
      async getAlerts() { return { alerts: [] }; }, async listModelProviderCredentials() { return { credentials: [] }; },
      async setModelProviderCredential() { return { provider: 'DEEPSEEK' }; }, async deleteModelProviderCredential() { return null; },
      async testModelProviderCredential() { return { ok: true }; }, async disableModelProviderCredential() { return { ok: true }; },
      async createOrganization(name) { calls.push(`organization:${name}`); return { organizationId: 'org-1' }; },
      async acceptInvitation(token) { calls.push(`accepted:${token}`); return { accepted: true }; },
    };
    await executeCliCommand(parseCliCommand(['organizations', 'create', 'Treasury Ops']), api, async () => parseActionInput(actionValue));
    const token = 'invitation-token-material-that-is-long-enough';
    const accepted = await executeCliCommand(parseCliCommand(['invitations', 'accept', '@invite.txt']), api,
      async () => parseActionInput(actionValue), async () => token);
    expect(accepted).toEqual({ accepted: true });
    expect(calls).toEqual(['organization:Treasury Ops', `accepted:${token}`]);
    expect(JSON.stringify(accepted)).not.toContain(token);
  });

  it('validates action JSON with the same shared contract as the API', () => {
    expect(parseActionInput(actionValue)).toMatchObject({ actionId: 'action-1', organizationId: 'org-1' });
    expect(() => parseActionInput({ ...actionValue, unreviewed: true })).toThrow();
  });

  it('dispatches simulation through the SDK without local policy evaluation', async () => {
    let simulatedActionId = '';
    const api: CliApi = {
      ...baseApi,
      async listAgents() { return { agents: [] }; },
      async createAgent() { return { created: true }; },
      async listPolicies() { return { policies: [] }; },
      async simulateAction(action) { simulatedActionId = action.actionId; return { verdict: 'ALLOW' }; },
      async requestAction() { return { state: 'RESERVED' }; },
      async getAction() { return null; },
      async getReceipts() { return { receipts: [] }; },
      async getAuditEvents() { return { events: [] }; },
      async getAlerts() { return { alerts: [] }; },
      async listModelProviderCredentials() { return { credentials: [] }; },
      async setModelProviderCredential(provider) { return { provider }; },
      async deleteModelProviderCredential(provider) { return { provider }; },
      async testModelProviderCredential(provider) { return { provider }; },
      async disableModelProviderCredential(provider) { return { provider }; },
      async createOrganization(name) { return { organizationId: name }; },
      async acceptInvitation() { return { accepted: true }; },
    };
    const input = parseActionInput(actionValue);
    const result = await executeCliCommand(parseCliCommand(['actions', 'simulate', '-']), api, async () => input);
    expect(result).toEqual({ verdict: 'ALLOW' });
    expect(simulatedActionId).toBe('action-1');
  });
});
