import { describe, expect, it } from 'vitest';
import { AgentCreatedSchema, InvitationCreatedSchema, WebhookCreatedSchema, WebhookReplaySchema, WebhookRotatedSchema } from '../src/api/schemas';

const endpoint = {
  id: '00000000-0000-4000-8000-000000000001',
  url: 'https://receiver.example/events',
  eventTypes: ['ACTION_HELD'],
  enabled: true,
  createdAt: '2026-10-07T00:00:00.000Z',
  updatedAt: '2026-10-07T00:00:00.000Z',
};

describe('one-time credential response contracts', () => {
  it('requires agent credentials to be explicitly marked as shown once', () => {
    const result = { agent: { id: 'agent-1', displayName: 'Treasury', status: 'ACTIVE', keyVersion: 1, createdAt: '2026-10-07T00:00:00.000Z' }, credential: { token: 'agent-secret', shownOnce: true } };
    expect(AgentCreatedSchema.parse(result).credential.token).toBe('agent-secret');
    expect(AgentCreatedSchema.safeParse({ ...result, credential: { token: 'agent-secret' } }).success).toBe(false);
  });

  it('distinguishes an invitation creation from a replay without exposing a missing token', () => {
    const invitation = { id: 'invite-1', organizationId: 'org-1', role: 'APPROVER', state: 'PENDING', expiresAt: '2026-10-08T00:00:00.000Z', createdAt: '2026-10-07T00:00:00.000Z' };
    expect(InvitationCreatedSchema.parse({ invitation, invitationToken: 'invite-secret', shownOnce: true }).invitationToken).toBe('invite-secret');
    expect(InvitationCreatedSchema.parse({ invitation, replayed: true }).replayed).toBe(true);
  });

  it('validates one-time webhook creation and rotation separately from secretless replay', () => {
    expect(WebhookCreatedSchema.parse({ endpoint, signingSecret: 'signing-secret', shownOnce: true }).signingSecret).toBe('signing-secret');
    expect(WebhookRotatedSchema.parse({ endpointId: endpoint.id, signingSecret: 'rotated-secret', shownOnce: true }).signingSecret).toBe('rotated-secret');
    expect(WebhookReplaySchema.parse({ endpoint, replayed: true }).replayed).toBe(true);
    expect(WebhookCreatedSchema.safeParse({ endpoint, replayed: true }).success).toBe(false);
  });
});
