import { expect, it } from 'vitest';
import { clearAgentRegistrationIntent, getAgentRegistrationIntentKey, parseAgentRegistrationResponse } from '../src/api/agentRegistration';

const agent = {
  id: 'agent-1', displayName: 'Treasury', status: 'ACTIVE',
  keyVersion: 1, createdAt: '2026-10-08T00:00:00.000Z',
};

it('distinguishes a new agent with a one-time credential from a secretless replay', () => {
  expect(parseAgentRegistrationResponse({ agent, credential: { token: 'agent-secret', shownOnce: true } }))
    .toMatchObject({ kind: 'CREATED', token: 'agent-secret' });
  expect(parseAgentRegistrationResponse({ agent, replayed: true }))
    .toMatchObject({ kind: 'REPLAY', agentId: 'agent-1' });
});

it('rejects a replay that claims to expose a credential or omits replay evidence', () => {
  expect(() => parseAgentRegistrationResponse({ agent, replayed: true, credential: { token: 'fake', shownOnce: true } })).toThrow();
  expect(() => parseAgentRegistrationResponse({ agent })).toThrow();
});

it('retains a registration retry key across remounts without storing a credential', () => {
  sessionStorage.clear();
  const first = getAgentRegistrationIntentKey('org-a', 'owner', 'agent-1', 'Treasury');
  const afterReload = getAgentRegistrationIntentKey('org-a', 'owner', 'agent-1', 'Treasury');
  expect(afterReload).toBe(first);
  expect(sessionStorage.getItem('mandate.agentRegistration/org-a/owner/agent-1')).not.toContain('secret');
  expect(getAgentRegistrationIntentKey('org-a', 'owner', 'agent-1', 'Changed name')).not.toBe(first);
  expect(getAgentRegistrationIntentKey('org-b', 'owner', 'agent-1', 'Treasury')).not.toBe(first);
  expect(getAgentRegistrationIntentKey('org-a', 'another-owner', 'agent-1', 'Treasury')).not.toBe(first);
  const next = getAgentRegistrationIntentKey('org-a', 'owner', 'agent-2', 'Treasury');
  clearAgentRegistrationIntent('org-a', 'owner', 'agent-2');
  expect(getAgentRegistrationIntentKey('org-a', 'owner', 'agent-2', 'Treasury')).not.toBe(next);
  sessionStorage.clear();
});

it('replaces a corrupt pending identity once and then reuses the replacement', () => {
  sessionStorage.clear();
  sessionStorage.setItem('mandate.agentRegistration/org-a/owner/agent-1', '{corrupt');
  const replacement = getAgentRegistrationIntentKey('org-a', 'owner', 'agent-1', 'Treasury');
  expect(getAgentRegistrationIntentKey('org-a', 'owner', 'agent-1', 'Treasury')).toBe(replacement);
  sessionStorage.clear();
});
