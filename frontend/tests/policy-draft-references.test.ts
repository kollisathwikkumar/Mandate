import { describe, expect, it } from 'vitest';
import { validatePolicyDraftReferences } from '../src/app/policyDraftReferences';

const agent = { id: 'treasury-bot', status: 'ACTIVE' as const };
const account = {
  chainId: 10143,
  address: '0x2222222222222222222222222222222222222222',
  adapter: 'evm-smart-account' as const,
  status: 'ACTIVE' as const,
};
const selection = {
  agentId: 'treasury-bot',
  chainId: 10143,
  account: account.address,
  adapter: 'evm-smart-account' as const,
};

describe('validatePolicyDraftReferences', () => {
  it('accepts a matching active agent and account on the selected chain and adapter', () => {
    expect(validatePolicyDraftReferences(selection, [agent], [account])).toBe('ready');
  });

  it('rejects an unknown or revoked agent', () => {
    expect(validatePolicyDraftReferences({ ...selection, agentId: 'missing' }, [agent], [account])).toBe('agent-unavailable');
    expect(validatePolicyDraftReferences(selection, [{ ...agent, status: 'REVOKED' }], [account])).toBe('agent-unavailable');
  });

  it('rejects an account address that is not registered in the organization', () => {
    expect(validatePolicyDraftReferences({ ...selection, account: '0x3333333333333333333333333333333333333333' }, [agent], [account])).toBe('account-unavailable');
  });

  it('rejects an account registered for another chain', () => {
    expect(validatePolicyDraftReferences(selection, [agent], [{ ...account, chainId: 1 }])).toBe('account-unavailable');
  });

  it('rejects a paused or unsupported account', () => {
    expect(validatePolicyDraftReferences(selection, [agent], [{ ...account, status: 'PAUSED' }])).toBe('account-unavailable');
    expect(validatePolicyDraftReferences(selection, [agent], [{ ...account, status: 'UNSUPPORTED' }])).toBe('account-unavailable');
  });

  it('matches account addresses case-insensitively', () => {
    expect(validatePolicyDraftReferences({ ...selection, account: account.address.toUpperCase().replace('0X', '0x') }, [agent], [account])).toBe('ready');
  });
});
