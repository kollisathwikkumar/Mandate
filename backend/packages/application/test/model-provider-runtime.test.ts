import { describe, expect, it, vi } from 'vitest';
import type { ModelCredentialRecord, ModelCredentialRepository } from '../../ports/src/model-credential-repository.js';
import type { ModelSecretStore } from '../../ports/src/model-secret-store.js';
import { ModelProviderRuntime } from '../src/model-provider-runtime.js';

describe('ModelProviderRuntime', () => {
  it('resolves an active secret only through the secret-store port', async () => {
    const record: ModelCredentialRecord = {
      provider: 'DEEPSEEK', secretReference: 'secret://opaque', maskedSuffix: '1234', state: 'ACTIVE',
      createdAt: '2026-01-01T00:00:00.000Z', rotatedAt: null, verifiedAt: null, disabledAt: null,
    };
    const getCredential = vi.fn(async () => record);
    const getSecret = vi.fn(async () => 'server-only-test-secret');
    const repository: ModelCredentialRepository = {
      getHumanRole: async () => null, listCredentials: async () => [], getCredential,
      writeCredential: async () => { throw new Error('unused'); },
      updateCredentialState: async () => null, deleteCredential: async () => null,
      markVerified: async () => undefined,
    };
    const secrets: ModelSecretStore = { put: async () => 'unused', get: getSecret, delete: async () => undefined };
    const runtime = new ModelProviderRuntime(repository, secrets);
    await expect(runtime.resolveActiveCredential('org-test', 'DEEPSEEK')).resolves.toBe('server-only-test-secret');
    expect(getCredential).toHaveBeenCalledWith('org-test', 'DEEPSEEK');
    expect(getSecret).toHaveBeenCalledWith('secret://opaque');
  });

  it('does not resolve missing or disabled credentials', async () => {
    const disabled: ModelCredentialRecord = {
      provider: 'OPENAI', secretReference: 'secret://disabled', maskedSuffix: '0000', state: 'DISABLED',
      createdAt: '2026-01-01T00:00:00.000Z', rotatedAt: null, verifiedAt: null, disabledAt: '2026-01-02T00:00:00.000Z',
    };
    const getCredential = vi.fn(async (_orgId: string, provider: 'OPENAI' | 'DEEPSEEK') => provider === 'OPENAI' ? disabled : null);
    const getSecret = vi.fn(async () => 'should-not-be-read');
    const repository: ModelCredentialRepository = {
      getHumanRole: async () => null, listCredentials: async () => [], getCredential,
      writeCredential: async () => { throw new Error('unused'); },
      updateCredentialState: async () => null, deleteCredential: async () => null,
      markVerified: async () => undefined,
    };
    const secrets: ModelSecretStore = { put: async () => 'unused', get: getSecret, delete: async () => undefined };
    const runtime = new ModelProviderRuntime(repository, secrets);
    await expect(runtime.resolveActiveCredential('org-test', 'OPENAI')).resolves.toBeNull();
    await expect(runtime.resolveActiveCredential('org-test', 'DEEPSEEK')).resolves.toBeNull();
    expect(getSecret).not.toHaveBeenCalled();
  });
});
