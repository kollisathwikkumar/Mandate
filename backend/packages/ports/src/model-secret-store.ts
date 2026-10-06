import type { ModelProvider } from './model-credential-repository.js';

export interface ModelSecretStore {
  put(organizationId: string, provider: ModelProvider, value: string): Promise<string>;
  get(secretReference: string): Promise<string>;
  delete(secretReference: string): Promise<void>;
}

export type ProviderTestReason = 'PROVIDER_AUTH_FAILED' | 'PROVIDER_UNAVAILABLE' | 'PROVIDER_UNSUPPORTED';

export interface ProviderTestResult {
  readonly ok: boolean;
  readonly reason: ProviderTestReason | null;
}

export interface ModelProviderTester {
  test(provider: ModelProvider, apiKey: string): Promise<ProviderTestResult>;
}
