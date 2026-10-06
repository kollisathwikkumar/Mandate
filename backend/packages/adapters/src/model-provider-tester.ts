import type { ModelProvider } from '../../ports/src/model-credential-repository.js';
import type { ModelProviderTester, ProviderTestResult } from '../../ports/src/model-secret-store.js';

const PROVIDER_ENDPOINTS: Readonly<Partial<Record<ModelProvider, { readonly url: string; readonly headers: (apiKey: string) => HeadersInit }>>> = {
  DEEPSEEK: { url: 'https://api.deepseek.com/models', headers: (apiKey) => ({ authorization: `Bearer ${apiKey}` }) },
  OPENAI: { url: 'https://api.openai.com/v1/models', headers: (apiKey) => ({ authorization: `Bearer ${apiKey}` }) },
  ANTHROPIC: { url: 'https://api.anthropic.com/v1/models', headers: (apiKey) => ({ 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }) },
};

export class HttpModelProviderTester implements ModelProviderTester {
  public async test(provider: ModelProvider, apiKey: string): Promise<ProviderTestResult> {
    const endpoint = PROVIDER_ENDPOINTS[provider];
    if (endpoint === undefined) return { ok: false, reason: 'PROVIDER_UNSUPPORTED' };
    try {
      const response = await fetch(endpoint.url, {
        method: 'GET',
        headers: endpoint.headers(apiKey),
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (response.status === 401 || response.status === 403) return { ok: false, reason: 'PROVIDER_AUTH_FAILED' };
      return response.ok ? { ok: true, reason: null } : { ok: false, reason: 'PROVIDER_UNAVAILABLE' };
    } catch {
      return { ok: false, reason: 'PROVIDER_UNAVAILABLE' };
    }
  }
}
