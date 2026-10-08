import { expect, it } from 'vitest';
import { ProviderTestSchema } from '../src/api/schemas';
it('accepts the real backend successful provider test with a null reason', () => {
  expect(ProviderTestSchema.parse({ ok: true, reason: null, credential: { provider: 'OPENAI', maskedSuffix: 'test', state: 'ACTIVE', verifiedAt: '2026-10-07T00:00:00.000Z' } }).ok).toBe(true);
});
it('preserves a provider rejection reason', () => {
  expect(ProviderTestSchema.parse({ ok: false, reason: 'PROVIDER_AUTH_FAILED', credential: null }).reason).toBe('PROVIDER_AUTH_FAILED');
});
