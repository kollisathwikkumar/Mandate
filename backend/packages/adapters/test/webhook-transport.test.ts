import { describe, expect, it } from 'vitest';
import { isPublicAddress, validatePublicHttpsWebhookUrl, type WebhookDnsResolver } from '../src/webhooks/https-webhook-transport.js';

const resolver = (addresses: readonly { readonly address: string; readonly family: number }[]): WebhookDnsResolver => ({
  async lookup() { return addresses; },
});

describe('public HTTPS webhook destination validation', () => {
  it('allows public IPv4 and public DNS answers', async () => {
    await expect(validatePublicHttpsWebhookUrl('https://203.0.113.8/hook', resolver([]))).rejects.toThrow('WEBHOOK_URL_PRIVATE_ADDRESS');
    await expect(validatePublicHttpsWebhookUrl('https://198.51.100.8/hook', resolver([]))).rejects.toThrow('WEBHOOK_URL_PRIVATE_ADDRESS');
    await expect(validatePublicHttpsWebhookUrl('https://example.test/hook', resolver([
      { address: '8.8.8.8', family: 4 }, { address: '2606:4700:4700::1111', family: 6 },
    ]))).resolves.toBeInstanceOf(URL);
  });

  it('rejects non-HTTPS, credentials, fragments, nonstandard ports, and local hostnames', async () => {
    for (const value of [
      'http://example.test/hook', 'https://user:pass@example.test/hook', 'https://example.test/hook#frag', 'https://example.test/hook?token=secret',
      'https://example.test:8443/hook', 'https://localhost/hook', 'https://service.localhost/hook',
    ]) await expect(validatePublicHttpsWebhookUrl(value, resolver([{ address: '8.8.8.8', family: 4 }]))).rejects.toThrow('WEBHOOK_URL_INVALID');
  });

  it('rejects any private or malformed DNS answer and reserved literal ranges', async () => {
    for (const address of ['127.0.0.1', '10.4.0.1', '169.254.1.1', '192.168.0.2', '::1', 'fc00::1', 'fe80::1', '4000::1', '::ffff:808:808']) {
      expect(isPublicAddress(address)).toBe(false);
    }
    await expect(validatePublicHttpsWebhookUrl('https://rebind.example/hook', resolver([
      { address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 },
    ]))).rejects.toThrow('WEBHOOK_URL_PRIVATE_ADDRESS');
    await expect(validatePublicHttpsWebhookUrl('https://bad.example/hook', resolver([{ address: 'not-ip', family: 0 }]))).rejects.toThrow('WEBHOOK_URL_PRIVATE_ADDRESS');
  });

  it('rejects empty and failed DNS resolution', async () => {
    await expect(validatePublicHttpsWebhookUrl('https://empty.example/hook', resolver([]))).rejects.toThrow('WEBHOOK_URL_PRIVATE_ADDRESS');
    await expect(validatePublicHttpsWebhookUrl('https://failed.example/hook', { async lookup() { throw new Error('dns'); } })).rejects.toThrow('WEBHOOK_URL_DNS_FAILED');
  });
});
