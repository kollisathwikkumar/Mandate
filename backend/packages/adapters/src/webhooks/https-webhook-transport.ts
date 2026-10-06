import { BlockList, isIP } from 'node:net';
import type { LookupOptions } from 'node:dns';
import { lookup as systemLookup } from 'node:dns/promises';
import { request } from 'node:https';
import type { WebhookTransport, WebhookUrlValidator } from '../../../ports/src/webhook.js';

const blockedIPv4 = new BlockList();
for (const subnet of [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
]) {
  const [network, prefix] = subnet.split('/');
  if (network === undefined || prefix === undefined) throw new Error('Invalid IPv4 blocklist entry');
  blockedIPv4.addSubnet(network, Number(prefix), 'ipv4');
}
const blockedIPv6 = new BlockList();
const globallyRoutableIPv6 = new BlockList();
globallyRoutableIPv6.addSubnet('2000::', 3, 'ipv6');
for (const subnet of [
  '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32',
  '2002::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8',
]) {
  const [network, prefix] = subnet.split('/');
  if (network === undefined || prefix === undefined) throw new Error('Invalid IPv6 blocklist entry');
  blockedIPv6.addSubnet(network, Number(prefix), 'ipv6');
}

export interface WebhookDnsResolver {
  lookup(hostname: string): Promise<readonly { readonly address: string; readonly family: number }[]>;
}

const systemResolver: WebhookDnsResolver = {
  async lookup(hostname) {
    const records = await systemLookup(hostname, { all: true, verbatim: true });
    return records.map(({ address, family }) => ({ address, family }));
  },
};

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !blockedIPv4.check(address, 'ipv4');
  if (family === 6) return globallyRoutableIPv6.check(address, 'ipv6') && !blockedIPv6.check(address, 'ipv6');
  return false;
}

export async function validatePublicHttpsWebhookUrl(value: string, resolver: WebhookDnsResolver = systemResolver): Promise<URL> {
  if (value.length > 2048) throw new Error('WEBHOOK_URL_INVALID');
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('WEBHOOK_URL_INVALID'); }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '' || url.search !== ''
    || (url.port !== '' && url.port !== '443') || hostname === '' || hostname.endsWith('.localhost') || hostname === 'localhost') {
    throw new Error('WEBHOOK_URL_INVALID');
  }
  const literalFamily = isIP(hostname);
  if (literalFamily !== 0) {
    if (!isPublicAddress(hostname)) throw new Error('WEBHOOK_URL_PRIVATE_ADDRESS');
    return url;
  }
  let addresses: readonly { readonly address: string; readonly family: number }[];
  try { addresses = await resolver.lookup(hostname); } catch { throw new Error('WEBHOOK_URL_DNS_FAILED'); }
  if (addresses.length === 0 || addresses.some(({ address, family }) => (family !== 4 && family !== 6) || !isPublicAddress(address))) {
    throw new Error('WEBHOOK_URL_PRIVATE_ADDRESS');
  }
  return url;
}

export class PublicHttpsWebhookUrlValidator implements WebhookUrlValidator {
  public constructor(private readonly resolver: WebhookDnsResolver = systemResolver) {}
  public async validate(url: string): Promise<void> { await validatePublicHttpsWebhookUrl(url, this.resolver); }
}

type LookupAddress = { readonly address: string; readonly family: number };
type LookupCallback = (error: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

function publicLookup(resolver: WebhookDnsResolver): (hostname: string, options: LookupOptions, callback: LookupCallback) => void {
  return (hostname, _options, callback) => {
    void resolver.lookup(hostname).then((addresses) => {
      const address = addresses[0];
      if (address === undefined || addresses.some(({ address: candidate, family }) => (family !== 4 && family !== 6) || !isPublicAddress(candidate))) {
        callback(new Error('WEBHOOK_URL_PRIVATE_ADDRESS'), '', 0);
        return;
      }
      callback(null, address.address, address.family);
    }).catch(() => callback(new Error('WEBHOOK_URL_DNS_FAILED'), '', 0));
  };
}

export class PublicHttpsWebhookTransport implements WebhookTransport {
  public constructor(private readonly resolver: WebhookDnsResolver = systemResolver, private readonly timeoutMs = 5_000) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 15_000) throw new RangeError('timeoutMs must be from 100 to 15000');
  }

  public async send(input: {
    readonly url: string; readonly deliveryId: string; readonly eventType: string;
    readonly timestampSeconds: number; readonly body: string; readonly signature: string;
  }): Promise<number> {
    const url = await validatePublicHttpsWebhookUrl(input.url, this.resolver);
    if (Buffer.byteLength(input.body, 'utf8') > 65_536 || !Number.isSafeInteger(input.timestampSeconds)
      || !/^sha256=[0-9a-f]{64}$/.test(input.signature)) throw new Error('WEBHOOK_REQUEST_INVALID');
    return new Promise<number>((resolve, reject) => {
      const req = request(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json', 'content-length': Buffer.byteLength(input.body, 'utf8'),
          'user-agent': 'Mandate-Webhooks/1.0', 'x-mandate-delivery': input.deliveryId,
          'x-mandate-event': input.eventType, 'x-mandate-timestamp': String(input.timestampSeconds),
          'x-mandate-signature': input.signature,
        },
        lookup: publicLookup(this.resolver), servername: url.hostname.replace(/^\[|\]$/g, ''),
        timeout: this.timeoutMs, maxHeaderSize: 16_384,
      }, (response) => {
        response.resume();
        resolve(response.statusCode ?? 0);
      });
      req.once('timeout', () => req.destroy(new Error('WEBHOOK_TIMEOUT')));
      req.once('error', reject);
      req.end(input.body);
    });
  }
}
