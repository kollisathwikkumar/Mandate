import proxyAddress from '@fastify/proxy-addr';

const CATCH_ALL_PROXY_CIDRS = new Set(['*', '0.0.0.0/0', '::/0']);

export function parseTrustedProxyCidrs(value: string | undefined): readonly string[] | undefined {
  if (value === undefined || value.trim() === '') return undefined;
  const entries = value.split(',').map((entry) => entry.trim());
  if (entries.some((entry) => entry.length === 0)) throw new Error('MANDATE_TRUSTED_PROXY_CIDRS contains an empty proxy CIDR');
  if (entries.some((entry) => CATCH_ALL_PROXY_CIDRS.has(entry.toLowerCase()))) {
    throw new Error('MANDATE_TRUSTED_PROXY_CIDRS cannot contain catch-all proxy trust');
  }
  try {
    proxyAddress.compile(entries);
  } catch {
    throw new Error('MANDATE_TRUSTED_PROXY_CIDRS contains an invalid IP/CIDR');
  }
  return entries;
}
