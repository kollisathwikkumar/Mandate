function normalizeEndpoint(endpoint: string): string {
  let url: URL;
  try { url = new URL(endpoint); } catch { throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS contains an invalid endpoint'); }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const loopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS endpoints must use HTTPS or loopback HTTP');
  }
  if (url.username !== '' || url.password !== '' || url.hash !== '') {
    throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS contains an unsupported endpoint component');
  }
  return url.toString();
}

/** Parses ordered, per-chain backup RPCs for caller-signed transaction submission. */
export function parseBroadcastRpcFallbackUrls(
  value: string | undefined,
  primaryUrls: Readonly<Record<number, string>>,
): Readonly<Record<number, readonly string[]>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch {
    throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS must be a JSON object keyed by decimal chain ID');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS must be a JSON object keyed by decimal chain ID');
  }

  const result: Record<number, readonly string[]> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key || primaryUrls[chainId] === undefined
      || !Array.isArray(entry) || entry.length < 1 || entry.length > 3
      || entry.some((endpoint) => typeof endpoint !== 'string' || endpoint.trim() === '')) {
      throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS contains an invalid chain ID or endpoint list');
    }
    const endpoints = (entry as string[]).map((endpoint) => normalizeEndpoint(endpoint.trim()));
    const primary = normalizeEndpoint(primaryUrls[chainId] as string);
    if (new Set(endpoints).size !== endpoints.length || endpoints.includes(primary)) {
      throw new Error('MANDATE_BROADCAST_RPC_FALLBACK_URLS contains duplicate endpoints');
    }
    result[chainId] = endpoints;
  }
  return result;
}
