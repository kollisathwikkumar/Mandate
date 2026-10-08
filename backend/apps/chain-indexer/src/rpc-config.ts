export function parseIndexerRpcFallbackUrls(
  value: string | undefined,
  primaryUrls: Readonly<Record<number, string>>,
): Readonly<Record<number, readonly string[]>> {
  if (value === undefined || value.trim() === '') return {};
  const errorPrefix = 'MANDATE_INDEXER_RPC_FALLBACK_URLS';
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error(`${errorPrefix} must be a JSON object keyed by decimal chain ID`); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${errorPrefix} must be a JSON object keyed by decimal chain ID`);
  }

  const result: Record<number, readonly string[]> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key || !Array.isArray(entry)
      || entry.length === 0 || !entry.every((url: unknown) => typeof url === 'string' && url.trim() !== '')) {
      throw new Error(`${errorPrefix} contains an invalid chain ID or URL list`);
    }
    const primary = primaryUrls[chainId];
    if (primary === undefined) throw new Error(`${errorPrefix} has no matching primary chain`);
    const urls = entry.map((url: string) => url.trim());
    const normalizedPrimary = normalizeEndpoint(primary);
    const normalizedFallbacks = urls.map(normalizeEndpoint);
    if (new Set(normalizedFallbacks).size !== normalizedFallbacks.length) throw new Error(`${errorPrefix} contains duplicate URLs`);
    if (normalizedFallbacks.includes(normalizedPrimary)) throw new Error(`${errorPrefix} duplicates the primary URL`);
    result[chainId] = urls;
  }
  return result;
}

function normalizeEndpoint(endpoint: string): string {
  let url: URL;
  try { url = new URL(endpoint); } catch { throw new Error('Indexer RPC must use HTTPS or loopback HTTP'); }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const local = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error('Indexer RPC must use HTTPS or loopback HTTP');
  if (url.username !== '' || url.password !== '' || url.hash !== '') throw new Error('Indexer RPC URL contains unsupported components');
  return url.href;
}
