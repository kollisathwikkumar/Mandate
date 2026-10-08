/** Parses secondary JSON-RPC read endpoints used by receipt reconciliation. */
export function parseReceiptRpcFallbackUrls(
  value: string | undefined,
  primaryUrls: Readonly<Record<number, string>>,
): Readonly<Record<number, readonly string[]>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch {
    throw new Error('MANDATE_RECEIPT_RPC_FALLBACK_URLS must be a JSON object keyed by decimal chain ID');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('MANDATE_RECEIPT_RPC_FALLBACK_URLS must be a JSON object keyed by decimal chain ID');
  }
  const result: Record<number, readonly string[]> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key
      || primaryUrls[chainId] === undefined || !Array.isArray(entry) || entry.length < 1 || entry.length > 3
      || entry.some((endpoint) => typeof endpoint !== 'string' || endpoint.trim() === '')) {
      throw new Error('MANDATE_RECEIPT_RPC_FALLBACK_URLS contains an invalid chain ID or endpoint list');
    }
    const endpoints = entry as string[];
    if (new Set(endpoints).size !== endpoints.length || endpoints.includes(primaryUrls[chainId] as string)) {
      throw new Error('MANDATE_RECEIPT_RPC_FALLBACK_URLS contains duplicate endpoints');
    }
    result[chainId] = endpoints;
  }
  return result;
}
