import { describe, expect, it } from 'vitest';
import { parseIndexerRpcFallbackUrls } from '../src/rpc-config.js';

describe('indexer RPC failover configuration', () => {
  const primaries = { 10143: 'https://primary.example/rpc', 143: 'http://127.0.0.1:8545' };

  it('accepts a fallback list only for configured chains and preserves endpoint priority', () => {
    expect(parseIndexerRpcFallbackUrls(
      '{"10143":["https://backup-a.example/rpc","https://backup-b.example/rpc"]}', primaries,
    )).toEqual({ 10143: ['https://backup-a.example/rpc', 'https://backup-b.example/rpc'] });
    expect(parseIndexerRpcFallbackUrls(
      '{"143":["http://127.0.0.1:8546"]}', primaries,
    )).toEqual({ 143: ['http://127.0.0.1:8546'] });
  });

  it('returns no fallbacks for an omitted or empty configuration', () => {
    expect(parseIndexerRpcFallbackUrls(undefined, primaries)).toEqual({});
    expect(parseIndexerRpcFallbackUrls('{}', primaries)).toEqual({});
  });

  it('rejects malformed, empty, duplicate, unsafe, and unmatched fallback configuration', () => {
    expect(() => parseIndexerRpcFallbackUrls('{', primaries)).toThrow('MANDATE_INDEXER_RPC_FALLBACK_URLS');
    expect(() => parseIndexerRpcFallbackUrls('[]', primaries)).toThrow('MANDATE_INDEXER_RPC_FALLBACK_URLS');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":[]}', primaries)).toThrow('MANDATE_INDEXER_RPC_FALLBACK_URLS');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":[""]}', primaries)).toThrow('MANDATE_INDEXER_RPC_FALLBACK_URLS');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":"https://backup.example/rpc"}', primaries)).toThrow('MANDATE_INDEXER_RPC_FALLBACK_URLS');
    expect(() => parseIndexerRpcFallbackUrls('{"01":["https://backup.example/rpc"]}', primaries)).toThrow('MANDATE_INDEXER_RPC_FALLBACK_URLS');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":["https://backup.example/rpc","https://backup.example/rpc"]}', primaries)).toThrow('duplicate');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":["https://backup.example/rpc","https://backup.example:443/rpc"]}', primaries)).toThrow('duplicate');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":["https://primary.example/rpc"]}', primaries)).toThrow('primary URL');
    expect(() => parseIndexerRpcFallbackUrls('{"1":["https://backup.example/rpc"]}', primaries)).toThrow('primary chain');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":["http://rpc.example/rpc"]}', primaries)).toThrow('HTTPS or loopback HTTP');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":["https://user:pass@backup.example/rpc"]}', primaries)).toThrow('unsupported components');
    expect(() => parseIndexerRpcFallbackUrls('{"10143":["https://backup.example/rpc#fragment"]}', primaries)).toThrow('unsupported components');
  });
});
