import { describe, expect, it } from 'vitest';
import { parseBroadcastRpcFallbackUrls } from '../src/broadcast-rpc-config.js';

describe('parseBroadcastRpcFallbackUrls', () => {
  const primary = { 10143: 'https://primary.example/rpc' };

  it('defaults to no broadcaster fallbacks', () => {
    expect(parseBroadcastRpcFallbackUrls(undefined, primary)).toEqual({});
  });

  it('preserves the configured order of up to three backups', () => {
    expect(parseBroadcastRpcFallbackUrls('{"10143":["https://backup-1.example/rpc","https://backup-2.example/rpc"]}', primary))
      .toEqual({ 10143: ['https://backup-1.example/rpc', 'https://backup-2.example/rpc'] });
  });

  it.each([
    '{',
    '[]',
    '{"010143":["https://backup.example/rpc"]}',
    '{"1":["https://backup.example/rpc"]}',
    '{"10143":[]}',
    '{"10143":["https://a.example/rpc","https://b.example/rpc","https://c.example/rpc","https://d.example/rpc"]}',
    '{"10143":[""]}',
    '{"10143":["https://same.example/rpc","https://same.example/rpc"]}',
    '{"10143":["https://same.example/rpc","https://same.example:443/rpc"]}',
    '{"10143":["http://rpc.example/rpc"]}',
    '{"10143":["https://user:secret@rpc.example/rpc"]}',
    '{"10143":["https://primary.example/rpc"]}',
  ])('rejects malformed or unsafe fallback configuration %s', (input) => {
    expect(() => parseBroadcastRpcFallbackUrls(input, primary)).toThrow();
  });
});
