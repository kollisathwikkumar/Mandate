import { describe, expect, it } from 'vitest';
import { parseReceiptRpcFallbackUrls } from '../src/receipt-rpc-config.js';

describe('parseReceiptRpcFallbackUrls', () => {
  const primary = { 10143: 'https://primary.example/rpc' };

  it('defaults to no receipt-read fallbacks', () => {
    expect(parseReceiptRpcFallbackUrls(undefined, primary)).toEqual({});
  });

  it('parses up to three ordered fallbacks for configured chains', () => {
    expect(parseReceiptRpcFallbackUrls('{"10143":["https://backup-1.example/rpc","https://backup-2.example/rpc"]}', primary))
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
    '{"10143":["https://primary.example/rpc"]}',
  ])('rejects malformed or unsafe configuration %s', (input) => {
    expect(() => parseReceiptRpcFallbackUrls(input, primary)).toThrow();
  });
});
