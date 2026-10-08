import { describe, expect, it } from 'vitest';
import { parseCorsAllowedOrigins } from '../src/cors-config.js';

describe('parseCorsAllowedOrigins', () => {
  it('leaves CORS disabled when no browser origins are configured', () => {
    expect(parseCorsAllowedOrigins(undefined)).toBeUndefined();
    expect(parseCorsAllowedOrigins('')).toBeUndefined();
    expect(parseCorsAllowedOrigins('   ')).toBeUndefined();
  });

  it('parses and canonicalizes an exact origin allowlist', () => {
    expect(parseCorsAllowedOrigins('https://app.example.com, http://localhost:5173'))
      .toEqual(['https://app.example.com', 'http://localhost:5173']);
  });

  it('rejects wildcard, null, path-bearing, insecure, duplicate, and malformed origins', () => {
    for (const value of ['*', 'null', 'https://app.example.com/path', 'http://app.example.com', 'https://user:pass@app.example.com', 'https://app.example.com,https://app.example.com', 'https://app.example.com,']) {
      expect(() => parseCorsAllowedOrigins(value), value).toThrow();
    }
  });
});
