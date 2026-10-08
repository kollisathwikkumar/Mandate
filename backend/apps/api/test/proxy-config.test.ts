import { describe, expect, it } from 'vitest';
import { parseTrustedProxyCidrs } from '../src/proxy-config.js';

describe('parseTrustedProxyCidrs', () => {
  it('returns no proxy trust when no CIDR allowlist is configured', () => {
    expect(parseTrustedProxyCidrs(undefined)).toBeUndefined();
    expect(parseTrustedProxyCidrs('')).toBeUndefined();
    expect(parseTrustedProxyCidrs('   ')).toBeUndefined();
  });

  it('parses and trims a comma-separated explicit proxy CIDR allowlist', () => {
    expect(parseTrustedProxyCidrs('10.20.0.0/24, 192.0.2.10, 2001:db8::/32'))
      .toEqual(['10.20.0.0/24', '192.0.2.10', '2001:db8::/32']);
  });

  it('rejects empty entries and catch-all proxy trust', () => {
    expect(() => parseTrustedProxyCidrs('10.0.0.0/8,')).toThrow('empty proxy CIDR');
    expect(() => parseTrustedProxyCidrs('*,10.0.0.0/8')).toThrow('catch-all');
    expect(() => parseTrustedProxyCidrs('0.0.0.0/0')).toThrow('catch-all');
    expect(() => parseTrustedProxyCidrs('::/0')).toThrow('catch-all');
    expect(() => parseTrustedProxyCidrs('not-an-ip-or-cidr')).toThrow('invalid IP/CIDR');
  });
});
