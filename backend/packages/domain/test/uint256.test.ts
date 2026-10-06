import { describe, expect, it } from 'vitest';
import { parseUint256, UINT256_MAX } from '../src/uint256.js';

describe('uint256 base-unit parsing', () => {
  it('parses zero when the field permits zero', () => {
    expect(parseUint256('0', true)).toBe(0n);
  });

  it('parses a positive amount and the maximum EVM uint256', () => {
    expect(parseUint256('42', false)).toBe(42n);
    expect(parseUint256(UINT256_MAX.toString(), false)).toBe(UINT256_MAX);
  });

  it('rejects non-canonical decimal values, disallowed zero, and uint256 overflow', () => {
    expect(parseUint256('01', true)).toBeNull();
    expect(parseUint256('1.2', true)).toBeNull();
    expect(parseUint256('0', false)).toBeNull();
    expect(parseUint256((UINT256_MAX + 1n).toString(), true)).toBeNull();
  });
});
