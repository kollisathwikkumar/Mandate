export const UINT256_MAX = (1n << 256n) - 1n;

export function parseUint256(value: string, allowZero: boolean): bigint | null {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    return null;
  }

  const parsed = BigInt(value);
  if (parsed > UINT256_MAX) {
    return null;
  }
  if (!allowZero && parsed === 0n) {
    return null;
  }
  return parsed;
}
