import { describe, expect, it } from 'vitest';
import { canVerifyAccount } from '../src/app/accountVerificationAction';

describe('canVerifyAccount', () => {
  it('allows an unverified paused account to be checked', () => {
    expect(canVerifyAccount('PAUSED', null)).toBe(true);
  });

  it('allows an unverified active account to be checked again', () => {
    expect(canVerifyAccount('ACTIVE', null)).toBe(true);
  });

  it('does not allow verification for an unsupported account', () => {
    expect(canVerifyAccount('UNSUPPORTED', null)).toBe(false);
  });

  it('hides verification after the account has been verified', () => {
    expect(canVerifyAccount('ACTIVE', '2026-10-07T00:00:00.000Z')).toBe(false);
  });

  it('does not expose verification for a verified paused account', () => {
    expect(canVerifyAccount('PAUSED', '2026-10-07T00:00:00.000Z')).toBe(false);
  });
});
