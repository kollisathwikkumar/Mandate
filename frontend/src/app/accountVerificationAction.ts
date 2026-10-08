export type AccountVerificationStatus = 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED';

export function canVerifyAccount(status: AccountVerificationStatus, verifiedAt: string | null): boolean {
  return verifiedAt === null && status !== 'UNSUPPORTED';
}
