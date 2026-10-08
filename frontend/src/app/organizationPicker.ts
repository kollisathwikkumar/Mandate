export function canSwitchOrganization(membershipCount: number): boolean {
  return membershipCount > 1;
}
