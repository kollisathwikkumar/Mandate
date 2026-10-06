import type { OrganizationRole } from '../../domain/src/principal.js';

export interface OrganizationMemberSummary {
  readonly subject: string;
  readonly role: OrganizationRole;
  readonly createdAt: string;
}

export interface OrganizationMembershipRepository {
  getHumanRole(organizationId: string, subject: string): Promise<OrganizationRole | null>;
  listMembers(organizationId: string, principalId: string): Promise<readonly OrganizationMemberSummary[]>;
  setMemberRole(input: { readonly organizationId: string; readonly principalId: string; readonly subject: string; readonly role: OrganizationRole; readonly idempotencyKey: string; readonly requestHash: string }): Promise<{ readonly kind: 'CREATED' | 'UPDATED' | 'REPLAY'; readonly member: OrganizationMemberSummary }>;
  removeMember(input: { readonly organizationId: string; readonly principalId: string; readonly subject: string; readonly idempotencyKey: string; readonly requestHash: string }): Promise<'REMOVED' | 'REPLAY'>;
}
