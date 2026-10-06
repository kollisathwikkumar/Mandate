import type { AccountCreate } from '../../api-contracts/src/schemas.js';
import type { OrganizationRole } from '../../domain/src/principal.js';
import type { AccountEnrollmentProof } from './account-enrollment-verifier.js';

export interface AccountSummary extends AccountCreate {
  readonly status: 'PAUSED' | 'ACTIVE' | 'UNSUPPORTED';
  readonly createdAt: string;
  readonly guardAddress: string | null;
  readonly moduleAddress: string | null;
  readonly verifiedAt: string | null;
}

export interface AccountRegistrationInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly request: AccountCreate;
}

export type AccountRegistrationOutcome =
  | { readonly kind: 'CREATED'; readonly account: AccountSummary }
  | { readonly kind: 'REPLAY'; readonly account: AccountSummary };

export interface AccountActivationInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly accountId: string;
  readonly proof: AccountEnrollmentProof;
}

export type AccountActivationOutcome =
  | { readonly kind: 'ACTIVATED'; readonly account: AccountSummary }
  | { readonly kind: 'REPLAY'; readonly account: AccountSummary };

export interface AccountRepository {
  getHumanRole(organizationId: string, subject: string): Promise<OrganizationRole | null>;
  listAccounts(organizationId: string): Promise<readonly AccountSummary[]>;
  getAccount(organizationId: string, accountId: string): Promise<AccountSummary | null>;
  registerAccount(input: AccountRegistrationInput): Promise<AccountRegistrationOutcome>;
  activateAccount(input: AccountActivationInput): Promise<AccountActivationOutcome>;
}
