import type { AccountCreate } from '../../api-contracts/src/schemas.js';
import type { AccountActivationOutcome, AccountRepository, AccountRegistrationOutcome, AccountSummary } from '../../ports/src/account-repository.js';
import type { Principal } from '../../domain/src/principal.js';
import type { AccountEnrollmentVerifier } from '../../ports/src/account-enrollment-verifier.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';
import { ApplicationAccessError } from './agent-service.js';

export class AccountApplicationService {
  public constructor(private readonly repository: AccountRepository, private readonly verifier: AccountEnrollmentVerifier) {}

  public async listAccounts(principal: Principal, organizationId: string): Promise<readonly AccountSummary[]> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return this.repository.listAccounts(organizationId);
  }

  public async registerAccount(
    principal: Principal,
    organizationId: string,
    idempotencyKey: string,
    request: AccountCreate,
  ): Promise<AccountRegistrationOutcome> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    if (role !== 'OWNER' && role !== 'ADMIN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      return await this.repository.registerAccount({ organizationId, principalId: principal.subject, idempotencyKey, request });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      throw error;
    }
  }

  public async verifyAccount(
    principal: Principal,
    organizationId: string,
    accountId: string,
    idempotencyKey: string,
  ): Promise<AccountActivationOutcome> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    if (role !== 'OWNER' && role !== 'ADMIN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const account = await this.repository.getAccount(organizationId, accountId);
    if (account === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    const proof = await this.verifier.verify({ chainId: account.chainId, address: account.address });
    try {
      return await this.repository.activateAccount({ organizationId, principalId: principal.subject, idempotencyKey, accountId, proof });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      throw error;
    }
  }
}
