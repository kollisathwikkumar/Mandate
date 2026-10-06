import type { Principal } from '../../domain/src/principal.js';
import type { ApprovalOutcome, ApprovalRepository } from '../../ports/src/approval-repository.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';
import { ApplicationAccessError } from './agent-service.js';

export class ApprovalApplicationService {
  public constructor(private readonly repository: ApprovalRepository) {}

  public async decide(
    principal: Principal,
    organizationId: string,
    actionId: string,
    idempotencyKey: string,
    actionHash: string,
    outcome: 'APPROVED' | 'DENIED',
  ): Promise<ApprovalOutcome> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      return await this.repository.approveAction({
        organizationId,
        actionId,
        approverSubject: principal.subject,
        idempotencyKey,
        actionHash,
        outcome,
      });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) {
        throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      }
      throw error;
    }
  }
}
