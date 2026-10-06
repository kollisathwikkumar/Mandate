import type { Principal } from '../../domain/src/principal.js';
import type { ExecutionReorgResolutionRepository, ExecutionReorgResolutionResult } from '../../ports/src/execution-reorg-resolution.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';
import { ApplicationAccessError } from './agent-service.js';

export class ExecutionReorgResolutionService {
  public constructor(private readonly repository: ExecutionReorgResolutionRepository) {}

  public async resolve(
    principal: Principal,
    input: Omit<Parameters<ExecutionReorgResolutionRepository['resolveDeepReorg']>[0], 'actorSubject'>,
  ): Promise<ExecutionReorgResolutionResult> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      return await this.repository.resolveDeepReorg({ ...input, actorSubject: principal.subject });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) {
        throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      }
      throw error;
    }
  }
}
