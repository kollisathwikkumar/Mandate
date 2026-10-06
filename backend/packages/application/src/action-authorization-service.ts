import { ApplicationAccessError } from './agent-service.js';
import type { Principal } from '../../domain/src/principal.js';
import { ActionAuthorizationConflictError, type ActionAuthorizationContext, type ActionAuthorizationOutcome, type ActionAuthorizationRepository } from '../../ports/src/action-authorization-repository.js';
import type { ActionExecutionStateReader } from '../../ports/src/action-execution-state-reader.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';
import { ActionExecutionAuthorizationError, buildActionExecutionAuthorization, parseActionExecutionAuthorization, type ActionExecutionAuthorization } from '../../chain/src/action-execution-authorization.js';

export { ActionAuthorizationConflictError } from '../../ports/src/action-authorization-repository.js';

export class ActionAuthorizationApplicationService {
  public constructor(
    private readonly repository: ActionAuthorizationRepository,
    private readonly stateReader: ActionExecutionStateReader,
  ) {}

  public async authorizeAction(
    principal: Principal,
    organizationId: string,
    actionId: string,
    idempotencyKey: string,
  ): Promise<ActionAuthorizationOutcome> {
    if (principal.type !== 'AGENT') throw new ApplicationAccessError(403, 'FORBIDDEN');
    if (principal.organizationId !== organizationId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    const identity = {
      organizationId, agentId: principal.agentId, agentKeyVersion: principal.keyVersion,
      credentialId: principal.credentialId, actionId,
    };
    let context: ActionAuthorizationContext;
    try {
      context = await this.repository.getAuthorizationContext(identity);
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) {
        throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      }
      throw error;
    }
    if (context.existingAuthorization !== null) {
      if (context.existingAuthorization.idempotencyKey !== idempotencyKey) {
        throw new ActionAuthorizationConflictError('Action already has an authorization under a different idempotency key', 'IDEMPOTENCY_CONFLICT');
      }
      if (context.existingAuthorization.status !== 'ACTIVE') {
        throw new ActionAuthorizationConflictError('Action authorization is no longer active');
      }
      if (context.existingAuthorization.authorization.deadline <= Math.floor(Date.now() / 1000)) {
        throw new ActionAuthorizationConflictError('Action authorization has expired and must be replanned');
      }
      const authorization = parseActionExecutionAuthorization(context.existingAuthorization.authorization);
      return { kind: 'REPLAY', result: { actionId, state: 'AUTHORIZED', authorization } };
    }
    if (context.actionState !== 'RESERVED' || context.policyState !== 'ACTIVE'
      || context.currentRevision !== context.action.policyRevision
      || context.currentRevisionHash !== context.action.policyRevisionHash
      || context.accountStatus !== 'ACTIVE' || context.accountAddress !== context.action.account
      || context.accountChainId !== context.action.chainId || !context.grantActive
      || context.reservationExpiresAt === null || new Date(context.reservationExpiresAt).getTime() <= Date.now()
      || context.guardAddress.length === 0 || context.moduleAddress.length === 0) {
      throw new ActionAuthorizationConflictError('Action, active grant, account, or reservation is no longer eligible for authorization');
    }

    const state = await this.stateReader.readState({
      chainId: context.action.chainId,
      safeAddress: context.accountAddress,
      guardAddress: context.guardAddress,
      moduleAddress: context.moduleAddress,
      agentAddress: context.policy.agentAddress,
    });
    let authorization: ActionExecutionAuthorization;
    try {
      authorization = buildActionExecutionAuthorization({ action: context.action, policy: context.policy, state });
    } catch (error: unknown) {
      if (error instanceof ActionExecutionAuthorizationError) {
        throw new ActionAuthorizationConflictError('Current chain state does not authorize this exact action');
      }
      throw error;
    }
    try {
      return await this.repository.saveAuthorization({ ...identity, idempotencyKey, authorization });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) {
        throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      }
      throw error;
    }
  }
}
