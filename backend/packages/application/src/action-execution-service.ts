import { ApplicationAccessError } from './agent-service.js';
import type { Principal } from '../../domain/src/principal.js';
import type { ActionAuthorizationContext, ActionAuthorizationRepository } from '../../ports/src/action-authorization-repository.js';
import type { ActionExecutionSubmissionIdentity, ActionExecutionSubmissionRepository, ActionExecutionSubmissionResult } from '../../ports/src/action-execution-submission-repository.js';
import { ActionExecutionAuthorizationError, validateSignedActionExecutionTransaction } from '../../chain/src/action-execution-authorization.js';
import { ActionTransactionSubmissionError, type ActionTransactionSubmitter } from '../../ports/src/action-transaction-submitter.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';

export class ActionExecutionRequestError extends Error {
  public constructor(public readonly statusCode: 400 | 409, public readonly code: 'INVALID_REQUEST' | 'RESOURCE_CONFLICT', message: string) {
    super(message);
    this.name = 'ActionExecutionRequestError';
  }
}

export type ActionExecutionOutcome =
  | { readonly kind: 'CREATED'; readonly result: ActionExecutionSubmissionResult }
  | { readonly kind: 'REPLAY'; readonly result: ActionExecutionSubmissionResult };

export class ActionExecutionApplicationService {
  public constructor(
    private readonly authorizationRepository: ActionAuthorizationRepository,
    private readonly submissionRepository: ActionExecutionSubmissionRepository,
    private readonly transactionSubmitter: ActionTransactionSubmitter,
  ) {}

  public async executeAction(
    principal: Principal,
    organizationId: string,
    actionId: string,
    idempotencyKey: string,
    signature: string,
    rawTransaction: string,
  ): Promise<ActionExecutionOutcome> {
    if (principal.type !== 'AGENT') throw new ApplicationAccessError(403, 'FORBIDDEN');
    if (principal.organizationId !== organizationId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    const identity = {
      organizationId, agentId: principal.agentId, agentKeyVersion: principal.keyVersion,
      credentialId: principal.credentialId, actionId,
    };
    let context: ActionAuthorizationContext;
    try { context = await this.authorizationRepository.getAuthorizationContext(identity); }
    catch (error: unknown) {
      if (error instanceof RepositoryAccessError) {
        throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      }
      throw error;
    }
    const stored = context.existingAuthorization;
    if (stored === null || stored.authorization.actionId !== actionId || stored.authorization.agentAddress !== context.policy.agentAddress
      || stored.authorization.keyVersion !== principal.keyVersion) {
      throw new ActionExecutionRequestError(409, 'RESOURCE_CONFLICT', 'No matching active action authorization exists');
    }
    let transaction: ReturnType<typeof validateSignedActionExecutionTransaction>;
    try { transaction = validateSignedActionExecutionTransaction(stored.authorization, signature, rawTransaction); }
    catch (error: unknown) {
      if (error instanceof ActionExecutionAuthorizationError) {
        throw new ActionExecutionRequestError(400, 'INVALID_REQUEST', 'Agent signature or signed transaction does not match the stored authorization');
      }
      throw error;
    }
    const submission: ActionExecutionSubmissionIdentity = {
      ...identity, idempotencyKey, transactionHash: transaction.transactionHash,
      outerSender: transaction.from, outerNonce: transaction.nonce,
    };
    const reservation = await this.submissionRepository.reserveSubmission(submission);
    if (reservation.kind === 'REPLAY') return { kind: 'REPLAY', result: reservation.result };
    let submitted: { readonly transactionHash: string };
    try {
      submitted = await this.transactionSubmitter.submitRawTransaction({
        chainId: stored.authorization.chainId,
        rawTransaction,
      });
    } catch (error: unknown) {
      if (error instanceof ActionTransactionSubmissionError) throw error;
      throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
    }
    if (submitted.transactionHash.toLowerCase() !== transaction.transactionHash.toLowerCase()) {
      throw new ActionTransactionSubmissionError('RPC_UNAVAILABLE');
    }
    return this.submissionRepository.completeSubmission(submission);
  }
}
