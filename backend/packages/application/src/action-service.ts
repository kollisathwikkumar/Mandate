import { ApplicationAccessError } from './agent-service.js';
import type { Principal } from '../../domain/src/principal.js';
import type { ActionRepository, ActionSubmissionOutcome } from '../../ports/src/action-repository.js';
import type { ActionIntent } from '../../policy/src/schema.js';

export class ActionApplicationService {
  public constructor(private readonly repository: ActionRepository) {}

  public async submitAction(
    principal: Principal,
    organizationId: string,
    idempotencyKey: string,
    action: ActionIntent,
  ): Promise<ActionSubmissionOutcome> {
    if (principal.type !== 'AGENT') throw new ApplicationAccessError(403, 'FORBIDDEN');
    if (principal.organizationId !== organizationId || action.organizationId !== organizationId) {
      throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    }
    if (action.agentId !== principal.agentId || action.agentKeyVersion !== principal.keyVersion) {
      throw new ApplicationAccessError(403, 'FORBIDDEN');
    }
    return this.repository.submitAction({
      organizationId,
      agentId: principal.agentId,
      agentKeyVersion: principal.keyVersion,
      credentialId: principal.credentialId,
      idempotencyKey,
      action,
    });
  }
}
