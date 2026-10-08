import type { Principal } from '../../domain/src/principal.js';
import type { PolicyListItem, PolicyRepository, PolicySimulationResult, PolicyWriteOutcome } from '../../ports/src/policy-repository.js';
import type { ActionIntent, PolicyRevision } from '../../policy/src/schema.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';
import { ApplicationAccessError } from './agent-service.js';

export class PolicyApplicationService {
  public constructor(private readonly repository: PolicyRepository) {}

  public async listPolicies(principal: Principal, organizationId: string): Promise<readonly PolicyListItem[]> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return this.repository.listPolicies(organizationId);
  }

  public async getRevision(principal: Principal, organizationId: string, policyId: string, revision: number): Promise<PolicyRevision> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    const policy = await this.repository.getRevision(organizationId, policyId, revision);
    if (policy === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return policy;
  }

  public async simulateAction(
    principal: Principal,
    organizationId: string,
    policyId: string,
    action: ActionIntent,
  ): Promise<PolicySimulationResult> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    if (action.organizationId !== organizationId || action.policyId !== policyId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    try {
      return await this.repository.simulateAction(organizationId, policyId, action);
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) {
        throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      }
      throw error;
    }
  }

  public async createDraft(
    principal: Principal,
    organizationId: string,
    idempotencyKey: string,
    revision: PolicyRevision,
  ): Promise<PolicyWriteOutcome> {
    return this.writePolicy(principal, organizationId, idempotencyKey, revision, 'CREATE_DRAFT');
  }

  public async createRevision(
    principal: Principal,
    organizationId: string,
    idempotencyKey: string,
    revision: PolicyRevision,
  ): Promise<PolicyWriteOutcome> {
    return this.writePolicy(principal, organizationId, idempotencyKey, revision, 'CREATE_REVISION');
  }

  private async writePolicy(
    principal: Principal,
    organizationId: string,
    idempotencyKey: string,
    revision: PolicyRevision,
    operation: 'CREATE_DRAFT' | 'CREATE_REVISION',
  ): Promise<PolicyWriteOutcome> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    if (revision.organizationId !== organizationId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    if (role !== 'OWNER' && role !== 'ADMIN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const input = { organizationId, principalId: principal.subject, idempotencyKey, revision };
    return operation === 'CREATE_DRAFT' ? this.repository.createDraft(input) : this.repository.createRevision(input);
  }
}
