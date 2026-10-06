import type { AgentCreate } from '../../api-contracts/src/schemas.js';
import type { OrganizationRole, Principal } from '../../domain/src/principal.js';
import type { AgentListItem, AgentRegistrationResult, AgentRepository } from '../../ports/src/agent-repository.js';
import { RepositoryAccessError } from '../../ports/src/repository-errors.js';

export class ApplicationAccessError extends Error {
  public constructor(public readonly statusCode: 403 | 404, public readonly code: 'FORBIDDEN' | 'RESOURCE_NOT_FOUND') {
    super(code === 'FORBIDDEN' ? 'The principal is not allowed to perform this operation' : 'The requested resource was not found');
    this.name = 'ApplicationAccessError';
  }
}

export class AgentApplicationService {
  public constructor(private readonly repository: AgentRepository) {}

  public async humanOrganizations(subject: string): Promise<readonly { readonly organizationId: string; readonly role: OrganizationRole }[]> {
    return this.repository.getHumanOrganizations(subject);
  }

  public async listAgents(principal: Principal, organizationId: string): Promise<readonly AgentListItem[]> {
    if (principal.type === 'AGENT') {
      if (principal.organizationId !== organizationId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      const allAgents = await this.repository.listAgents(organizationId);
      return allAgents.filter((agent) => agent.id === principal.agentId);
    }

    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return this.repository.listAgents(organizationId);
  }

  public async registerAgent(
    principal: Principal,
    organizationId: string,
    idempotencyKey: string,
    request: AgentCreate,
  ): Promise<AgentRegistrationResult> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    if (role !== 'OWNER' && role !== 'ADMIN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    try {
      return await this.repository.registerAgent({ organizationId, principalId: principal.subject, idempotencyKey, request });
    } catch (error: unknown) {
      if (error instanceof RepositoryAccessError) throw new ApplicationAccessError(error.statusCode, error.statusCode === 403 ? 'FORBIDDEN' : 'RESOURCE_NOT_FOUND');
      throw error;
    }
  }
}
