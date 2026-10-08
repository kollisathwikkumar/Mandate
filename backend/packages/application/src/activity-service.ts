import type { ActionDetailRecord, ActionListItem, ActivityRepository, AlertRecord, AuditEventRecord, ReceiptRecord } from '../../ports/src/activity-repository.js';
import type { ActionState } from '../../domain/src/action-state.js';
import type { Principal } from '../../domain/src/principal.js';
import { ApplicationAccessError } from './agent-service.js';

export class ActivityApplicationService {
  public constructor(private readonly repository: ActivityRepository) {}

  private async authorize(principal: Principal, organizationId: string): Promise<string | null> {
    if (principal.type === 'AGENT') {
      if (principal.organizationId !== organizationId) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      return principal.agentId;
    }
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return null;
  }

  public async getAction(principal: Principal, organizationId: string, actionId: string): Promise<ActionDetailRecord> {
    const agentId = await this.authorize(principal, organizationId);
    const action = await this.repository.getAction(organizationId, actionId, agentId);
    if (action === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return action;
  }

  public async listActions(principal: Principal, organizationId: string, state: ActionState | null, limit: number): Promise<readonly ActionListItem[]> {
    const agentId = await this.authorize(principal, organizationId);
    return this.repository.listActions(organizationId, agentId, state, limit);
  }

  public async listAuditEvents(principal: Principal, organizationId: string, limit: number, beforeSequence: string | null): Promise<readonly AuditEventRecord[]> {
    const agentId = await this.authorize(principal, organizationId);
    return this.repository.listAuditEvents(organizationId, agentId, limit, beforeSequence);
  }

  public async listReceipts(principal: Principal, organizationId: string, limit: number, actionId: string | null = null): Promise<readonly ReceiptRecord[]> {
    const agentId = await this.authorize(principal, organizationId);
    return this.repository.listReceipts(organizationId, agentId, limit, actionId);
  }

  public async listAlerts(principal: Principal, organizationId: string, limit: number): Promise<readonly AlertRecord[]> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    return this.repository.listAlerts(organizationId, limit);
  }
}
