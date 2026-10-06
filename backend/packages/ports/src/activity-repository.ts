import type { ActionState } from '../../domain/src/action-state.js';
import type { JsonObject } from '../../domain/src/json-value.js';
import type { PolicyReasonCode, PolicyVerdict } from '../../domain/src/reason-code.js';
import type { ActionIntent } from '../../policy/src/schema.js';

export interface AuditEventRecord {
  readonly sequence: string;
  readonly eventType: string;
  readonly actorType: string;
  readonly actorId: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly correlationId: string;
  readonly payload: JsonObject;
  readonly previousHash: string | null;
  readonly eventHash: string;
  readonly createdAt: string;
}

export interface ReservationRecord {
  readonly state: 'ACTIVE' | 'CONSUMED' | 'RELEASED' | 'EXPIRED';
  readonly amount: string;
  readonly leaseExpiresAt: string;
}

export interface ActionDetailRecord {
  readonly actionId: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly actionHash: string;
  readonly state: ActionState;
  readonly verdict: PolicyVerdict | null;
  readonly reason: PolicyReasonCode | null;
  readonly action: ActionIntent;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly reservation: ReservationRecord | null;
  readonly events: readonly AuditEventRecord[];
}

export interface ReceiptRecord {
  readonly id: string;
  readonly actionId: string;
  readonly chainId: number;
  readonly transactionHash: string;
  readonly blockNumber: string;
  readonly blockHash: string;
  readonly status: 'TENTATIVE' | 'FINAL' | 'REORGED';
  readonly receipt: JsonObject;
  readonly observedAt: string;
}

export interface AlertRecord {
  readonly id: string;
  readonly eventType: string;
  readonly title: string;
  readonly aggregateId: string;
  readonly createdAt: string;
}

export interface ActivityRepository {
  getHumanRole(organizationId: string, subject: string): Promise<string | null>;
  getAction(organizationId: string, actionId: string, agentId: string | null): Promise<ActionDetailRecord | null>;
  listAuditEvents(organizationId: string, agentId: string | null, limit: number, beforeSequence: string | null): Promise<readonly AuditEventRecord[]>;
  listReceipts(organizationId: string, agentId: string | null, limit: number): Promise<readonly ReceiptRecord[]>;
  listAlerts(organizationId: string, limit: number): Promise<readonly AlertRecord[]>;
}
