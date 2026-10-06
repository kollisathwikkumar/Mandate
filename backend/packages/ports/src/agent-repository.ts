import type { AgentCreate } from '../../api-contracts/src/schemas.js';
import type { OrganizationRole } from '../../domain/src/principal.js';

export interface AgentSummary {
  readonly id: string;
  readonly displayName: string;
  readonly status: 'ACTIVE';
  readonly keyVersion: number;
  readonly createdAt: string;
}

export interface AgentListItem {
  readonly id: string;
  readonly displayName: string;
  readonly status: 'ACTIVE' | 'REVOKED';
  readonly keyVersion: number;
  readonly createdAt: string;
}

export interface AgentRegistrationInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly request: AgentCreate;
}

export type AgentRegistrationResult =
  | { readonly kind: 'CREATED'; readonly agent: AgentSummary; readonly token: string }
  | { readonly kind: 'REPLAY'; readonly agent: AgentSummary };

export interface AgentCredentialIdentity {
  readonly organizationId: string;
  readonly agentId: string;
  readonly keyVersion: number;
  readonly credentialId: string;
}

export interface AgentRepository {
  getHumanRole(organizationId: string, subject: string): Promise<OrganizationRole | null>;
  getHumanOrganizations(subject: string): Promise<readonly { readonly organizationId: string; readonly role: OrganizationRole }[]>;
  listAgents(organizationId: string): Promise<readonly AgentListItem[]>;
  registerAgent(input: AgentRegistrationInput): Promise<AgentRegistrationResult>;
  findAgentByCredentialHash(secretHash: string): Promise<AgentCredentialIdentity | null>;
}
