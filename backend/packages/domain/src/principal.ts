export interface HumanPrincipal {
  readonly type: 'HUMAN';
  readonly subject: string;
  readonly verifiedEmail?: string;
}

export interface AgentPrincipal {
  readonly type: 'AGENT';
  readonly organizationId: string;
  readonly agentId: string;
  readonly keyVersion: number;
  readonly credentialId: string;
}

export type Principal = HumanPrincipal | AgentPrincipal;

export type OrganizationRole = 'OWNER' | 'ADMIN' | 'APPROVER' | 'VIEWER';
