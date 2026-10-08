export type ModelProvider = 'DEEPSEEK' | 'OPENAI' | 'ANTHROPIC' | 'OTHER';
export type ModelCredentialState = 'ACTIVE' | 'DISABLED' | 'ERROR';

export interface ModelCredentialSummary {
  readonly provider: ModelProvider;
  readonly maskedSuffix: string;
  readonly state: ModelCredentialState;
  readonly createdAt: string;
  readonly rotatedAt: string | null;
  readonly verifiedAt: string | null;
  readonly disabledAt: string | null;
}

export interface ModelCredentialRecord extends ModelCredentialSummary {
  readonly secretReference: string;
}

export interface ModelCredentialWriteInput {
  readonly organizationId: string;
  readonly principalId: string;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly provider: ModelProvider;
  readonly secretReference: string;
  readonly maskedSuffix: string;
}

export type ModelCredentialWriteOutcome =
  | { readonly kind: 'CREATED'; readonly credential: ModelCredentialSummary; readonly replacedSecretReference: string | null }
  | { readonly kind: 'REPLAY'; readonly credential: ModelCredentialSummary };

export interface ModelCredentialRepository {
  getHumanRole(organizationId: string, subject: string): Promise<string | null>;
  listCredentials(organizationId: string): Promise<readonly ModelCredentialSummary[]>;
  getCredential(organizationId: string, provider: ModelProvider): Promise<ModelCredentialRecord | null>;
  writeCredential(input: ModelCredentialWriteInput): Promise<ModelCredentialWriteOutcome>;
  updateCredentialState(organizationId: string, principalId: string, provider: ModelProvider, state: ModelCredentialState): Promise<ModelCredentialRecord | null>;
  deleteCredential(organizationId: string, principalId: string, provider: ModelProvider): Promise<ModelCredentialRecord | null>;
  markVerified(organizationId: string, principalId: string, provider: ModelProvider, secretReference: string, state: 'ACTIVE' | 'ERROR'): Promise<ModelCredentialRecord | null>;
}
