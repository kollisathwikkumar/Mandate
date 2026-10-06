import type { JsonObject } from '../../domain/src/json-value.js';

export const WEBHOOK_EVENT_TYPES = [
  'ACTION_BLOCKED', 'ACTION_HELD', 'ACTION_RESERVED', 'ACTION_AUTHORIZED', 'ACTION_SUBMITTED', 'ACTION_RECONCILED',
  'ACTION_REVERTED', 'ACTION_DROPPED', 'ACTION_DEEP_REORG_DETECTED', 'ACTION_RECEIPT_REORGED',
  'ACTION_RECEIPT_TENTATIVE', 'ACTION_TRANSACTION_REPLACED', 'ACTION_APPROVED', 'ACTION_DENIED', 'ACTION_EXPIRED',
  'POLICY_DRAFT_CREATED', 'POLICY_REVISION_CREATED', 'POLICY_ACTIVATION_PLAN_CREATED', 'POLICY_ACTIVATED',
  'POLICY_REVOCATION_PLAN_CREATED', 'POLICY_REVOKED', 'AGENT_REGISTERED', 'ACCOUNT_PROTECTION_PAUSED',
  'MODEL_PROVIDER_CREDENTIAL_WRITTEN', 'WEBHOOK_ENDPOINT_CREATED', 'WEBHOOK_ENDPOINT_UPDATED', 'WEBHOOK_ENDPOINT_DELETED',
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export interface WebhookEndpointSummary {
  readonly id: string;
  readonly url: string;
  readonly eventTypes: readonly WebhookEventType[];
  readonly enabled: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface WebhookDeliverySummary {
  readonly id: string;
  readonly endpointId: string;
  readonly eventType: string;
  readonly status: 'PENDING' | 'DELIVERED' | 'FAILED';
  readonly attempts: number;
  readonly availableAt: string;
  readonly deliveredAt: string | null;
  readonly lastErrorCode: string | null;
}

export type WebhookEndpointMutationOutcome<TKind extends string> = {
  readonly kind: TKind;
  readonly endpoint: WebhookEndpointSummary;
};

export type WebhookSecretRotationOutcome = {
  readonly kind: 'ROTATED' | 'REPLAY';
  readonly priorSecretReference: string | null;
};

export type WebhookRemovalOutcome = {
  readonly kind: 'REMOVED' | 'REPLAY';
  readonly secretReference: string | null;
};

export interface WebhookEndpointRepository {
  getHumanRole(organizationId: string, subject: string): Promise<string | null>;
  list(organizationId: string, principalId: string): Promise<readonly WebhookEndpointSummary[]>;
  create(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string; readonly url: string;
    readonly eventTypes: readonly WebhookEventType[]; readonly secretReference: string;
  }): Promise<WebhookEndpointMutationOutcome<'CREATED' | 'REPLAY'>>;
  rotateSecret(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string; readonly secretReference: string;
  }): Promise<WebhookSecretRotationOutcome>;
  setEnabled(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string; readonly enabled: boolean;
  }): Promise<WebhookEndpointMutationOutcome<'UPDATED' | 'REPLAY'>>;
  disableAndRemove(input: {
    readonly organizationId: string; readonly principalId: string; readonly endpointId: string;
    readonly idempotencyKey: string; readonly requestHash: string;
  }): Promise<WebhookRemovalOutcome>;
  clearSecretReference(input: { readonly organizationId: string; readonly endpointId: string; readonly secretReference: string }): Promise<void>;
  clearPriorSecretReference(input: { readonly organizationId: string; readonly endpointId: string; readonly secretReference: string }): Promise<void>;
  listDeliveries(input: { readonly organizationId: string; readonly principalId: string; readonly endpointId: string; readonly limit: number }): Promise<readonly WebhookDeliverySummary[]>;
}

export interface WebhookSecretStore {
  put(organizationId: string, endpointId: string, secret: string): Promise<string>;
  get(secretReference: string): Promise<string>;
  delete(secretReference: string): Promise<void>;
}

export interface WebhookUrlValidator {
  validate(url: string): Promise<void>;
}

export interface WebhookDeliveryPayload {
  readonly id: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly organizationId: string;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly createdAt: string;
  readonly data: JsonObject;
}

export interface WebhookTransport {
  send(input: { readonly url: string; readonly deliveryId: string; readonly eventType: string; readonly timestampSeconds: number; readonly body: string; readonly signature: string }): Promise<number>;
}
