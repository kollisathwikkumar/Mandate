export interface ResolveExecutionReorgInput {
  readonly organizationId: string;
  readonly actionId: string;
  readonly actorSubject: string;
  readonly idempotencyKey: string;
  readonly disposition: 'CONSUMED' | 'RELEASED';
  readonly reason: string;
  readonly evidenceHash: string | null;
}

export interface ExecutionReorgResolutionResult {
  readonly kind: 'CREATED' | 'REPLAY';
  readonly actionId: string;
  readonly actionState: 'REORGED';
  readonly reservationState: 'CONSUMED' | 'RELEASED';
  readonly disposition: 'CONSUMED' | 'RELEASED';
  readonly reason: string;
  readonly evidenceHash: string | null;
  readonly actorSubject: string;
  readonly resolvedAt: string;
  readonly incident: {
    readonly blockNumber: number;
    readonly previousBlockHash: string;
    readonly canonicalBlockHash: string;
  };
}

export interface ExecutionReorgResolutionRepository {
  resolveDeepReorg(input: ResolveExecutionReorgInput): Promise<ExecutionReorgResolutionResult>;
}
