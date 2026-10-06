import { describe, expect, it, vi } from 'vitest';
import { ExecutionReorgResolutionService } from '../src/execution-reorg-resolution-service.js';
import type { ExecutionReorgResolutionRepository, ResolveExecutionReorgInput } from '../../ports/src/execution-reorg-resolution.js';
import type { Principal } from '../../domain/src/principal.js';

const input: Omit<ResolveExecutionReorgInput, 'actorSubject'> = {
  organizationId: 'org-a', actionId: 'action-a', idempotencyKey: 'resolve-1',
  disposition: 'CONSUMED', reason: 'Treasury confirmed the transfer settled outside the canonical view.', evidenceHash: null,
};

describe('ExecutionReorgResolutionService', () => {
  it('allows only a human principal and preserves the supplied incident disposition', async () => {
    const resolve = vi.fn().mockResolvedValue({ kind: 'CREATED', actionId: 'action-a', actionState: 'REORGED', reservationState: 'CONSUMED' });
    const repository: ExecutionReorgResolutionRepository = { resolveDeepReorg: resolve };
    const service = new ExecutionReorgResolutionService(repository);
    const human: Principal = { type: 'HUMAN', subject: 'owner-a' };
    await expect(service.resolve(human, input)).resolves.toMatchObject({ kind: 'CREATED', actionState: 'REORGED', reservationState: 'CONSUMED' });
    expect(resolve).toHaveBeenCalledWith({ ...input, actorSubject: 'owner-a' });
  });

  it('rejects agent principals before reaching the repository', async () => {
    const resolve = vi.fn();
    const service = new ExecutionReorgResolutionService({ resolveDeepReorg: resolve });
    const agent: Principal = { type: 'AGENT', organizationId: 'org-a', agentId: 'agent-a', keyVersion: 1, credentialId: 'cred-a' };
    await expect(service.resolve(agent, input)).rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    expect(resolve).not.toHaveBeenCalled();
  });
});
