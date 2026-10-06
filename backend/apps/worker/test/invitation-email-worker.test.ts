import type { Pool, PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { InvitationEmailDeliveryWorker } from '../src/invitation-email-worker.js';

describe('InvitationEmailDeliveryWorker batch transaction', () => {
  it('rejects batch sizes outside the bounded range before acquiring PostgreSQL', async () => {
    const connect = vi.fn();
    const worker = new InvitationEmailDeliveryWorker(
      { connect } as unknown as Pool,
      { encrypt: () => 'ciphertext', decrypt: () => 'token' },
      { send: async () => {} },
      { from: 'mandate@example.com', acceptUrl: 'https://console.example.com/accept' },
    );
    for (const batchSize of [0, -1, 1.5, 51, Number.NaN]) {
      await expect(worker.runBatch(batchSize)).rejects.toThrow('batchSize must be an integer from 1 to 50');
    }
    expect(connect).not.toHaveBeenCalled();
  });

  it('rolls back and releases a claimed-batch transaction when PostgreSQL fails', async () => {
    const queries: string[] = [];
    const release = vi.fn();
    const client = {
      async query(sql: string): Promise<{ rows: never[]; rowCount: number }> {
        queries.push(sql);
        if (sql === 'BEGIN' || sql === 'ROLLBACK') return { rows: [], rowCount: 0 };
        throw new Error('postgres unavailable');
      },
      release,
    } as unknown as PoolClient;
    const pool = { connect: async () => client } as unknown as Pool;
    const worker = new InvitationEmailDeliveryWorker(
      pool,
      { encrypt: () => 'ciphertext', decrypt: () => 'token' },
      { send: async () => {} },
      { from: 'mandate@example.com', acceptUrl: 'https://console.example.com/accept' },
    );
    await expect(worker.runBatch()).rejects.toThrow('postgres unavailable');
    expect(queries[0]).toBe('BEGIN');
    expect(queries.at(-1)).toBe('ROLLBACK');
    expect(release).toHaveBeenCalledOnce();
  });
});
