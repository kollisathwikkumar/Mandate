import { describe, expect, it } from 'vitest';
import { runBatchWithIsolation } from '../src/batch-boundary.js';

describe('worker batch failure boundary', () => {
  it('continues other work after an outbox claim failure and retries on the next cycle', async () => {
    const failures: string[] = [];
    let attempts = 0;
    const outbox = () => {
      attempts += 1;
      if (attempts === 1) return Promise.reject(new Error('private database URL'));
      return Promise.resolve({ claimed: 1 });
    };
    const first = await runBatchWithIsolation('outbox-worker', outbox, (component) => failures.push(component));
    const webhook = await runBatchWithIsolation('webhook-delivery-worker', async () => ({ claimed: 2 }), (component) => failures.push(component));
    const second = await runBatchWithIsolation('outbox-worker', outbox, (component) => failures.push(component));
    expect(first).toBeNull();
    expect(webhook).toEqual({ claimed: 2 });
    expect(second).toEqual({ claimed: 1 });
    expect(failures).toEqual(['outbox-worker']);
    expect(JSON.stringify(failures)).not.toContain('private database URL');
  });
});
