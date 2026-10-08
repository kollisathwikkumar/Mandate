import { describe, expect, it, vi } from 'vitest';
import { createAsyncOnce } from '../src/auth/asyncOnce';

describe('createAsyncOnce', () => {
  it('shares one in-flight operation across repeated callback effects', async () => {
    const once = createAsyncOnce<string>();
    const operation = vi.fn(async () => 'signed-in');

    const first = once(operation);
    const second = once(operation);

    expect(second).toBe(first);
    await expect(Promise.all([first, second])).resolves.toEqual(['signed-in', 'signed-in']);
    expect(operation).toHaveBeenCalledTimes(1);
  });

  it('keeps a failed callback from exchanging the same authorization code twice', async () => {
    const once = createAsyncOnce<string>();
    const operation = vi.fn(async () => { throw new Error('invalid_grant'); });

    const first = once(operation);
    const second = once(operation);

    expect(second).toBe(first);
    await expect(first).rejects.toThrow('invalid_grant');
    await expect(second).rejects.toThrow('invalid_grant');
    expect(operation).toHaveBeenCalledTimes(1);
  });
});
