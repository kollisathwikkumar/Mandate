import { expect, it, vi } from 'vitest';
import { createMutationTransport } from '../src/api/mutationTransport';
it('reuses the key after an uncertain network outcome and renews it after confirmed success', async () => {
  const headers: Headers[] = [];
  let fail = true;
  const transport = createMutationTransport(async (_url, options) => {
    headers.push(new Headers(options?.headers));
    if (fail) { fail = false; throw new Error('connection lost after commit'); }
    return new Response('{}', { status: 201 });
  });
  const options = { method: 'POST', body: '{"revision":2}' };
  await expect(transport('/policy/revisions', options)).rejects.toThrow('connection lost');
  await transport('/policy/revisions', options);
  await transport('/policy/revisions', options);
  expect(headers[0]?.get('Idempotency-Key')).toBeTruthy();
  expect(headers[1]?.get('Idempotency-Key')).toBe(headers[0]?.get('Idempotency-Key'));
  expect(headers[2]?.get('Idempotency-Key')).not.toBe(headers[0]?.get('Idempotency-Key'));
});
it('retains failed HTTP attempts and separates changed request bodies and endpoints', async () => {
  const keys: (string | null)[] = [];
  const transport = createMutationTransport(async (_url, options) => { keys.push(new Headers(options?.headers).get('Idempotency-Key')); return new Response('{}', { status: 503 }); });
  await transport('/a', { method: 'POST', body: 'one' });
  await transport('/a', { method: 'POST', body: 'one' });
  await transport('/a', { method: 'POST', body: 'two' });
  await transport('/b', { method: 'POST', body: 'two' });
  expect(keys[0]).toBe(keys[1]);
  expect(new Set([keys[0], keys[2], keys[3]]).size).toBe(3);
});
it('preserves an explicitly supplied cleanup key', async () => {
  let received: string | null = null;
  const send = vi.fn(async (_url: string, options: RequestInit) => { received = new Headers(options.headers).get('Idempotency-Key'); return new Response('{}'); });
  const transport = createMutationTransport(send);
  await transport('/rotate', { method: 'POST', headers: { 'Idempotency-Key': 'cleanup-key' } });
  expect(received).toBe('cleanup-key');
  expect(send).toHaveBeenCalledWith('/rotate', expect.objectContaining({ headers: expect.any(Headers) }));
});
