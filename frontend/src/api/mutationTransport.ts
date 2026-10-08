import { useRef } from 'react';

type MutationOptions = Omit<RequestInit, 'body' | 'method'> & { readonly method: string; readonly body?: string };
type Transport = (path: string, options: RequestInit) => Promise<Response>;

/** Component-lifetime retry identity. Never stores bodies or credentials in browser storage. */
export function createMutationTransport(send: Transport = fetch): (path: string, options: MutationOptions) => Promise<Response> {
  const pending = new Map<string, { body: string | undefined; key: string }>();
  return async (path, options) => {
    const headers = new Headers(options.headers);
    const operation = `${options.method}:${path}`;
    const previous = pending.get(operation);
    const key = headers.get('Idempotency-Key') ?? (previous?.body === options.body ? previous?.key : undefined) ?? crypto.randomUUID();
    pending.set(operation, { body: options.body, key });
    headers.set('Idempotency-Key', key);
    const response = await send(path, { ...options, headers });
    if (response.ok) await response.clone().arrayBuffer();
    if (response.ok && pending.get(operation)?.key === key) pending.delete(operation);
    return response;
  };
}

export function useMutationTransport(): ReturnType<typeof createMutationTransport> {
  const ref = useRef<ReturnType<typeof createMutationTransport> | null>(null);
  if (ref.current === null) ref.current = createMutationTransport();
  return ref.current;
}
