import type { ZodType } from 'zod';

export class ApiFailure extends Error {
  constructor(message: string, readonly status: number, readonly code: string, readonly requestId: string) { super(message); this.name = 'ApiFailure'; }
}

export interface RequestOptions {
  readonly token: string;
  readonly method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly body?: object;
  readonly idempotency?: boolean;
  readonly signal?: AbortSignal;
}

export async function request<T>(path: string, schema: ZodType<T>, options: RequestOptions): Promise<T> {
  const headers = new Headers({ Authorization: `Bearer ${options.token}`, Accept: 'application/json' });
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (options.idempotency === true) headers.set('Idempotency-Key', crypto.randomUUID());
  const response = await fetch(path, { method: options.method ?? 'GET', headers, ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }), signal: options.signal });
  if (response.status === 204) return schema.parse({});
  const body = await response.json();
  if (!response.ok) {
    const errorResult = typeof body === 'object' && body !== null ? body : {};
    const apiError = 'error' in errorResult ? errorResult.error : null;
    const normalized = typeof apiError === 'object' && apiError !== null ? apiError : {};
    const message = 'message' in normalized && typeof normalized.message === 'string' ? normalized.message : `Request failed (${response.status})`;
    const code = 'code' in normalized && typeof normalized.code === 'string' ? normalized.code : 'REQUEST_FAILED';
    const requestId = 'requestId' in normalized && typeof normalized.requestId === 'string' ? normalized.requestId : '';
    throw new ApiFailure(message, response.status, code, requestId);
  }
  return schema.parse(body);
}
