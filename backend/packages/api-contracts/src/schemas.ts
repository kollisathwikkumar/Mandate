import { z } from 'zod';

export const AgentCreateSchema = z.object({
  id: z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/),
  displayName: z.string().trim().min(1).max(160),
}).strict();

export type AgentCreate = z.infer<typeof AgentCreateSchema>;

export const AccountCreateSchema = z.object({
  id: z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/),
  chainId: z.number().int().positive().safe(),
  address: z.string().regex(/^0x[0-9a-fA-F]{40}$/).transform((value) => value.toLowerCase()),
  adapter: z.literal('evm-smart-account'),
}).strict();

export type AccountCreate = z.infer<typeof AccountCreateSchema>;

export const API_ERROR_CODES = [
  'UNAUTHENTICATED',
  'FORBIDDEN',
  'RESOURCE_NOT_FOUND',
  'INVALID_REQUEST',
  'IDEMPOTENCY_CONFLICT',
  'RESOURCE_CONFLICT',
  'DEPENDENCY_UNAVAILABLE',
  'INTERNAL_ERROR',
  'RATE_LIMITED',
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

export const ApiErrorSchema = z.object({
  error: z.object({
    code: z.enum(API_ERROR_CODES),
    message: z.string(),
    requestId: z.string(),
  }).strict(),
}).strict();

export const AgentSummarySchema = z.object({
  id: z.string(),
  displayName: z.string(),
  status: z.enum(['ACTIVE', 'REVOKED']),
  keyVersion: z.number().int().positive(),
  createdAt: z.string().datetime(),
}).strict();

export const AgentCreatedResponseSchema = z.object({
  agent: AgentSummarySchema.extend({ status: z.literal('ACTIVE') }),
  credential: z.object({ token: z.string(), shownOnce: z.literal(true) }).strict(),
}).strict();

export interface ApiErrorBody {
  readonly error: {
    readonly code: ApiErrorCode;
    readonly message: string;
    readonly requestId: string;
  };
}
