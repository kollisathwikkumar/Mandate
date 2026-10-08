import { AgentCreatedSchema, AgentReplaySchema } from './schemas';
import { z } from 'zod';

const pendingIntentSchema = z.object({ displayName: z.string(), idempotencyKey: z.string().uuid(), createdAt: z.number().finite().nonnegative() }).strict();
const retryWindowMs = 23 * 60 * 60 * 1000; // Shorter than the backend's 24-hour command-idempotency lifetime.

function storageKey(organizationId: string, subject: string, agentId: string): string {
  return `mandate.agentRegistration/${encodeURIComponent(organizationId)}/${encodeURIComponent(subject)}/${encodeURIComponent(agentId)}`;
}

/** Tab-scoped retry identity. Stores only non-secret intent metadata, never credentials. */
export function getAgentRegistrationIntentKey(organizationId: string, subject: string, agentId: string, displayName: string): string {
  const key = storageKey(organizationId, subject, agentId);
  let raw: string | null;
  try { raw = sessionStorage.getItem(key); } catch { return crypto.randomUUID(); }
  let previous: ReturnType<typeof pendingIntentSchema.safeParse> | null = null;
  try {
    if (raw !== null) previous = pendingIntentSchema.safeParse(JSON.parse(raw));
  } catch { /* A corrupt record is replaced below. */ }
  const age = previous?.success ? Date.now() - previous.data.createdAt : -1;
  if (previous?.success && previous.data.displayName === displayName && age >= 0 && age < retryWindowMs) return previous.data.idempotencyKey;
  const idempotencyKey = crypto.randomUUID();
  try { sessionStorage.setItem(key, JSON.stringify({ displayName, idempotencyKey, createdAt: Date.now() })); } catch { /* Retry remains tab-local if storage is disabled. */ }
  return idempotencyKey;
}

export function clearAgentRegistrationIntent(organizationId: string, subject: string, agentId: string): void {
  try { sessionStorage.removeItem(storageKey(organizationId, subject, agentId)); } catch { /* Storage can be unavailable. */ }
}

export type AgentRegistrationOutcome =
  | { readonly kind: 'CREATED'; readonly agentId: string; readonly token: string }
  | { readonly kind: 'REPLAY'; readonly agentId: string };

export function parseAgentRegistrationResponse(body: unknown): AgentRegistrationOutcome {
  const created = AgentCreatedSchema.strict().safeParse(body);
  if (created.success) return { kind: 'CREATED', agentId: created.data.agent.id, token: created.data.credential.token };
  const replay = AgentReplaySchema.safeParse(body);
  if (replay.success) return { kind: 'REPLAY', agentId: replay.data.agent.id };
  throw new Error('Agent registration response did not match the documented API contract.');
}
