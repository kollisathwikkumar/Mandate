import { createHash } from 'node:crypto';
import { PolicyRevisionSchema, type PolicyRevision } from './schema.js';

export function canonicalizePolicyRevision(revision: PolicyRevision): string {
  const canonicalRevision = PolicyRevisionSchema.parse(revision);
  return JSON.stringify(canonicalRevision);
}

export function hashPolicyRevision(revision: PolicyRevision): string {
  const digest = createHash('sha256').update(canonicalizePolicyRevision(revision), 'utf8').digest('hex');
  return `0x${digest}`;
}
