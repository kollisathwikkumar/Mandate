import { z } from 'zod';
import { parseUint256 } from '../../domain/src/uint256.js';

const identifierSchema = z.string().trim().min(1).max(128);
const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/).transform((value) => value.toLowerCase());
const selectorSchema = z.string().regex(/^0x[0-9a-fA-F]{8}$/).transform((value) => value.toLowerCase());
const timestampSchema = z.number().int().nonnegative().safe();
const uintSchema = z.string().refine((value) => parseUint256(value, true) !== null);
const positiveUintSchema = z.string().refine((value) => parseUint256(value, false) !== null);
const uniqueAddressesSchema = z.array(addressSchema).min(1).refine((values) => new Set(values).size === values.length).transform((values) => [...values].sort());
const uniqueSelectorsSchema = z.array(selectorSchema).min(1).refine((values) => new Set(values).size === values.length).transform((values) => [...values].sort());

export const PolicyRevisionSchema = z.object({
  schemaVersion: z.literal(1),
  policyId: identifierSchema,
  revision: z.number().int().positive().safe(),
  organizationId: identifierSchema,
  owner: addressSchema,
  account: addressSchema,
  agentId: identifierSchema,
  agentAddress: addressSchema,
  agentKeyVersion: z.number().int().positive().safe(),
  chainId: z.number().int().positive().safe(),
  adapter: z.literal('evm-smart-account'),
  target: addressSchema,
  selectors: uniqueSelectorsSchema,
  asset: addressSchema,
  recipients: uniqueAddressesSchema,
  limits: z.object({
    perAction: positiveUintSchema,
    cumulative: positiveUintSchema,
    windowSeconds: z.number().int().positive().safe(),
    approvalThreshold: uintSchema.optional(),
    maxActions: z.number().int().positive().safe().optional(),
  }).strict(),
  validAfter: timestampSchema,
  expiresAt: timestampSchema,
  nonceEpoch: z.number().int().nonnegative().safe(),
}).strict().superRefine((value, context) => {
  if (value.expiresAt <= value.validAfter) {
    context.addIssue({ code: 'custom', path: ['expiresAt'], message: 'must be later than validAfter' });
  }
});

export type PolicyRevision = z.infer<typeof PolicyRevisionSchema>;

export const ActionIntentSchema = z.object({
  actionId: identifierSchema,
  idempotencyKey: identifierSchema,
  policyId: identifierSchema,
  policyRevision: z.number().int().positive().safe(),
  policyRevisionHash: z.string().regex(/^0x[0-9a-f]{64}$/),
  organizationId: identifierSchema,
  account: addressSchema,
  agentId: identifierSchema,
  agentKeyVersion: z.number().int().positive().safe(),
  chainId: z.number().int().positive().safe(),
  target: addressSchema,
  selector: selectorSchema,
  asset: addressSchema,
  recipient: addressSchema,
  amount: z.string().refine((value) => parseUint256(value, false) !== null),
  nonce: z.number().int().nonnegative().safe(),
  nonceEpoch: z.number().int().nonnegative().safe(),
  expiresAt: timestampSchema,
}).strict();

export type ActionIntent = z.infer<typeof ActionIntentSchema>;
