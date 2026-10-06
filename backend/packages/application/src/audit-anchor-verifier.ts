import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import { canonicalizeAuditExportJson } from './audit-export-service.js';

export interface AuditAnchorVerification {
  readonly valid: boolean;
  readonly reason: 'INVALID_FORMAT' | 'KEY_FINGERPRINT_MISMATCH' | 'PAYLOAD_MISMATCH' | 'CHECKPOINT_HASH_MISMATCH' | 'PREVIOUS_CHECKPOINT_MISMATCH' | 'SIGNATURE_INVALID' | null;
  readonly checkpointHash: string | null;
  readonly sequence: string | null;
  readonly previousCheckpointHash: string | null;
}

interface AnchorEnvelope {
  readonly payload: {
    readonly schemaVersion: 1;
    readonly organizationHash: string;
    readonly eventSequence: string;
    readonly eventHash: string;
    readonly previousCheckpointHash: string | null;
  };
  readonly canonicalPayload: string;
  readonly algorithm: 'Ed25519';
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly keyFingerprint: string;
  readonly signature: string;
}

function failure(reason: NonNullable<AuditAnchorVerification['reason']>): AuditAnchorVerification {
  return { valid: false, reason, checkpointHash: null, sequence: null, previousCheckpointHash: null };
}

function isEnvelope(value: unknown): value is AnchorEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const envelope = value as Record<string, unknown>;
  if (typeof envelope.payload !== 'object' || envelope.payload === null || Array.isArray(envelope.payload)) return false;
  const payload = envelope.payload as Record<string, unknown>;
  const envelopeKeys = Object.keys(envelope).sort().join(',');
  const payloadKeys = Object.keys(payload).sort().join(',');
  return envelopeKeys === 'algorithm,canonicalPayload,keyFingerprint,keyId,payload,publicKeyPem,signature'
    && payloadKeys === 'eventHash,eventSequence,organizationHash,previousCheckpointHash,schemaVersion'
    && payload.schemaVersion === 1 && typeof payload.organizationHash === 'string'
    && typeof payload.eventSequence === 'string' && typeof payload.eventHash === 'string'
    && (payload.previousCheckpointHash === null || typeof payload.previousCheckpointHash === 'string')
    && typeof envelope.canonicalPayload === 'string' && envelope.algorithm === 'Ed25519'
    && typeof envelope.keyId === 'string' && typeof envelope.publicKeyPem === 'string'
    && typeof envelope.keyFingerprint === 'string' && typeof envelope.signature === 'string';
}

export function verifyAuditAnchor(
  serializedEnvelope: string,
  trustedKeyFingerprint: string,
  expectedCheckpointHash: string,
  expectedPreviousCheckpointHash?: string | null,
): AuditAnchorVerification {
  try {
    const parsed: unknown = JSON.parse(serializedEnvelope);
    if (!isEnvelope(parsed) || !/^[0-9a-f]{64}$/.test(trustedKeyFingerprint)
      || !/^[0-9a-f]{64}$/.test(expectedCheckpointHash)) return failure('INVALID_FORMAT');
    const envelope = parsed;
    const payload = envelope.payload;
    if (!/^[0-9a-f]{64}$/.test(payload.organizationHash)
      || !/^[1-9][0-9]{0,18}$/.test(payload.eventSequence)
      || BigInt(payload.eventSequence) > 9_223_372_036_854_775_807n
      || !/^0x[0-9a-f]{64}$/.test(payload.eventHash)
      || (payload.previousCheckpointHash !== null && !/^[0-9a-f]{64}$/.test(payload.previousCheckpointHash))
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(envelope.keyId)
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.signature)) return failure('INVALID_FORMAT');
    if (expectedPreviousCheckpointHash !== undefined
      && payload.previousCheckpointHash !== expectedPreviousCheckpointHash) return failure('PREVIOUS_CHECKPOINT_MISMATCH');
    if (canonicalizeAuditExportJson(payload) !== envelope.canonicalPayload
      || canonicalizeAuditExportJson(envelope) !== serializedEnvelope) return failure('PAYLOAD_MISMATCH');
    const publicKey: KeyObject = createPublicKey(envelope.publicKeyPem);
    if (publicKey.asymmetricKeyType !== 'ed25519') return failure('KEY_FINGERPRINT_MISMATCH');
    const fingerprint = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    if (fingerprint !== trustedKeyFingerprint || fingerprint !== envelope.keyFingerprint) return failure('KEY_FINGERPRINT_MISMATCH');
    const checkpointHash = createHash('sha256').update(serializedEnvelope, 'utf8').digest('hex');
    if (checkpointHash !== expectedCheckpointHash) return failure('CHECKPOINT_HASH_MISMATCH');
    const signatureInput = Buffer.from(`MANDATE_AUDIT_ANCHOR_V1\n${envelope.keyId}\n${envelope.canonicalPayload}`, 'utf8');
    if (!verify(null, signatureInput, publicKey, Buffer.from(envelope.signature, 'base64'))) return failure('SIGNATURE_INVALID');
    return {
      valid: true,
      reason: null,
      checkpointHash,
      sequence: payload.eventSequence,
      previousCheckpointHash: payload.previousCheckpointHash,
    };
  } catch {
    return failure('INVALID_FORMAT');
  }
}
