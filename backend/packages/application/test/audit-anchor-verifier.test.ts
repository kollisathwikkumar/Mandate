import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditAnchorService } from '../src/audit-anchor-service.js';
import { verifyAuditAnchor } from '../src/audit-anchor-verifier.js';
import type { AuditAnchorRepository, AuditAnchorSnapshot, AuditAnchorStorage } from '../../ports/src/audit-anchor.js';
import { canonicalizeAuditExportJson, Ed25519AuditExportSigner } from '../src/audit-export-service.js';

const pair = generateKeyPairSync('ed25519');
const signer = new Ed25519AuditExportSigner('verifier-test-key', pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
const snapshot: AuditAnchorSnapshot = {
  organizationId: 'org-verifier', previousAnchor: null,
  sourceHead: { sequence: '9', eventHash: `0x${'a'.repeat(64)}` },
};

async function makeEnvelope(): Promise<{ body: string; fingerprint: string }> {
  let body = '';
  const repository: AuditAnchorRepository = {
    async getCandidateOrganizationIds() { return ['org-verifier']; },
    async anchorLatest(_organizationId, createCheckpoint) { await createCheckpoint(snapshot); return true; },
  };
  const storage: AuditAnchorStorage = {
    async putImmutable(_key, value) { body = value; return { versionId: 'v1', retainedUntil: '2030-01-01T00:00:00.000Z' }; },
  };
  await new AuditAnchorService(repository, storage, signer, 1, 1).runBatch();
  const parsed = JSON.parse(body) as { keyFingerprint: string };
  return { body, fingerprint: parsed.keyFingerprint };
}

describe('verifyAuditAnchor', () => {
  it('verifies signed canonical checkpoints and optional storage/chain expectations', async () => {
    const { body, fingerprint } = await makeEnvelope();
    const hash = createHash('sha256').update(body).digest('hex');
    expect(verifyAuditAnchor(body, fingerprint, hash, null)).toMatchObject({ valid: true, checkpointHash: hash, sequence: '9' });
    expect(verifyAuditAnchor(body, fingerprint, 'f'.repeat(64))).toMatchObject({ valid: false, reason: 'CHECKPOINT_HASH_MISMATCH' });
    expect(verifyAuditAnchor(body, fingerprint, hash, 'b'.repeat(64))).toMatchObject({ valid: false, reason: 'PREVIOUS_CHECKPOINT_MISMATCH' });
  });

  it('rejects changed bytes, signatures, and untrusted fingerprints', async () => {
    const { body, fingerprint } = await makeEnvelope();
    const parsed = JSON.parse(body) as { payload: { eventSequence: string }; signature: string };
    parsed.payload.eventSequence = '10';
    expect(verifyAuditAnchor(JSON.stringify(parsed), fingerprint, '0'.repeat(64)).valid).toBe(false);
    const replacedSignature = JSON.parse(body) as { signature: string };
    replacedSignature.signature = Buffer.alloc(64).toString('base64');
    const reserialized = canonicalizeAuditExportJson(replacedSignature);
    expect(verifyAuditAnchor(reserialized, fingerprint, createHash('sha256').update(reserialized).digest('hex')).reason).toBe('SIGNATURE_INVALID');
    const hash = createHash('sha256').update(body).digest('hex');
    expect(verifyAuditAnchor(body, '0'.repeat(64), hash).reason).toBe('KEY_FINGERPRINT_MISMATCH');
    expect(verifyAuditAnchor('{', fingerprint, hash).reason).toBe('INVALID_FORMAT');
  });

  it('rejects non-envelope JSON and malformed checkpoint fields', async () => {
    const { body, fingerprint } = await makeEnvelope();
    for (const invalid of [null, [], {}, { payload: null }, { payload: [] }]) {
      expect(verifyAuditAnchor(JSON.stringify(invalid), fingerprint, '0'.repeat(64)).reason).toBe('INVALID_FORMAT');
    }
    const original = JSON.parse(body) as { payload: Record<string, unknown>; keyId: string; signature: string };
    const mutations: Array<(value: typeof original) => void> = [
      (value) => { value.payload.organizationHash = 'x'; },
      (value) => { value.payload.eventSequence = '9223372036854775808'; },
      (value) => { value.payload.eventSequence = '0'; },
      (value) => { value.payload.eventHash = 'x'; },
      (value) => { value.payload.previousCheckpointHash = 'x'; },
      (value) => { value.keyId = 'bad key'; },
      (value) => { value.signature = '!'; },
    ];
    for (const mutate of mutations) {
      const value = structuredClone(original);
      mutate(value);
      const serialized = canonicalizeAuditExportJson(value);
      expect(verifyAuditAnchor(serialized, fingerprint, '0'.repeat(64)).reason).toBe('INVALID_FORMAT');
    }
    const badCanonical = JSON.parse(body) as { canonicalPayload: string };
    badCanonical.canonicalPayload = '{}';
    expect(verifyAuditAnchor(canonicalizeAuditExportJson(badCanonical), fingerprint, '0'.repeat(64)).reason).toBe('PAYLOAD_MISMATCH');
    const extraField = JSON.parse(body) as Record<string, unknown>;
    extraField.untrusted = 'unsigned metadata';
    expect(verifyAuditAnchor(canonicalizeAuditExportJson(extraField), fingerprint, '0'.repeat(64)).reason).toBe('INVALID_FORMAT');
    const badPem = JSON.parse(body) as { publicKeyPem: string };
    badPem.publicKeyPem = 'not a public key';
    expect(verifyAuditAnchor(canonicalizeAuditExportJson(badPem), fingerprint, '0'.repeat(64)).reason).toBe('INVALID_FORMAT');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const wrongKeyType = JSON.parse(body) as { publicKeyPem: string };
    wrongKeyType.publicKeyPem = rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(verifyAuditAnchor(canonicalizeAuditExportJson(wrongKeyType), fingerprint, '0'.repeat(64)).reason).toBe('KEY_FINGERPRINT_MISMATCH');
  });
});
