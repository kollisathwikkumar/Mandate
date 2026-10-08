import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditExportService, canonicalizeAuditExportJson, Ed25519AuditExportSigner, verifyAuditExport } from '../src/audit-export-service.js';
import type { AuditEventRecord, ActivityRepository } from '../../ports/src/activity-repository.js';
import type { Principal } from '../../domain/src/principal.js';

const keyPair = generateKeyPairSync('ed25519');
const signer = new Ed25519AuditExportSigner(
  'test-audit-key-v1',
  keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
);

function event(sequence: string, previousHash: string | null, eventHash: string): AuditEventRecord {
  return {
    sequence, eventType: 'ACTION_CREATED', actorType: 'AGENT', actorId: 'agent-a',
    subjectType: 'ACTION', subjectId: `action-${sequence}`, correlationId: `corr-${sequence}`,
    payload: { nested: { b: 2, a: 1 }, sequence }, previousHash, eventHash, createdAt: '2026-10-06T00:00:00.000Z',
  };
}

function repository(role: string | null, events: readonly AuditEventRecord[]): ActivityRepository {
  return {
    getHumanRole: async () => role,
    getAction: async () => null,
    listActions: async () => [],
    listAuditEvents: async () => events,
    listReceipts: async () => [],
    listAlerts: async () => [],
  };
}

describe('AuditExportService', () => {
  it('creates an ascending, Ed25519-signed export that verifies with the embedded public key', async () => {
    const events = [event('12', '0x' + 'b'.repeat(64), '0x' + 'c'.repeat(64)), event('9', null, '0x' + 'b'.repeat(64))];
    const service = new AuditExportService(repository('OWNER', events), signer, () => new Date('2026-10-06T01:02:03.000Z'));

    const result = await service.create({ type: 'HUMAN', subject: 'owner-a' }, 'org-a', 100, null);

    expect(result.payload.events.map((entry) => entry.sequence)).toEqual(['9', '12']);
    expect(result.payload.fromSequence).toBe('9');
    expect(result.payload.throughSequence).toBe('12');
    expect(result.payload.integrityNotice).toContain('not proof of source truth or completeness');
    expect(verifyAuditExport(result, result.keyFingerprint)).toEqual({ valid: true, reason: null });
  });

  it('denies agents and non-administrator members', async () => {
    const service = new AuditExportService(repository('VIEWER', []), signer);
    await expect(service.create({ type: 'AGENT', organizationId: 'org-a', agentId: 'agent-a', keyVersion: 1, credentialId: 'cred-a' }, 'org-a', 100, null))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    const missing = new AuditExportService(repository(null, []), signer);
    await expect(missing.create({ type: 'HUMAN', subject: 'former-member' }, 'org-a', 100, null))
      .rejects.toMatchObject({ statusCode: 404, code: 'RESOURCE_NOT_FOUND' });
    await expect(service.create({ type: 'HUMAN', subject: 'viewer-a' }, 'org-a', 100, null))
      .rejects.toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
  });

  it('rejects invalid bounds and a broken internal audit hash link', async () => {
    const invalidLimit = new AuditExportService(repository('ADMIN', []), signer);
    await expect(invalidLimit.create({ type: 'HUMAN', subject: 'admin-a' }, 'org-a', 10_001, null)).rejects.toThrow('Audit export limit');
    const broken = new AuditExportService(repository('ADMIN', [event('2', '0x' + 'd'.repeat(64), '0x' + 'c'.repeat(64)), event('1', null, '0x' + 'b'.repeat(64))]), signer);
    await expect(broken.create({ type: 'HUMAN', subject: 'admin-a' }, 'org-a', 100, null)).rejects.toThrow('Audit event hash chain is inconsistent');
    await expect(invalidLimit.create({ type: 'HUMAN', subject: 'admin-a' }, 'org-a', 100, '0')).rejects.toThrow('Audit export cursor is invalid');
  });

  it('detects changed payload bytes and changed key fingerprint', async () => {
    const result = await new AuditExportService(repository('OWNER', [event('1', null, '0x' + 'b'.repeat(64))]), signer)
      .create({ type: 'HUMAN', subject: 'owner-a' }, 'org-a', 100, null);
    expect(verifyAuditExport({ ...result, canonicalPayload: result.canonicalPayload.replace('ACTION_CREATED', 'ACTION_TAMPERED') }, result.keyFingerprint)).toEqual({ valid: false, reason: 'SIGNATURE_INVALID' });
    expect(verifyAuditExport({ ...result, keyFingerprint: '0'.repeat(64) }, result.keyFingerprint)).toEqual({ valid: false, reason: 'KEY_FINGERPRINT_MISMATCH' });
    expect(verifyAuditExport({ ...result, keyId: 'forged-key' }, result.keyFingerprint)).toEqual({ valid: false, reason: 'SIGNATURE_INVALID' });
    expect(verifyAuditExport({ ...result, publicKeyPem: 'not a PEM key' }, result.keyFingerprint)).toEqual({ valid: false, reason: 'SIGNATURE_INVALID' });
    expect(verifyAuditExport(result, 'not-a-fingerprint')).toEqual({ valid: false, reason: 'KEY_FINGERPRINT_MISMATCH' });

    const changedPayload = { ...result.payload, events: [{ ...event('1', null, '0x' + 'b'.repeat(64)), eventType: 'ACTION_TAMPERED' }] };
    expect(verifyAuditExport({ ...result, payload: changedPayload }, result.keyFingerprint)).toEqual({ valid: false, reason: 'PAYLOAD_MISMATCH' });

    const brokenPayload = { ...result.payload, events: [event('1', null, '0x' + 'b'.repeat(64)), event('2', '0x' + 'd'.repeat(64), '0x' + 'c'.repeat(64))] };
    const brokenCanonical = canonicalizeAuditExportJson(brokenPayload);
    const brokenSignature = signer.sign(brokenCanonical);
    expect(verifyAuditExport({ ...result, ...brokenSignature, payload: brokenPayload, canonicalPayload: brokenCanonical }, result.keyFingerprint))
      .toEqual({ valid: false, reason: 'HASH_CHAIN_INVALID' });
  });

  it('handles empty exports, rejects non-Ed25519 and malformed JSON values, and serializes canonical JSON deterministically', async () => {
    const empty = await new AuditExportService(repository('OWNER', []), signer).create({ type: 'HUMAN', subject: 'owner-a' }, 'org-a', 1, null);
    expect(empty.payload.fromSequence).toBeNull();
    expect(empty.payload.throughSequence).toBeNull();
    expect(verifyAuditExport(empty, empty.keyFingerprint)).toEqual({ valid: true, reason: null });
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(() => new Ed25519AuditExportSigner('rsa-key', rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())).toThrow('must be Ed25519');
    expect(() => new Ed25519AuditExportSigner('bad key', keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())).toThrow('key ID is invalid');
    expect(canonicalizeAuditExportJson({ z: -0, a: ['x', true, null], b: 1 })).toBe('{"a":["x",true,null],"b":1,"z":0}');
    expect(() => canonicalizeAuditExportJson(Symbol('not-json'))).toThrow('not JSON serializable');
    expect(() => canonicalizeAuditExportJson(Number.POSITIVE_INFINITY)).toThrow('non-finite number');
  });

  it('rejects malformed, duplicate, or non-increasing event sequences and malformed hashes', async () => {
    const owner: Principal = { type: 'HUMAN', subject: 'owner-a' };
    const invalidExports: readonly (readonly AuditEventRecord[])[] = [
      [event('0', null, '0x' + 'b'.repeat(64))],
      [event('01', null, '0x' + 'b'.repeat(64))],
      [event('1', null, '0x' + 'B'.repeat(64))],
      [event('1', '0x' + 'B'.repeat(64), '0x' + 'b'.repeat(64))],
      [event('1', null, '0x' + 'b'.repeat(64)), event('1', '0x' + 'b'.repeat(64), '0x' + 'c'.repeat(64))],
    ];
    for (const events of invalidExports) {
      const service = new AuditExportService(repository('OWNER', events), signer);
      await expect(service.create(owner, 'org-a', 100, null)).rejects.toThrow('Audit event hash chain is inconsistent');
    }
  });
});
