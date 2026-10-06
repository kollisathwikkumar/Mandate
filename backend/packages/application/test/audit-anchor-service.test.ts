import { generateKeyPairSync, verify, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditAnchorService } from '../src/audit-anchor-service.js';
import type { AuditAnchorRepository, AuditAnchorSnapshot, AuditAnchorStorage } from '../../ports/src/audit-anchor.js';
import { Ed25519AuditExportSigner } from '../src/audit-export-service.js';

const pair = generateKeyPairSync('ed25519');
const signer = new Ed25519AuditExportSigner('anchor-key-v1', pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
const head = { sequence: '42', eventHash: `0x${'a'.repeat(64)}` };

function repository(snapshot: AuditAnchorSnapshot | null, fail = false): AuditAnchorRepository {
  return {
    async getCandidateOrganizationIds(limit) { expect(limit).toBe(25); return snapshot === null ? [] : [snapshot.organizationId]; },
    async anchorLatest(organizationId, createRecord) {
      if (fail) throw new Error('database is unavailable');
      if (snapshot === null || organizationId !== snapshot.organizationId) throw new Error('unexpected anchor candidate');
      return await createRecord(snapshot) !== null;
    },
  };
}

function customRepository(getCandidates: () => Promise<readonly string[]>, anchorLatest: AuditAnchorRepository['anchorLatest']): AuditAnchorRepository {
  return { getCandidateOrganizationIds: getCandidates, anchorLatest };
}

function storage(fail = false): AuditAnchorStorage & { readonly bodies: string[]; readonly keys: string[] } {
  const bodies: string[] = [];
  const keys: string[] = [];
  return {
    bodies, keys,
    async putImmutable(key, body, retentionDays) {
      keys.push(key); bodies.push(body);
      if (fail) throw new Error('S3 is unavailable');
      return { versionId: 'version-1', retainedUntil: '2027-10-06T00:00:00.000Z' };
    },
  };
}

describe('AuditAnchorService', () => {
  it('signs and writes a deterministic checkpoint for the current org audit head', async () => {
    const checkpointStorage = storage();
    const service = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: null, sourceHead: head }), checkpointStorage, signer, 25, 365);

    const result = await service.runBatch();

    expect(result).toEqual({ candidates: 1, anchored: 1, failed: 0 });
    expect(checkpointStorage.keys[0]).toMatch(/^mandate-audit\/v1\/[a-f0-9]{64}\/42-[a-f0-9]{64}\.json$/);
    const serialized = checkpointStorage.bodies[0];
    expect(serialized).toBeDefined();
    const envelope = JSON.parse(serialized ?? '') as { payload: { eventSequence: string; eventHash: string; previousCheckpointHash: string | null }; canonicalPayload: string; keyId: string; publicKeyPem: string; keyFingerprint: string; signature: string };
    expect(envelope.payload).toMatchObject({ eventSequence: '42', eventHash: head.eventHash, previousCheckpointHash: null });
    expect(envelope.canonicalPayload).toContain('"schemaVersion":1');
    expect(envelope.keyId).toBe('anchor-key-v1');
    const publicKey = pair.publicKey as KeyObject;
    expect(verify(null, Buffer.from(`MANDATE_AUDIT_ANCHOR_V1\n${envelope.keyId}\n${envelope.canonicalPayload}`), publicKey, Buffer.from(envelope.signature, 'base64'))).toBe(true);
  });

  it('chains a checkpoint to the prior immutable checkpoint and skips an unchanged head', async () => {
    const previousAnchor = {
      organizationId: 'org-a', checkpointSequence: '39', eventHash: `0x${'9'.repeat(64)}`,
      previousCheckpointHash: null, checkpointHash: 'b'.repeat(64), objectKey: 'old-key', objectVersionId: 'old-version',
      keyId: 'anchor-key-v1', keyFingerprint: 'c'.repeat(64), signature: 'sig', retainedUntil: '2027-10-06T00:00:00.000Z',
    };
    const checkpointStorage = storage();
    const service = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor, sourceHead: head }), checkpointStorage, signer, 25, 365);
    const result = await service.runBatch();
    expect(result.anchored).toBe(1);
    const envelope = JSON.parse(checkpointStorage.bodies[0] ?? '') as { payload: { previousCheckpointHash: string } };
    expect(envelope.payload.previousCheckpointHash).toBe(previousAnchor.checkpointHash);

    const upToDate = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: { ...previousAnchor, checkpointSequence: head.sequence, eventHash: head.eventHash }, sourceHead: head }), storage(), signer, 25, 365);
    await expect(upToDate.runBatch()).resolves.toEqual({ candidates: 1, anchored: 0, failed: 0 });
  });

  it('returns bounded failure counts without logging sensitive exception data', async () => {
    const failedStorage = storage(true);
    const service = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: null, sourceHead: head }), failedStorage, signer, 25, 365);
    await expect(service.runBatch()).resolves.toEqual({ candidates: 1, anchored: 0, failed: 1 });
    const databaseFailure = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: null, sourceHead: head }, true), storage(), signer, 25, 365);
    await expect(databaseFailure.runBatch()).resolves.toEqual({ candidates: 1, anchored: 0, failed: 1 });
    const noCandidates = new AuditAnchorService(repository(null), storage(), signer, 25, 365);
    await expect(noCandidates.runBatch()).resolves.toEqual({ candidates: 0, anchored: 0, failed: 0 });
    const failedQuery = new AuditAnchorService(customRepository(async () => { throw new Error('db secret'); }, async () => false), storage(), signer, 25, 365);
    await expect(failedQuery.runBatch()).resolves.toEqual({ candidates: 0, anchored: 0, failed: 1 });
  });

  it('skips changed, absent, invalid prior heads and rejects invalid storage evidence', async () => {
    const emptyHeadRepo = customRepository(async () => ['org-a'], async (_org, create) => {
      return await create({ organizationId: 'org-a', previousAnchor: null, sourceHead: null }) !== null;
    });
    await expect(new AuditAnchorService(emptyHeadRepo, storage(), signer, 25, 365).runBatch())
      .resolves.toEqual({ candidates: 1, anchored: 0, failed: 0 });
    const mismatchRepo = customRepository(async () => ['org-a'], async (_org, create) => {
      return await create({ organizationId: 'different-org', previousAnchor: null, sourceHead: head }) !== null;
    });
    await expect(new AuditAnchorService(mismatchRepo, storage(), signer, 25, 365).runBatch())
      .resolves.toEqual({ candidates: 1, anchored: 0, failed: 1 });
    const invalidPrevious = {
      organizationId: 'org-a', checkpointSequence: '0', eventHash: head.eventHash,
      previousCheckpointHash: null, checkpointHash: 'b'.repeat(64), objectKey: 'old', objectVersionId: 'v1',
      keyId: 'anchor-key-v1', keyFingerprint: 'c'.repeat(64), signature: 'sig', retainedUntil: '2030-01-01T00:00:00Z',
    };
    const oldHeadRepo = customRepository(async () => ['org-a'], async (_org, create) => {
      return await create({ organizationId: 'org-a', previousAnchor: invalidPrevious, sourceHead: head }) !== null;
    });
    await expect(new AuditAnchorService(oldHeadRepo, storage(), signer, 25, 365).runBatch())
      .resolves.toEqual({ candidates: 1, anchored: 0, failed: 0 });
    const invalidStorage: AuditAnchorStorage = { async putImmutable() { return { versionId: '', retainedUntil: 'invalid' }; } };
    await expect(new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: null, sourceHead: head }), invalidStorage, signer, 25, 365).runBatch())
      .resolves.toEqual({ candidates: 1, anchored: 0, failed: 1 });
  });

  it('validates batch size, retention, organization head hash, and source sequence', async () => {
    const noCandidates = repository(null);
    expect(() => new AuditAnchorService(noCandidates, storage(), signer, 0, 365)).toThrow('batch size');
    expect(() => new AuditAnchorService(noCandidates, storage(), signer, 25, 0)).toThrow('retention');
    const invalidHash = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: null, sourceHead: { sequence: '42', eventHash: 'bad' } }), storage(), signer, 25, 365);
    await expect(invalidHash.runBatch()).resolves.toEqual({ candidates: 1, anchored: 0, failed: 1 });
    const invalidSequence = new AuditAnchorService(repository({ organizationId: 'org-a', previousAnchor: null, sourceHead: { sequence: '0', eventHash: head.eventHash } }), storage(), signer, 25, 365);
    await expect(invalidSequence.runBatch()).resolves.toEqual({ candidates: 1, anchored: 0, failed: 1 });
  });
});
