import { createHash } from 'node:crypto';
import type { AuditAnchorCheckpointRecord, AuditAnchorRepository, AuditAnchorStorage } from '../../ports/src/audit-anchor.js';
import { canonicalizeAuditExportJson, type AuditExportSigner } from './audit-export-service.js';

const MAX_POSTGRES_BIGINT = 9_223_372_036_854_775_807n;

export interface AuditAnchorBatchResult {
  readonly candidates: number;
  readonly anchored: number;
  readonly failed: number;
}

interface AuditAnchorPayload {
  readonly schemaVersion: 1;
  readonly organizationHash: string;
  readonly eventSequence: string;
  readonly eventHash: string;
  readonly previousCheckpointHash: string | null;
}

interface SignedAuditAnchor {
  readonly payload: AuditAnchorPayload;
  readonly canonicalPayload: string;
  readonly algorithm: 'Ed25519';
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly keyFingerprint: string;
  readonly signature: string;
}

function isSequence(value: string): boolean {
  if (!/^[1-9][0-9]{0,18}$/.test(value)) return false;
  return BigInt(value) <= MAX_POSTGRES_BIGINT;
}

export class AuditAnchorService {
  public constructor(
    private readonly repository: AuditAnchorRepository,
    private readonly storage: AuditAnchorStorage,
    private readonly signer: AuditExportSigner,
    private readonly batchSize: number,
    private readonly retentionDays: number,
  ) {
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 500) throw new Error('Audit anchor batch size must be an integer from 1 to 500');
    if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 36_500) throw new Error('Audit anchor retention must be an integer from 1 to 36500 days');
  }

  public async runBatch(): Promise<AuditAnchorBatchResult> {
    let organizationIds: readonly string[];
    try {
      organizationIds = await this.repository.getCandidateOrganizationIds(this.batchSize);
    } catch {
      return { candidates: 0, anchored: 0, failed: 1 };
    }
    let anchored = 0;
    let failed = 0;
    for (const organizationId of organizationIds) {
      try {
        const didAnchor = await this.repository.anchorLatest(organizationId, async (snapshot) => {
          if (snapshot.organizationId !== organizationId || organizationId.length === 0 || organizationId.length > 128) {
            throw new Error('Audit anchor organization is invalid');
          }
          const sourceHead = snapshot.sourceHead;
          if (sourceHead === null) return null;
          if (!isSequence(sourceHead.sequence) || !/^0x[0-9a-f]{64}$/.test(sourceHead.eventHash)) {
            throw new Error('Audit anchor source head is invalid');
          }
          const previousAnchor = snapshot.previousAnchor;
          if (previousAnchor !== null) {
            if (!isSequence(previousAnchor.checkpointSequence)
              || BigInt(sourceHead.sequence) <= BigInt(previousAnchor.checkpointSequence)
              || !/^[0-9a-f]{64}$/.test(previousAnchor.checkpointHash)) {
              return null;
            }
          }
          const organizationHash = createHash('sha256').update(organizationId, 'utf8').digest('hex');
          const payload: AuditAnchorPayload = {
            schemaVersion: 1,
            organizationHash,
            eventSequence: sourceHead.sequence,
            eventHash: sourceHead.eventHash,
            previousCheckpointHash: previousAnchor?.checkpointHash ?? null,
          };
          const canonicalPayload = canonicalizeAuditExportJson(payload);
          const signatureMetadata = this.signer.sign(canonicalPayload, 'MANDATE_AUDIT_ANCHOR_V1');
          const envelope: SignedAuditAnchor = {
            payload,
            canonicalPayload,
            ...signatureMetadata,
          };
          const body = canonicalizeAuditExportJson(envelope);
          const checkpointHash = createHash('sha256').update(body, 'utf8').digest('hex');
          const objectKey = `mandate-audit/v1/${organizationHash}/${sourceHead.sequence}-${checkpointHash}.json`;
          const storageResult = await this.storage.putImmutable(objectKey, body, this.retentionDays);
          if (storageResult.versionId.trim() === '' || !Number.isFinite(Date.parse(storageResult.retainedUntil))) {
            throw new Error('Audit anchor storage returned invalid retention evidence');
          }
          const record: AuditAnchorCheckpointRecord = {
            organizationId,
            checkpointSequence: sourceHead.sequence,
            eventHash: sourceHead.eventHash,
            previousCheckpointHash: previousAnchor?.checkpointHash ?? null,
            checkpointHash,
            objectKey,
            objectVersionId: storageResult.versionId,
            keyId: signatureMetadata.keyId,
            keyFingerprint: signatureMetadata.keyFingerprint,
            signature: signatureMetadata.signature,
            retainedUntil: new Date(storageResult.retainedUntil).toISOString(),
          };
          return record;
        });
        if (didAnchor) anchored += 1;
      } catch {
        failed += 1;
      }
    }
    return { candidates: organizationIds.length, anchored, failed };
  }
}
