export interface AuditAnchorSourceHead {
  readonly sequence: string;
  readonly eventHash: string;
}

export interface AuditAnchorCheckpointRecord {
  readonly organizationId: string;
  readonly checkpointSequence: string;
  readonly eventHash: string;
  readonly previousCheckpointHash: string | null;
  readonly checkpointHash: string;
  readonly objectKey: string;
  readonly objectVersionId: string;
  readonly keyId: string;
  readonly keyFingerprint: string;
  readonly signature: string;
  readonly retainedUntil: string;
}

export interface AuditAnchorSnapshot {
  readonly organizationId: string;
  readonly previousAnchor: AuditAnchorCheckpointRecord | null;
  readonly sourceHead: AuditAnchorSourceHead | null;
}

export interface AuditAnchorRepository {
  getCandidateOrganizationIds(limit: number): Promise<readonly string[]>;
  anchorLatest(
    organizationId: string,
    createCheckpoint: (snapshot: AuditAnchorSnapshot) => Promise<AuditAnchorCheckpointRecord | null>,
  ): Promise<boolean>;
}

export interface AuditAnchorStorageResult {
  readonly versionId: string;
  readonly retainedUntil: string;
}

export interface AuditAnchorStorage {
  putImmutable(key: string, body: string, retentionDays: number): Promise<AuditAnchorStorageResult>;
}
