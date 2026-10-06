export interface AuditAnchorRuntimeConfig {
  readonly bucket: string;
  readonly signingSecretArn: string;
  readonly retentionDays: number;
  readonly intervalMs: number;
  readonly batchSize: number;
}

export function readAuditAnchorRuntimeConfig(environment: Readonly<Record<string, string | undefined>>): AuditAnchorRuntimeConfig | null {
  const bucket = environment.MANDATE_AUDIT_ANCHOR_BUCKET?.trim() ?? '';
  const signingSecretArn = environment.MANDATE_AUDIT_SIGNING_SECRET_ARN?.trim() ?? '';
  if (bucket === '') {
    if (environment.MANDATE_AUDIT_ANCHOR_RETENTION_DAYS !== undefined) {
      throw new Error('MANDATE_AUDIT_ANCHOR_BUCKET is required when anchor retention is configured');
    }
    return null;
  }
  if (signingSecretArn === '') throw new Error('MANDATE_AUDIT_SIGNING_SECRET_ARN is required when audit anchoring is enabled');
  const retentionDays = Number(environment.MANDATE_AUDIT_ANCHOR_RETENTION_DAYS);
  const intervalMs = Number(environment.MANDATE_AUDIT_ANCHOR_INTERVAL_MS ?? '60000');
  const batchSize = Number(environment.MANDATE_AUDIT_ANCHOR_BATCH_SIZE ?? '25');
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 36_500) {
    throw new Error('MANDATE_AUDIT_ANCHOR_RETENTION_DAYS must be an integer from 1 to 36500');
  }
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 1000 || intervalMs > 86_400_000) {
    throw new Error('MANDATE_AUDIT_ANCHOR_INTERVAL_MS must be an integer from 1000 to 86400000');
  }
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 500) {
    throw new Error('MANDATE_AUDIT_ANCHOR_BATCH_SIZE must be an integer from 1 to 500');
  }
  return { bucket, signingSecretArn, retentionDays, intervalMs, batchSize };
}
