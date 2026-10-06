import { describe, expect, it } from 'vitest';
import { readAuditAnchorRuntimeConfig } from '../src/audit-anchor-runtime.js';

describe('readAuditAnchorRuntimeConfig', () => {
  it('keeps anchoring disabled unless a bucket is configured', () => {
    expect(readAuditAnchorRuntimeConfig({})).toBeNull();
    expect(() => readAuditAnchorRuntimeConfig({ MANDATE_AUDIT_ANCHOR_RETENTION_DAYS: '365' })).toThrow('BUCKET');
  });

  it('requires explicit secret and retention and supplies bounded cadence defaults', () => {
    expect(() => readAuditAnchorRuntimeConfig({ MANDATE_AUDIT_ANCHOR_BUCKET: 'mandate-audit' })).toThrow('SIGNING_SECRET_ARN');
    expect(() => readAuditAnchorRuntimeConfig({
      MANDATE_AUDIT_ANCHOR_BUCKET: 'mandate-audit', MANDATE_AUDIT_SIGNING_SECRET_ARN: 'secret',
    })).toThrow('RETENTION_DAYS');
    expect(readAuditAnchorRuntimeConfig({
      MANDATE_AUDIT_ANCHOR_BUCKET: 'mandate-audit', MANDATE_AUDIT_SIGNING_SECRET_ARN: 'secret',
      MANDATE_AUDIT_ANCHOR_RETENTION_DAYS: '365',
    })).toEqual({ bucket: 'mandate-audit', signingSecretArn: 'secret', retentionDays: 365, intervalMs: 60_000, batchSize: 25 });
  });

  it('rejects values outside operational bounds', () => {
    for (const [name, value] of [
      ['MANDATE_AUDIT_ANCHOR_RETENTION_DAYS', '0'],
      ['MANDATE_AUDIT_ANCHOR_INTERVAL_MS', '999'],
      ['MANDATE_AUDIT_ANCHOR_BATCH_SIZE', '501'],
    ] as const) {
      expect(() => readAuditAnchorRuntimeConfig({
        MANDATE_AUDIT_ANCHOR_BUCKET: 'mandate-audit', MANDATE_AUDIT_SIGNING_SECRET_ARN: 'secret',
        MANDATE_AUDIT_ANCHOR_RETENTION_DAYS: '365', [name]: value,
      })).toThrow(name);
    }
  });
});
