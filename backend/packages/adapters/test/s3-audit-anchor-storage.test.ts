import { describe, expect, it } from 'vitest';
import { GetObjectCommand, HeadObjectCommand, PutObjectCommand, S3Client, type HeadObjectCommandOutput, type PutObjectCommandInput, type PutObjectCommandOutput } from '@aws-sdk/client-s3';
import { AwsS3ObjectLockApi, resolveS3Region, S3AuditAnchorStorage, type S3ObjectLockApi } from '../src/aws/s3-audit-anchor-storage.js';

class FakeS3ObjectLockApi implements S3ObjectLockApi {
  public putInput: PutObjectCommandInput | null = null;
  public putOutput: PutObjectCommandOutput = { $metadata: {}, VersionId: 'version-1' };
  public putError: unknown = null;
  public shouldThrow = false;
  public headOutput: HeadObjectCommandOutput = {
    $metadata: {}, VersionId: 'version-1', ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date('2027-10-06T00:00:00.000Z'),
  };
  public objectBody = new TextEncoder().encode('checkpoint');

  public async putObject(input: PutObjectCommandInput): Promise<PutObjectCommandOutput> {
    this.putInput = input;
    if (this.shouldThrow || this.putError !== null) throw this.putError;
    return this.putOutput;
  }
  public async headObject(): Promise<HeadObjectCommandOutput> { return this.headOutput; }
  public async getObject(): Promise<Uint8Array> { return this.objectBody; }
}

describe('S3AuditAnchorStorage', () => {
  it('prefers AWS_REGION and falls back to AWS_DEFAULT_REGION like the other AWS adapters', () => {
    expect(resolveS3Region('us-east-1', 'eu-west-1')).toBe('us-east-1');
    expect(resolveS3Region(undefined, 'ap-south-1')).toBe('ap-south-1');
    expect(resolveS3Region('   ', 'ap-south-1')).toBe('ap-south-1');
    expect(resolveS3Region('  us-east-1  ', 'eu-west-1')).toBe('us-east-1');
    expect(resolveS3Region(undefined, '  ap-south-1  ')).toBe('ap-south-1');
    expect(resolveS3Region(undefined, undefined)).toBeUndefined();
    expect(() => new S3AuditAnchorStorage('bucket')).not.toThrow();
  });

  it('uses the default current-time provider when one is not injected', async () => {
    const api = new FakeS3ObjectLockApi();
    const result = await new S3AuditAnchorStorage('bucket', api).putImmutable('key', 'body', 1);
    expect(Date.parse(result.retainedUntil)).toBeGreaterThan(Date.now());
  });

  it('maps AWS SDK commands to the S3 boundary and validates object response bodies', async () => {
    const commands: object[] = [];
    const api = new AwsS3ObjectLockApi({
      async send(command: object) {
        commands.push(command);
        if (command instanceof GetObjectCommand) return { Body: { async transformToByteArray() { return new Uint8Array([1, 2]); } } };
        if (command instanceof HeadObjectCommand) return { VersionId: 'v1' };
        return { VersionId: 'v2' };
      },
    } as unknown as S3Client);
    await api.putObject({ Bucket: 'b', Key: 'k', Body: 'body' });
    await api.headObject({ Bucket: 'b', Key: 'k' });
    await expect(api.getObject({ Bucket: 'b', Key: 'k' })).resolves.toEqual(new Uint8Array([1, 2]));
    expect(commands[0]).toBeInstanceOf(PutObjectCommand);
    expect(commands[1]).toBeInstanceOf(HeadObjectCommand);
    expect(commands[2]).toBeInstanceOf(GetObjectCommand);
    const missingBody = new AwsS3ObjectLockApi({ async send() { return {}; } } as unknown as S3Client);
    await expect(missingBody.getObject({ Bucket: 'b', Key: 'k' })).rejects.toThrow('body is missing');
  });

  it('creates a conditional compliance-retained object and returns its exact version evidence', async () => {
    const api = new FakeS3ObjectLockApi();
    const storage = new S3AuditAnchorStorage('separate-audit-bucket', api, () => new Date('2026-10-06T00:00:00.000Z'));
    await expect(storage.putImmutable('org/42-hash.json', 'checkpoint', 365)).resolves.toEqual({
      versionId: 'version-1', retainedUntil: '2027-10-06T00:00:00.000Z',
    });
    expect(api.putInput).toMatchObject({
      Bucket: 'separate-audit-bucket', Key: 'org/42-hash.json', ContentType: 'application/json',
      IfNoneMatch: '*', ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date('2027-10-06T00:00:00.000Z'),
    });
    expect(Buffer.from(api.putInput?.Body as Uint8Array).toString('utf8')).toBe('checkpoint');
  });

  it('accepts a prior conditional write only when the locked S3 version contains identical bytes', async () => {
    const api = new FakeS3ObjectLockApi();
    api.putError = Object.assign(new Error('Precondition Failed'), { $metadata: { httpStatusCode: 412 } });
    api.objectBody = new TextEncoder().encode('checkpoint');
    const storage = new S3AuditAnchorStorage('separate-audit-bucket', api, () => new Date('2026-10-06T00:00:00.000Z'));
    await expect(storage.putImmutable('org/42-hash.json', 'checkpoint', 365)).resolves.toEqual({
      versionId: 'version-1', retainedUntil: '2027-10-06T00:00:00.000Z',
    });
    api.objectBody = new TextEncoder().encode('different bytes');
    await expect(storage.putImmutable('org/42-hash.json', 'checkpoint', 365)).rejects.toThrow('Existing immutable audit anchor object does not match');
    api.objectBody = new TextEncoder().encode('checkpoint');
    api.headOutput = { $metadata: {}, VersionId: 'version-1', ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date('2027-01-01T00:00:00.000Z') };
    await expect(storage.putImmutable('org/42-hash.json', 'checkpoint', 365)).rejects.toThrow('Existing immutable audit anchor object does not match');
  });

  it('rejects missing object-lock retention, non-compliance mode, expired objects, and invalid config', async () => {
    const api = new FakeS3ObjectLockApi();
    api.putOutput = { $metadata: {} };
    const storage = new S3AuditAnchorStorage('bucket', api, () => new Date('2026-10-06T00:00:00.000Z'));
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toThrow('versioned Object Lock storage');
    api.putError = Object.assign(new Error('Precondition Failed'), { $metadata: { httpStatusCode: 412 } });
    api.headOutput = { $metadata: {}, VersionId: 'v', ObjectLockMode: 'GOVERNANCE', ObjectLockRetainUntilDate: new Date('2027-10-06T00:00:00Z') };
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toThrow('Existing immutable audit anchor object does not match');
    api.headOutput = { $metadata: {}, VersionId: 'v', ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date('2026-10-05T00:00:00Z') };
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toThrow('Existing immutable audit anchor object does not match');
    expect(() => new S3AuditAnchorStorage('', api)).toThrow('bucket');
    await expect(storage.putImmutable('key', 'body', 0)).rejects.toThrow('retention days');
    await expect(storage.putImmutable('', 'body', 30)).rejects.toThrow('key and body');
    await expect(storage.putImmutable('key', '', 30)).rejects.toThrow('key and body');
    api.putOutput = { $metadata: {}, VersionId: 'v' };
    api.putError = new Error('non-retryable');
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toThrow('non-retryable');
    api.putError = Object.assign(new Error('Precondition Failed'), { name: 'PreconditionFailed' });
    api.headOutput = { $metadata: {}, VersionId: 'v', ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date('2027-10-06T00:00:00Z') };
    api.objectBody = new TextEncoder().encode('body');
    await expect(storage.putImmutable('key', 'body', 30)).resolves.toMatchObject({ versionId: 'v' });
    api.headOutput = { $metadata: {}, ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date('2027-10-06T00:00:00Z') };
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toThrow('does not match');
    api.headOutput = { $metadata: {}, VersionId: 'v', ObjectLockMode: 'COMPLIANCE' };
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toThrow('does not match');
    api.putError = null;
    api.shouldThrow = true;
    await expect(storage.putImmutable('key', 'body', 30)).rejects.toBeNull();
  });
});
