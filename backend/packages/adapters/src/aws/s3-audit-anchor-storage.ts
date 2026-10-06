import {
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
  type GetObjectCommandInput,
  type HeadObjectCommandInput,
  type HeadObjectCommandOutput,
  type PutObjectCommandInput,
  type PutObjectCommandOutput,
} from '@aws-sdk/client-s3';
import type { AuditAnchorStorage, AuditAnchorStorageResult } from '../../../ports/src/audit-anchor.js';

export interface S3ObjectLockApi {
  putObject(input: PutObjectCommandInput): Promise<PutObjectCommandOutput>;
  headObject(input: HeadObjectCommandInput): Promise<HeadObjectCommandOutput>;
  getObject(input: GetObjectCommandInput): Promise<Uint8Array>;
}

export class AwsS3ObjectLockApi implements S3ObjectLockApi {
  public constructor(private readonly client = new S3Client(
    process.env.AWS_REGION === undefined ? {} : { region: process.env.AWS_REGION },
  )) {}

  public async putObject(input: PutObjectCommandInput): Promise<PutObjectCommandOutput> {
    return this.client.send(new PutObjectCommand(input));
  }

  public async headObject(input: HeadObjectCommandInput): Promise<HeadObjectCommandOutput> {
    return this.client.send(new HeadObjectCommand(input));
  }

  public async getObject(input: GetObjectCommandInput): Promise<Uint8Array> {
    const result = await this.client.send(new GetObjectCommand(input));
    if (result.Body === undefined) throw new Error('Audit anchor object body is missing');
    return result.Body.transformToByteArray();
  }
}

function isPreconditionFailed(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  if ('name' in error && error.name === 'PreconditionFailed') return true;
  if ('$metadata' in error && typeof error.$metadata === 'object' && error.$metadata !== null
    && 'httpStatusCode' in error.$metadata && error.$metadata.httpStatusCode === 412) return true;
  return false;
}

export class S3AuditAnchorStorage implements AuditAnchorStorage {
  private readonly api: S3ObjectLockApi;
  private readonly now: () => Date;

  public constructor(
    private readonly bucket: string,
    api?: S3ObjectLockApi,
    now: () => Date = () => new Date(),
  ) {
    if (bucket.trim() === '') throw new Error('Audit anchor S3 bucket is required');
    this.api = api ?? new AwsS3ObjectLockApi();
    this.now = now;
  }

  public async putImmutable(key: string, body: string, retentionDays: number): Promise<AuditAnchorStorageResult> {
    if (key.trim() === '' || body.length === 0) throw new Error('Audit anchor key and body are required');
    if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 36_500) {
      throw new Error('Audit anchor retention days must be an integer from 1 to 36500');
    }
    const requestedRetainUntilMs = this.now().getTime() + retentionDays * 86_400_000;
    const retainUntil = new Date(Math.ceil(requestedRetainUntilMs / 1000) * 1000);
    const input: PutObjectCommandInput = {
      Bucket: this.bucket,
      Key: key,
      Body: Buffer.from(body, 'utf8'),
      ContentType: 'application/json',
      IfNoneMatch: '*',
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: retainUntil,
    };
    try {
      const result = await this.api.putObject(input);
      if (result.VersionId === undefined || result.VersionId.trim() === '') {
        throw new Error('S3 did not return versioned Object Lock storage evidence');
      }
      return { versionId: result.VersionId, retainedUntil: retainUntil.toISOString() };
    } catch (error: unknown) {
      if (!isPreconditionFailed(error)) throw error;
      const [head, existingBytes] = await Promise.all([
        this.api.headObject({ Bucket: this.bucket, Key: key }),
        this.api.getObject({ Bucket: this.bucket, Key: key }),
      ]);
      const existingBody = Buffer.from(existingBytes).toString('utf8');
      const existingRetention = head.ObjectLockRetainUntilDate;
      if (existingBody !== body || head.VersionId === undefined || head.VersionId.trim() === ''
        || head.ObjectLockMode !== 'COMPLIANCE' || existingRetention === undefined
        || existingRetention.getTime() < retainUntil.getTime()) {
        throw new Error('Existing immutable audit anchor object does not match the expected bytes and retention');
      }
      return { versionId: head.VersionId, retainedUntil: existingRetention.toISOString() };
    }
  }
}
