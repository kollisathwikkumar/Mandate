import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { z } from 'zod';
import { Ed25519AuditExportSigner } from '../../../application/src/audit-export-service.js';

const AuditSigningSecretSchema = z.object({
  keyId: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  privateKeyPem: z.string().min(1).max(16_384),
}).strict();

const configuredRegion = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;

export class AwsAuditExportKeyStore {
  public constructor(private readonly client = new SecretsManagerClient(
    configuredRegion === undefined ? {} : { region: configuredRegion },
  )) {}

  public async loadSigner(secretReference: string): Promise<Ed25519AuditExportSigner> {
    if (secretReference.trim() === '') throw new Error('Audit signing secret reference is invalid');
    const result = await this.client.send(new GetSecretValueCommand({ SecretId: secretReference }));
    if (result.SecretString === undefined || result.SecretString.length > 20_000) throw new Error('Audit signing secret is unavailable');
    let parsed: unknown;
    try { parsed = JSON.parse(result.SecretString) as unknown; } catch { throw new Error('Audit signing secret format is invalid'); }
    const secret = AuditSigningSecretSchema.parse(parsed);
    return new Ed25519AuditExportSigner(secret.keyId, secret.privateKeyPem);
  }
}
