import { createHash, randomUUID } from 'node:crypto';
import {
  CreateSecretCommand,
  DeleteSecretCommand,
  GetSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import type { ModelSecretStore } from '../../../ports/src/model-secret-store.js';
import type { ModelProvider } from '../../../ports/src/model-credential-repository.js';
import type { WebhookSecretStore } from '../../../ports/src/webhook.js';
import { resolveAwsRegion } from './region.js';

const configuredRegion = resolveAwsRegion(process.env.AWS_REGION, process.env.AWS_DEFAULT_REGION);
const secretRecoveryWindowDays = 7;

export class AwsModelSecretStore implements ModelSecretStore {
  public constructor(private readonly client = new SecretsManagerClient(
    configuredRegion === undefined ? {} : { region: configuredRegion },
  )) {}

  public async put(organizationId: string, provider: ModelProvider, value: string): Promise<string> {
    const tenantHash = createHash('sha256').update(organizationId).digest('hex').slice(0, 24);
    const result = await this.client.send(new CreateSecretCommand({
      Name: `mandate/model-providers/${tenantHash}/${provider.toLowerCase()}/${randomUUID()}`,
      SecretString: value,
    }));
    if (result.ARN === undefined) throw new Error('Secret manager did not return a stable secret reference');
    return result.ARN;
  }

  public async get(secretReference: string): Promise<string> {
    const result = await this.client.send(new GetSecretValueCommand({ SecretId: secretReference }));
    if (result.SecretString === undefined) throw new Error('Secret manager value is not a string');
    return result.SecretString;
  }

  public async delete(secretReference: string): Promise<void> {
    try {
      await this.client.send(new DeleteSecretCommand({ SecretId: secretReference, RecoveryWindowInDays: secretRecoveryWindowDays }));
    } catch (error: unknown) {
      if (typeof error === 'object' && error !== null && '$metadata' in error && 'name' in error && error.name === 'ResourceNotFoundException') return;
      throw error;
    }
  }
}

export class AwsWebhookSecretStore implements WebhookSecretStore {
  public constructor(private readonly client = new SecretsManagerClient(
    configuredRegion === undefined ? {} : { region: configuredRegion },
  )) {}

  public async put(organizationId: string, endpointId: string, secret: string): Promise<string> {
    const tenantHash = createHash('sha256').update(organizationId).digest('hex').slice(0, 24);
    const result = await this.client.send(new CreateSecretCommand({
      Name: `mandate/webhooks/${tenantHash}/${endpointId}/${randomUUID()}`,
      SecretString: secret,
    }));
    if (result.ARN === undefined) throw new Error('Secret manager did not return a stable secret reference');
    return result.ARN;
  }

  public async get(secretReference: string): Promise<string> {
    const result = await this.client.send(new GetSecretValueCommand({ SecretId: secretReference }));
    if (result.SecretString === undefined) throw new Error('Secret manager value is not a string');
    return result.SecretString;
  }

  public async delete(secretReference: string): Promise<void> {
    try {
      await this.client.send(new DeleteSecretCommand({ SecretId: secretReference, RecoveryWindowInDays: secretRecoveryWindowDays }));
    } catch (error: unknown) {
      if (typeof error === 'object' && error !== null && '$metadata' in error && 'name' in error && error.name === 'ResourceNotFoundException') return;
      throw error;
    }
  }
}
