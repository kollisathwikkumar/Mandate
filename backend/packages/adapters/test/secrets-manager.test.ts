import { describe, expect, it } from 'vitest';
import { DeleteSecretCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { AwsModelSecretStore, AwsWebhookSecretStore } from '../src/aws/secrets-manager.js';

function captureClient(commands: DeleteSecretCommand[]): SecretsManagerClient {
  return {
    async send(command: DeleteSecretCommand) {
      commands.push(command);
      return {};
    },
  } as unknown as SecretsManagerClient;
}

describe('AWS Secrets Manager deletion', () => {
  it('schedules model provider secret deletion with a recoverable window', async () => {
    const commands: DeleteSecretCommand[] = [];
    await new AwsModelSecretStore(captureClient(commands)).delete('model-secret-arn');
    expect(commands).toHaveLength(1);
    expect(commands[0]).toBeInstanceOf(DeleteSecretCommand);
    expect(commands[0]?.input).toEqual({ SecretId: 'model-secret-arn', RecoveryWindowInDays: 7 });
  });

  it('schedules webhook signing secret deletion with a recoverable window', async () => {
    const commands: DeleteSecretCommand[] = [];
    await new AwsWebhookSecretStore(captureClient(commands)).delete('webhook-secret-arn');
    expect(commands).toHaveLength(1);
    expect(commands[0]).toBeInstanceOf(DeleteSecretCommand);
    expect(commands[0]?.input).toEqual({ SecretId: 'webhook-secret-arn', RecoveryWindowInDays: 7 });
  });

  it('treats a missing model secret as an idempotent delete', async () => {
    const client = {
      async send() {
        throw Object.assign(new Error('not found'), { name: 'ResourceNotFoundException', $metadata: {} });
      },
    } as unknown as SecretsManagerClient;
    await expect(new AwsModelSecretStore(client).delete('missing')).resolves.toBeUndefined();
    await expect(new AwsWebhookSecretStore(client).delete('missing')).resolves.toBeUndefined();
  });
});
