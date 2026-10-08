import { createServer, type Server } from 'node:http';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { afterEach, describe, expect, it } from 'vitest';
import { AwsAuditExportKeyStore } from '../src/aws/audit-export-key-store.js';

interface SecretsFixture {
  readonly client: SecretsManagerClient;
  readonly requests: Array<{ target: string | undefined; body: string }>;
  close(): Promise<void>;
}

async function startSecretsFixture(responseBody: string): Promise<SecretsFixture> {
  const requests: Array<{ target: string | undefined; body: string }> = [];
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const headerTarget = request.headers['x-amz-target'];
      const target = Array.isArray(headerTarget) ? headerTarget.join(',') : headerTarget;
      requests.push({ target, body: Buffer.concat(chunks).toString('utf8') });
      response.writeHead(200, {
        'content-type': 'application/x-amz-json-1.1',
        'x-amzn-requestid': 'local-test-request',
      });
      response.end(responseBody);
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('Secrets Manager fixture did not bind a TCP port');
  const endpoint = `http://127.0.0.1:${address.port}`;
  const client = new SecretsManagerClient({
    endpoint,
    region: 'ap-south-1',
    credentials: { accessKeyId: 'local-test-access-key', secretAccessKey: 'local-test-secret-key' },
  });
  return {
    client,
    requests,
    async close(): Promise<void> {
      client.destroy();
      await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
    },
  };
}

const fixtures: SecretsFixture[] = [];

afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((fixture) => fixture.close()));
});

function makeKeyPair(): { readonly keyId: string; readonly privateKeyPem: string } {
  const keyPair = generateKeyPairSync('ed25519');
  return {
    keyId: 'mandate-audit-key-1',
    privateKeyPem: keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

function secretResponse(value: string): string {
  return JSON.stringify({ SecretString: value });
}

function fixture(response: string): Promise<SecretsFixture> {
  return startSecretsFixture(response).then((created) => {
    fixtures.push(created);
    return created;
  });
}

describe('AwsAuditExportKeyStore', () => {
  it('loads an Ed25519 key from Secrets Manager and returns a working signer', async () => {
    const key = makeKeyPair();
    const secretReference = 'arn:aws:secretsmanager:ap-south-1:111122223333:secret:mandate/audit-signing';
    const local = await fixture(secretResponse(JSON.stringify(key)));
    const signer = await new AwsAuditExportKeyStore(local.client).loadSigner(secretReference);
    const signed = signer.sign('canonical-payload');
    const signingMessage = Buffer.from(`MANDATE_AUDIT_EXPORT_V1\n${key.keyId}\ncanonical-payload`, 'utf8');

    expect(local.requests).toEqual([{
      target: 'secretsmanager.GetSecretValue',
      body: JSON.stringify({ SecretId: secretReference }),
    }]);
    expect(signed.algorithm).toBe('Ed25519');
    expect(signed.keyId).toBe(key.keyId);
    expect(verify(null, signingMessage, createPublicKey(signed.publicKeyPem), Buffer.from(signed.signature, 'base64'))).toBe(true);
  });

  it('rejects a blank secret reference without contacting Secrets Manager', async () => {
    const local = await fixture('{}');
    await expect(new AwsAuditExportKeyStore(local.client).loadSigner('  ')).rejects.toThrow('secret reference is invalid');
    expect(local.requests).toHaveLength(0);
  });

  it('rejects an absent or oversized secret value', async () => {
    const absent = await fixture('{}');
    await expect(new AwsAuditExportKeyStore(absent.client).loadSigner('secret-arn')).rejects.toThrow('secret is unavailable');
    const oversized = await fixture(secretResponse('x'.repeat(20_001)));
    await expect(new AwsAuditExportKeyStore(oversized.client).loadSigner('secret-arn')).rejects.toThrow('secret is unavailable');
  });

  it('rejects malformed JSON and strict-schema violations', async () => {
    const malformed = await fixture(secretResponse('not-json'));
    await expect(new AwsAuditExportKeyStore(malformed.client).loadSigner('secret-arn')).rejects.toThrow('secret format is invalid');
    const key = makeKeyPair();
    const wrongShape = await fixture(secretResponse(JSON.stringify({ ...key, extra: 'not-allowed' })));
    await expect(new AwsAuditExportKeyStore(wrongShape.client).loadSigner('secret-arn')).rejects.toThrow();
    const invalidId = await fixture(secretResponse(JSON.stringify({ ...key, keyId: '../bad' })));
    await expect(new AwsAuditExportKeyStore(invalidId.client).loadSigner('secret-arn')).rejects.toThrow();
  });

  it('rejects invalid and non-Ed25519 private keys', async () => {
    const invalidPem = await fixture(secretResponse(JSON.stringify({ keyId: 'key-1', privateKeyPem: 'not-a-private-key' })));
    await expect(new AwsAuditExportKeyStore(invalidPem.client).loadSigner('secret-arn')).rejects.toThrow();
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const wrongAlgorithm = await fixture(secretResponse(JSON.stringify({ keyId: 'key-1', privateKeyPem: rsaPem })));
    await expect(new AwsAuditExportKeyStore(wrongAlgorithm.client).loadSigner('secret-arn')).rejects.toThrow('must be Ed25519');
  });
});
