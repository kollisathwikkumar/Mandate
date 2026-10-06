import { Pool } from 'pg';
import { EvmExecutionReceiptReader } from '../../../packages/adapters/src/chain/evm-execution-receipt-reader.js';
import { ExecutionReconciliationStore } from '../../../packages/adapters/src/postgres/execution-reconciliation-store.js';
import { ExecutionReconciliationService } from '../../../packages/application/src/execution-reconciliation-service.js';
import { OutboxWorker } from './outbox-worker.js';
import { WebhookDeliveryWorker } from './webhook-delivery-worker.js';
import { AwsWebhookSecretStore } from '../../../packages/adapters/src/aws/secrets-manager.js';
import { PublicHttpsWebhookTransport } from '../../../packages/adapters/src/webhooks/https-webhook-transport.js';
import { AuditAnchorStore } from '../../../packages/adapters/src/postgres/audit-anchor-store.js';
import { S3AuditAnchorStorage } from '../../../packages/adapters/src/aws/s3-audit-anchor-storage.js';
import { AwsAuditExportKeyStore } from '../../../packages/adapters/src/aws/audit-export-key-store.js';
import { AuditAnchorService } from '../../../packages/application/src/audit-anchor-service.js';
import { readAuditAnchorRuntimeConfig } from './audit-anchor-runtime.js';
import { readInvitationEmailRuntimeConfig } from './invitation-email-runtime.js';
import { AesGcmInvitationTokenCipher } from '../../../packages/adapters/src/crypto/aes-gcm-invitation-token-cipher.js';
import { SesInvitationEmailTransport } from '../../../packages/adapters/src/aws/ses-invitation-email-transport.js';
import { InvitationEmailDeliveryWorker } from './invitation-email-worker.js';

function parseNumberMap(value: string | undefined, name: string, maximum: number): Readonly<Record<number, number>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error(`${name} must be a JSON object keyed by decimal chain ID`); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error(`${name} must be a JSON object keyed by decimal chain ID`);
  const result: Record<number, number> = {};
  for (const [key, valueEntry] of Object.entries(parsed)) {
    const chainId = Number(key);
    const valueNumber = typeof valueEntry === 'number' ? valueEntry : Number(valueEntry);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key
      || !Number.isSafeInteger(valueNumber) || valueNumber < 1 || valueNumber > maximum) {
      throw new Error(`${name} contains an invalid chain ID or value`);
    }
    result[chainId] = valueNumber;
  }
  return result;
}

function parseRpcUrls(value: string | undefined): Readonly<Record<number, string>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error('MANDATE_EVM_RPC_URLS must be a JSON object keyed by decimal chain ID'); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('MANDATE_EVM_RPC_URLS must be a JSON object keyed by decimal chain ID');
  const result: Record<number, string> = {};
  for (const [key, entry] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key || typeof entry !== 'string' || entry.trim() === '') {
      throw new Error('MANDATE_EVM_RPC_URLS contains an invalid chain ID or URL');
    }
    result[chainId] = entry;
  }
  return result;
}

const databaseUrl = process.env.DATABASE_URL;
const pollIntervalMs = Number(process.env.MANDATE_WORKER_POLL_MS ?? '1000');
if (databaseUrl === undefined) throw new Error('DATABASE_URL is required');
if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 100 || pollIntervalMs > 60000) {
  throw new Error('MANDATE_WORKER_POLL_MS must be an integer from 100 to 60000');
}

const pool = new Pool({ connectionString: databaseUrl, max: 5, application_name: 'mandate-worker' });
const worker = new OutboxWorker(pool);
const webhookWorker = new WebhookDeliveryWorker(pool, new AwsWebhookSecretStore(), new PublicHttpsWebhookTransport());
const rpcUrls = parseRpcUrls(process.env.MANDATE_EVM_RPC_URLS);
const confirmationDepths = parseNumberMap(process.env.MANDATE_CHAIN_CONFIRMATIONS, 'MANDATE_CHAIN_CONFIRMATIONS', 10000);
if ((Object.keys(rpcUrls).length === 0) !== (Object.keys(confirmationDepths).length === 0)
  || Object.keys(rpcUrls).some((chainId) => confirmationDepths[Number(chainId)] === undefined)
  || Object.keys(confirmationDepths).some((chainId) => rpcUrls[Number(chainId)] === undefined)) {
  throw new Error('Execution reconciliation requires matching MANDATE_EVM_RPC_URLS and MANDATE_CHAIN_CONFIRMATIONS chain entries');
}
const reconciler = Object.keys(rpcUrls).length === 0 || Object.keys(confirmationDepths).length === 0
  ? null
  : new ExecutionReconciliationService(new ExecutionReconciliationStore(pool), new EvmExecutionReceiptReader(rpcUrls), confirmationDepths);
const auditAnchorConfig = readAuditAnchorRuntimeConfig(process.env);
const auditAnchorService = auditAnchorConfig === null ? null : new AuditAnchorService(
  new AuditAnchorStore(pool),
  new S3AuditAnchorStorage(auditAnchorConfig.bucket),
  await new AwsAuditExportKeyStore().loadSigner(auditAnchorConfig.signingSecretArn),
  auditAnchorConfig.batchSize,
  auditAnchorConfig.retentionDays,
);
const invitationEmailConfig = readInvitationEmailRuntimeConfig(process.env);
const invitationEmailWorker = invitationEmailConfig === null ? null : new InvitationEmailDeliveryWorker(
  pool,
  new AesGcmInvitationTokenCipher(invitationEmailConfig.encryptionKeyHex),
  new SesInvitationEmailTransport(),
  { from: invitationEmailConfig.from, acceptUrl: invitationEmailConfig.acceptUrl },
);
let nextAuditAnchorAt = auditAnchorConfig === null ? Number.POSITIVE_INFINITY : Date.now() + auditAnchorConfig.intervalMs;
let stopping = false;
process.once('SIGINT', () => { stopping = true; });
process.once('SIGTERM', () => { stopping = true; });

while (!stopping) {
  const now = Date.now();
  if (auditAnchorService !== null && auditAnchorConfig !== null && now >= nextAuditAnchorAt) {
    const result = await auditAnchorService.runBatch();
    if (result.candidates > 0 || result.failed > 0) {
      process.stdout.write(`${JSON.stringify({ component: 'audit-anchor-worker', ...result })}\n`);
    }
    nextAuditAnchorAt = Date.now() + auditAnchorConfig.intervalMs;
  }
  const result = await worker.runBatch();
  if (result.claimed > 0 || result.failed > 0) {
    process.stdout.write(`${JSON.stringify({ component: 'outbox-worker', ...result })}\n`);
  }
  const webhookResult = await webhookWorker.runBatch();
  if (webhookResult.claimed > 0) {
    process.stdout.write(`${JSON.stringify({ component: 'webhook-delivery-worker', ...webhookResult })}\n`);
  }
  const invitationEmailResult = invitationEmailWorker === null ? null : await invitationEmailWorker.runBatch();
  if (invitationEmailResult !== null && (invitationEmailResult.claimed > 0 || invitationEmailResult.failed > 0)) {
    process.stdout.write(`${JSON.stringify({ component: 'invitation-email-worker', ...invitationEmailResult })}\n`);
  }
  let reconciliationWorked = false;
  if (reconciler !== null) {
    const reconciled = await reconciler.runBatch();
    if (reconciled.finalized > 0 || reconciled.dropped > 0 || reconciled.deepReorged > 0 || reconciled.reorged > 0 || reconciled.failed > 0) {
      process.stdout.write(`${JSON.stringify({ component: 'execution-reconciler', ...reconciled })}\n`);
      reconciliationWorked = reconciled.finalized > 0 || reconciled.dropped > 0 || reconciled.deepReorged > 0 || reconciled.reorged > 0;
    }
  }
  if (result.claimed === 0 && webhookResult.claimed === 0 && (invitationEmailResult === null || invitationEmailResult.claimed === 0) && !reconciliationWorked && !stopping) {
    const anchorWait = Math.max(0, nextAuditAnchorAt - Date.now());
    await new Promise<void>((resolve) => setTimeout(resolve, Math.min(pollIntervalMs, anchorWait)));
  }
}

await pool.end();
