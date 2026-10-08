import { Pool } from 'pg';
import { createApiServer } from './app.js';
import { AwsAuditExportKeyStore } from '../../../packages/adapters/src/aws/audit-export-key-store.js';
import { AesGcmInvitationTokenCipher } from '../../../packages/adapters/src/crypto/aes-gcm-invitation-token-cipher.js';
import { postgresTlsOptions } from '../../../packages/adapters/src/postgres/connection-options.js';
import { parseBroadcastRpcFallbackUrls } from './broadcast-rpc-config.js';
import { parseTrustedProxyCidrs } from './proxy-config.js';
import { parseCorsAllowedOrigins } from './cors-config.js';

function parseChainRpcUrls(value: string | undefined): Readonly<Record<number, string>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error('MANDATE_EVM_RPC_URLS must be a JSON object keyed by decimal chain ID'); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('MANDATE_EVM_RPC_URLS must be a JSON object keyed by decimal chain ID');
  const result: Record<number, string> = {};
  for (const [key, url] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key || typeof url !== 'string' || url.trim() === '') {
      throw new Error('MANDATE_EVM_RPC_URLS contains an invalid chain ID or URL');
    }
    result[chainId] = url;
  }
  return result;
}

function parseTrustedSafeSingletons(value: string | undefined): Readonly<Record<number, string>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error('MANDATE_SAFE_SINGLETONS must be a JSON object keyed by decimal chain ID'); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('MANDATE_SAFE_SINGLETONS must be a JSON object keyed by decimal chain ID');
  const result: Record<number, string> = {};
  for (const [key, address] of Object.entries(parsed)) {
    const chainId = Number(key);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key
      || typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address) || address.toLowerCase() === `0x${'0'.repeat(40)}`) {
      throw new Error('MANDATE_SAFE_SINGLETONS contains an invalid chain ID or address');
    }
    result[chainId] = address.toLowerCase();
  }
  return result;
}

function parseChainConfirmations(value: string | undefined): Readonly<Record<number, number>> {
  if (value === undefined || value.trim() === '') return {};
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new Error('MANDATE_CHAIN_CONFIRMATIONS must be a JSON object keyed by decimal chain ID'); }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('MANDATE_CHAIN_CONFIRMATIONS must be a JSON object keyed by decimal chain ID');
  const result: Record<number, number> = {};
  for (const [key, confirmationValue] of Object.entries(parsed)) {
    const chainId = Number(key);
    const confirmations = typeof confirmationValue === 'number' ? confirmationValue : Number(confirmationValue);
    if (!Number.isSafeInteger(chainId) || chainId < 1 || String(chainId) !== key
      || !Number.isSafeInteger(confirmations) || confirmations < 1 || confirmations > 10000) {
      throw new Error('MANDATE_CHAIN_CONFIRMATIONS contains an invalid chain ID or finality depth');
    }
    result[chainId] = confirmations;
  }
  return result;
}

const databaseUrl = process.env.DATABASE_URL;
const jwksUrl = process.env.MANDATE_JWT_JWKS_URL;
const issuer = process.env.MANDATE_JWT_ISSUER;
const audienceValue = process.env.MANDATE_JWT_AUDIENCE;
function parseJwtAudience(value: string | undefined): string | string[] | undefined {
  if (value === undefined) return undefined;
  const audiences = value.split(',').map((entry) => entry.trim());
  if (audiences.some((entry) => entry.length === 0)) throw new Error('MANDATE_JWT_AUDIENCE must be a non-empty value or comma-separated audience allowlist');
  return audiences.length === 1 ? audiences[0] : audiences;
}
const audience = parseJwtAudience(audienceValue);
const trustedProxyCidrs = parseTrustedProxyCidrs(process.env.MANDATE_TRUSTED_PROXY_CIDRS);
const corsAllowedOrigins = parseCorsAllowedOrigins(process.env.MANDATE_CORS_ALLOWED_ORIGINS);
const host = process.env.HOST ?? '127.0.0.1';
const portText = process.env.PORT ?? '3000';
const port = Number(portText);

if (databaseUrl === undefined || jwksUrl === undefined || issuer === undefined || audience === undefined) {
  throw new Error('DATABASE_URL, MANDATE_JWT_JWKS_URL, MANDATE_JWT_ISSUER, and MANDATE_JWT_AUDIENCE are required');
}
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be a valid TCP port');

const pool = new Pool({
  connectionString: databaseUrl,
  max: 20,
  application_name: 'mandate-api',
  ...postgresTlsOptions(databaseUrl, process.env.NODE_ENV, process.env.DATABASE_SSL_CA_PATH),
});
const auditSigningSecretReference = process.env.MANDATE_AUDIT_SIGNING_SECRET_ARN;
const auditExportSigner = auditSigningSecretReference === undefined || auditSigningSecretReference.trim() === ''
  ? undefined
  : await new AwsAuditExportKeyStore().loadSigner(auditSigningSecretReference);
const invitationTokenEncryptionKey = process.env.MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX;
const invitationTokenCipher = invitationTokenEncryptionKey === undefined || invitationTokenEncryptionKey.trim() === ''
  ? undefined
  : new AesGcmInvitationTokenCipher(invitationTokenEncryptionKey);
const chainRpcUrls = parseChainRpcUrls(process.env.MANDATE_EVM_RPC_URLS);
const chainRpcFallbackUrls = parseBroadcastRpcFallbackUrls(process.env.MANDATE_BROADCAST_RPC_FALLBACK_URLS, chainRpcUrls);
const trustedSafeSingletons = parseTrustedSafeSingletons(process.env.MANDATE_SAFE_SINGLETONS);
const chainConfirmations = parseChainConfirmations(process.env.MANDATE_CHAIN_CONFIRMATIONS);
const app = await createApiServer({ pool, jwksUrl, issuer, audience, logger: true, chainRpcUrls, chainRpcFallbackUrls, trustedSafeSingletons, chainConfirmations, ...(trustedProxyCidrs === undefined ? {} : { trustedProxyCidrs }), ...(corsAllowedOrigins === undefined ? {} : { corsAllowedOrigins }), ...(auditExportSigner === undefined ? {} : { auditExportSigner }), ...(invitationTokenCipher === undefined ? {} : { invitationTokenCipher }) });

try {
  await app.listen({ host, port });
  app.log.info({ host, port }, 'Mandate API listening');
} catch (error: unknown) {
  await pool.end();
  throw error;
}

let shuttingDown = false;
const shutdown = async (signal: string): Promise<void> => {
  if (shuttingDown) return;
  shuttingDown = true;
  app.log.info({ signal }, 'Mandate API shutting down');
  await app.close();
  await pool.end();
};

process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
