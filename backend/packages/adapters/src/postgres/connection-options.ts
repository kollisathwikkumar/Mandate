import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { PoolConfig } from 'pg';

const CONNECTION_STRING_SSL_PARAMETERS = ['sslmode', 'sslcert', 'sslkey', 'sslrootcert'] as const;

export function postgresTlsOptions(
  databaseUrl: string,
  nodeEnvironment: string | undefined,
  caPath: string | undefined,
): Pick<PoolConfig, 'ssl'> {
  const tlsRequired = nodeEnvironment === 'production';
  const configuredCaPath = caPath?.trim();
  if (!tlsRequired && (configuredCaPath === undefined || configuredCaPath === '')) return {};
  if (configuredCaPath === undefined || configuredCaPath === '') {
    throw new Error('DATABASE_SSL_CA_PATH is required in production');
  }
  if (!isAbsolute(configuredCaPath)) throw new Error('DATABASE_SSL_CA_PATH must be an absolute path');

  let connectionUrl: URL;
  try {
    connectionUrl = new URL(databaseUrl);
  } catch {
    throw new Error('DATABASE_URL must be a valid PostgreSQL URL');
  }
  if (connectionUrl.protocol !== 'postgres:' && connectionUrl.protocol !== 'postgresql:') {
    throw new Error('DATABASE_URL must use the PostgreSQL protocol');
  }
  if (CONNECTION_STRING_SSL_PARAMETERS.some((parameter) => connectionUrl.searchParams.has(parameter))) {
    throw new Error('Remove PostgreSQL SSL query parameters from DATABASE_URL; configure TLS with DATABASE_SSL_CA_PATH');
  }

  let ca: string;
  try {
    ca = readFileSync(configuredCaPath, 'utf8');
  } catch {
    throw new Error('Could not read the PostgreSQL TLS CA certificate at DATABASE_SSL_CA_PATH');
  }
  if (!ca.includes('-----BEGIN CERTIFICATE-----') || !ca.includes('-----END CERTIFICATE-----')) {
    throw new Error('DATABASE_SSL_CA_PATH must contain a PEM-encoded CA certificate');
  }

  return { ssl: { ca, rejectUnauthorized: true } };
}
