import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { postgresTlsOptions } from '../src/postgres/connection-options.js';

const caPem = '-----BEGIN CERTIFICATE-----\nZmFrZS1jZXJ0\n-----END CERTIFICATE-----\n';
const databaseUrl = 'postgresql://mandate:secret@db.example.internal:5432/mandate';
const temporaryDirectories: string[] = [];

function writeCa(contents = caPem): string {
  const directory = mkdtempSync(join(tmpdir(), 'mandate-postgres-ca-'));
  temporaryDirectories.push(directory);
  const path = join(directory, 'rds-global-bundle.pem');
  writeFileSync(path, contents, { mode: 0o600 });
  return path;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe('postgresTlsOptions', () => {
  it('allows local development connections without TLS configuration', () => {
    expect(postgresTlsOptions(databaseUrl, 'development', undefined)).toEqual({});
    expect(postgresTlsOptions(databaseUrl, 'test', undefined)).toEqual({});
  });

  it('requires a CA and enables certificate-verified TLS in production', () => {
    expect(() => postgresTlsOptions(databaseUrl, 'production', undefined)).toThrow('DATABASE_SSL_CA_PATH is required');
    expect(postgresTlsOptions(databaseUrl, 'production', writeCa())).toEqual({ ssl: { ca: caPem, rejectUnauthorized: true } });
  });

  it('allows explicitly configured certificate-verified TLS outside production', () => {
    expect(postgresTlsOptions(databaseUrl, 'development', writeCa())).toEqual({ ssl: { ca: caPem, rejectUnauthorized: true } });
  });

  it('rejects relative, unreadable, and non-PEM CA paths', () => {
    expect(() => postgresTlsOptions(databaseUrl, 'production', 'ca.pem')).toThrow('absolute path');
    expect(() => postgresTlsOptions(databaseUrl, 'production', '/missing/mandate-ca.pem')).toThrow('Could not read');
    expect(() => postgresTlsOptions(databaseUrl, 'production', writeCa('not a certificate'))).toThrow('PEM-encoded');
  });

  it('rejects SSL URL parameters that would override the verified TLS configuration', () => {
    const caPath = writeCa();
    for (const parameter of ['sslmode=disable', 'sslmode=require', 'sslrootcert=%2Ftmp%2Fother.pem', 'sslcert=x', 'sslkey=x']) {
      expect(() => postgresTlsOptions(`${databaseUrl}?${parameter}`, 'production', caPath)).toThrow('Remove PostgreSQL SSL query parameters');
    }
  });

  it('rejects malformed database URLs and non-PostgreSQL protocols when TLS is configured', () => {
    const caPath = writeCa();
    expect(() => postgresTlsOptions('not-a-url', 'production', caPath)).toThrow('valid PostgreSQL URL');
    expect(() => postgresTlsOptions('https://db.example.internal', 'production', caPath)).toThrow('PostgreSQL protocol');
  });
});
