import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../src/postgres/migrate.js';

const connectionString = process.env.DATABASE_URL;

describe.skipIf(connectionString === undefined)('PostgreSQL migration checksums', () => {
  let checksums: Record<string, string>;
  let rows: readonly { id: string; checksum: string | null }[];

  beforeAll(async () => {
    if (connectionString === undefined) throw new Error('DATABASE_URL is required');
    const client = new Client({ connectionString });
    await client.connect();
    try {
      checksums = JSON.parse(await readFile(resolve(process.cwd(), 'migrations/checksums.json'), 'utf8')) as Record<string, string>;
      await migrate(client);
      const result = await client.query<{ id: string; checksum: string | null }>(
        'SELECT id, checksum FROM schema_migrations ORDER BY id',
      );
      rows = result.rows;
    } finally {
      await client.end();
    }
  });

  it('persists exact checksums for every SQL migration and no unmanifested migration', () => {
    expect(rows).toHaveLength(Object.keys(checksums).length);
    for (const row of rows) expect(row.checksum).toBe(checksums[row.id]);
  });
});
