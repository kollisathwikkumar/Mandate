import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Client } from 'pg';

const MIGRATION_DIRECTORY = resolve(process.cwd(), 'migrations');
const MIGRATION_LOCK_ID = '684450008035';

export async function migrate(client: Client): Promise<readonly string[]> {
  await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_ID]);
  try {
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const files = (await readdir(MIGRATION_DIRECTORY)).filter((file) => /^\d+_[a-z0-9_]+\.sql$/.test(file)).sort();
    const applied: string[] = [];

    for (const file of files) {
      const existing = await client.query<{ id: string }>('SELECT id FROM schema_migrations WHERE id = $1', [file]);
      if (existing.rowCount !== 0) continue;

      const sql = await readFile(resolve(MIGRATION_DIRECTORY, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [file]);
        await client.query('COMMIT');
        applied.push(file);
      } catch (error: unknown) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
    return applied;
  } finally {
    await client.query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_LOCK_ID]);
  }
}
