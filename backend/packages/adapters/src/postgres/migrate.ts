import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { Client } from 'pg';
import { verifyMigrationChecksums } from './migration-integrity.js';

const MIGRATION_DIRECTORY = resolve(process.cwd(), 'migrations');
const MIGRATION_LOCK_ID = '684450008035';

export async function migrate(client: Client): Promise<readonly string[]> {
  await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_ID]);
  try {
    const files = (await readdir(MIGRATION_DIRECTORY)).filter((file) => /^\d+_[a-z0-9_]+\.sql$/.test(file)).sort();
    const contents: Record<string, string> = {};
    for (const file of files) contents[file] = await readFile(resolve(MIGRATION_DIRECTORY, file), 'utf8');
    const expected = JSON.parse(await readFile(resolve(MIGRATION_DIRECTORY, 'checksums.json'), 'utf8')) as Record<string, string>;
    const checksums = verifyMigrationChecksums(files, contents, expected);

    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      id text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(), checksum text
    )`);
    await client.query('ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text');
    const applied: string[] = [];

    for (const file of files) {
      const checksum = checksums[file];
      const existing = await client.query<{ id: string; checksum: string | null }>(
        'SELECT id, checksum FROM schema_migrations WHERE id = $1', [file],
      );
      const row = existing.rows[0];
      if (row !== undefined) {
        if (row.checksum !== null && row.checksum !== checksum) {
          throw new Error(`Applied migration checksum mismatch: ${file}`);
        }
        if (row.checksum === null) {
          await client.query('UPDATE schema_migrations SET checksum = $2 WHERE id = $1 AND checksum IS NULL', [file, checksum]);
        }
        continue;
      }

      await client.query('BEGIN');
      try {
        await client.query(contents[file] ?? '');
        await client.query('INSERT INTO schema_migrations (id, checksum) VALUES ($1, $2)', [file, checksum]);
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
