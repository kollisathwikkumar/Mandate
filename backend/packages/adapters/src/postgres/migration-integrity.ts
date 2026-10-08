import { createHash } from 'node:crypto';

const MIGRATION_FILE = /^\d+_[a-z0-9_]+\.sql$/;

export function verifyMigrationChecksums(files: readonly string[], contents: Readonly<Record<string, string>>,
  expected: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  const names = files.filter((file) => MIGRATION_FILE.test(file)).sort();
  const actualNames = Object.keys(expected).sort();
  if (names.length !== actualNames.length || names.some((file, index) => file !== actualNames[index])) {
    throw new Error('Migration checksum manifest does not match the SQL migration files');
  }
  const result: Record<string, string> = {};
  for (const file of names) {
    const sql = contents[file];
    const checksum = expected[file];
    if (sql === undefined || checksum === undefined || !/^[0-9a-f]{64}$/.test(checksum)) {
      throw new Error(`Migration checksum manifest entry is invalid: ${file}`);
    }
    const actual = createHash('sha256').update(sql, 'utf8').digest('hex');
    if (actual !== checksum) throw new Error(`Migration checksum mismatch: ${file}`);
    result[file] = actual;
  }
  return result;
}
