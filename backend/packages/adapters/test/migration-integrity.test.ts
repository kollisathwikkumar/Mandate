import { describe, expect, it } from 'vitest';
import { verifyMigrationChecksums } from '../src/postgres/migration-integrity.js';

const sql = 'CREATE TABLE example (id integer);\n';
const valid = { '001_initial.sql': '9a84f800837cef2f6c386c8f5ea2ebb56dfd87555b4d28bd4c88ee98aff5f21a' };

describe('migration checksum manifest', () => {
  it('accepts an exact manifest and returns the verified checksum set', () => {
    const actual = verifyMigrationChecksums(['001_initial.sql'], { '001_initial.sql': sql }, valid);
    expect(actual).toEqual(valid);
  });

  it('rejects edits to a migration already represented in the manifest', () => {
    expect(() => verifyMigrationChecksums(['001_initial.sql'], { '001_initial.sql': `${sql}-- edited\n` }, valid))
      .toThrow('Migration checksum mismatch: 001_initial.sql');
  });

  it('rejects a missing or untracked SQL migration', () => {
    expect(() => verifyMigrationChecksums(['001_initial.sql', '002_new.sql'], { '001_initial.sql': sql }, valid))
      .toThrow('Migration checksum manifest does not match the SQL migration files');
  });

  it('rejects malformed manifest values', () => {
    expect(() => verifyMigrationChecksums(['001_initial.sql'], { '001_initial.sql': sql }, { '001_initial.sql': 'bad' }))
      .toThrow('Migration checksum manifest entry is invalid: 001_initial.sql');
  });
});
