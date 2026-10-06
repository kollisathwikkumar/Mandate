import { Client } from 'pg';
import { migrate } from './migrate.js';

const connectionString = process.env.DATABASE_URL;
if (connectionString === undefined || connectionString.length === 0) {
  process.stderr.write('DATABASE_URL is required\n');
  process.exitCode = 1;
} else {
  const client = new Client({ connectionString, application_name: 'mandate-migrator' });
  try {
    await client.connect();
    const applied = await migrate(client);
    process.stdout.write(applied.length === 0 ? 'Database schema is up to date\n' : `Applied migrations: ${applied.join(', ')}\n`);
  } catch (error: unknown) {
    process.stderr.write(`Database migration failed: ${error instanceof Error ? error.message : 'unknown database error'}\n`);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}
