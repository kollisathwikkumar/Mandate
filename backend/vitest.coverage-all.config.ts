import { defineConfig } from 'vitest/config';

if (process.env.DATABASE_URL === undefined || process.env.DATABASE_URL.trim() === '') {
  throw new Error('Full-source coverage requires DATABASE_URL so PostgreSQL integration tests run instead of skipping');
}

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['apps/*/src/**/*.ts', 'packages/*/src/**/*.ts'],
      exclude: ['**/*.d.ts'],
      reporter: ['text', 'json-summary'],
      thresholds: { statements: 75, branches: 70, functions: 80, lines: 82 },
    },
  },
});
