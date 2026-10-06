import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['packages/policy/src/**/*.ts', 'packages/domain/src/**/*.ts'],
      reporter: ['text', 'json-summary'],
      thresholds: { lines: 100, functions: 100, branches: 100, statements: 100 },
    },
  },
});
