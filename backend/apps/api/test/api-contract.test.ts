import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createApiServer } from '../src/app.js';
import { openApiDocument } from '../src/openapi.js';

function registeredOperations(app: FastifyInstance): ReadonlySet<string> {
  const hierarchy: string[] = [];
  const operations = new Set<string>();
  for (const line of app.printRoutes({ commonPrefix: false }).split('\n')) {
    const match = /^([│ ]*)(?:├──|└──) (.+?) \(([^)]+)\)$/.exec(line);
    if (match === null) continue;
    const indentation = match[1];
    const segment = match[2];
    const methodList = match[3];
    if (indentation === undefined || segment === undefined || methodList === undefined) continue;
    const depth = Math.floor(indentation.length / 4);
    const parent = depth === 0 ? '' : hierarchy[depth - 1] ?? '';
    const path = depth === 0 ? segment : `${parent}${segment}`;
    hierarchy.length = depth;
    hierarchy[depth] = path;
    for (const method of methodList.split(',').map((entry) => entry.trim())) {
      if (method === 'HEAD') continue;
      operations.add(`${method} ${path.replace(/:([A-Za-z0-9_]+)/g, '{$1}')}`);
    }
  }
  return operations;
}

function documentedOperations(): ReadonlySet<string> {
  const operations = new Set<string>();
  const paths = openApiDocument.paths as Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  for (const [path, methods] of Object.entries(paths)) {
    for (const method of Object.keys(methods)) {
      if (['get', 'post', 'put', 'patch', 'delete'].includes(method)) operations.add(`${method.toUpperCase()} ${path}`);
    }
  }
  return operations;
}

describe('REST/OpenAPI contract parity', () => {
  const pool = new Pool({ connectionString: 'postgresql://mandate:mandate@127.0.0.1:1/mandate', connectionTimeoutMillis: 100 });
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await createApiServer({
      pool,
      jwksUrl: 'http://127.0.0.1:1/.well-known/jwks.json',
      issuer: 'https://identity.example.test/',
      audience: 'mandate-api-test',
      logger: false,
    });
    await app.ready();
  });

  afterAll(async () => {
    await app?.close();
    await pool.end();
  });

  it('documents every registered API operation and has no stale OpenAPI operation', () => {
    expect([...registeredOperations(app)].sort()).toEqual([...documentedOperations()].sort());
  });

  it('assigns a unique operationId to every documented operation', () => {
    const paths = openApiDocument.paths as Readonly<Record<string, Readonly<Record<string, unknown>>>>;
    const operationIds: string[] = [];
    for (const methods of Object.values(paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue;
        if (typeof operation !== 'object' || operation === null || !('operationId' in operation)
          || typeof operation.operationId !== 'string') {
          throw new Error(`OpenAPI ${method.toUpperCase()} operation has no operationId`);
        }
        operationIds.push(operation.operationId);
      }
    }
    expect(new Set(operationIds).size).toBe(operationIds.length);
  });

  it('documents the action-scoped receipt query used by MCP', () => {
    const route = openApiDocument.paths['/api/v1/orgs/{orgId}/receipts'].get;
    expect(route.parameters).toContainEqual(expect.objectContaining({ name: 'actionId', in: 'query', required: false }));
  });
});
