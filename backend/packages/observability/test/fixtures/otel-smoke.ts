import { startObservability, shutdownObservability } from '../../src/sdk.js';

startObservability();
const { default: Fastify } = await import('fastify');
const app = Fastify({ logger: false });
app.get('/probe', async () => ({ status: 'ok' }));
await app.listen({ host: '127.0.0.1', port: 0 });
const address = app.server.address();
if (address === null || typeof address === 'string') throw new Error('Smoke server did not bind a TCP port');
try {
  const response = await fetch(`http://127.0.0.1:${address.port}/probe?api_key=TRACE_SECRET_CANARY`);
  if (!response.ok) throw new Error(`Smoke request returned HTTP ${response.status}`);
  await response.arrayBuffer();
} finally {
  await app.close();
  await shutdownObservability();
}
process.stdout.write('OTEL_SMOKE_OK\n');
