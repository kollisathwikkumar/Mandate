import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { describe, expect, it } from 'vitest';

function readBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

describe('OpenTelemetry exporter integration', () => {
  it('exports actual Fastify request traces and runtime metrics without query secrets', async () => {
    const requests: Array<{ path: string; body: Buffer }> = [];
    const collector = createServer(async (request: IncomingMessage, response: ServerResponse) => {
      requests.push({ path: request.url ?? '', body: await readBody(request) });
      response.writeHead(200, { 'content-type': 'application/x-protobuf' });
      response.end();
    });
    collector.listen(0, '127.0.0.1');
    await once(collector, 'listening');
    const address = collector.address();
    if (address === null || typeof address === 'string') throw new Error('Collector did not bind a TCP port');
    const endpoint = `http://127.0.0.1:${address.port}`;
    const child = spawn(process.execPath, [
      '--experimental-loader=@opentelemetry/instrumentation/hook.mjs',
      '--import', 'tsx',
      'packages/observability/test/fixtures/otel-smoke.ts',
    ], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        MANDATE_OTEL_ENABLED: 'true',
        OTEL_SERVICE_NAME: 'mandate-otel-smoke',
        OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
        MANDATE_OTEL_SAMPLE_RATIO: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    try {
      const [code] = await once(child, 'exit') as [number | null, NodeJS.Signals | null];
      const out = Buffer.concat(stdout).toString('utf8');
      const err = Buffer.concat(stderr).toString('utf8');
      expect({ code, out, err }).toMatchObject({ code: 0 });
      expect(out).toContain('OTEL_SMOKE_OK');
      expect(requests.map((item) => item.path)).toEqual(expect.arrayContaining(['/v1/traces', '/v1/metrics']));
      const traceBodies = requests.filter((item) => item.path === '/v1/traces').map((item) => item.body);
      expect(traceBodies.length).toBeGreaterThan(0);
      const allBodies = Buffer.concat(requests.map((item) => item.body));
      const exportText = allBodies.toString('utf8');
      expect(exportText).toContain('mandate-otel-smoke');
      expect(exportText).toContain('url.query');
      expect(exportText).toContain('[REDACTED]');
      expect(exportText).not.toContain('TRACE_SECRET_CANARY');
      expect(exportText).not.toContain('process.owner');
      expect(exportText).not.toContain('host.name');
    } finally {
      if (child.exitCode === null) child.kill('SIGKILL');
      collector.close();
      await once(collector, 'close');
    }
  }, 25_000);
});
