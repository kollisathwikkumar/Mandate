import { startMcpServerFromEnvironment } from './server.js';

void startMcpServerFromEnvironment().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'MCP server startup failed';
  console.error(message);
  process.exitCode = 1;
});
