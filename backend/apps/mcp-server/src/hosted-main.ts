import { startHostedMcpFromEnvironment } from './hosted.js';

void startHostedMcpFromEnvironment().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Hosted MCP server startup failed';
  console.error(message);
  process.exitCode = 1;
});
