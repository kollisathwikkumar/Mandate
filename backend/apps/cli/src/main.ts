import { readFile } from 'node:fs/promises';
import { JsonValueSchema, MandateClient } from '../../../packages/sdk/src/client.js';
import { CLI_USAGE, executeCliCommand, parseActionInput, parseCliCommand, type CliCommand } from './commands.js';

async function readStdin(): Promise<string> {
  let output = '';
  for await (const chunk of process.stdin) output += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
  return output;
}

async function readAction(reference: string) {
  const text = await readInput(reference);
  const parsed = JsonValueSchema.parse(JSON.parse(text));
  return parseActionInput(parsed);
}

async function readInput(reference: string): Promise<string> {
  return reference === '-' ? readStdin()
    : reference.startsWith('@') ? readFile(reference.slice(1), 'utf8')
      : reference;
}

async function readSecret(reference: string): Promise<string> {
  const value = await readInput(reference);
  return value.trim();
}

async function main(args: readonly string[], environment: NodeJS.ProcessEnv): Promise<void> {
  const command: CliCommand = parseCliCommand(args);
  if (command.kind === 'help') {
    process.stdout.write(`${CLI_USAGE}\n`);
    return;
  }
  const apiUrl = environment.MANDATE_API_URL;
  const token = environment.MANDATE_API_TOKEN;
  if (apiUrl === undefined || token === undefined) throw new Error('MANDATE_API_URL and MANDATE_API_TOKEN are required');
  const organizationId = environment.MANDATE_ORGANIZATION_ID;
  const client = await MandateClient.connect({ apiUrl, token, ...(organizationId === undefined ? {} : { organizationId }) });
  const result = await executeCliCommand(command, client, readAction, readSecret);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

try {
  await main(process.argv.slice(2), process.env);
} catch (error) {
  const message = error instanceof Error ? error.message : 'Mandate CLI failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
