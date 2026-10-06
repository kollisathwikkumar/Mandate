import { readFile } from 'node:fs/promises';
import { verifyAuditAnchor } from '../../../packages/application/src/audit-anchor-verifier.js';

function parseArguments(args: readonly string[]): { path: string; fingerprint: string; checkpointHash: string; previousHash?: string | null } {
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (name === undefined || value === undefined || !name.startsWith('--') || options.has(name)) {
      throw new Error('Usage: npm run audit-anchor:verify -- --file <path> --trusted-fingerprint <sha256> --checkpoint-hash <sha256> [--previous-checkpoint-hash <sha256|none>]');
    }
    options.set(name, value);
  }
  const path = options.get('--file');
  const fingerprint = options.get('--trusted-fingerprint');
  if (path === undefined || fingerprint === undefined || options.get('--checkpoint-hash') === undefined || [...options.keys()].some((key) => ![
    '--file', '--trusted-fingerprint', '--checkpoint-hash', '--previous-checkpoint-hash',
  ].includes(key))) {
    throw new Error('Usage: npm run audit-anchor:verify -- --file <path> --trusted-fingerprint <sha256> --checkpoint-hash <sha256> [--previous-checkpoint-hash <sha256|none>]');
  }
  const checkpointHash = options.get('--checkpoint-hash');
  const previous = options.get('--previous-checkpoint-hash');
  return {
    path,
    fingerprint,
    checkpointHash: checkpointHash ?? '',
    ...(previous === undefined ? {} : { previousHash: previous === 'none' ? null : previous }),
  };
}

try {
  const options = parseArguments(process.argv.slice(2));
  const serialized = await readFile(options.path, 'utf8');
  const result = verifyAuditAnchor(serialized, options.fingerprint, options.checkpointHash, options.previousHash);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.valid) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : 'Audit anchor verification failed'}\n`);
  process.exitCode = 1;
}
