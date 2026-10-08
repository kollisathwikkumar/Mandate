import { access, chmod, cp, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RUNTIME_FILES = [
  'apps/cli/src/main.js',
  'apps/cli/src/commands.js',
  'packages/sdk/src/client.js',
  'packages/api-contracts/src/schemas.js',
  'packages/policy/src/schema.js',
  'packages/ports/src/webhook.js',
  'packages/domain/src/uint256.js',
] as const;

export interface StageCliPackageInput {
  readonly distRoot: string;
  readonly outputDirectory: string;
  readonly packageVersion: string;
  readonly zodVersion: string;
}

export async function stageCliPackage(input: StageCliPackageInput): Promise<void> {
  const requiredFiles = [
    ...RUNTIME_FILES,
  ];
  for (const relativePath of requiredFiles) {
    const source = join(input.distRoot, relativePath);
    if (!(await stat(source).then((value) => value.isFile()).catch(() => false))) {
      throw new Error(`CLI build output is incomplete: ${relativePath}`);
    }
  }
  await mkdir(input.outputDirectory, { recursive: false });
  try {
    await mkdir(join(input.outputDirectory, 'runtime'), { recursive: true });
    for (const relativePath of RUNTIME_FILES) {
      const destination = join(input.outputDirectory, 'runtime', relativePath);
      await mkdir(dirname(destination), { recursive: true });
      await cp(join(input.distRoot, relativePath), destination);
    }
    await mkdir(join(input.outputDirectory, 'bin'), { recursive: true });
    const binPath = join(input.outputDirectory, 'bin', 'mandate.js');
    await writeFile(binPath, "#!/usr/bin/env node\nimport '../runtime/apps/cli/src/main.js';\n", { encoding: 'utf8', mode: 0o755 });
    await chmod(binPath, 0o755);
    await writeFile(join(input.outputDirectory, 'package.json'), `${JSON.stringify({
      name: 'mandate-cli',
      version: input.packageVersion,
      description: 'Command-line client for the Mandate authorization control plane',
      type: 'module',
      engines: { node: '>=22' },
      bin: { mandate: 'bin/mandate.js' },
      files: ['bin', 'runtime', 'README.md'],
      dependencies: { zod: input.zodVersion },
    }, null, 2)}\n`, 'utf8');
    await writeFile(join(input.outputDirectory, 'README.md'), [
      '# Mandate CLI',
      '',
      'Node.js 22 or newer is required. Install this package and run `mandate --help`.',
      '',
      'Configure `MANDATE_API_URL` and `MANDATE_API_TOKEN`. Set `MANDATE_ORGANIZATION_ID` when the identity has multiple organizations.',
      'Provider keys, invitation tokens, signatures, and raw transactions must be read from protected files or stdin, not command-line literals.',
      '',
    ].join('\n'), 'utf8');
  } catch (error: unknown) {
    await rm(input.outputDirectory, { recursive: true, force: true });
    throw error;
  }
}

async function main(): Promise<void> {
  const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const rootPackage = JSON.parse(await readFile(join(backendRoot, 'package.json'), 'utf8')) as {
    readonly version: string;
    readonly dependencies: Readonly<Record<string, string>>;
  };
  const zodVersion = rootPackage.dependencies.zod;
  if (zodVersion === undefined) throw new Error('Root package does not declare zod');
  const distRoot = join(backendRoot, 'dist');
  const packDestination = join(distRoot, 'release');
  await mkdir(packDestination, { recursive: true });
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'mandate-cli-package-'));
  const packageDirectory = join(temporaryRoot, 'package');
  try {
    await stageCliPackage({ distRoot, outputDirectory: packageDirectory, packageVersion: rootPackage.version, zodVersion });
    const packed = spawnSync('npm', ['pack', packageDirectory, '--json', '--pack-destination', packDestination], {
      cwd: backendRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (packed.error !== undefined) throw packed.error;
    if (packed.status !== 0) throw new Error(`npm pack failed: ${packed.stderr.trim()}`);
    const result = JSON.parse(packed.stdout) as readonly { readonly filename: string }[];
    const filename = result[0]?.filename;
    if (filename === undefined) throw new Error('npm pack did not report an archive filename');
    const archivePath = join(packDestination, filename);
    await access(archivePath);
    process.stdout.write(`${archivePath}\n`);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'CLI packaging failed'}\n`);
    process.exitCode = 1;
  });
}
