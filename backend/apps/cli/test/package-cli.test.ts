import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { stageCliPackage } from '../../../scripts/package-cli.js';

const temporaryDirectories: string[] = [];

async function fixtureDist(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'mandate-cli-package-'));
  temporaryDirectories.push(root);
  const required = [
    'apps/cli/src/main.js', 'apps/cli/src/commands.js',
    'packages/sdk/src/client.js', 'packages/api-contracts/src/schemas.js',
    'packages/policy/src/schema.js', 'packages/ports/src/webhook.js', 'packages/domain/src/uint256.js',
  ];
  for (const path of required) {
    const destination = join(root, path);
    await mkdir(join(destination, '..'), { recursive: true });
    await writeFile(destination, `// fixture ${path}\n`, 'utf8');
  }
  return root;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('stageCliPackage', () => {
  it('creates an installable ESM bin package with only the CLI runtime closure', async () => {
    const distRoot = await fixtureDist();
    const outputRoot = await mkdtemp(join(tmpdir(), 'mandate-cli-release-'));
    temporaryDirectories.push(outputRoot);
    const outputDirectory = join(outputRoot, 'package');
    await stageCliPackage({ distRoot, outputDirectory, packageVersion: '0.1.0', zodVersion: '^4.6.5' });
    const metadata = JSON.parse(await readFile(join(outputDirectory, 'package.json'), 'utf8')) as {
      readonly name: string; readonly version: string; readonly type: string; readonly bin: Readonly<Record<string, string>>;
      readonly dependencies: Readonly<Record<string, string>>; readonly files: readonly string[];
    };
    expect(metadata).toMatchObject({ name: 'mandate-cli', version: '0.1.0', type: 'module', bin: { mandate: 'bin/mandate.js' }, dependencies: { zod: '^4.6.5' } });
    expect(metadata.files).toEqual(['bin', 'runtime', 'README.md']);
    expect(await readFile(join(outputDirectory, 'bin/mandate.js'), 'utf8')).toContain("import '../runtime/apps/cli/src/main.js';");
    expect(await readFile(join(outputDirectory, 'runtime/packages/sdk/src/client.js'), 'utf8')).toContain('fixture packages/sdk/src/client.js');
    expect(await readFile(join(outputDirectory, 'README.md'), 'utf8')).toContain('MANDATE_API_URL');
    await expect(readFile(join(outputDirectory, 'runtime/apps/cli/src/audit-anchor-verify.js'), 'utf8')).rejects.toThrow();
    await expect(readFile(join(outputDirectory, 'runtime/packages/ports/src/index.js'), 'utf8')).rejects.toThrow();
  });

  it('rejects an incomplete build before leaving a partial package', async () => {
    const distRoot = await mkdtemp(join(tmpdir(), 'mandate-cli-incomplete-'));
    temporaryDirectories.push(distRoot);
    const outputRoot = await mkdtemp(join(tmpdir(), 'mandate-cli-incomplete-out-'));
    temporaryDirectories.push(outputRoot);
    const outputDirectory = join(outputRoot, 'package');
    await expect(stageCliPackage({ distRoot, outputDirectory, packageVersion: '0.1.0', zodVersion: '^4.6.5' })).rejects.toThrow();
    await expect(readFile(join(outputDirectory, 'package.json'), 'utf8')).rejects.toThrow();
  });
});
