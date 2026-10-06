import { readFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { spawn, type ChildProcess } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { resolve } from 'node:path';
import { AbiCoder, Contract, ContractFactory, JsonRpcProvider, Wallet, ZeroAddress, parseEther, toUtf8Bytes, keccak256, type ContractTransactionResponse, type InterfaceAbi, type Signer } from 'ethers';
import solc from 'solc';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EvmAccountEnrollmentVerifier } from '../../adapters/src/chain/evm-account-enrollment-verifier.js';
import { EvmSafePolicyActivationReader } from '../../adapters/src/chain/evm-safe-policy-activation-reader.js';
import { EvmActionExecutionStateReader } from '../../adapters/src/chain/evm-action-execution-state-reader.js';
import { EvmActionTransactionSubmitter } from '../../adapters/src/chain/evm-action-transaction-submitter.js';
import { EvmExecutionReceiptReader } from '../../adapters/src/chain/evm-execution-receipt-reader.js';
import { EvmSafePolicyActivationFinalizer } from '../../adapters/src/chain/evm-safe-policy-activation-finalizer.js';
import { EvmSafePolicyRevocationFinalizer } from '../../adapters/src/chain/evm-safe-policy-revocation-finalizer.js';
import { compileEvmSafePolicy } from '../src/evm-safe-policy-compiler.js';
import { buildSafePolicyActivationPlan } from '../src/safe-policy-activation-plan.js';
import { buildSafePolicyRevocationPlan } from '../src/safe-policy-revocation-plan.js';

interface ContractArtifact { readonly abi: InterfaceAbi; readonly bytecode: string; }
interface CompiledContract { readonly abi: InterfaceAbi; readonly evm: { readonly bytecode: { readonly object: string } }; }
interface SolcOutput { readonly errors?: readonly { readonly severity: string; readonly formattedMessage: string }[]; readonly contracts?: Readonly<Record<string, Readonly<Record<string, CompiledContract>>>>; }
interface SafeTx {
  readonly to: string; readonly value: bigint; readonly data: string; readonly operation: number;
  readonly safeTxGas: bigint; readonly baseGas: bigint; readonly gasPrice: bigint;
  readonly gasToken: string; readonly refundReceiver: string; readonly nonce: bigint;
}

const safeTxTypes = { SafeTx: [
  { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' },
  { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
  { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' },
  { name: 'refundReceiver', type: 'address' }, { name: 'nonce', type: 'uint256' },
] };
const actionTypes = { MandateAction: [
  { name: 'safe', type: 'address' }, { name: 'chainId', type: 'uint256' }, { name: 'module', type: 'address' },
  { name: 'policyEpoch', type: 'uint64' }, { name: 'agent', type: 'address' }, { name: 'keyVersion', type: 'uint64' },
  { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'dataHash', type: 'bytes32' },
  { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' },
] };

function parseArtifact(value: unknown): ContractArtifact {
  if (typeof value !== 'object' || value === null || !('abi' in value) || !Array.isArray(value.abi)
    || !('bytecode' in value) || typeof value.bytecode !== 'string' || !value.bytecode.startsWith('0x')) {
    throw new Error('Invalid Safe release artifact');
  }
  return { abi: value.abi as InterfaceAbi, bytecode: value.bytecode };
}

function getCompiled(output: SolcOutput, source: string, name: string): CompiledContract {
  const compiled = output.contracts?.[source]?.[name];
  if (compiled === undefined || compiled.evm.bytecode.object.length === 0) throw new Error(`Solidity compiler did not emit ${name}`);
  return compiled;
}

async function readJson(path: string): Promise<unknown> { return JSON.parse(await readFile(path, 'utf8')) as unknown; }

describe('Safe execution-boundary enforcement contracts (Anvil + Safe v1.5.0)', () => {
  let anvil: ChildProcess | undefined;
  let provider: JsonRpcProvider;
  let owner: Signer;
  let agent: Signer;
  let recipient: string;
  let safeAddress: string;
  let safeSingletonAddress: string;
  let guardAddress: string;
  let moduleAddress: string;
  let tokenAddress: string;
  let guard: Contract;
  let module: Contract;
  let token: Contract;
  let safe: Contract;
  let rogue: Contract;
  let chainId: bigint;
  let rpcUrl: string;

  async function executeSafeTransaction(to: string, value: bigint, data: string, operation = 0): Promise<number> {
    const nonce = await safe.getFunction('nonce')() as bigint;
    const tx: SafeTx = { to, value, data, operation, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ZeroAddress, refundReceiver: ZeroAddress, nonce };
    const signature = await owner.signTypedData({ chainId, verifyingContract: safeAddress }, safeTxTypes, tx);
    const transaction = await safe.getFunction('execTransaction')(
      to, value, data, operation, 0, 0, 0, ZeroAddress, ZeroAddress, signature,
    ) as ContractTransactionResponse;
    const receipt = await transaction.wait();
    if (receipt === null) throw new Error('Safe transaction did not produce a receipt');
    return receipt.blockNumber;
  }

  async function executeSafeTransactionWithHash(to: string, value: bigint, data: string, operation = 0): Promise<string> {
    const nonce = await safe.getFunction('nonce')() as bigint;
    const tx: SafeTx = { to, value, data, operation, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ZeroAddress, refundReceiver: ZeroAddress, nonce };
    const signature = await owner.signTypedData({ chainId, verifyingContract: safeAddress }, safeTxTypes, tx);
    const transaction = await safe.getFunction('execTransaction')(
      to, value, data, operation, 0, 0, 0, ZeroAddress, ZeroAddress, signature,
    ) as ContractTransactionResponse;
    const receipt = await transaction.wait();
    if (receipt === null) throw new Error('Safe transaction did not produce a receipt');
    return receipt.hash.toLowerCase();
  }

  async function agentSignature(to: string, value: bigint, data: string, nonce: bigint, deadline: bigint, signer: Signer = agent): Promise<string> {
    const agentAddress = await agent.getAddress();
    const epoch = await guard.getFunction('policyEpoch')() as bigint;
    return signer.signTypedData(
      { name: 'MandateAgentModule', version: '1', chainId, verifyingContract: moduleAddress },
      actionTypes,
      { safe: safeAddress, chainId, module: moduleAddress, policyEpoch: epoch, agent: agentAddress, keyVersion: 1,
        to, value, dataHash: keccak256(data), nonce, deadline },
    );
  }

  async function executeAgent(to: string, value: bigint, data: string, deadline: bigint, keyVersion: number, nonce: bigint, signature: string): Promise<number> {
    const transaction = await module.connect(agent).getFunction('execute')(to, value, data, deadline, keyVersion, nonce, signature, { gasLimit: 1_000_000n }) as ContractTransactionResponse;
    const receipt = await transaction.wait();
    if (receipt === null) throw new Error('Agent module transaction did not produce a receipt');
    return receipt.blockNumber;
  }

  beforeAll(async () => {
    const portServer = createServer();
    await new Promise<void>((resolveListen, reject) => {
      portServer.once('error', reject);
      portServer.listen(0, '127.0.0.1', resolveListen);
    });
    const portInfo = portServer.address();
    if (portInfo === null || typeof portInfo === 'string') throw new Error('Could not allocate Anvil port');
    const port = portInfo.port;
    rpcUrl = `http://127.0.0.1:${port}`;
    await new Promise<void>((resolveClose, reject) => portServer.close((error) => error === undefined ? resolveClose() : reject(error)));
    anvil = spawn(resolve('node_modules/.bin/anvil'), ['--host', '127.0.0.1', '--port', String(port), '--silent'], { stdio: 'ignore' });
    provider = new JsonRpcProvider(rpcUrl, 31337, { staticNetwork: true });
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (anvil.exitCode !== null) throw new Error(`Anvil exited with status ${anvil.exitCode}`);
      try { await provider.getBlockNumber(); ready = true; break; } catch { await delay(100); }
    }
    if (!ready) throw new Error('Anvil did not become ready');

    owner = await provider.getSigner(0);
    agent = await provider.getSigner(1);
    recipient = await (await provider.getSigner(2)).getAddress();
    chainId = (await provider.getNetwork()).chainId;

    const safeRoot = resolve('node_modules/@safe-global/safe-smart-account/build/artifacts/contracts');
    const safeArtifact = parseArtifact(await readJson(resolve(safeRoot, 'Safe.sol/Safe.json')));
    const proxyArtifact = parseArtifact(await readJson(resolve(safeRoot, 'proxies/SafeProxy.sol/SafeProxy.json')));
    const guardSource = await readFile(new URL('../../../contracts/src/MandateSafeGuard.sol', import.meta.url), 'utf8');
    const moduleSource = await readFile(new URL('../../../contracts/src/MandateAgentModule.sol', import.meta.url), 'utf8');
    const testSource = await readFile(new URL('../../../contracts/test/MockERC20.sol', import.meta.url), 'utf8');
    const compilerInput = {
      language: 'Solidity',
      sources: { 'MandateSafeGuard.sol': { content: guardSource }, 'MandateAgentModule.sol': { content: moduleSource }, 'MockERC20.sol': { content: testSource } },
      settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
    };
    const compiled = JSON.parse(solc.compile(JSON.stringify(compilerInput))) as SolcOutput;
    const compileErrors = (compiled.errors ?? []).filter(({ severity }) => severity === 'error');
    expect(compileErrors.map(({ formattedMessage }) => formattedMessage)).toEqual([]);

    const safeSingleton = await new ContractFactory(safeArtifact.abi, safeArtifact.bytecode, owner).deploy();
    await safeSingleton.waitForDeployment();
    safeSingletonAddress = await safeSingleton.getAddress();
    const proxy = await new ContractFactory(proxyArtifact.abi, proxyArtifact.bytecode, owner).deploy(safeSingletonAddress);
    await proxy.waitForDeployment();
    safeAddress = await proxy.getAddress();
    safe = new Contract(safeAddress, safeArtifact.abi, owner);
    const setupData = safe.interface.encodeFunctionData('setup', [[await owner.getAddress()], 1, ZeroAddress, '0x', ZeroAddress, ZeroAddress, 0, ZeroAddress]);
    await (await owner.sendTransaction({ to: safeAddress, data: setupData })).wait();

    const guardArtifact = getCompiled(compiled, 'MandateSafeGuard.sol', 'MandateSafeGuard');
    const moduleArtifact = getCompiled(compiled, 'MandateAgentModule.sol', 'MandateAgentModule');
    const tokenArtifact = getCompiled(compiled, 'MockERC20.sol', 'MockERC20');
    const guardFactory = new ContractFactory(guardArtifact.abi, `0x${guardArtifact.evm.bytecode.object}`, owner);
    const deployedGuard = await guardFactory.deploy(safeAddress);
    await deployedGuard.waitForDeployment();
    guardAddress = await deployedGuard.getAddress();
    guard = new Contract(guardAddress, guardArtifact.abi, owner);
    const moduleFactory = new ContractFactory(moduleArtifact.abi, `0x${moduleArtifact.evm.bytecode.object}`, owner);
    const deployedModule = await moduleFactory.deploy(safeAddress, guardAddress);
    await deployedModule.waitForDeployment();
    moduleAddress = await deployedModule.getAddress();
    module = new Contract(moduleAddress, moduleArtifact.abi, owner);
    const tokenFactory = new ContractFactory(tokenArtifact.abi, `0x${tokenArtifact.evm.bytecode.object}`, owner);
    const deployedToken = await tokenFactory.deploy();
    await deployedToken.waitForDeployment();
    tokenAddress = await deployedToken.getAddress();
    token = new Contract(tokenAddress, tokenArtifact.abi, owner);
    const rogueArtifact = getCompiled(compiled, 'MockERC20.sol', 'UntrustedSafeModule');
    const deployedRogue = await new ContractFactory(rogueArtifact.abi, `0x${rogueArtifact.evm.bytecode.object}`, owner).deploy();
    await deployedRogue.waitForDeployment();
    rogue = new Contract(await deployedRogue.getAddress(), rogueArtifact.abi, owner);

    const latest = await provider.getBlock('latest');
    if (latest === null) throw new Error('Anvil block unavailable');
    const configData = guard.interface.encodeFunctionData('configurePolicy', [{
      revisionHash: keccak256(toUtf8Bytes('mandate-policy-revision-1')), nextEpoch: 1,
      policyValidUntil: latest.timestamp + 86400, windowDuration: 86400, actionCountLimit: 5,
      assets: [ZeroAddress, tokenAddress], perActionLimits: [parseEther('0.5'), 500000],
      perWindowLimits: [parseEther('1'), 1000000], approvalThresholds: [parseEther('0.3'), 450000],
      approvalRequired: [true, true], recipients: [recipient],
    }]);
    await executeSafeTransaction(guardAddress, 0n, configData);
    await executeSafeTransaction(guardAddress, 0n, guard.interface.encodeFunctionData('setAgentModule', [moduleAddress]));
    await executeSafeTransaction(moduleAddress, 0n, module.interface.encodeFunctionData('setAgent', [await agent.getAddress(), 1, true]));
    await executeSafeTransaction(safeAddress, 0n, safe.interface.encodeFunctionData('enableModule', [moduleAddress]));
    await executeSafeTransaction(safeAddress, 0n, safe.interface.encodeFunctionData('enableModule', [await rogue.getAddress()]));
    await (await owner.sendTransaction({ to: safeAddress, value: parseEther('2') })).wait();
    await (await token.getFunction('mint')(safeAddress, 2_000_000n)).wait();
    await executeSafeTransaction(safeAddress, 0n, safe.interface.encodeFunctionData('setGuard', [guardAddress]));
    await executeSafeTransaction(safeAddress, 0n, safe.interface.encodeFunctionData('setModuleGuard', [guardAddress]));
  }, 60000);

  afterAll(async () => {
    if (provider !== undefined) await provider.destroy();
    if (anvil !== undefined && anvil.exitCode === null) {
      anvil.kill('SIGTERM');
      await once(anvil, 'exit');
    }
  });

  it('encodes the canonical typed policy into the deployed guard ABI without weakening target, selector, asset or approval fields', async () => {
    const latest = await provider.getBlock('latest');
    if (latest === null) throw new Error('Anvil block unavailable');
    const revision = {
      schemaVersion: 1 as const, policyId: 'onchain-policy', revision: 1, organizationId: 'local-org',
      owner: await owner.getAddress(), account: safeAddress, agentId: 'local-agent', agentAddress: await agent.getAddress(), agentKeyVersion: 1,
      chainId: Number(chainId), adapter: 'evm-smart-account' as const, target: tokenAddress,
      selectors: ['0xa9059cbb'], asset: tokenAddress, recipients: [recipient],
      limits: { perAction: '100000', cumulative: '500000', windowSeconds: 3600, approvalThreshold: '80000', maxActions: 5 },
      validAfter: latest.timestamp, expiresAt: latest.timestamp + 3600, nonceEpoch: 0,
    };
    const compiledPolicy = compileEvmSafePolicy(revision, latest.timestamp);
    const decoded = guard.interface.parseTransaction({ data: compiledPolicy.configurePolicyCalldata });
    expect(decoded?.name).toBe('configurePolicy');
    expect(decoded?.args[0].revisionHash).toBe(compiledPolicy.revisionHash);
    expect(decoded?.args[0].assets).toEqual([tokenAddress]);
    expect(decoded?.args[0].perActionLimits).toEqual([100000n]);
    expect(decoded?.args[0].approvalThresholds).toEqual([80000n]);
    expect(decoded?.args[0].approvalRequired).toEqual([true]);
  });

  it('installs the exact transaction and module guard interfaces on Safe and executes an allowed owner transfer', async () => {
    expect(await guard.getFunction('supportsInterface')('0xe6d7a83a')).toBe(true);
    expect(await guard.getFunction('supportsInterface')('0x58401ed8')).toBe(true);
    expect(await guard.getFunction('isFullyInstalled')()).toBe(true);
    const before = await provider.getBalance(recipient);
    const blockNumber = await executeSafeTransaction(recipient, parseEther('0.1'), '0x');
    const after = await provider.getBalance(recipient, blockNumber);
    expect(after - before).toBe(parseEther('0.1'));
  });

  it('verifies the registered Safe, its paired guards, configured agent module, and enabled module against local RPC', async () => {
    const verifier = new EvmAccountEnrollmentVerifier({ 31337: rpcUrl }, { 31337: safeSingletonAddress });
    await expect(verifier.verify({ chainId: 31337, address: safeAddress })).resolves.toMatchObject({
      safeAddress: safeAddress.toLowerCase(), guardAddress: guardAddress.toLowerCase(), moduleAddress: moduleAddress.toLowerCase(),
    });
    await expect(verifier.verify({ chainId: 31337, address: recipient })).rejects.toMatchObject({ code: 'ACCOUNT_NOT_ENROLLED' });
    await expect(new EvmAccountEnrollmentVerifier({}, {}).verify({ chainId: 31337, address: safeAddress })).rejects.toMatchObject({ code: 'UNSUPPORTED_CHAIN' });
    await expect(new EvmAccountEnrollmentVerifier({ 1: rpcUrl }, { 1: safeSingletonAddress }).verify({ chainId: 1, address: safeAddress })).rejects.toMatchObject({ code: 'CHAIN_ID_MISMATCH' });
  });

  it('reads a verified Safe nonce, paired guards, epoch and agent key state for owner-signature planning', async () => {
    const reader = new EvmSafePolicyActivationReader({ 31337: rpcUrl });
    const state = await reader.readState({
      chainId: 31337, safeAddress, guardAddress, moduleAddress, agentAddress: await agent.getAddress(),
    });
    expect(state).toMatchObject({
      chainId: 31337, safeAddress: safeAddress.toLowerCase(), guardAddress: guardAddress.toLowerCase(),
      moduleAddress: moduleAddress.toLowerCase(), policyEpoch: 1n, safeThreshold: 1n,
      safeOwners: [(await owner.getAddress()).toLowerCase()],
    });
    expect(state.safeNonce).toBeGreaterThan(0n);
    await expect(reader.readState({
      chainId: 31337, safeAddress, guardAddress: recipient, moduleAddress, agentAddress: await agent.getAddress(),
    })).rejects.toMatchObject({ code: 'CHAIN_STATE_MISMATCH' });
  });

  it('reads one pinned and verified Safe execution snapshot including the module nonce', async () => {
    const reader = new EvmActionExecutionStateReader({ 31337: rpcUrl });
    const state = await reader.readState({
      chainId: 31337, safeAddress, guardAddress, moduleAddress, agentAddress: await agent.getAddress(),
    });
    expect(state).toMatchObject({
      safeAddress: safeAddress.toLowerCase(), guardAddress: guardAddress.toLowerCase(), moduleAddress: moduleAddress.toLowerCase(),
      chainId: 31337, policyEpoch: 1n, policyEnabled: true, agentKeyVersion: 1n, agentActive: true, moduleNonce: 0n,
    });
    expect(state.blockNumber).toBeGreaterThan(0);
    expect(state.blockHash).toMatch(/^0x[0-9a-f]{64}$/);
    await expect(reader.readState({
      chainId: 31337, safeAddress, guardAddress: recipient, moduleAddress, agentAddress: await agent.getAddress(),
    })).rejects.toMatchObject({ code: 'CHAIN_STATE_MISMATCH' });
  });

  it('rejects policy configurations that name a non-contract as an ERC-20 asset', async () => {
    const invalidConfiguration = guard.interface.encodeFunctionData('configurePolicy', [{
      revisionHash: keccak256(toUtf8Bytes('invalid-no-code-token')), nextEpoch: 2,
      policyValidUntil: BigInt((await provider.getBlock('latest'))?.timestamp ?? 0) + 86400n,
      windowDuration: 86400, actionCountLimit: 5, assets: [await agent.getAddress()],
      perActionLimits: [1n], perWindowLimits: [2n], approvalThresholds: [0n],
      approvalRequired: [false], recipients: [recipient],
    }]);
    await expect(executeSafeTransaction(guardAddress, 0n, invalidConfiguration)).rejects.toThrow();
    expect(await guard.getFunction('policyEpoch')()).toBe(1n);
  });

  it('enforces ERC-20 target/selector, recipient and per-action policy at the Safe transaction boundary', async () => {
    const agentAddress = await agent.getAddress();
    const initialNonce = await module.getFunction('nextNonce')(agentAddress) as bigint;
    const initialUsage = await guard.getFunction('assetWindowUsage')(tokenAddress) as readonly [bigint, bigint];
    const deadline = BigInt((await provider.getBlock('latest'))?.timestamp ?? 0) + 600n;
    const failingData = token.interface.encodeFunctionData('transfer', [recipient, 100000n]);
    const failingSignature = await agentSignature(tokenAddress, 0n, failingData, initialNonce, deadline);
    await (await token.getFunction('setTransfersEnabled')(false)).wait();
    await expect(executeAgent(tokenAddress, 0n, failingData, deadline, 1, initialNonce, failingSignature)).rejects.toThrow();
    const usageAfterFailedCall = await guard.getFunction('assetWindowUsage')(tokenAddress) as readonly [bigint, bigint];
    expect(await module.getFunction('nextNonce')(agentAddress)).toBe(initialNonce);
    expect(usageAfterFailedCall[1]).toBe(initialUsage[1]);
    await (await token.getFunction('setTransfersEnabled')(true)).wait();

    const transfer = token.interface.encodeFunctionData('transfer', [recipient, 400000n]);
    await executeSafeTransaction(tokenAddress, 0n, transfer);
    expect(await token.getFunction('balanceOf')(recipient)).toBe(400000n);
    const approval = token.interface.encodeFunctionData('approve', [recipient, 1n]);
    await expect(executeSafeTransaction(tokenAddress, 0n, approval)).rejects.toThrow();
    const tooLarge = token.interface.encodeFunctionData('transfer', [recipient, 500001n]);
    await expect(executeSafeTransaction(tokenAddress, 0n, tooLarge)).rejects.toThrow();
    const wrongRecipient = token.interface.encodeFunctionData('transfer', [await agent.getAddress(), 1n]);
    await expect(executeSafeTransaction(tokenAddress, 0n, wrongRecipient)).rejects.toThrow();
    expect(await token.getFunction('balanceOf')(recipient)).toBe(400000n);
  });

  it('executes agent-signed exact calls through the enabled module and rejects replay, over-limit, expired and wrong-key actions', async () => {
    const deadline = BigInt((await provider.getBlock('latest'))?.timestamp ?? 0) + 600n;
    const nonce = await module.getFunction('nextNonce')(await agent.getAddress()) as bigint;
    const actionData = '0x';
    const signature = await agentSignature(recipient, parseEther('0.2'), actionData, nonce, deadline);
    const args = [recipient, parseEther('0.2'), actionData, deadline, 1, nonce, signature] as const;
    const before = await provider.getBalance(recipient);
    const agentWallet = new Wallet(`0x${'59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'}`).connect(provider);
    expect(agentWallet.address.toLowerCase()).toBe((await agent.getAddress()).toLowerCase());
    const rawTransaction = await agentWallet.signTransaction({
      chainId: Number(chainId), nonce: await agentWallet.getNonce(), gasLimit: 1_000_000n,
      gasPrice: 1_000_000_000n, to: moduleAddress, value: 0n,
      data: module.interface.encodeFunctionData('execute', args),
    });
    const submitter = new EvmActionTransactionSubmitter({ 31337: rpcUrl });
    const submitted = await submitter.submitRawTransaction({ chainId: Number(chainId), rawTransaction });
    expect(submitted.transactionHash).toMatch(/^0x[0-9a-f]{64}$/);
    await expect(submitter.submitRawTransaction({ chainId: Number(chainId), rawTransaction }))
      .resolves.toEqual({ transactionHash: submitted.transactionHash });
    const receipt = await provider.getTransactionReceipt(submitted.transactionHash);
    if (receipt === null) throw new Error('Agent module transaction did not produce a receipt');
    expect(receipt.status).toBe(1);
    const receiptReader = new EvmExecutionReceiptReader({ [Number(chainId)]: rpcUrl });
    await expect(receiptReader.observe({ chainId: Number(chainId), transactionHash: submitted.transactionHash, requiredConfirmations: 1 }))
      .resolves.toMatchObject({ transactionHash: submitted.transactionHash.toLowerCase(), status: 'FINAL', executionResult: 'SUCCESS' });
    await expect(receiptReader.observe({ chainId: Number(chainId), transactionHash: submitted.transactionHash, requiredConfirmations: 10000 }))
      .resolves.toMatchObject({ status: 'TENTATIVE', executionResult: 'SUCCESS' });
    const checkpointBlock = await provider.getBlock(receipt.blockNumber);
    if (checkpointBlock === null || checkpointBlock.hash === null) throw new Error('Agent transaction block is unavailable');
    await expect(receiptReader.getSenderNonceAtCheckpoint({ chainId: Number(chainId), sender: agentWallet.address,
      blockNumber: receipt.blockNumber, blockHash: checkpointBlock.hash.toLowerCase() })).resolves.toEqual({
      senderNonce: await provider.getTransactionCount(agentWallet.address, receipt.blockNumber), timestampSeconds: checkpointBlock.timestamp,
    });
    await expect(receiptReader.getSenderNonceAtCheckpoint({ chainId: Number(chainId), sender: agentWallet.address,
      blockNumber: receipt.blockNumber, blockHash: `0x${'0'.repeat(64)}` })).rejects.toThrow('CHECKPOINT_NOT_CANONICAL');
    await expect(receiptReader.getCanonicalBlockAtFinality({ chainId: Number(chainId), blockNumber: receipt.blockNumber }))
      .resolves.toMatchObject({ blockHash: checkpointBlock.hash.toLowerCase(), confirmations: expect.any(Number) });
    expect(await provider.getBalance(recipient, receipt.blockNumber) - before).toBe(parseEther('0.2'));
    await expect(executeAgent(...args)).rejects.toThrow();

    const nextNonce = await module.getFunction('nextNonce')(await agent.getAddress()) as bigint;
    const excessive = parseEther('0.6');
    const excessiveSignature = await agentSignature(recipient, excessive, actionData, nextNonce, deadline);
    await expect(executeAgent(recipient, excessive, actionData, deadline, 1, nextNonce, excessiveSignature)).rejects.toThrow();
    expect(await module.getFunction('nextNonce')(await agent.getAddress())).toBe(nextNonce);

    const stale = BigInt((await provider.getBlock('latest'))?.timestamp ?? 0) - 1n;
    const staleSignature = await agentSignature(recipient, 1n, actionData, nextNonce, stale);
    await expect(executeAgent(recipient, 1n, actionData, stale, 1, nextNonce, staleSignature)).rejects.toThrow();
    const wrongVersionSignature = await agentSignature(recipient, 1n, actionData, nextNonce, deadline);
    await expect(executeAgent(recipient, 1n, actionData, deadline, 2, nextNonce, wrongVersionSignature)).rejects.toThrow();
    const forgedSignature = await agentSignature(recipient, 1n, actionData, nextNonce, deadline, owner);
    await expect(executeAgent(recipient, 1n, actionData, deadline, 1, nextNonce, forgedSignature)).rejects.toThrow();
    const exactCallSignature = await agentSignature(recipient, 1n, actionData, nextNonce, deadline);
    await expect(executeAgent(recipient, 2n, actionData, deadline, 1, nextNonce, exactCallSignature)).rejects.toThrow();
  });

  it('requires an owner-authorized exact-call approval for an agent action above policy threshold', async () => {
    const currentNonce = await module.getFunction('nextNonce')(await agent.getAddress()) as bigint;
    const amount = parseEther('0.4');
    const deadline = BigInt((await provider.getBlock('latest'))?.timestamp ?? 0) + 600n;
    const signature = await agentSignature(recipient, amount, '0x', currentNonce, deadline);
    await expect(executeAgent(recipient, amount, '0x', deadline, 1, currentNonce, signature)).rejects.toThrow();
    const approveData = guard.interface.encodeFunctionData('approveAgentAction', [
      await agent.getAddress(), 1, currentNonce, recipient, amount, '0x', deadline, deadline,
    ]);
    await executeSafeTransaction(guardAddress, 0n, approveData);
    const encodedApproval = AbiCoder.defaultAbiCoder().encode(
      ['address', 'uint256', 'bytes32', 'uint64', 'address', 'uint64', 'uint256', 'address', 'uint256', 'bytes32', 'uint256'],
      [safeAddress, chainId, keccak256(toUtf8Bytes('mandate-policy-revision-1')), 1, await agent.getAddress(), 1, currentNonce, recipient, amount, keccak256('0x'), deadline],
    );
    const approvalHash = keccak256(encodedApproval);
    expect(await guard.getFunction('actionApprovals')(approvalHash)).toBe(deadline);
    const substitutedAmount = parseEther('0.41');
    const substitutedSignature = await agentSignature(recipient, substitutedAmount, '0x', currentNonce, deadline);
    await expect(executeAgent(recipient, substitutedAmount, '0x', deadline, 1, currentNonce, substitutedSignature)).rejects.toThrow();
    expect(await module.getFunction('nextNonce')(await agent.getAddress())).toBe(currentNonce);
    expect(await guard.getFunction('actionApprovals')(approvalHash)).toBe(deadline);
    const before = await provider.getBalance(recipient);
    const executionBlock = await executeAgent(recipient, amount, '0x', deadline, 1, currentNonce, signature);
    expect(await guard.getFunction('actionApprovals')(approvalHash)).toBe(0n);
    expect(await provider.getBalance(recipient, executionBlock) - before).toBe(amount);
  });

  it('denies delegatecall and rejects a different enabled Safe module', async () => {
    await expect(executeSafeTransaction(recipient, 0n, '0x', 1)).rejects.toThrow();
    await expect(rogue.getFunction('execute')(safeAddress, recipient, 1, '0x')).rejects.toThrow();
    expect(await provider.getBalance(recipient)).toBeGreaterThan(0n);
    await executeSafeTransaction(recipient, parseEther('0.1'), '0x');
    expect(await guard.getFunction('actionsInWindow')()).toBe(5n);
    await expect(executeSafeTransaction(recipient, parseEther('0.1'), '0x')).rejects.toThrow();
  });

  it('fails closed on policy expiry, then revokes the epoch and disables future actions', async () => {
    await provider.send('evm_increaseTime', [86401]);
    await provider.send('evm_mine', []);
    await expect(executeSafeTransaction(recipient, 1n, '0x')).rejects.toThrow();
    const previousEpoch = await guard.getFunction('policyEpoch')() as bigint;
    await executeSafeTransaction(guardAddress, 0n, guard.interface.encodeFunctionData('revokePolicy'));
    expect(await guard.getFunction('policyEnabled')()).toBe(false);
    expect(await guard.getFunction('policyEpoch')()).toBe(previousEpoch + 1n);
    await expect(executeSafeTransaction(recipient, 1n, '0x')).rejects.toThrow();
    const currentNonce = await module.getFunction('nextNonce')(await agent.getAddress()) as bigint;
    const deadline = BigInt((await provider.getBlock('latest'))?.timestamp ?? 0) + 600n;
    const signature = await agentSignature(recipient, 1n, '0x', currentNonce, deadline);
    await expect(executeAgent(recipient, 1n, '0x', deadline, 1, currentNonce, signature)).rejects.toThrow();
  });

  it('executes compiler output through the Safe owner threshold and activates the matching on-chain revision', async () => {
    const latest = await provider.getBlock('latest');
    if (latest === null) throw new Error('Anvil block unavailable');
    const epoch = await guard.getFunction('policyEpoch')() as bigint;
    const revision = {
      schemaVersion: 1 as const, policyId: 'activated-policy', revision: 1, organizationId: 'local-org',
      owner: await owner.getAddress(), account: safeAddress, agentId: 'local-agent', agentAddress: await agent.getAddress(), agentKeyVersion: 2,
      chainId: Number(chainId), adapter: 'evm-smart-account' as const, target: tokenAddress,
      selectors: ['0xa9059cbb'], asset: tokenAddress, recipients: [recipient],
      limits: { perAction: '100000', cumulative: '500000', windowSeconds: 3600, approvalThreshold: '80000', maxActions: 5 },
      validAfter: latest.timestamp, expiresAt: latest.timestamp + 3600, nonceEpoch: Number(epoch),
    };
    const currentAgentKey = await module.getFunction('agents')(await agent.getAddress()) as readonly [bigint, boolean];
    const activationPlan = buildSafePolicyActivationPlan(revision, {
      safeAddress, guardAddress, moduleAddress, chainId: Number(chainId), timestampSeconds: latest.timestamp,
      safeNonce: await safe.getFunction('nonce')() as bigint, policyEpoch: epoch,
      policyEnabled: await guard.getFunction('policyEnabled')() as boolean,
      policyRevisionHash: await guard.getFunction('policyRevisionHash')() as string,
      safeOwners: await safe.getFunction('getOwners')() as readonly string[],
      safeThreshold: await safe.getFunction('getThreshold')() as bigint,
      agentKeyVersion: currentAgentKey[0], agentActive: currentAgentKey[1],
    });
    expect(activationPlan.calls.map(({ purpose }) => purpose)).toEqual(['REGISTER_AGENT', 'CONFIGURE_POLICY']);
    const transactionHashes: string[] = [];
    for (const call of activationPlan.calls) {
      const onChainHash = await safe.getFunction('getTransactionHash')(
        call.to, 0, call.data, 0, 0, 0, 0, ZeroAddress, ZeroAddress, BigInt(call.nonce),
      ) as string;
      expect(call.safeTxHash).toBe(onChainHash);
      transactionHashes.push(await executeSafeTransactionWithHash(call.to, 0n, call.data));
    }
    expect(await guard.getFunction('policyEnabled')()).toBe(true);
    expect(await guard.getFunction('policyEpoch')()).toBe(epoch + 1n);
    expect(await guard.getFunction('policyRevisionHash')()).toBe(activationPlan.revisionHash);
    expect(await module.getFunction('agents')(await agent.getAddress())).toEqual([2n, true]);
    const finalizer = new EvmSafePolicyActivationFinalizer({ 31337: rpcUrl }, { 31337: 2 });
    const finalizationInput = { planId: '69d2e7c8-4046-4fc5-9a85-75525a451a52', plan: activationPlan, transactionHashes, minimumConfirmations: 2 };
    await expect(finalizer.verifyFinalizedActivation(finalizationInput)).rejects.toMatchObject({ code: 'NOT_FINALIZED' });
    await provider.send('evm_mine', []);
    const finalized = await finalizer.verifyFinalizedActivation(finalizationInput);
    expect(finalized).toMatchObject({ planId: finalizationInput.planId, revisionHash: activationPlan.revisionHash, policyEpoch: activationPlan.resultingPolicyEpoch });
    expect(finalized.receipts).toHaveLength(2);
    expect(finalized.receipts.every(({ confirmations, status }) => confirmations >= 2 && status === 'FINAL')).toBe(true);

    const activeState = await new EvmSafePolicyActivationReader({ 31337: rpcUrl }).readState({
      chainId: Number(chainId), safeAddress, guardAddress, moduleAddress, agentAddress: await agent.getAddress(),
    });
    const revocationPlan = buildSafePolicyRevocationPlan(activeState, await agent.getAddress());
    const revocationHash = await safe.getFunction('getTransactionHash')(
      revocationPlan.call.to, 0, revocationPlan.call.data, 0, 0, 0, 0, ZeroAddress, ZeroAddress, BigInt(revocationPlan.call.nonce),
    ) as string;
    expect(revocationPlan.call.safeTxHash).toBe(revocationHash);
    const revocationTransactionHash = await executeSafeTransactionWithHash(revocationPlan.call.to, 0n, revocationPlan.call.data);
    expect(await guard.getFunction('policyEnabled')()).toBe(false);
    expect(await guard.getFunction('policyEpoch')()).toBe(BigInt(revocationPlan.resultingPolicyEpoch));
    const revocationFinalizer = new EvmSafePolicyRevocationFinalizer({ 31337: rpcUrl }, { 31337: 2 });
    const revocationInput = { planId: 'a8f446bf-2d36-4e80-a8b9-3c5359206013', plan: revocationPlan, transactionHash: revocationTransactionHash, minimumConfirmations: 2 };
    await expect(revocationFinalizer.verifyFinalizedRevocation(revocationInput)).rejects.toMatchObject({ code: 'NOT_FINALIZED' });
    await provider.send('evm_mine', []);
    const finalizedRevocation = await revocationFinalizer.verifyFinalizedRevocation(revocationInput);
    expect(finalizedRevocation).toMatchObject({
      planId: revocationInput.planId, revisionHash: revocationPlan.revisionHash,
      previousPolicyEpoch: revocationPlan.expectedPolicyEpoch, policyEpoch: revocationPlan.resultingPolicyEpoch,
    });
    expect(finalizedRevocation.receipt).toMatchObject({ safeTxHash: revocationPlan.call.safeTxHash, transactionHash: revocationTransactionHash, status: 'FINAL' });
  });
});
