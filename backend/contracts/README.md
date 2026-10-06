# Safe enforcement slice

This directory contains the first execution-boundary slice for the architecture's selected EVM/Safe direction:

- `src/MandateSafeGuard.sol` implements Safe transaction and module guards. It allows only native-currency transfers and canonical ERC-20 `transfer(address,uint256)` calls. It rejects delegatecall, unlisted assets/recipients, unsupported selectors, stale/disabled policy epochs, expired policy, per-action/window overages, excessive action count, and Safe gas reimbursement parameters. Per-asset `approvalThreshold` rules require a one-time Safe-owner approval bound to the exact agent, key version, nonce, target, value, calldata hash, policy epoch/revision, and deadline.
- `src/MandateAgentModule.sol` accepts EIP-712 agent-authorized calls, with Safe + chain + module + epoch + agent key version + exact calldata/value + nonce + deadline binding. The agent private key stays with the agent; the module has no signing key or general arbitrary-call method.
- `test/MockERC20.sol` supplies local-only fixtures, including a failing-transfer mode used to prove accounting and nonce rollback.

## Safe setup sequence

Deploy a Safe proxy, a `MandateSafeGuard` with that Safe address, and a `MandateAgentModule` with that Safe and guard. Through threshold-approved Safe owner transactions:

1. Call `configurePolicy(PolicyConfig)` and `setAgentModule` on the guard; configure the module's `setAgent` entry for the exact agent address/key version. `PolicyConfig` carries aligned asset, per-action, per-window, approval-threshold, and approval-required arrays plus recipient allowlists.
2. Enable the exact `MandateAgentModule` as a Safe module. Do not leave unrelated modules enabled; the module guard rejects them.
3. Set this guard using **both** `setGuard(guard)` and `setModuleGuard(guard)`; verify `isFullyInstalled() == true` and the Safe storage guard addresses before accepting the account as protected.
4. Fund the Safe and run a test transfer on the target network before registering it as an executable account.

The guard checks that both guard storage slots still point to itself on each supported transfer, and the agent module checks the same before attempting execution. Safe owners retain Safe-native authority to replace/remove guards and modules for recovery; if either guard changes, the account is no longer considered Mandate-enforced and the API/indexer must mark the grant unsupported/revoked.

`configurePolicy` requires the next monotonically increasing epoch. `revokePolicy` disables execution and increments the epoch, invalidating earlier agent signatures. When the action amount exceeds a configured threshold, an owner calls `approveAgentAction` through a threshold-approved Safe transaction. The approval is consumed in the same transaction that routes the agent call through the Safe, so failure reverts the approval consumption, nonce, and spend counters atomically; a changed call cannot reuse it. Limits are asset-denominated (native wei or the configured token's smallest unit), not cross-asset USD; price-oracle valuation is not implemented. One Safe transaction has one transfer call; batching, swaps, arbitrary contract methods, delegatecall, gas reimbursement, dynamic quotes and human-held approval payloads are unsupported and fail closed in this slice.

## Build and tests

`npm run test:integration -- packages/chain/test/safe-enforcement.integration.test.ts` compiles these sources with Solidity 0.8.36, optimizer and `viaIR`, starts local Anvil, deploys the pinned Safe v1.5.0 release artifacts as a singleton/proxy, installs both guards, and exercises owner and agent calls against the real Safe execution code. Tests cover allowed native/ERC-20 calls, target-selector/recipient/per-action denial, nonce replay, expiry, key-version mismatch, untrusted enabled module rejection, delegatecall rejection, policy revocation, and rollback when the target transfer reverts.

The approval integration test checks a rejected no-approval call, an owner-authorized exact action, rejection of a changed amount, and one-time consumption. It submits the bounded agent call with a fixed local gas limit because Anvil's estimate-gas simulation returned a false missing-approval revert for this nested Safe path; an actual mined local Anvil transaction succeeds. The production chain adapter must validate simulation/estimation behavior against each supported RPC before enabling execution.

This is not a testnet deployment, formal verification, independent contract audit, or production-ready adapter. Before real funds: pin compiler/build artifacts and chain deployments, add invariant/fuzz tests, deploy/verify on Monad testnet, implement registration and status monitoring in the API/indexer, exercise recovery on a disposable Safe, and obtain independent review. Safe owner governance can always intentionally dismantle the guard; Mandate must show the account as unprotected after that event.
