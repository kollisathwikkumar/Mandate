// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

/// @notice Safe v1.4+/v1.5 transaction-guard ABI. Enum.Operation is ABI-encoded as uint8.
interface ISafeTransactionGuard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;
    function checkAfterExecution(bytes32 txHash, bool success) external;
}

/// @notice Safe v1.4+/v1.5 module-guard ABI.
interface ISafeModuleGuard {
    function checkModuleTransaction(address to, uint256 value, bytes memory data, uint8 operation, address module)
        external returns (bytes32 moduleTxHash);
    function checkAfterModuleExecution(bytes32 txHash, bool success) external;
}

interface IERC165Guard {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface ISafeGuardStorage {
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);
    function getTransactionHash(
        address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas,
        uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, uint256 nonce
    ) external view returns (bytes32);
    function nonce() external view returns (uint256);
}

/// @notice Dual Safe transaction/module guard for native and ERC-20 transfers.
/// @dev Deploy per Safe. Configure while the Safe is still unguarded, then install this
///      contract with both setGuard and setModuleGuard through owner-threshold Safe txs.
///      Any non-transfer selector, delegatecall, unconfigured module, or missing paired
///      guard fails closed. Safe owners retain an explicit Safe-native recovery path.
contract MandateSafeGuard is ISafeTransactionGuard, ISafeModuleGuard, IERC165Guard {
    error OnlySafe();
    error InvalidConfiguration();
    error PolicyInactive();
    error PolicyExpired();
    error UnsupportedCall();
    error AssetNotAllowed();
    error RecipientNotAllowed();
    error ActionLimitExceeded();
    error ReentrantExecution();
    error IncompleteGuardInstallation();
    error FailedExecution();
    error InvalidAfterExecution();
    error ActionApprovalRequired();

    uint8 private constant CALL_OPERATION = 0;
    uint8 private constant DELEGATECALL_OPERATION = 1;
    uint256 private constant MAX_CONFIG_ITEMS = 32;
    bytes32 private constant SAFE_TX_GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 private constant SAFE_MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes4 private constant ERC20_TRANSFER_SELECTOR = 0xa9059cbb;
    bytes4 private constant SAFE_SET_GUARD_SELECTOR = bytes4(keccak256("setGuard(address)"));
    bytes4 private constant SAFE_SET_MODULE_GUARD_SELECTOR = bytes4(keccak256("setModuleGuard(address)"));
    bytes4 private constant SAFE_ENABLE_MODULE_SELECTOR = bytes4(keccak256("enableModule(address)"));
    bytes4 private constant SAFE_DISABLE_MODULE_SELECTOR = bytes4(keccak256("disableModule(address,address)"));

    struct AssetLimit { uint256 perAction; uint256 perWindow; uint256 approvalThreshold; bool approvalRequired; }
    struct WindowUsage { uint64 startedAt; uint256 spent; }
    struct PolicyConfig {
        bytes32 revisionHash;
        uint64 nextEpoch;
        uint64 policyValidUntil;
        uint32 windowDuration;
        uint32 actionCountLimit;
        address[] assets;
        uint256[] perActionLimits;
        uint256[] perWindowLimits;
        uint256[] approvalThresholds;
        bool[] approvalRequired;
        address[] recipients;
    }

    address public immutable safe;
    address public agentModule;
    bytes32 public policyRevisionHash;
    uint64 public policyEpoch;
    uint64 public validUntil;
    uint32 public windowSeconds;
    uint32 public maxActionsPerWindow;
    uint32 public actionsInWindow;
    uint64 public actionWindowStartedAt;
    bool public policyEnabled;
    bool private executionLocked;
    bytes32 private pendingExecutionHash;

    address[] private configuredAssets;
    address[] private configuredRecipients;
    mapping(address => AssetLimit) public assetLimits;
    mapping(address => WindowUsage) public assetWindowUsage;
    mapping(address => bool) public recipientAllowed;
    mapping(bytes32 => uint64) public actionApprovals;

    event PolicyConfigured(bytes32 indexed revisionHash, uint64 indexed epoch, uint64 validUntil);
    event PolicyRevoked(uint64 indexed epoch);
    event AgentModuleConfigured(address indexed module);
    event AgentActionApproved(address indexed agent, uint64 indexed keyVersion, uint256 indexed nonce, bytes32 actionHash, uint64 validUntil);
    event ActionEnforced(bytes32 indexed actionHash, address indexed asset, address indexed recipient, uint256 amount, uint64 epoch);

    constructor(address safeAddress) {
        if (safeAddress.code.length == 0) revert InvalidConfiguration();
        safe = safeAddress;
    }

    modifier onlySafe() { if (msg.sender != safe) revert OnlySafe(); _; }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(ISafeTransactionGuard).interfaceId
            || interfaceId == type(ISafeModuleGuard).interfaceId
            || interfaceId == type(IERC165Guard).interfaceId;
    }

    function configurePolicy(PolicyConfig calldata config) external onlySafe {
        uint256 itemCount = config.assets.length;
        if (config.revisionHash == bytes32(0) || config.nextEpoch != policyEpoch + 1
            || config.policyValidUntil <= block.timestamp || config.windowDuration == 0
            || config.actionCountLimit == 0 || itemCount == 0 || itemCount > MAX_CONFIG_ITEMS
            || itemCount != config.perActionLimits.length || itemCount != config.perWindowLimits.length
            || itemCount != config.approvalThresholds.length || itemCount != config.approvalRequired.length
            || config.recipients.length == 0 || config.recipients.length > MAX_CONFIG_ITEMS) revert InvalidConfiguration();

        for (uint256 index; index < configuredAssets.length; ++index) delete assetLimits[configuredAssets[index]];
        for (uint256 index; index < configuredRecipients.length; ++index) delete recipientAllowed[configuredRecipients[index]];
        delete configuredAssets;
        delete configuredRecipients;

        for (uint256 index; index < itemCount; ++index) {
            address asset = config.assets[index];
            uint256 perAction = config.perActionLimits[index];
            uint256 perWindow = config.perWindowLimits[index];
            uint256 approvalThreshold = config.approvalThresholds[index];
            bool needsApproval = config.approvalRequired[index];
            if ((asset != address(0) && asset.code.length == 0) || perAction == 0 || perWindow < perAction
                || (!needsApproval && approvalThreshold != 0) || approvalThreshold > perAction
                || assetLimits[asset].perWindow != 0) revert InvalidConfiguration();
            assetLimits[asset] = AssetLimit({ perAction: perAction, perWindow: perWindow, approvalThreshold: approvalThreshold, approvalRequired: needsApproval });
            configuredAssets.push(asset);
            delete assetWindowUsage[asset];
        }
        for (uint256 index; index < config.recipients.length; ++index) {
            address recipient = config.recipients[index];
            if (recipient == address(0) || recipientAllowed[recipient]) revert InvalidConfiguration();
            recipientAllowed[recipient] = true;
            configuredRecipients.push(recipient);
        }
        policyRevisionHash = config.revisionHash;
        policyEpoch = config.nextEpoch;
        validUntil = config.policyValidUntil;
        windowSeconds = config.windowDuration;
        maxActionsPerWindow = config.actionCountLimit;
        actionsInWindow = 0;
        actionWindowStartedAt = uint64((block.timestamp / config.windowDuration) * config.windowDuration);
        policyEnabled = true;
        emit PolicyConfigured(config.revisionHash, config.nextEpoch, config.policyValidUntil);
    }

    function revokePolicy() external onlySafe {
        if (policyEpoch == type(uint64).max) revert InvalidConfiguration();
        policyEnabled = false;
        ++policyEpoch;
        emit PolicyRevoked(policyEpoch);
    }

    function setAgentModule(address module) external onlySafe {
        if (module != address(0) && module.code.length == 0) revert InvalidConfiguration();
        agentModule = module;
        emit AgentModuleConfigured(module);
    }

    function approveAgentAction(
        address agent,
        uint64 keyVersion,
        uint256 agentNonce,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 actionDeadline,
        uint64 approvalValidUntil
    ) external onlySafe {
        if (!policyEnabled || agent == address(0) || keyVersion == 0 || actionDeadline <= block.timestamp
            || actionDeadline > validUntil || approvalValidUntil <= block.timestamp || approvalValidUntil > actionDeadline) {
            revert InvalidConfiguration();
        }
        (address asset,, uint256 amount) = _decodeAction(to, value, data);
        AssetLimit memory limits = assetLimits[asset];
        if (!limits.approvalRequired || amount <= limits.approvalThreshold) revert InvalidConfiguration();
        bytes32 actionHash = _agentActionHash(agent, keyVersion, agentNonce, to, value, keccak256(data), actionDeadline);
        actionApprovals[actionHash] = approvalValidUntil;
        emit AgentActionApproved(agent, keyVersion, agentNonce, actionHash, approvalValidUntil);
    }

    function consumeAgentActionApproval(
        address agent,
        uint64 keyVersion,
        uint256 agentNonce,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 actionDeadline
    ) external {
        if (msg.sender != agentModule || agent == address(0) || keyVersion == 0) revert UnsupportedCall();
        (address asset,, uint256 amount) = _decodeAction(to, value, data);
        AssetLimit memory limits = assetLimits[asset];
        if (limits.approvalRequired && amount > limits.approvalThreshold) {
            bytes32 actionHash = _agentActionHash(agent, keyVersion, agentNonce, to, value, keccak256(data), actionDeadline);
            uint64 approvalExpiry = actionApprovals[actionHash];
            if (approvalExpiry <= block.timestamp || actionDeadline <= block.timestamp) revert ActionApprovalRequired();
            delete actionApprovals[actionHash];
        }
    }

    function isFullyInstalled() external view returns (bool) {
        return _safeStorageAddress(SAFE_TX_GUARD_SLOT) == address(this)
            && _safeStorageAddress(SAFE_MODULE_GUARD_SLOT) == address(this);
    }

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory,
        address
    ) external {
        _onlySafe();
        if (executionLocked) revert ReentrantExecution();
        executionLocked = true;

        if (_isSafeAdministrationCall(to, data) && value == 0) {
            _requireExecutionMetadata(operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver);
            pendingExecutionHash = ISafeGuardStorage(safe).getTransactionHash(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver,
                ISafeGuardStorage(safe).nonce() - 1
            );
            return;
        }
        _requireFullyInstalled();
        _requireExecutionMetadata(operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver);
        (address asset, address recipient, uint256 amount) = _decodeAction(to, value, data);
        bytes32 actionHash = _consume(asset, recipient, amount);
        pendingExecutionHash = ISafeGuardStorage(safe).getTransactionHash(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver,
            ISafeGuardStorage(safe).nonce() - 1
        );
        emit ActionEnforced(actionHash, asset, recipient, amount, policyEpoch);
    }

    function checkAfterExecution(bytes32 txHash, bool success) external {
        _onlySafe();
        if (!executionLocked || txHash != pendingExecutionHash) revert InvalidAfterExecution();
        if (!success) revert FailedExecution();
        executionLocked = false;
        pendingExecutionHash = bytes32(0);
    }

    function checkModuleTransaction(address to, uint256 value, bytes memory data, uint8 operation, address module)
        external returns (bytes32 moduleTxHash)
    {
        _onlySafe();
        if (executionLocked) revert ReentrantExecution();
        executionLocked = true;
        _requireFullyInstalled();
        if (module == address(0) || module != agentModule) revert UnsupportedCall();
        _requireExecutionMetadata(operation, 0, 0, 0, address(0), payable(address(0)));
        (address asset, address recipient, uint256 amount) = _decodeAction(to, value, data);
        moduleTxHash = keccak256(abi.encode(safe, module, to, value, keccak256(data), policyEpoch));
        _consume(asset, recipient, amount);
        pendingExecutionHash = moduleTxHash;
        emit ActionEnforced(moduleTxHash, asset, recipient, amount, policyEpoch);
    }

    function checkAfterModuleExecution(bytes32 txHash, bool success) external {
        _onlySafe();
        if (!executionLocked || txHash != pendingExecutionHash) revert InvalidAfterExecution();
        if (!success) revert FailedExecution();
        executionLocked = false;
        pendingExecutionHash = bytes32(0);
    }

    function _onlySafe() private view { if (msg.sender != safe) revert OnlySafe(); }

    function _requireFullyInstalled() private view {
        if (_safeStorageAddress(SAFE_TX_GUARD_SLOT) != address(this)
            || _safeStorageAddress(SAFE_MODULE_GUARD_SLOT) != address(this)) revert IncompleteGuardInstallation();
    }

    function _safeStorageAddress(bytes32 slot) private view returns (address result) {
        bytes memory storageWord = ISafeGuardStorage(safe).getStorageAt(uint256(slot), 1);
        if (storageWord.length != 32) revert IncompleteGuardInstallation();
        assembly { result := mload(add(storageWord, 32)) }
    }

    function _isSafeAdministrationCall(address to, bytes memory data) private view returns (bool) {
        if (to == safe && data.length >= 4) {
            bytes4 selector;
            assembly { selector := mload(add(data, 32)) }
            if (selector == SAFE_SET_GUARD_SELECTOR || selector == SAFE_SET_MODULE_GUARD_SELECTOR
                || selector == SAFE_DISABLE_MODULE_SELECTOR) return true;
            if (selector == SAFE_ENABLE_MODULE_SELECTOR && data.length == 36) {
                address candidate;
                assembly { candidate := mload(add(data, 36)) }
                return agentModule != address(0) && candidate == agentModule;
            }
            return false;
        }
        if ((to == address(this) || to == agentModule) && data.length >= 4) {
            bytes4 selector;
            assembly { selector := mload(add(data, 32)) }
            return selector == this.configurePolicy.selector || selector == this.revokePolicy.selector
                || selector == this.setAgentModule.selector || selector == this.approveAgentAction.selector
                || (to == agentModule && selector == bytes4(keccak256("setAgent(address,uint64,bool)")));
        }
        return false;
    }

    function _requireExecutionMetadata(
        uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
        address gasToken, address payable refundReceiver
    ) private pure {
        if (operation != CALL_OPERATION || safeTxGas != 0 || baseGas != 0 || gasPrice != 0
            || gasToken != address(0) || refundReceiver != address(0)) revert UnsupportedCall();
        if (DELEGATECALL_OPERATION == operation) revert UnsupportedCall();
    }

    function _decodeAction(address to, uint256 value, bytes memory data)
        private view returns (address asset, address recipient, uint256 amount)
    {
        if (!policyEnabled) revert PolicyInactive();
        if (block.timestamp >= validUntil) revert PolicyExpired();
        if (data.length == 0 && value > 0) {
            asset = address(0);
            recipient = to;
            amount = value;
        } else if (value == 0 && data.length == 68) {
            bytes4 selector;
            assembly { selector := mload(add(data, 32)) }
            if (selector != ERC20_TRANSFER_SELECTOR) revert UnsupportedCall();
            assembly {
                recipient := mload(add(data, 36))
                amount := mload(add(data, 68))
            }
            asset = to;
        } else {
            revert UnsupportedCall();
        }
        if (amount == 0) revert UnsupportedCall();
        if (assetLimits[asset].perWindow == 0) revert AssetNotAllowed();
        if (!recipientAllowed[recipient]) revert RecipientNotAllowed();
    }

    function _consume(address asset, address recipient, uint256 amount) private returns (bytes32 actionHash) {
        AssetLimit memory limits = assetLimits[asset];
        if (amount > limits.perAction) revert ActionLimitExceeded();
        uint64 start = uint64((block.timestamp / windowSeconds) * windowSeconds);
        if (start != actionWindowStartedAt) {
            actionWindowStartedAt = start;
            actionsInWindow = 0;
        }
        if (actionsInWindow >= maxActionsPerWindow) revert ActionLimitExceeded();
        ++actionsInWindow;
        WindowUsage storage usage = assetWindowUsage[asset];
        if (usage.startedAt != start) {
            usage.startedAt = start;
            usage.spent = 0;
        }
        uint256 nextSpent = usage.spent + amount;
        if (nextSpent > limits.perWindow) revert ActionLimitExceeded();
        usage.spent = nextSpent;
        actionHash = keccak256(abi.encode(safe, block.chainid, policyRevisionHash, policyEpoch, asset, recipient, amount));
    }

    function _agentActionHash(
        address agent, uint64 keyVersion, uint256 agentNonce, address to, uint256 value, bytes32 dataHash, uint256 actionDeadline
    ) private view returns (bytes32) {
        return keccak256(abi.encode(
            safe, block.chainid, policyRevisionHash, policyEpoch, agent, keyVersion,
            agentNonce, to, value, dataHash, actionDeadline
        ));
    }
}
