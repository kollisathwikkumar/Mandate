// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

interface IMandateGuardState {
    function policyEpoch() external view returns (uint64);
    function policyEnabled() external view returns (bool);
    function isFullyInstalled() external view returns (bool);
    function consumeAgentActionApproval(
        address agent, uint64 keyVersion, uint256 agentNonce, address to, uint256 value, bytes calldata data, uint256 actionDeadline
    ) external;
}

interface ISafeModuleExecution {
    function execTransactionFromModule(address to, uint256 value, bytes memory data, uint8 operation) external returns (bool success);
}

/// @notice Non-custodial, EIP-712 agent entry point for one Safe.
/// @dev The Safe must enable this module and install its matching MandateSafeGuard as
///      both transaction and module guard. Every signature binds chain, Safe, epoch,
///      key version, exact call bytes, deadline, and per-agent monotonic nonce.
contract MandateAgentModule {
    error OnlySafe();
    error AgentInactive();
    error InvalidKeyVersion();
    error InvalidNonce();
    error SignatureExpired();
    error InvalidSignature();
    error PolicyUnavailable();
    error GuardNotInstalled();
    error ExecutionFailed();

    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ACTION_TYPEHASH = keccak256("MandateAction(address safe,uint256 chainId,address module,uint64 policyEpoch,address agent,uint64 keyVersion,address to,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)");
    bytes32 private constant NAME_HASH = keccak256("MandateAgentModule");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct AgentKey { uint64 version; bool active; }

    address public immutable safe;
    IMandateGuardState public immutable guard;
    mapping(address => AgentKey) public agents;
    mapping(address => uint256) public nextNonce;

    event AgentKeyConfigured(address indexed agent, uint64 indexed keyVersion, bool active);
    event AgentActionExecuted(address indexed agent, uint64 indexed keyVersion, uint256 indexed nonce, bytes32 actionHash);

    constructor(address safeAddress, address guardAddress) {
        if (safeAddress.code.length == 0 || guardAddress.code.length == 0) revert PolicyUnavailable();
        safe = safeAddress;
        guard = IMandateGuardState(guardAddress);
    }

    function setAgent(address agent, uint64 keyVersion, bool active) external {
        if (msg.sender != safe) revert OnlySafe();
        if (agent == address(0) || keyVersion == 0) revert InvalidKeyVersion();
        AgentKey storage current = agents[agent];
        if (keyVersion < current.version) revert InvalidKeyVersion();
        current.version = keyVersion;
        current.active = active;
        emit AgentKeyConfigured(agent, keyVersion, active);
    }

    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        uint64 keyVersion,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bytes32 actionHash) {
        if (!guard.policyEnabled() || !guard.isFullyInstalled()) revert PolicyUnavailable();
        if (deadline <= block.timestamp) revert SignatureExpired();
        AgentKey memory agent = agents[msg.sender];
        if (!agent.active) revert AgentInactive();
        if (agent.version != keyVersion) revert InvalidKeyVersion();
        if (nonce != nextNonce[msg.sender]) revert InvalidNonce();

        bytes32 structHash = keccak256(abi.encode(
            ACTION_TYPEHASH, safe, block.chainid, address(this), guard.policyEpoch(), msg.sender,
            keyVersion, to, value, keccak256(data), nonce, deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        if (_recover(digest, signature) != msg.sender) revert InvalidSignature();

        ++nextNonce[msg.sender];
        actionHash = keccak256(abi.encode(safe, block.chainid, guard.policyEpoch(), msg.sender, keyVersion, to, value, keccak256(data), nonce, deadline));
        guard.consumeAgentActionApproval(msg.sender, keyVersion, nonce, to, value, data, deadline);
        bool success = ISafeModuleExecution(safe).execTransactionFromModule(to, value, data, 0);
        if (!success) revert ExecutionFailed();
        emit AgentActionExecuted(msg.sender, keyVersion, nonce, actionHash);
    }

    function _domainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert InvalidSignature();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }
}
