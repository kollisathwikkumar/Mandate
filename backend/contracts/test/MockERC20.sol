// SPDX-License-Identifier: MIT
pragma solidity ^0.8.36;

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public transfersEnabled = true;

    function mint(address account, uint256 amount) external { balanceOf[account] += amount; }
    function setTransfersEnabled(bool enabled) external { transfersEnabled = enabled; }
    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(transfersEnabled, "transfers disabled");
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

interface ISafeModuleCall {
    function execTransactionFromModule(address to, uint256 value, bytes memory data, uint8 operation) external returns (bool success);
}

contract UntrustedSafeModule {
    function execute(address safe, address to, uint256 value, bytes calldata data) external returns (bool) {
        return ISafeModuleCall(safe).execTransactionFromModule(to, value, data, 0);
    }
}
