// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title OwnerBatch
 * @notice EIP-7702 delegate that lets one executor run a batch of calls as the delegating EOA.
 * @dev why: the Orchestrator's CREATE2 initcode carries its first owner, the key that leaked in
 *      October 2026, and every account address derives from the Orchestrator's. A new chain must
 *      therefore deploy it with that owner. With the old owner's EOA delegated here, the new
 *      owner sends one transaction in which the old owner deploys the Orchestrator and hands it
 *      over, so the leaked key never controls it on its own and needs no gas on that chain.
 */
contract OwnerBatch {
    struct Call {
        address target;
        uint256 value;
        bytes data;
        bool allowFailure;
    }

    /// @dev Immutable, so it sits in this contract's code and holds for every EOA delegating
    ///      here, without touching the EOA's storage.
    address public immutable EXECUTOR;

    error Unauthorized();
    error CallFailed(uint256 index, bytes reason);

    constructor(address executor) {
        EXECUTOR = executor;
    }

    function execute(Call[] calldata calls) external payable {
        if (msg.sender != EXECUTOR && msg.sender != address(this)) revert Unauthorized();
        for (uint256 i; i < calls.length; ++i) {
            (bool success, bytes memory result) =
                calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success && !calls[i].allowFailure) revert CallFailed(i, result);
        }
    }
}
