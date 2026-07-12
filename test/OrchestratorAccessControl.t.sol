// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Orchestrator} from "../src/Orchestrator.sol";

/// @dev Guards the #426 deploy-gate patch: withdrawTokens must be owner-only.
contract OrchestratorAccessControlTest is Test {
    Orchestrator internal orchestrator;
    address internal owner = address(0xA11CE);
    address internal attacker = address(0xBAD);

    function setUp() public {
        orchestrator = new Orchestrator(owner);
    }

    function test_owner_isBakedFromConstructor() public view {
        assertEq(orchestrator.owner(), owner);
    }

    function test_withdrawTokens_revertsForNonOwner() public {
        vm.deal(address(orchestrator), 1 ether);
        vm.prank(attacker);
        vm.expectRevert(Ownable.Unauthorized.selector);
        orchestrator.withdrawTokens(address(0), attacker, 1 ether);
        assertEq(attacker.balance, 0);
    }

    function test_withdrawTokens_ownerCanSweepNative() public {
        vm.deal(address(orchestrator), 1 ether);
        vm.prank(owner);
        orchestrator.withdrawTokens(address(0), owner, 1 ether);
        assertEq(owner.balance, 1 ether);
    }
}
