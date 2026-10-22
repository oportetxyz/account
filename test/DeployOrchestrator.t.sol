// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Config} from "forge-std/Config.sol";
import {LibEIP7702} from "solady/accounts/LibEIP7702.sol";
import {SafeSingletonDeployer} from "../deploy/SafeSingletonDeployer.sol";
import {DeployOrchestrator, IOwnable} from "../deploy/DeployOrchestrator.s.sol";
import {OwnerBatch} from "../deploy/OwnerBatch.sol";
import {Orchestrator} from "../src/Orchestrator.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {SimpleFunder} from "../src/SimpleFunder.sol";

/// @dev What a new chain deploy must produce: the canonical account set at the addresses every
///      other chain has, and an Orchestrator owned by the current owner, never by the leaked key.
contract DeployOrchestratorTest is Test, Config, SafeSingletonDeployer {
    bytes internal constant FACTORY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    bytes32 internal constant SALT =
        0xdf08a9fa957a9ac004f84f3a8ab7318a7be55d59948f46497bd3717865295b61;

    DeployOrchestrator internal script;
    uint256 internal initOwnerKey;
    address internal initOwner;
    address internal newOwner;
    address internal expected;

    function setUp() public {
        vm.etch(SAFE_SINGLETON_FACTORY, FACTORY_CODE);
        script = new DeployOrchestrator();
        (initOwner, initOwnerKey) = makeAddrAndKey("leaked owner");
        newOwner = makeAddr("new owner");
        expected = computeAddress(type(Orchestrator).creationCode, abi.encode(initOwner), SALT);
    }

    function test_handsOverInTheDeployTransaction() public {
        address orchestrator = script.handover(initOwnerKey, newOwner, SALT, expected);

        assertEq(orchestrator, expected);
        assertEq(IOwnable(orchestrator).owner(), newOwner);
        // The leaked key spent nothing: it only signed the authorization.
        assertEq(initOwner.balance, 0);
    }

    function test_repeatIsANoop() public {
        script.handover(initOwnerKey, newOwner, SALT, expected);
        script.handover(initOwnerKey, newOwner, SALT, expected);
        assertEq(IOwnable(expected).owner(), newOwner);
    }

    function test_bareDeployLandingFirstIsStillHandedOver() public {
        vm.prank(makeAddr("racer"));
        (bool success,) = SAFE_SINGLETON_FACTORY.call(
            abi.encodePacked(SALT, type(Orchestrator).creationCode, abi.encode(initOwner))
        );
        assertTrue(success);
        assertEq(IOwnable(expected).owner(), initOwner);

        script.handover(initOwnerKey, newOwner, SALT, expected);
        assertEq(IOwnable(expected).owner(), newOwner);
    }

    function test_stopsWhenTheLeakedKeyTookItFirst() public {
        address attacker = makeAddr("attacker");
        (bool success,) = SAFE_SINGLETON_FACTORY.call(
            abi.encodePacked(SALT, type(Orchestrator).creationCode, abi.encode(initOwner))
        );
        assertTrue(success);
        vm.prank(initOwner);
        IOwnable(expected).transferOwnership(attacker);

        vm.expectRevert(bytes("Orchestrator owned by an unknown address"));
        script.handover(initOwnerKey, newOwner, SALT, expected);
    }

    function test_stopsOnAnAddressOtherThanConfigured() public {
        vm.expectRevert(bytes("Orchestrator address differs from orchestrator_deployed"));
        script.handover(initOwnerKey, newOwner, SALT, makeAddr("elsewhere"));
    }

    function test_batchRejectsAnyoneButTheExecutor() public {
        OwnerBatch batch = new OwnerBatch(newOwner);
        vm.signAndAttachDelegation(address(batch), initOwnerKey);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(OwnerBatch.Unauthorized.selector);
        OwnerBatch(initOwner).execute(new OwnerBatch.Call[](0));
    }

    /// @dev For every chain in config.toml, the args DeployMain and DeployOrchestrator read
    ///      reproduce the addresses recorded as deployed, so a new chain gets the same set.
    function test_configReproducesTheDeployedSet() public {
        // why: the loader resolves each chain's ${RPC_<id>} endpoint; nothing here is fetched.
        uint256[7] memory ids = [uint256(84532), 11155931, 8453, 137, 4153, 1, 4663];
        for (uint256 i = 0; i < ids.length; i++) {
            vm.setEnv(string.concat("RPC_", vm.toString(ids[i])), "http://unused");
        }
        _loadConfig("./deploy/config.toml", false);
        assertEq(config.getChainIds().length, ids.length, "add the new chain's id above");
        uint256[] memory chainIds = config.getChainIds();
        assertGt(chainIds.length, 0);
        for (uint256 i = 0; i < chainIds.length; i++) {
            uint256 id = chainIds[i];
            bytes32 salt = config.get(id, "salt").toBytes32();
            address orchestrator = computeAddress(
                type(Orchestrator).creationCode,
                abi.encode(config.get(id, "orchestrator_owner").toAddress()),
                salt
            );
            assertEq(
                orchestrator, config.get(id, "orchestrator_deployed").toAddress(), "orchestrator"
            );

            address account =
                computeAddress(type(IthacaAccount).creationCode, abi.encode(orchestrator), salt);
            assertEq(account, config.get(id, "ithaca_account_deployed").toAddress(), "account");
            assertEq(
                computeAddress(LibEIP7702.proxyInitCode(account, address(0)), salt),
                config.get(id, "account_proxy_deployed").toAddress(),
                "account proxy"
            );

            assertEq(
                computeAddress(
                    type(SimpleFunder).creationCode,
                    abi.encode(
                        config.get(id, "funder_signer").toAddress(),
                        config.get(id, "funder_owner").toAddress()
                    ),
                    salt
                ),
                config.get(id, "simple_funder_deployed").toAddress(),
                "simple funder"
            );
        }
    }
}
