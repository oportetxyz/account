// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console} from "forge-std/Script.sol";
import {Config} from "forge-std/Config.sol";
import {SafeSingletonDeployer} from "./SafeSingletonDeployer.sol";
import {OwnerBatch} from "./OwnerBatch.sol";
import {Orchestrator} from "../src/Orchestrator.sol";

interface IOwnable {
    function owner() external view returns (address);
    function transferOwnership(address newOwner) external payable;
}

/**
 * @title DeployOrchestrator
 * @notice Deploys the Orchestrator on a new chain at its canonical address and hands it to the
 *         current owner in the same transaction. Run it before DeployMain on every new chain.
 *
 * @dev why: `orchestrator_owner` in config.toml is the Orchestrator's CREATE2 constructor arg,
 *      and IthacaAccount and the AccountProxy derive their addresses from the Orchestrator's,
 *      so it stays the original owner (0x6249...D8d9) for good. That key leaked in October
 *      2026. Deployed the usual way, the Orchestrator would sit with the leaked key until a
 *      second transaction moved it.
 *
 *      Here the old owner signs an EIP-7702 authorization delegating its EOA to OwnerBatch,
 *      whose only executor is `funder_owner`. The new owner sends one type-4 transaction in
 *      which the old owner deploys the Orchestrator through the Safe Singleton Factory and
 *      transfers it to the new owner. The old key signs only the authorization and needs no
 *      gas on the chain, so there is nothing on it to sweep.
 *
 *      Whoever holds the leaked key can race the deploy. The deploy call may fail, so a bare
 *      deploy landing first still ends with our handover. If they also take ownership first,
 *      the chain cannot join the canonical set and the run stops. Send it through a private
 *      RPC where the chain has one, and run it as soon as the chain is chosen.
 *
 *      Without --broadcast every call runs against a fork of the chain: the dry run.
 *
 * Environment:
 *   ORCHESTRATOR_INIT_OWNER_KEY   private key of `orchestrator_owner`, Infisical oportet prod
 *                                 /relay LEGACY_RELAY_FUNDER_OWNER_KEY
 *   RPC_<chainId>                 the chain's RPC
 *
 * The new owner (`funder_owner`) sends the transaction, so forge needs its wallet:
 * `--private-keys <key>`, `--account <name>` or `--ledger --sender <addr>`, and the new owner
 * needs gas on the chain.
 *
 * Usage:
 *   forge script deploy/DeployOrchestrator.s.sol:DeployOrchestrator --sig "run(uint256)" <id>
 *   forge script deploy/DeployOrchestrator.s.sol:DeployOrchestrator --sig "run(uint256)" <id> \
 *     --broadcast --private-keys <new owner key>
 *   # then DeployMain for the rest of the set; it finds the Orchestrator already deployed
 */
contract DeployOrchestrator is Script, Config, SafeSingletonDeployer {
    string internal configPath = "/deploy/config.toml";

    function run(uint256 chainId) external {
        _placeholderOtherRpcs(chainId);
        _loadConfig(string.concat(vm.projectRoot(), configPath), false);
        uint256 initOwnerKey = vm.envUint("ORCHESTRATOR_INIT_OWNER_KEY");
        require(
            vm.addr(initOwnerKey) == config.get(chainId, "orchestrator_owner").toAddress(),
            "ORCHESTRATOR_INIT_OWNER_KEY is not orchestrator_owner"
        );
        address newOwner = config.get(chainId, "funder_owner").toAddress();
        bytes32 salt = config.get(chainId, "salt").toBytes32();
        address expected = config.get(chainId, "orchestrator_deployed").toAddress();

        vm.createSelectFork(vm.envString(string.concat("RPC_", vm.toString(chainId))));
        require(block.chainid == chainId, "chain id mismatch");
        console.log(
            string.concat(
                "\n=== ",
                config.get(chainId, "name").toString(),
                " (",
                vm.toString(chainId),
                ") ==="
            )
        );

        handover(initOwnerKey, newOwner, salt, expected);
    }

    /// @dev Repeatable: a chain where the Orchestrator already belongs to `newOwner` is left
    ///      alone, so a run that stopped halfway can be sent again.
    function handover(uint256 initOwnerKey, address newOwner, bytes32 salt, address expected)
        public
        returns (address orchestrator)
    {
        address initOwner = vm.addr(initOwnerKey);
        require(newOwner != address(0) && newOwner != initOwner, "bad new owner");

        bytes memory args = abi.encode(initOwner);
        orchestrator = computeAddress(type(Orchestrator).creationCode, args, salt);
        require(orchestrator == expected, "Orchestrator address differs from orchestrator_deployed");

        if (orchestrator.code.length > 0) {
            address owner = IOwnable(orchestrator).owner();
            if (owner == newOwner) {
                console.log("Orchestrator already deployed and handed over:", orchestrator);
                return orchestrator;
            }
            // why: anyone else here means the leaked key moved it first; the address on this
            // chain no longer belongs to us.
            require(owner == initOwner, "Orchestrator owned by an unknown address");
        }

        address batch = _deployBatch(newOwner, salt);

        OwnerBatch.Call[] memory calls = new OwnerBatch.Call[](2);
        // why: allowed to fail, so a deploy someone else landed first still gets handed over.
        calls[0] = OwnerBatch.Call({
            target: SAFE_SINGLETON_FACTORY,
            value: 0,
            data: abi.encodePacked(salt, type(Orchestrator).creationCode, args),
            allowFailure: true
        });
        calls[1] = OwnerBatch.Call({
            target: orchestrator,
            value: 0,
            data: abi.encodeCall(IOwnable.transferOwnership, (newOwner)),
            allowFailure: false
        });

        // why: signed at the old owner's current nonce; the sender is the new owner, so that
        // nonce is not bumped before the authorization is checked.
        vm.attachDelegation(vm.signDelegation(batch, initOwnerKey));
        vm.broadcast(newOwner);
        OwnerBatch(initOwner).execute(calls);

        require(orchestrator.code.length > 0, "Orchestrator not deployed");
        require(IOwnable(orchestrator).owner() == newOwner, "Orchestrator not handed over");
        console.log("Orchestrator deployed:", orchestrator);
        console.log("Owner:", newOwner);
    }

    /// @dev The config loader resolves every chain's ${RPC_<id>}, but only the target chain is
    ///      forked, so the others get a placeholder instead of each needing a live endpoint.
    function _placeholderOtherRpcs(uint256 chainId) internal {
        string[] memory ids =
            vm.parseTomlKeys(vm.readFile(string.concat(vm.projectRoot(), configPath)), "$");
        for (uint256 i = 0; i < ids.length; i++) {
            string memory name = string.concat("RPC_", ids[i]);
            if (vm.envExists(name) || vm.parseUint(ids[i]) == chainId) continue;
            vm.setEnv(name, "http://unused");
        }
    }

    function _deployBatch(address executor, bytes32 salt) internal returns (address batch) {
        bytes memory args = abi.encode(executor);
        batch = computeAddress(type(OwnerBatch).creationCode, args, salt);
        if (batch.code.length > 0) return batch;
        require(
            broadcastDeploy(executor, type(OwnerBatch).creationCode, args, salt) == batch,
            "CREATE2 address mismatch"
        );
        console.log("OwnerBatch deployed:", batch);
    }
}
