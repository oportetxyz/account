// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console} from "forge-std/Script.sol";
import {Config} from "forge-std/Config.sol";
import {SafeSingletonDeployer} from "./SafeSingletonDeployer.sol";
import {SimpleFunder} from "../src/SimpleFunder.sol";

interface IOwnable {
    function owner() external view returns (address);
    function transferOwnership(address newOwner) external payable;
}

interface ISimpleFunder is IOwnable {
    function funder() external view returns (address);
    function gasWallets(address) external view returns (bool);
    function orchestrators(address) external view returns (bool);
    function setGasWallet(address[] memory wallets, bool isGasWallet) external;
    function setOrchestrators(address[] memory ocs, bool val) external;
    function withdrawTokens(address token, address recipient, uint256 amount) external;
}

/**
 * @title RotateKeys
 * @notice Moves the relay off leaked keys, chain by chain, in two passes so the relay keeps
 *         serving throughout.
 *
 *         `prepare` deploys a new SimpleFunder with clean owner and signer args (one CREATE2
 *         address on every chain), configures it, and funds the new funder and the new signers
 *         to a float sized from the chain's gas price. It leaves the old signers running, so the
 *         live relay is untouched and the new relay can go live on a funded set.
 *
 *         `retire` runs once the new relay is live: the old funder is emptied into the new one,
 *         the Orchestrator's ownership moves to the new owner, and the old owner and old signers
 *         sweep what is left. Everything left goes to the new funder, not to the new signers, so
 *         a hot key never holds more than one top-up.
 *
 *         `run` does both back to back, for a chain where downtime does not matter.
 *
 * @dev why: the account set (Orchestrator -> IthacaAccount -> AccountProxy) is not redeployed.
 *      Accounts bind the Orchestrator address immutably and `funder_owner` is its CREATE2 arg,
 *      so `deploy/config.toml` keeps the OLD `funder_owner` to keep that set reproducible.
 *      The SimpleFunder sits outside that chain (only the relay's `funder` points at it), so it
 *      is replaced, and its initcode now carries keys the attacker does not hold: nobody else
 *      can claim its address on a chain we have not reached yet.
 *
 *      After `prepare`, set `funder` in oportet-relay `deploy/railway/relay.yaml` to the address
 *      this script prints, and `simple_funder_deployed` in config.toml to the same.
 *
 *      Every step checks the chain first, so a pass that stops halfway can be repeated.
 *      Without --broadcast every call runs against a fork of each chain: the dry run.
 *
 * Float (prepare): each new signer gets one relay top-up, TOP_UP_GAS at the chain's live
 * eth_gasPrice, and the new funder gets FUNDER_TOP_UPS of them. FUND_TARGET_<chainId> (wei)
 * sets what the new funder plus new signers hold once `retire` has run, with the signers still
 * at one top-up each: what `retire` will sweep in later counts toward it, so only the rest moves
 * now.
 * The float is paid from the old funder first, then from what the old signers hold above one
 * top-up, then from the new owner's own balance; a chain still short stops the pass and logs
 * the amount to send to the new owner, which a chain with a FUND_TARGET above its old money
 * needs before the pass.
 *
 * Environment:
 *   OLD_FUNDER_OWNER_KEY      private key of the current owner (0x6249...D8d9)
 *   OLD_GAS_SIGNER_MNEMONIC   the relay's current RELAY_MNEMONIC
 *   NEW_FUNDER_OWNER          address that owns the new funder and the Orchestrator
 *   NEW_FUNDER_SIGNER         address of the new RELAY_FUNDER_SIGNER_KEY
 *   NEW_GAS_SIGNER_MNEMONIC   the new RELAY_MNEMONIC; only addresses are derived from it
 *   RPC_<chainId>             one per chain passed in
 *   FUND_TARGET_<chainId>     optional float for that chain in wei, see above
 *   SWEEP_TIP_WEI             optional priority fee assumed for gas reserves (1 gwei)
 *
 * The new owner signs on every chain (setOrchestrators, setGasWallet, and any float it pays),
 * so forge needs a wallet for NEW_FUNDER_OWNER: `--ledger --sender <addr>`, `--account <name>`
 * or `--private-keys <key>`. Its gas comes from the old owner in `prepare`.
 *
 * Usage:
 *   forge script deploy/RotateKeys.s.sol:RotateKeys --sig "prepare(uint256[])" \
 *     "[8453,137,4153,1,4663,11155931]"                       # dry run
 *   forge script deploy/RotateKeys.s.sol:RotateKeys --sig "prepare(uint256[])" \
 *     "[8453,137,4153,1,4663,11155931]" --broadcast --multi --slow --ledger --sender <owner>
 *   # switch the relay to the new funder and mnemonic, then the same with "retire(uint256[])"
 */
contract RotateKeys is Script, Config, SafeSingletonDeployer {
    /// @dev The relay runs `num_signers: 3`, but FundSigners defaults to 10, so the first
    /// 10 indices of the old mnemonic are checked and every one still a gas wallet is revoked.
    uint256 internal constant OLD_SIGNER_SCAN = 10;

    /// @dev Gas units held back from each sweep. A plain transfer is 21k; the rest covers
    /// forge's estimate multiplier and Arbitrum-style L1 fees folded into the gas limit.
    uint256 internal constant SWEEP_RESERVE_GAS = 100_000;

    /// @dev One relay top-up: MIN_SIGNER_GAS (10M) times TOP_UP_MULTIPLIER (3) in
    /// oportet-relay `src/transactions/signer.rs`, so a new signer starts where the relay
    /// would refill it to.
    uint256 internal constant TOP_UP_GAS = 30_000_000;

    /// @dev Top-ups the new funder holds after `prepare` when no FUND_TARGET is set.
    uint256 internal constant FUNDER_TOP_UPS = 10;

    /// @dev Gas the new owner needs for setOrchestrators plus setGasWallet, with headroom.
    uint256 internal constant CONFIGURE_GAS = 400_000;

    /// @dev Gas the old owner spends in `retire` (revoke signers, withdraw, two ownership
    /// transfers), held back when counting what it will sweep.
    uint256 internal constant RETIRE_GAS = 300_000;

    string internal configPath = "/deploy/config.toml";

    uint256 internal oldOwnerKey;
    address internal oldOwner;
    string internal oldMnemonic;
    address internal newOwner;
    address internal newFunderSigner;
    address[] internal newSigners;
    bytes internal newFunderArgs;
    address internal newFunder;

    struct RotationChain {
        uint256 id;
        string name;
        ISimpleFunder oldFunder;
        IOwnable orchestrator;
        address[] orchestrators;
        bytes32 salt;
    }

    function prepare(uint256[] memory chainIds) external {
        _setUp();
        for (uint256 i = 0; i < chainIds.length; i++) {
            _prepareChain(_selectChain(chainIds[i]));
        }
        console.log("\nNew SimpleFunder on every chain:", newFunder);
        console.log("Set it as `funder` in relay.yaml and `simple_funder_deployed` in config.toml");
    }

    function retire(uint256[] memory chainIds) external {
        _setUp();
        for (uint256 i = 0; i < chainIds.length; i++) {
            _retireChain(_selectChain(chainIds[i]));
        }
    }

    function run(uint256[] memory chainIds) external {
        _setUp();
        for (uint256 i = 0; i < chainIds.length; i++) {
            RotationChain memory chain = _selectChain(chainIds[i]);
            _prepareChain(chain);
            _retireChain(chain);
        }
        console.log("\nNew SimpleFunder on every chain:", newFunder);
        console.log("Set it as `funder` in relay.yaml and `simple_funder_deployed` in config.toml");
    }

    function _setUp() internal {
        _loadConfig(string.concat(vm.projectRoot(), configPath), false);
        _loadKeys();
    }

    function _loadKeys() internal {
        oldOwnerKey = vm.envUint("OLD_FUNDER_OWNER_KEY");
        oldOwner = vm.addr(oldOwnerKey);
        oldMnemonic = vm.envString("OLD_GAS_SIGNER_MNEMONIC");
        newOwner = vm.envAddress("NEW_FUNDER_OWNER");
        newFunderSigner = vm.envAddress("NEW_FUNDER_SIGNER");

        string memory newMnemonic = vm.envString("NEW_GAS_SIGNER_MNEMONIC");
        require(
            keccak256(bytes(newMnemonic)) != keccak256(bytes(oldMnemonic)),
            "new mnemonic equals old"
        );
        require(newOwner != address(0) && newOwner != oldOwner, "bad NEW_FUNDER_OWNER");
        require(newFunderSigner != address(0), "bad NEW_FUNDER_SIGNER");

        console.log("Old owner:        ", oldOwner);
        console.log("New owner:        ", newOwner);
        console.log("New funder signer:", newFunderSigner);
        // why: the relay derives its signers from index 0 up, so the new set must match
        // the relay's num_signers (3 on every chain in relay.yaml).
        for (uint256 i = 0; i < 3; i++) {
            newSigners.push(vm.addr(vm.deriveKey(newMnemonic, uint32(i))));
            console.log("New gas signer", i, newSigners[i]);
        }

        newFunderArgs = abi.encode(newFunderSigner, newOwner);
    }

    function _selectChain(uint256 chainId) internal returns (RotationChain memory chain) {
        chain.id = chainId;
        chain.name = config.get(chainId, "name").toString();
        chain.oldFunder = ISimpleFunder(config.get(chainId, "simple_funder_deployed").toAddress());
        chain.orchestrator = IOwnable(config.get(chainId, "orchestrator_deployed").toAddress());
        chain.orchestrators = _supportedOrchestrators(chainId, address(chain.orchestrator));
        chain.salt = config.get(chainId, "salt").toBytes32();

        vm.createSelectFork(vm.envString(string.concat("RPC_", vm.toString(chainId))));
        require(block.chainid == chainId, "chain id mismatch");
        console.log(string.concat("\n=== ", chain.name, " (", vm.toString(chainId), ") ==="));

        // why: one address on every chain is the point of the redeploy, so a chain whose salt
        // differs from the first one stops the run instead of splitting the set.
        address predicted =
            computeAddress(type(SimpleFunder).creationCode, newFunderArgs, chain.salt);
        if (newFunder == address(0)) newFunder = predicted;
        require(predicted == newFunder, "new SimpleFunder address differs across chains");
        require(predicted != address(chain.oldFunder), "new funder args equal the old ones");
    }

    function _prepareChain(RotationChain memory chain) internal {
        _deployNewFunder(chain.salt);
        _fundNewOwnerGas();
        _configureNewFunder(chain.orchestrators);
        _fundFloat(chain);
    }

    function _retireChain(RotationChain memory chain) internal {
        require(newFunder.code.length > 0, "run prepare on this chain first");
        _retireOldFunder(chain.oldFunder);
        _rotateOrchestrator(chain.orchestrator);
        _sweep(oldOwnerKey, newFunder, "old owner");
        _sweepOldSigners();
        _assertRotated(chain.oldFunder, chain.orchestrator, chain.orchestrators);
    }

    function _deployNewFunder(bytes32 salt) internal {
        if (newFunder.code.length > 0) {
            console.log("New SimpleFunder already deployed:", newFunder);
            return;
        }
        // why: the factory deploys the same contract whoever sends it, so the old owner pays
        // while it still holds gas; the sender has no rights over the result.
        address deployed =
            broadcastDeploy(oldOwnerKey, type(SimpleFunder).creationCode, newFunderArgs, salt);
        require(deployed == newFunder, "CREATE2 address mismatch");
        console.log("New SimpleFunder deployed:", newFunder);
    }

    /// @dev The new owner starts empty; the old owner sends it enough for its configure calls.
    function _fundNewOwnerGas() internal {
        // why: twice the live price, so a fee bump between this and the configure calls
        // does not leave them unpaid.
        uint256 needed = CONFIGURE_GAS * 2 * _gasPrice();
        if (newOwner.balance >= needed) return;
        _send(oldOwnerKey, newOwner, needed - newOwner.balance, "new owner gas");
    }

    function _configureNewFunder(address[] memory orchestrators) internal {
        ISimpleFunder funder = ISimpleFunder(newFunder);
        bool orchestratorsSet = true;
        for (uint256 i = 0; i < orchestrators.length; i++) {
            if (!funder.orchestrators(orchestrators[i])) orchestratorsSet = false;
        }
        bool signersSet = true;
        for (uint256 i = 0; i < newSigners.length; i++) {
            if (!funder.gasWallets(newSigners[i])) signersSet = false;
        }
        if (orchestratorsSet && signersSet) return;

        vm.startBroadcast(newOwner);
        // why: fund() reverts OnlyOrchestrator unless the relay's Orchestrator is allowed.
        if (!orchestratorsSet) funder.setOrchestrators(orchestrators, true);
        if (!signersSet) funder.setGasWallet(newSigners, true);
        vm.stopBroadcast();
        console.log("New SimpleFunder: orchestrators and gas wallets set");
    }

    /// @dev Tops the new signers up to one relay top-up each and the new funder up to the rest
    /// of the chain's float, paying from the old funder, then the old signers' surplus, then
    /// the new owner. Amounts already in place count, so a repeated pass sends only the gap.
    function _fundFloat(RotationChain memory chain) internal {
        uint256 price = _gasPrice();
        uint256 topUp = TOP_UP_GAS * price;
        uint256 signersFloat = topUp * newSigners.length;
        string memory targetVar = string.concat("FUND_TARGET_", vm.toString(chain.id));
        bool targetSet = vm.envExists(targetVar);
        uint256 target = targetSet ? vm.envUint(targetVar) : signersFloat + topUp * FUNDER_TOP_UPS;
        require(target >= signersFloat, "FUND_TARGET below one top-up per signer");
        console.log("Float target:", target, "per signer:", topUp);

        address[] memory dests = new address[](newSigners.length + 1);
        uint256[] memory gaps = new uint256[](dests.length);
        for (uint256 i = 0; i < newSigners.length; i++) {
            dests[i] = newSigners[i];
            gaps[i] = _gap(newSigners[i], topUp);
        }
        dests[newSigners.length] = newFunder;
        gaps[newSigners.length] = _gap(newFunder, target - signersFloat);

        _payFromOldFunder(chain.oldFunder, dests, gaps);
        for (uint256 i = 0; i < OLD_SIGNER_SCAN; i++) {
            uint256 key = vm.deriveKey(oldMnemonic, uint32(i));
            // why: the old signer keeps one top-up so the live relay still has gas until the
            // new one takes over.
            _payFromKey(key, topUp, dests, gaps, string.concat("old signer ", vm.toString(i)));
        }
        if (targetSet) {
            uint256 last = gaps.length - 1;
            gaps[last] -= _min(gaps[last], _pendingSweeps(chain.oldFunder, price));
        }
        _payFromNewOwner(dests, gaps);

        uint256 short;
        for (uint256 i = 0; i < gaps.length; i++) {
            short += gaps[i];
        }
        if (short > 0) {
            console.log("Float short by (wei), send it to the new owner and repeat:", short);
            revert("float short");
        }
        console.log("Float in place. New funder:", newFunder.balance);
    }

    /// @dev What `retire` will still move into the new funder: the old funder's rest, the old
    /// signers above their sweep reserve, and the old owner after its retire calls.
    function _pendingSweeps(ISimpleFunder oldFunder, uint256 price)
        internal
        view
        returns (uint256 pending)
    {
        uint256 reserve = _sweepReserve();
        if (oldFunder.owner() == oldOwner) pending += address(oldFunder).balance;
        for (uint256 i = 0; i < OLD_SIGNER_SCAN; i++) {
            uint256 balance = vm.addr(vm.deriveKey(oldMnemonic, uint32(i))).balance;
            if (balance > reserve) pending += balance - reserve;
        }
        uint256 ownerKeeps = reserve + RETIRE_GAS * 2 * price;
        if (oldOwner.balance > ownerKeeps) pending += oldOwner.balance - ownerKeeps;
    }

    function _payFromOldFunder(
        ISimpleFunder oldFunder,
        address[] memory dests,
        uint256[] memory gaps
    ) internal {
        // why: once retired, the old funder belongs to the new owner and is already empty.
        if (oldFunder.owner() != oldOwner) return;
        uint256 available = address(oldFunder).balance;
        for (uint256 i = 0; i < dests.length && available > 0; i++) {
            uint256 amount = _min(gaps[i], available);
            if (amount == 0) continue;
            vm.broadcast(oldOwnerKey);
            oldFunder.withdrawTokens(address(0), dests[i], amount);
            console.log("  old funder ->", dests[i], amount);
            gaps[i] -= amount;
            available -= amount;
        }
    }

    function _payFromKey(
        uint256 key,
        uint256 keep,
        address[] memory dests,
        uint256[] memory gaps,
        string memory label
    ) internal {
        address from = vm.addr(key);
        for (uint256 i = 0; i < dests.length; i++) {
            if (gaps[i] == 0) continue;
            uint256 reserve = keep + _sweepReserve();
            if (from.balance <= reserve) return;
            uint256 amount = _min(gaps[i], from.balance - reserve);
            _send(key, dests[i], amount, label);
            gaps[i] -= amount;
        }
    }

    function _payFromNewOwner(address[] memory dests, uint256[] memory gaps) internal {
        for (uint256 i = 0; i < dests.length; i++) {
            if (gaps[i] == 0) continue;
            uint256 reserve = _sweepReserve();
            if (newOwner.balance <= reserve) return;
            uint256 amount = _min(gaps[i], newOwner.balance - reserve);
            vm.broadcast(newOwner);
            (bool ok,) = dests[i].call{value: amount}("");
            require(ok, "transfer failed");
            console.log("  new owner ->", dests[i], amount);
            gaps[i] -= amount;
        }
    }

    /// @dev Empties the old funder into the new one and takes it away from the leaked key.
    function _retireOldFunder(ISimpleFunder oldFunder) internal {
        if (oldFunder.owner() != oldOwner) {
            require(oldFunder.owner() == newOwner, "old SimpleFunder owned by unknown key");
            console.log("Old SimpleFunder already retired");
            return;
        }
        address[] memory oldSigners = _oldGasWallets(oldFunder);
        uint256 balance = address(oldFunder).balance;

        vm.startBroadcast(oldOwnerKey);
        if (oldSigners.length > 0) oldFunder.setGasWallet(oldSigners, false);
        // Native only: the funder holds no ERC-20 on any chain (read 2026-10-22), and fees in
        // tokens go to fee_recipient, not here.
        if (balance > 0) oldFunder.withdrawTokens(address(0), newFunder, balance);
        oldFunder.transferOwnership(newOwner);
        vm.stopBroadcast();
        console.log("Old SimpleFunder emptied into new one:", balance);
    }

    function _rotateOrchestrator(IOwnable orchestrator) internal {
        if (orchestrator.owner() != oldOwner) {
            require(orchestrator.owner() == newOwner, "Orchestrator owned by unknown key");
            return;
        }
        vm.broadcast(oldOwnerKey);
        orchestrator.transferOwnership(newOwner);
        console.log("Orchestrator ownership moved to new owner");
    }

    function _supportedOrchestrators(uint256 chainId, address deployed)
        internal
        view
        returns (address[] memory supported)
    {
        supported = config.get(chainId, "supported_orchestrators").toAddressArray();
        for (uint256 i = 0; i < supported.length; i++) {
            if (supported[i] == deployed) return supported;
        }
        revert("supported_orchestrators must include orchestrator_deployed");
    }

    /// @dev Old mnemonic signers that are still gas wallets on the old funder.
    function _oldGasWallets(ISimpleFunder funder) internal view returns (address[] memory) {
        address[] memory found = new address[](OLD_SIGNER_SCAN);
        uint256 n;
        for (uint256 i = 0; i < OLD_SIGNER_SCAN; i++) {
            address signer = vm.addr(vm.deriveKey(oldMnemonic, uint32(i)));
            if (funder.gasWallets(signer)) found[n++] = signer;
        }
        // Shrink the array to the signers found.
        assembly ("memory-safe") {
            mstore(found, n)
        }
        return found;
    }

    /// @dev The new signers were funded in `prepare`, so what the old signers hold goes to the
    /// new funder, where only the owner can withdraw it. The old owner's rest goes there too.
    function _sweepOldSigners() internal {
        for (uint256 i = 0; i < OLD_SIGNER_SCAN; i++) {
            uint256 key = vm.deriveKey(oldMnemonic, uint32(i));
            _sweep(key, newFunder, string.concat("old signer ", vm.toString(i)));
        }
    }

    function _sweep(uint256 key, address to, string memory label) internal {
        uint256 reserve = _sweepReserve();
        uint256 balance = vm.addr(key).balance;
        if (balance <= reserve) {
            if (balance > 0) console.log(string.concat("  ", label, ": dust left"), balance);
            return;
        }
        _send(key, to, balance - reserve, label);
    }

    function _send(uint256 key, address to, uint256 amount, string memory label) internal {
        vm.broadcast(key);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        console.log(string.concat("  ", label, " ->"), to, amount);
    }

    function _tip() internal view returns (uint256 tip) {
        tip = vm.envOr("SWEEP_TIP_WEI", uint256(1 gwei));
        // why: Polygon rejects tips under 25 gwei, so 1 gwei would leave a transfer unmined.
        if (block.chainid == 137 && tip < 30 gwei) tip = 30 gwei;
    }

    /// @dev The chain's own eth_gasPrice (base fee plus its usual tip). A fixed tip would
    /// overstate cheap chains: 1 gwei is about 170 times Base's whole price.
    function _gasPrice() internal returns (uint256 price) {
        bytes memory raw = vm.rpc("eth_gasPrice", "[]");
        for (uint256 i = 0; i < raw.length; i++) {
            price = (price << 8) | uint8(raw[i]);
        }
    }

    function _sweepReserve() internal view returns (uint256) {
        return SWEEP_RESERVE_GAS * (3 * block.basefee + _tip());
    }

    function _gap(address account, uint256 wanted) internal view returns (uint256) {
        return account.balance >= wanted ? 0 : wanted - account.balance;
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function _assertRotated(
        ISimpleFunder oldFunder,
        IOwnable orchestrator,
        address[] memory orchestrators
    ) internal view {
        ISimpleFunder funder = ISimpleFunder(newFunder);
        require(funder.owner() == newOwner, "new SimpleFunder owner wrong");
        require(funder.funder() == newFunderSigner, "new SimpleFunder signer wrong");
        for (uint256 i = 0; i < orchestrators.length; i++) {
            require(funder.orchestrators(orchestrators[i]), "orchestrator not allowed");
        }
        for (uint256 i = 0; i < newSigners.length; i++) {
            require(funder.gasWallets(newSigners[i]), "new signer is not a gas wallet");
        }
        require(orchestrator.owner() == newOwner, "Orchestrator owner not rotated");
        require(oldFunder.owner() == newOwner, "old SimpleFunder owner not rotated");
        require(address(oldFunder).balance == 0, "old SimpleFunder not empty");
        for (uint256 i = 0; i < OLD_SIGNER_SCAN; i++) {
            require(
                !oldFunder.gasWallets(vm.addr(vm.deriveKey(oldMnemonic, uint32(i)))),
                "old signer still a gas wallet"
            );
        }
        console.log("Rotated. New funder balance:", newFunder.balance);
    }
}
