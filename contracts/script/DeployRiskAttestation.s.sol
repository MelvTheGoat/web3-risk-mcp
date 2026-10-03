// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {RiskAttestation} from "../src/RiskAttestation.sol";

/// @notice Deploys RiskAttestation. You sign the deployment with your own key,
/// on your own machine. See contracts/README.md for the full steps.
///
/// Recommended: an encrypted keystore (the key never sits in a file in plain text).
///   arc-cast wallet import arc-deployer --interactive
///   arc-forge script script/DeployRiskAttestation.s.sol --rpc-url arc --account arc-deployer --broadcast
///
/// Alternative: an environment variable, set only in your own terminal.
///   export DEPLOYER_PRIVATE_KEY=0x...   (never commit it, never paste it anywhere else)
///   arc-forge script script/DeployRiskAttestation.s.sol --rpc-url arc --broadcast
contract DeployRiskAttestation is Script {
    function run() external returns (RiskAttestation deployed) {
        uint256 key = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (key != 0) {
            vm.startBroadcast(key);
        } else {
            // Uses the wallet given on the command line, such as --account <keystore>.
            vm.startBroadcast();
        }
        deployed = new RiskAttestation();
        vm.stopBroadcast();
        console.log("RiskAttestation deployed at:", address(deployed));
    }
}
