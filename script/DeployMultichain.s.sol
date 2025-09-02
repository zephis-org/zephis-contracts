// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {MockDeployer} from "./Deploy.s.sol";

contract DeployMultichain is Script {
    struct NetworkConfig {
        string name;
        string rpcUrl;
        uint256 chainId;
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        NetworkConfig[] memory networks = new NetworkConfig[](7);

        // Mainnet configurations
        networks[0] = NetworkConfig("Ethereum Mainnet", vm.envString("ETHEREUM_RPC_URL"), 1);
        networks[1] = NetworkConfig("Polygon", vm.envString("POLYGON_RPC_URL"), 137);
        networks[2] = NetworkConfig("Arbitrum One", vm.envString("ARBITRUM_RPC_URL"), 42161);
        networks[3] = NetworkConfig("Optimism", vm.envString("OPTIMISM_RPC_URL"), 10);
        networks[4] = NetworkConfig("Base", vm.envString("BASE_RPC_URL"), 8453);

        // Testnet configurations
        networks[5] = NetworkConfig("Sepolia", vm.envString("SEPOLIA_RPC_URL"), 11155111);
        networks[6] = NetworkConfig("Polygon Mumbai", vm.envString("MUMBAI_RPC_URL"), 80001);

        console.log("=== ZEPHIS Multi-chain Deployment ===");
        console.log("Deployer:", vm.addr(deployerPrivateKey));
        console.log("");

        for (uint256 i = 0; i < networks.length; i++) {
            if (bytes(networks[i].rpcUrl).length == 0) {
                console.log("Skipping", networks[i].name, "- RPC URL not configured");
                continue;
            }

            console.log("Deploying to", networks[i].name, "...");

            vm.createSelectFork(networks[i].rpcUrl);
            vm.startBroadcast(deployerPrivateKey);

            MockDeployer mock = new MockDeployer();

            console.log("  Deployed at:", address(mock));
            console.log("  Chain ID:", networks[i].chainId);
            console.log("");

            vm.stopBroadcast();
        }

        console.log("=== Multi-chain Deployment Complete ===");
    }
}
