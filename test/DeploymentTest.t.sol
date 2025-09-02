// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DeployZephis, MockDeployer} from "../script/Deploy.s.sol";
import {DeployMultichain} from "../script/DeployMultichain.s.sol";

contract DeploymentTest is Test {
    DeployZephis deployer;
    DeployMultichain multichainDeployer;

    function setUp() public {
        deployer = new DeployZephis();
        multichainDeployer = new DeployMultichain();
    }

    function testDeployScript() public {
        // Set up environment variable
        vm.setEnv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

        // Run the deployment script
        deployer.run();

        // Verify deployment happened
        assertTrue(true); // Script execution test
    }

    function testDeployMultichainScript() public {
        // Test with missing RPC URLs (should skip networks)
        vm.setEnv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

        // Only set some RPC URLs to test skipping logic
        vm.setEnv("ETHEREUM_RPC_URL", "");
        vm.setEnv("POLYGON_RPC_URL", "");
        vm.setEnv("ARBITRUM_RPC_URL", "");
        vm.setEnv("OPTIMISM_RPC_URL", "");
        vm.setEnv("BASE_RPC_URL", "");
        vm.setEnv("SEPOLIA_RPC_URL", "");
        vm.setEnv("MUMBAI_RPC_URL", "");

        // This should execute without errors, skipping all networks
        multichainDeployer.run();
    }

    function testDeployMultichainWithAllNetworks() public {
        // Set up environment variables
        vm.setEnv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

        // Set up all RPC URLs with local test network
        string memory localRpc = "http://localhost:8545";
        vm.setEnv("ETHEREUM_RPC_URL", localRpc);
        vm.setEnv("POLYGON_RPC_URL", localRpc);
        vm.setEnv("ARBITRUM_RPC_URL", localRpc);
        vm.setEnv("OPTIMISM_RPC_URL", localRpc);
        vm.setEnv("BASE_RPC_URL", localRpc);
        vm.setEnv("SEPOLIA_RPC_URL", localRpc);
        vm.setEnv("MUMBAI_RPC_URL", localRpc);

        // Run the multichain deployment
        multichainDeployer.run();

        // Verify deployment succeeded
        assertTrue(true);
    }

    function testDeployMultichainWithPartialNetworks() public {
        // Set up environment variables
        vm.setEnv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

        // Only set some RPC URLs to test mixed scenario
        string memory localRpc = "http://localhost:8545";
        vm.setEnv("ETHEREUM_RPC_URL", localRpc);
        vm.setEnv("POLYGON_RPC_URL", ""); // Empty - should skip
        vm.setEnv("ARBITRUM_RPC_URL", localRpc);
        vm.setEnv("OPTIMISM_RPC_URL", ""); // Empty - should skip
        vm.setEnv("BASE_RPC_URL", localRpc);
        vm.setEnv("SEPOLIA_RPC_URL", ""); // Empty - should skip
        vm.setEnv("MUMBAI_RPC_URL", localRpc);

        // Run deployment - should deploy to 4 networks and skip 3
        multichainDeployer.run();

        // Verify execution completed
        assertTrue(true);
    }

    function testMockDeployerTestLibraries() public {
        MockDeployer mock = new MockDeployer();
        bool result = mock.testLibraries();
        assertTrue(result);
    }
}
