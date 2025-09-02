// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {ZephisVerifier} from "../src/ZephisVerifier.sol";
import {MathUtils} from "../src/utils/MathUtils.sol";
import {SecurityUtils} from "../src/utils/SecurityUtils.sol";

contract DeployZephis is Script {
    function run() external returns (address zephisVerifier) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        uint256 bn254FieldModulus = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        uint256 bn254GroupOrder = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        ZephisVerifier verifier = new ZephisVerifier(deployer, bn254FieldModulus, bn254GroupOrder);
        zephisVerifier = address(verifier);

        MockDeployer mock = new MockDeployer();
        mock.testLibraries();

        vm.stopBroadcast();

        return zephisVerifier;
    }
}

contract MockDeployer {
    using MathUtils for uint256;
    using SecurityUtils for bytes32;

    function testLibraries() external pure returns (bool) {
        uint256 a = MathUtils.add(5, 3);
        bytes32 hash = SecurityUtils.hashMessage("test");
        return a == 8 && hash != bytes32(0);
    }
}
