// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ZKTLSVerifier} from "../src/core/ZKTLSVerifier.sol";
import {HandshakeProof} from "../src/core/HandshakeProof.sol";
import {SessionKeyCommitment} from "../src/core/SessionKeyCommitment.sol";
import {TranscriptProof} from "../src/core/TranscriptProof.sol";
import {TrustedCAs} from "../src/registries/TrustedCAs.sol";

contract DeployScript is Script {
    struct DeployedContracts {
        address zkTLSVerifier;
        address handshakeProof;
        address sessionKeyCommitment;
        address transcriptProof;
        address trustedCAs;
    }

    function run() public returns (DeployedContracts memory deployed) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying ZEPHIS Protocol contracts...");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        deployed = _deployAllContracts();
        _configureContracts(deployed);
        _verifyDeployment(deployed);

        vm.stopBroadcast();

        _logDeploymentSummary(deployed);
        return deployed;
    }

    function _deployAllContracts() internal returns (DeployedContracts memory deployed) {
        console.log("\n=== Deploying Core Contracts ===");

        deployed.trustedCAs = address(new TrustedCAs());
        console.log("TrustedCAs deployed at:", deployed.trustedCAs);

        deployed.handshakeProof = address(new HandshakeProof(deployed.trustedCAs));
        console.log("HandshakeProof deployed at:", deployed.handshakeProof);

        deployed.sessionKeyCommitment = address(new SessionKeyCommitment());
        console.log("SessionKeyCommitment deployed at:", deployed.sessionKeyCommitment);

        deployed.transcriptProof = address(new TranscriptProof());
        console.log("TranscriptProof deployed at:", deployed.transcriptProof);

        deployed.zkTLSVerifier = address(new ZKTLSVerifier());
        console.log("ZKTLSVerifier deployed at:", deployed.zkTLSVerifier);
    }

    function _configureContracts(DeployedContracts memory deployed) internal {
        console.log("\n=== Configuring Contracts ===");

        HandshakeProof handshakeProof = HandshakeProof(deployed.handshakeProof);
        SessionKeyCommitment sessionKeyCommitment = SessionKeyCommitment(deployed.sessionKeyCommitment);
        TranscriptProof transcriptProof = TranscriptProof(deployed.transcriptProof);
        ZKTLSVerifier zkTLSVerifier = ZKTLSVerifier(deployed.zkTLSVerifier);

        bytes32 verifierRole = zkTLSVerifier.VERIFIER_ROLE();
        zkTLSVerifier.grantRole(verifierRole, deployed.handshakeProof);
        zkTLSVerifier.grantRole(verifierRole, deployed.sessionKeyCommitment);
        zkTLSVerifier.grantRole(verifierRole, deployed.transcriptProof);

        console.log("Granted VERIFIER_ROLE to component contracts");

        console.log("Basic role configuration completed");
    }

    function _verifyDeployment(DeployedContracts memory deployed) internal view {
        console.log("\n=== Verifying Deployment ===");

        require(deployed.zkTLSVerifier != address(0), "ZKTLSVerifier not deployed");
        require(deployed.handshakeProof != address(0), "HandshakeProof not deployed");
        require(deployed.sessionKeyCommitment != address(0), "SessionKeyCommitment not deployed");
        require(deployed.transcriptProof != address(0), "TranscriptProof not deployed");
        require(deployed.trustedCAs != address(0), "TrustedCAs not deployed");

        require(deployed.zkTLSVerifier.code.length > 0, "ZKTLSVerifier has no code");
        require(deployed.handshakeProof.code.length > 0, "HandshakeProof has no code");
        require(deployed.sessionKeyCommitment.code.length > 0, "SessionKeyCommitment has no code");
        require(deployed.transcriptProof.code.length > 0, "TranscriptProof has no code");
        require(deployed.trustedCAs.code.length > 0, "TrustedCAs has no code");

        console.log("All contracts deployed successfully");
    }

    function _logDeploymentSummary(DeployedContracts memory deployed) internal view {
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log("Network:", _getNetworkName());
        console.log("Block Number:", block.number);
        console.log("Timestamp:", block.timestamp);
        console.log("");
        console.log("Contract Addresses:");
        console.log("- ZKTLSVerifier:        %s", deployed.zkTLSVerifier);
        console.log("- HandshakeProof:       %s", deployed.handshakeProof);
        console.log("- SessionKeyCommitment: %s", deployed.sessionKeyCommitment);
        console.log("- TranscriptProof:      %s", deployed.transcriptProof);
        console.log("- TrustedCAs:           %s", deployed.trustedCAs);
        console.log("");
        console.log("Save these addresses for integration!");
    }

    function _getNetworkName() internal view returns (string memory) {
        if (block.chainid == 1) return "Mainnet";
        if (block.chainid == 11155111) return "Sepolia";
        if (block.chainid == 31337) return "Local";
        return "Unknown";
    }
}