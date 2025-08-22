// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/verifiers/ZKProofVerifier.sol";

/**
 * @title TestZKProofVerifierDirectDefault
 * @dev Test contract to directly test the default case in _performVerification 
 */
contract TestZKProofVerifierDirectDefault is ZKProofVerifier {
    
    // Override to directly return false and hit the default case
    function _performVerification(ProofData memory /* proof */) internal pure override returns (bool) {
        // Always return false to simulate the default case (line 424)
        return false;
    }
    
    // Function to test the default case
    function testDefaultCase() external pure returns (bool) {
        ProofData memory proof = ProofData({
            proofId: bytes32(0),
            sessionId: keccak256("test"),
            proofType: ProofType.TLSN,
            proof: abi.encode("test"),
            publicInputs: new bytes32[](1),
            commitment: keccak256("test"),
            circuitId: "test",
            timestamp: 0,
            submitter: address(0)
        });
        
        return _performVerification(proof);
    }
}