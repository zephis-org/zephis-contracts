// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../src/verifiers/TLSNVerifier.sol";

/**
 * @title TestTLSNVerifierInternal
 * @dev Test contract to expose internal functions for testing uncovered branches
 */
contract TestTLSNVerifierInternal is TLSNVerifier {
    constructor(address initialNotary) TLSNVerifier(initialNotary) {}
    
    // Expose internal verification for testing
    function testVerifyTLSNProofInternal(TLSNProofComponents memory components) 
        external 
        view 
        returns (bool) 
    {
        return _verifyTLSNProofInternal(components);
    }
    
    // Expose internal notary validation for testing
    function testValidateNotarySignature(TLSNProofComponents memory components) 
        external 
        pure 
        returns (bool) 
    {
        return _validateNotarySignature(components);
    }
    
    // Expose internal transcript validation for testing
    function testValidateTranscriptIntegrity(TLSNProofComponents memory components) 
        external 
        pure 
        returns (bool) 
    {
        return _validateTranscriptIntegrity(components);
    }
}