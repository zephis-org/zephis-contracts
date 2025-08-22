// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/verifiers/ZKProofVerifier.sol";

contract ZKProofVerifierBranchCoverageTest is Test {
    ZKProofVerifier public verifier;
    address public owner;
    address public verifierRole;
    address public user1;

    function setUp() public {
        owner = address(this);
        verifierRole = makeAddr("verifierRole");
        user1 = makeAddr("user1");

        verifier = new ZKProofVerifier();
        verifier.grantRole(verifier.VERIFIER_ROLE(), verifierRole);
        verifier.grantRole(verifier.CHALLENGER_ROLE(), makeAddr("challenger"));
    }

    function createSampleProof() internal pure returns (IZKProofVerifier.ProofData memory) {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("test_input");

        return IZKProofVerifier.ProofData({
            proofId: bytes32(0),
            sessionId: keccak256("test_session"),
            proofType: IZKProofVerifier.ProofType.TLSN,
            proof: abi.encode("test_proof_data"),
            publicInputs: publicInputs,
            commitment: keccak256("test_commitment"),
            circuitId: "test_circuit",
            timestamp: 0,
            submitter: address(0)
        });
    }

    // Test _submitProofInternal branches for require statements
    function testSubmitProofInvalidProofType() public {
        IZKProofVerifier.ProofData memory proofData = createSampleProof();
        
        // Disable TLSN to make it unsupported
        verifier.updateProofTypeSupport(IZKProofVerifier.ProofType.TLSN, false);
        
        vm.prank(user1);
        vm.expectRevert("ZKProofVerifier: Unsupported proof type");
        verifier.submitProof(proofData);
    }

    // Note: sessionId and commitment validations are not implemented in the contract

    function testSubmitProofEmptyCircuitId() public {
        IZKProofVerifier.ProofData memory proofData = createSampleProof();
        proofData.circuitId = ""; // Empty circuit ID
        
        vm.prank(user1);
        vm.expectRevert("ZKProofVerifier: Empty circuit ID");
        verifier.submitProof(proofData);
    }

    function testSubmitProofAlreadyExists() public {
        IZKProofVerifier.ProofData memory proofData = createSampleProof();
        
        vm.prank(user1);
        verifier.submitProof(proofData);
        
        // Submit same proof again (same session, type, commitment should generate same ID)
        vm.prank(user1);
        vm.expectRevert("ZKProofVerifier: Proof already exists");
        verifier.submitProof(proofData);
    }

    // Test all other missing branches
    function testVerifyProofNotFound() public {
        bytes32 fakeProofId = keccak256("fake");
        
        vm.prank(verifierRole);
        vm.expectRevert("ZKProofVerifier: Proof not found");
        verifier.verifyProof(fakeProofId);
    }

    function testVerifyProofAlreadyVerified() public {
        IZKProofVerifier.ProofData memory proofData = createSampleProof();
        
        vm.prank(user1);
        bytes32 proofId = verifier.submitProof(proofData);
        
        // First verification
        vm.prank(verifierRole);
        verifier.verifyProof(proofId);
        
        // Second verification attempt
        vm.prank(verifierRole);
        vm.expectRevert("ZKProofVerifier: Already verified");
        verifier.verifyProof(proofId);
    }

    function testBatchVerifyEmptyArray() public {
        bytes32[] memory emptyArray = new bytes32[](0);
        
        vm.prank(verifierRole);
        vm.expectRevert("ZKProofVerifier: Empty proof list");
        verifier.batchVerifyProofs(emptyArray);
    }

    function testBatchVerifyTooManyProofs() public {
        bytes32[] memory tooManyProofs = new bytes32[](101); // More than MAX_BATCH_SIZE (100)
        
        vm.prank(verifierRole);
        vm.expectRevert("ZKProofVerifier: Batch too large");
        verifier.batchVerifyProofs(tooManyProofs);
    }

    function testGetProofsBySubmitterLimitTooLarge() public {
        vm.expectRevert("ZKProofVerifier: Invalid limit");
        verifier.getProofsBySubmitter(user1, 0, 101); // More than MAX_QUERY_LIMIT (100)
    }

    function testUpdateProofTypeSupportUnauthorized() public {
        vm.prank(user1); // Not admin
        vm.expectRevert();
        verifier.updateProofTypeSupport(IZKProofVerifier.ProofType.CUSTOM, true);
    }

    function testGetVerificationStatsWithChallenges() public {
        IZKProofVerifier.ProofData memory proofData = createSampleProof();
        
        vm.prank(user1);
        bytes32 proofId = verifier.submitProof(proofData);
        
        // Verify the proof first
        vm.prank(verifierRole);
        verifier.verifyProof(proofId);
        
        // Challenge the proof
        vm.prank(makeAddr("challenger"));
        verifier.challengeProof(proofId, "Invalid proof");
        
        (, uint256 successfulVerifications, uint256 challengedCount,) = verifier.getVerificationStats();
        assertEq(challengedCount, 1);
        assertEq(successfulVerifications, 1);
    }
}