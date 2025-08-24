// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/core/ZKTLSVerifier.sol";
import "../src/registries/TrustedCAs.sol";

contract ZKTLSVerifierTest is Test {
    ZKTLSVerifier public verifier;
    TrustedCAs public trustedCAs;
    
    address public admin = address(0x1);
    address public user = address(0x2);

    function setUp() public {
        vm.startPrank(admin);
        
        trustedCAs = new TrustedCAs();
        verifier = new ZKTLSVerifier();
        
        vm.stopPrank();
    }

    function testInitialState() public view {
        assertTrue(verifier.hasRole(verifier.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(verifier.hasRole(verifier.VERIFIER_ROLE(), admin));
        assertTrue(verifier.hasRole(verifier.CIRCUIT_MANAGER_ROLE(), admin));
    }

    function testSetCircuitVerifier() public {
        address mockVerifier = address(0x123);
        uint256 circuitId = 1;

        vm.prank(admin);
        verifier.setCircuitVerifier(circuitId, mockVerifier);

        assertEq(verifier.getCircuitVerifier(circuitId), mockVerifier);
    }

    function testVerifyTLSProofInvalidCircuit() public {
        IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(999), uint256(1)]
        });

        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.InvalidCircuitId.selector);
        verifier.verifyTLSProof(proof);
    }

    function testVerifyTLSProofInvalidSession() public {
        IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(0),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.InvalidSessionId.selector);
        verifier.verifyTLSProof(proof);
    }

    function testIsValidSessionInitiallyFalse() public view {
        bytes32 sessionId = bytes32(uint256(1));
        assertFalse(verifier.isValidSession(sessionId));
    }

    function testGetVerificationResultEmpty() public view {
        bytes32 sessionId = bytes32(uint256(1));
        IZKTLSVerifier.VerificationResult memory result = verifier.getVerificationResult(sessionId);
        
        assertFalse(result.isValid);
        assertEq(result.sessionId, bytes32(0));
        assertEq(result.verifier, address(0));
        assertEq(result.timestamp, 0);
        assertEq(result.dataHash, bytes32(0));
    }

    function testGetSessionVerifier() public view {
        bytes32 sessionId = bytes32(uint256(1));
        address sessionVerifier = verifier.getSessionVerifier(sessionId);
        assertEq(sessionVerifier, address(0));
    }
    
    function testVerifyTLSProofInvalidCommitments() public {
        // Test handshake commitment zero
        IZKTLSVerifier.TLSProof memory proof1 = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(0), // Invalid
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.InvalidCommitment.selector);
        verifier.verifyTLSProof(proof1);
        
        // Test key commitment zero
        IZKTLSVerifier.TLSProof memory proof2 = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(0), // Invalid
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.InvalidCommitment.selector);
        verifier.verifyTLSProof(proof2);
        
        // Test transcript root zero
        IZKTLSVerifier.TLSProof memory proof3 = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(0), // Invalid
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.InvalidMerkleRoot.selector);
        verifier.verifyTLSProof(proof3);
    }
    
    function testSuccessfulProofVerification() public {
        // Setup mock verifier contract
        MockGroth16Verifier mockVerifier = new MockGroth16Verifier();
        mockVerifier.setResult(true);
        
        vm.prank(admin);
        verifier.setCircuitVerifier(1, address(mockVerifier));
        
        IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        bool result = verifier.verifyTLSProof(proof);
        assertTrue(result);
        
        // Check session is now valid
        assertTrue(verifier.isValidSession(proof.sessionId));
        
        // Check verification result
        IZKTLSVerifier.VerificationResult memory verResult = verifier.getVerificationResult(proof.sessionId);
        assertTrue(verResult.isValid);
        assertEq(verResult.sessionId, proof.sessionId);
        assertEq(verResult.verifier, admin);
    }
    
    function testSessionAlreadyExists() public {
        MockGroth16Verifier mockVerifier = new MockGroth16Verifier();
        mockVerifier.setResult(true);
        
        vm.prank(admin);
        verifier.setCircuitVerifier(1, address(mockVerifier));
        
        IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        verifier.verifyTLSProof(proof);
        
        // Try to verify same session again
        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.SessionAlreadyExists.selector);
        verifier.verifyTLSProof(proof);
    }
    
    function testProofVerificationFailed() public {
        MockGroth16Verifier mockVerifier = new MockGroth16Verifier();
        mockVerifier.setResult(false); // Verification will fail
        
        vm.prank(admin);
        verifier.setCircuitVerifier(1, address(mockVerifier));
        
        IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        vm.expectRevert(ZKTLSVerifierErrors.ProofVerificationFailed.selector);
        verifier.verifyTLSProof(proof);
        
        // Session should not be valid
        assertFalse(verifier.isValidSession(proof.sessionId));
    }
    
    function testSessionValidityExpiry() public {
        MockGroth16Verifier mockVerifier = new MockGroth16Verifier();
        mockVerifier.setResult(true);
        
        vm.prank(admin);
        verifier.setCircuitVerifier(1, address(mockVerifier));
        
        IZKTLSVerifier.TLSProof memory proof = IZKTLSVerifier.TLSProof({
            sessionId: bytes32(uint256(1)),
            handshakeCommitment: bytes32(uint256(2)),
            keyCommitment: bytes32(uint256(3)),
            transcriptRoot: bytes32(uint256(4)),
            groth16Proof: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)],
            publicInputs: [uint256(1), uint256(1)]
        });

        vm.prank(admin);
        verifier.verifyTLSProof(proof);
        
        // Initially valid
        assertTrue(verifier.isValidSession(proof.sessionId));
        
        // Warp time beyond validity period (3600 seconds + 1)
        vm.warp(block.timestamp + 3601);
        
        // Should no longer be valid
        assertFalse(verifier.isValidSession(proof.sessionId));
    }
}

// Mock Groth16 verifier contract for testing
contract MockGroth16Verifier {
    bool private _result = true;
    
    function setResult(bool result) external {
        _result = result;
    }
    
    // Receive function to handle ether
    receive() external payable {}
    
    // This function gets called via staticcall from ZKTLSVerifier._verifyGroth16Proof
    fallback() external payable {
        // Return the mock result as encoded bytes
        bytes memory result = abi.encode(_result);
        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}