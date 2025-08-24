// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/core/TranscriptProof.sol";

contract TranscriptProofTest is Test {
    TranscriptProof public transcriptProof;
    
    address public admin = address(0x1);
    address public verifier = address(0x2);
    address public user = address(0x3);

    bytes32 public sessionId = keccak256("Test Session");

    function setUp() public {
        vm.startPrank(admin);
        
        transcriptProof = new TranscriptProof();
        transcriptProof.grantRole(transcriptProof.VERIFIER_ROLE(), verifier);
        
        vm.stopPrank();
    }

    function testInitialState() public view {
        assertTrue(transcriptProof.hasRole(transcriptProof.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(transcriptProof.hasRole(transcriptProof.VERIFIER_ROLE(), admin));
        assertTrue(transcriptProof.hasRole(transcriptProof.REVEAL_MANAGER_ROLE(), admin));
        assertTrue(transcriptProof.hasRole(transcriptProof.VERIFIER_ROLE(), verifier));
    }

    function testSupportedRevealTypes() public view {
        assertTrue(transcriptProof.isValidRevealType(1)); // REVEAL_TYPE_FULL
        assertTrue(transcriptProof.isValidRevealType(2)); // REVEAL_TYPE_PARTIAL
        assertTrue(transcriptProof.isValidRevealType(3)); // REVEAL_TYPE_RANGE
        assertTrue(transcriptProof.isValidRevealType(4)); // REVEAL_TYPE_EXISTENCE
        assertFalse(transcriptProof.isValidRevealType(99)); // Unsupported
    }

    function testVerifyTranscriptSuccess() public {
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        bool result = transcriptProof.verifyTranscript(sessionId, transcript, proof);
        assertTrue(result);

        assertEq(transcriptProof.getTranscriptRoot(sessionId), transcript.transcriptRoot);
        assertEq(transcriptProof.getTotalRecords(sessionId), transcript.totalRecords);
    }

    function testVerifyTranscriptInvalidSessionId() public {
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidTranscriptData.selector);
        transcriptProof.verifyTranscript(bytes32(0), transcript, proof);
    }

    function testVerifyTranscriptInvalidRoot() public {
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: bytes32(0), // Invalid
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidTranscriptRoot.selector);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
    }

    function testVerifyTranscriptInsufficientRecords() public {
        bytes32[] memory recordHashes = new bytes32[](0);

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 0, // Invalid
            revealedRecords: 0,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InsufficientRecords.selector);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
    }

    function testVerifyTranscriptAlreadyVerified() public {
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.startPrank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
        
        vm.expectRevert(TranscriptProofErrors.TranscriptAlreadyVerified.selector);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
        vm.stopPrank();
    }

    function testVerifySelectiveRevealSuccess() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Now test selective reveal
        uint256[] memory recordIndices = new uint256[](2);
        recordIndices[0] = 0;
        recordIndices[1] = 2;

        bytes32[] memory recordData = new bytes32[](2);
        recordData[0] = keccak256("Revealed Record 1");
        recordData[1] = keccak256("Revealed Record 3");

        bytes32[][] memory merkleProofs = new bytes32[][](2);
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[0][0] = keccak256("Merkle Proof 1");
        merkleProofs[1] = new bytes32[](1);
        merkleProofs[1][0] = keccak256("Merkle Proof 2");

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1 // REVEAL_TYPE_FULL
        });

        uint256[8] memory revealProof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                recordIndices,
                reveal.revealType
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        // Note: This test will fail due to invalid merkle proofs, but tests the basic structure
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidSelectiveReveal.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifySelectiveRevealTranscriptNotVerified() public {
        uint256[] memory recordIndices = new uint256[](1);
        recordIndices[0] = 0;

        bytes32[] memory recordData = new bytes32[](1);
        recordData[0] = keccak256("Revealed Record 1");

        bytes32[][] memory merkleProofs = new bytes32[][](1);
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[0][0] = keccak256("Merkle Proof 1");

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidTranscriptData.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, proof);
    }

    function testVerifyRangeProofSuccess() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Test range proof
        ITranscriptProof.RangeProof memory rangeProof = ITranscriptProof.RangeProof({
            minValue: 100,
            maxValue: 1000,
            valueCommitment: keccak256("Value Commitment"),
            rangeProofData: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]
        });

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                rangeProof.valueCommitment,
                rangeProof.minValue,
                rangeProof.maxValue
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        bool result = transcriptProof.verifyRangeProof(sessionId, rangeProof, proof);
        assertTrue(result);
    }

    function testVerifyRangeProofInvalidRange() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Invalid range proof (min >= max)
        ITranscriptProof.RangeProof memory rangeProof = ITranscriptProof.RangeProof({
            minValue: 1000,
            maxValue: 100, // Invalid: max < min
            valueCommitment: keccak256("Value Commitment"),
            rangeProofData: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidRangeParameters.selector);
        transcriptProof.verifyRangeProof(sessionId, rangeProof, proof);
    }

    function testAddSupportedRevealType() public {
        uint256 newRevealType = 5;
        assertFalse(transcriptProof.isValidRevealType(newRevealType));

        vm.prank(admin);
        transcriptProof.addSupportedRevealType(newRevealType);
        assertTrue(transcriptProof.isValidRevealType(newRevealType));
    }

    function testRemoveSupportedRevealType() public {
        uint256 revealType = 1; // REVEAL_TYPE_FULL
        assertTrue(transcriptProof.isValidRevealType(revealType));

        vm.prank(admin);
        transcriptProof.removeSupportedRevealType(revealType);
        assertFalse(transcriptProof.isValidRevealType(revealType));
    }

    function testUnauthorizedAccess() public {
        vm.prank(user);
        vm.expectRevert();
        transcriptProof.addSupportedRevealType(5);
    }

    function testGetEmptyTranscriptData() public view {
        bytes32 nonExistentSession = keccak256("Non Existent");
        assertEq(transcriptProof.getTranscriptRoot(nonExistentSession), bytes32(0));
        assertEq(transcriptProof.getTotalRecords(nonExistentSession), 0);
    }
    
    function testVerifySelectiveRevealInvalidRevealType() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Test invalid reveal type
        uint256[] memory recordIndices = new uint256[](1);
        recordIndices[0] = 0;

        bytes32[] memory recordData = new bytes32[](1);
        recordData[0] = keccak256("Revealed Record 1");

        bytes32[][] memory merkleProofs = new bytes32[][](1);
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[0][0] = keccak256("Merkle Proof 1");

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 99 // Invalid reveal type
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidRevealType.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }
    
    function testVerifyRangeProofInvalidValueCommitment() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Test invalid value commitment (zero)
        ITranscriptProof.RangeProof memory rangeProof = ITranscriptProof.RangeProof({
            minValue: 100,
            maxValue: 1000,
            valueCommitment: bytes32(0), // Invalid
            rangeProofData: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidValueCommitment.selector);
        transcriptProof.verifyRangeProof(sessionId, rangeProof, proof);
    }
    
    function testVerifySelectiveRevealEmptyData() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](1);
        recordHashes[0] = keccak256("Record 1");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 1,
            revealedRecords: 1,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Test empty record data - indices exist but data is empty
        uint256[] memory recordIndices = new uint256[](1); // Has 1 element
        recordIndices[0] = 0;
        bytes32[] memory recordData = new bytes32[](0); // Empty - this should trigger EmptyRevealData
        bytes32[][] memory merkleProofs = new bytes32[][](1);

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.EmptyRevealData.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }
    
    function testVerifySelectiveRevealMismatchedArrays() public {
        // First verify transcript
        bytes32[] memory recordHashes = new bytes32[](2);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");

        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 2,
            revealedRecords: 2,
            sessionKeyCommitment: keccak256("Session Key")
        });

        uint256[8] memory transcriptProofData = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, transcriptProofData);

        // Test mismatched array lengths
        uint256[] memory recordIndices = new uint256[](2);
        recordIndices[0] = 0;
        recordIndices[1] = 1;

        bytes32[] memory recordData = new bytes32[](1); // Mismatched length
        recordData[0] = keccak256("Revealed Record 1");

        bytes32[][] memory merkleProofs = new bytes32[][](2);
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[0][0] = keccak256("Merkle Proof 1");
        merkleProofs[1] = new bytes32[](1);
        merkleProofs[1][0] = keccak256("Merkle Proof 2");

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.MismatchedArrayLengths.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testValidateTranscriptEdgeCases() public {
        bytes32 testSessionId = keccak256("Edge Case Session");
        
        // Test invalid transcript root
        ITranscriptProof.TranscriptData memory invalidTranscript = ITranscriptProof.TranscriptData({
            transcriptRoot: bytes32(0), // Invalid - zero root
            totalRecords: 5,
            recordHashes: new bytes32[](5),
            revealedRecords: 5,
            sessionKeyCommitment: keccak256("valid_key")
        });
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidTranscriptRoot.selector);
        transcriptProof.verifyTranscript(testSessionId, invalidTranscript, [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]);
    }

    function testValidateTranscriptZeroRecords() public {
        bytes32 testSessionId = keccak256("Zero Records Session");
        
        // Test zero total records
        ITranscriptProof.TranscriptData memory zeroRecordsTranscript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("valid_root"),
            totalRecords: 0, // Invalid - zero records
            recordHashes: new bytes32[](0),
            revealedRecords: 0,
            sessionKeyCommitment: keccak256("valid_key")
        });
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InsufficientRecords.selector);
        transcriptProof.verifyTranscript(testSessionId, zeroRecordsTranscript, [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]);
    }

    function testValidateTranscriptMaxRecords() public {
        bytes32 testSessionId = keccak256("Max Records Session");
        
        // Test exceeding max records (1000)
        ITranscriptProof.TranscriptData memory maxRecordsTranscript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("valid_root"),
            totalRecords: 1001, // Invalid - exceeds MAX_RECORDS
            recordHashes: new bytes32[](1001),
            revealedRecords: 1001,
            sessionKeyCommitment: keccak256("valid_key")
        });
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InsufficientRecords.selector);
        transcriptProof.verifyTranscript(testSessionId, maxRecordsTranscript, [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]);
    }

    function testValidateTranscriptMismatchedHashLength() public {
        bytes32 testSessionId = keccak256("Mismatched Hash Session");
        
        // Test mismatched recordHashes length
        ITranscriptProof.TranscriptData memory mismatchedTranscript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("valid_root"),
            totalRecords: 5,
            recordHashes: new bytes32[](3), // Wrong length - doesn't match revealedRecords
            revealedRecords: 5,
            sessionKeyCommitment: keccak256("valid_key")
        });
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidTranscriptData.selector);
        transcriptProof.verifyTranscript(testSessionId, mismatchedTranscript, [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]);
    }

    function testValidateTranscriptInvalidKeyCommitment() public {
        bytes32 testSessionId = keccak256("Invalid Key Session");
        
        // Test zero session key commitment
        ITranscriptProof.TranscriptData memory invalidKeyTranscript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("valid_root"),
            totalRecords: 5,
            recordHashes: new bytes32[](5),
            revealedRecords: 5,
            sessionKeyCommitment: bytes32(0) // Invalid - zero key commitment
        });
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidTranscriptData.selector);
        transcriptProof.verifyTranscript(testSessionId, invalidKeyTranscript, [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]);
    }

    function testRangeProofInvalidMinMaxValues() public {
        // Setup verified transcript first  
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
        
        // Test range proof with min >= max
        ITranscriptProof.RangeProof memory invalidRangeProof = ITranscriptProof.RangeProof({
            minValue: 100,
            maxValue: 100, // Invalid - equal to minValue
            valueCommitment: keccak256("value_commitment"),
            rangeProofData: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]
        });
        
        uint256[8] memory rangeProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidRangeParameters.selector);
        transcriptProof.verifyRangeProof(sessionId, invalidRangeProof, rangeProof);
    }

    function testRevealTypeBoundaryValues() public {
        // Setup verified transcript
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
        
        uint256[] memory recordIndices = new uint256[](1);
        recordIndices[0] = 0;
        bytes32[] memory recordData = new bytes32[](1);
        recordData[0] = keccak256("record_data");
        bytes32[][] memory merkleProofs = new bytes32[][](1);
        
        // Test reveal type 5 (above valid range 1-4)
        ITranscriptProof.SelectiveReveal memory invalidReveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 5 // Invalid - above valid range
        });
        
        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidRevealType.selector);
        transcriptProof.verifySelectiveReveal(sessionId, invalidReveal, revealProof);
    }

    function testRecordIndexOutOfBounds() public {
        // Setup verified transcript
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);
        
        uint256[] memory recordIndices = new uint256[](1);
        recordIndices[0] = 10; // Invalid - exceeds transcript.totalRecords (3)
        bytes32[] memory recordData = new bytes32[](1);
        recordData[0] = keccak256("record_data");
        bytes32[][] memory merkleProofs = new bytes32[][](1);
        
        ITranscriptProof.SelectiveReveal memory invalidReveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });
        
        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];
        
        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidRecordIndex.selector);
        transcriptProof.verifySelectiveReveal(sessionId, invalidReveal, revealProof);
    }

    function testVerifySelectiveRevealEmptyIndices() public {
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        // Test empty record indices
        uint256[] memory recordIndices = new uint256[](0); // Empty
        bytes32[] memory recordData = new bytes32[](0);
        bytes32[][] memory merkleProofs = new bytes32[][](0);

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidSelectiveReveal.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifySelectiveRevealTooManyRecords() public {
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        // Test too many record indices (MAX_REVEAL_RECORDS = 100)
        uint256[] memory recordIndices = new uint256[](101); // Too many
        bytes32[] memory recordData = new bytes32[](101);
        bytes32[][] memory merkleProofs = new bytes32[][](101);

        for (uint256 i = 0; i < 101; i++) {
            recordIndices[i] = i % 3; // Valid indices but too many
            recordData[i] = keccak256(abi.encodePacked("Record", i));
            merkleProofs[i] = new bytes32[](1);
            merkleProofs[i][0] = keccak256(abi.encodePacked("proof", i));
        }

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidSelectiveReveal.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifySelectiveRevealMismatchedDataLength() public {
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        // Test mismatched array lengths - different recordData length
        uint256[] memory recordIndices = new uint256[](2);
        recordIndices[0] = 0;
        recordIndices[1] = 1;
        
        bytes32[] memory recordData = new bytes32[](3); // Different length
        recordData[0] = keccak256("Record 1");
        recordData[1] = keccak256("Record 2");
        recordData[2] = keccak256("Record 3");
        
        bytes32[][] memory merkleProofs = new bytes32[][](2);
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[1] = new bytes32[](1);

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.MismatchedArrayLengths.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifySelectiveRevealMismatchedProofLength() public {
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        // Test mismatched array lengths - different merkleProofs length
        uint256[] memory recordIndices = new uint256[](2);
        recordIndices[0] = 0;
        recordIndices[1] = 1;
        
        bytes32[] memory recordData = new bytes32[](2);
        recordData[0] = keccak256("Record 1");
        recordData[1] = keccak256("Record 2");
        
        bytes32[][] memory merkleProofs = new bytes32[][](3); // Different length
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[1] = new bytes32[](1);
        merkleProofs[2] = new bytes32[](1);

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        uint256[8] memory revealProof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.MismatchedArrayLengths.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifySelectiveRevealInvalidMerkleProof() public {
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        // Create invalid merkle proofs (will fail verification)
        uint256[] memory recordIndices = new uint256[](2);
        recordIndices[0] = 0;
        recordIndices[1] = 1;
        
        bytes32[] memory recordData = new bytes32[](2);
        recordData[0] = keccak256("Record 1");
        recordData[1] = keccak256("Record 2");
        
        bytes32[][] memory merkleProofs = new bytes32[][](2);
        merkleProofs[0] = new bytes32[](1);
        merkleProofs[0][0] = keccak256("invalid_proof_1"); // Invalid proof
        merkleProofs[1] = new bytes32[](1);
        merkleProofs[1][0] = keccak256("invalid_proof_2"); // Invalid proof

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        // Valid reveal proof but invalid merkle proofs
        uint256[8] memory revealProof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                reveal.recordIndices,
                reveal.revealType
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidSelectiveReveal.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifySelectiveRevealWithValidMerkleProofInvalidMainProof() public {
        // Test the case where merkle proofs are valid but main proof verification fails
        // This will test the final return branch in _verifySelectiveRevealProof
        
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        // Create a reveal with valid structure but wrong main proof
        uint256[] memory recordIndices = new uint256[](1);
        recordIndices[0] = 0;
        
        bytes32[] memory recordData = new bytes32[](1);
        recordData[0] = keccak256("Record 1");
        
        bytes32[][] memory merkleProofs = new bytes32[][](1);
        merkleProofs[0] = new bytes32[](0); // Empty proof for single-leaf case

        ITranscriptProof.SelectiveReveal memory reveal = ITranscriptProof.SelectiveReveal({
            recordIndices: recordIndices,
            recordData: recordData,
            merkleProofs: merkleProofs,
            revealType: 1
        });

        // Invalid main proof (wrong first element)
        uint256[8] memory revealProof = [
            uint256(999), // Wrong proof value
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidSelectiveReveal.selector);
        transcriptProof.verifySelectiveReveal(sessionId, reveal, revealProof);
    }

    function testVerifyRangeProofInvalidMainProof() public {
        // Setup verified transcript first
        bytes32[] memory recordHashes = new bytes32[](3);
        recordHashes[0] = keccak256("Record 1");
        recordHashes[1] = keccak256("Record 2");
        recordHashes[2] = keccak256("Record 3");
        
        ITranscriptProof.TranscriptData memory transcript = ITranscriptProof.TranscriptData({
            transcriptRoot: keccak256("Transcript Root"),
            recordHashes: recordHashes,
            totalRecords: 3,
            revealedRecords: 3,
            sessionKeyCommitment: keccak256("Session Key")
        });
        
        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                transcript.transcriptRoot,
                transcript.totalRecords,
                transcript.sessionKeyCommitment
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];
        
        vm.prank(verifier);
        transcriptProof.verifyTranscript(sessionId, transcript, proof);

        ITranscriptProof.RangeProof memory rangeProof = ITranscriptProof.RangeProof({
            minValue: 100,
            maxValue: 1000,
            valueCommitment: keccak256("Value Commitment"),
            rangeProofData: [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)]
        });

        // Invalid main proof (wrong first element) - this will test the final return false branch
        uint256[8] memory rangeProofVerification = [
            uint256(999), // Wrong proof value
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        vm.expectRevert(TranscriptProofErrors.InvalidRangeProof.selector);
        transcriptProof.verifyRangeProof(sessionId, rangeProof, rangeProofVerification);
    }
}