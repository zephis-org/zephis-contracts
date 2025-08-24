// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ITranscriptProof {
    struct TranscriptData {
        bytes32 transcriptRoot;
        bytes32[] recordHashes;
        uint256 totalRecords;
        uint256 revealedRecords;
        bytes32 sessionKeyCommitment;
    }

    struct SelectiveReveal {
        uint256[] recordIndices;
        bytes32[] recordData;
        bytes32[][] merkleProofs;
        uint256 revealType;
    }

    struct RangeProof {
        uint256 minValue;
        uint256 maxValue;
        bytes32 valueCommitment;
        uint256[8] rangeProofData;
    }

    event TranscriptVerified(
        bytes32 indexed sessionId,
        bytes32 transcriptRoot,
        uint256 totalRecords,
        uint256 revealedRecords
    );

    event SelectiveDataRevealed(
        bytes32 indexed sessionId,
        uint256[] recordIndices,
        bytes32 dataHash,
        uint256 revealType
    );

    function verifyTranscript(
        bytes32 sessionId,
        TranscriptData calldata transcript,
        uint256[8] calldata proof
    ) external returns (bool);

    function verifySelectiveReveal(
        bytes32 sessionId,
        SelectiveReveal calldata reveal,
        uint256[8] calldata proof
    ) external returns (bool);

    function verifyRangeProof(
        bytes32 sessionId,
        RangeProof calldata rangeProof,
        uint256[8] calldata proof
    ) external returns (bool);

    function getTranscriptRoot(bytes32 sessionId) external view returns (bytes32);
    
    function getTotalRecords(bytes32 sessionId) external view returns (uint256);
    
    function isValidRevealType(uint256 revealType) external view returns (bool);
}