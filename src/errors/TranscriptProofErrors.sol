// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library TranscriptProofErrors {
    error InvalidTranscriptData();
    error InvalidTranscriptRoot();
    error InvalidRecordHash();
    error InvalidMerkleProof();
    error InvalidSelectiveReveal();
    error InvalidRangeProof();
    error UnsupportedRevealType();
    error TranscriptAlreadyVerified();
    error InvalidRecordIndex();
    error InvalidValueCommitment();
    error InvalidRangeParameters();
    error InsufficientRecords();
    error InvalidRevealType();
    error EmptyRevealData();
    error MismatchedArrayLengths();
}