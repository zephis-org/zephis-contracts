// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IZKTLSVerifier {
    struct TLSProof {
        bytes32 sessionId;
        bytes32 handshakeCommitment;
        bytes32 keyCommitment;
        bytes32 transcriptRoot;
        uint256[8] groth16Proof;
        uint256[2] publicInputs;
    }

    struct VerificationResult {
        bool isValid;
        bytes32 sessionId;
        address verifier;
        uint256 timestamp;
        bytes32 dataHash;
    }

    event ProofVerified(
        bytes32 indexed sessionId,
        address indexed verifier,
        bytes32 dataHash,
        uint256 timestamp
    );

    event ProofFailed(
        bytes32 indexed sessionId,
        address indexed verifier,
        string reason
    );

    function verifyTLSProof(TLSProof calldata proof) external returns (bool);
    
    function getVerificationResult(bytes32 sessionId) external view returns (VerificationResult memory);
    
    function isValidSession(bytes32 sessionId) external view returns (bool);
    
    function getSessionVerifier(bytes32 sessionId) external view returns (address);
}