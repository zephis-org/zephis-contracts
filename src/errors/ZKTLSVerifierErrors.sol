// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library ZKTLSVerifierErrors {
    error InvalidProof();
    error InvalidSessionId();
    error SessionAlreadyExists();
    error InvalidCommitment();
    error InvalidPublicInputs();
    error ProofVerificationFailed();
    error UnauthorizedVerifier();
    error ExpiredProof();
    error InvalidCircuitId();
    error InvalidMerkleRoot();
}