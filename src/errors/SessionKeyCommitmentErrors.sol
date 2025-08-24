// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library SessionKeyCommitmentErrors {
    error InvalidKeyDerivationData();
    error InvalidMasterSecretCommitment();
    error InvalidSessionKeyCommitment();
    error InvalidRandomCommitment();
    error UnsupportedKeyDerivationFunction();
    error InvalidHKDFParameters();
    error KeyDerivationAlreadyVerified();
    error InvalidProofForKeyDerivation();
    error InvalidHashFunction();
    error InvalidKeyLength();
}