// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library TrustedCAsErrors {
    error CAAlreadyExists();
    error CADoesNotExist();
    error CAExpired();
    error CARevoked();
    error InvalidCAHash();
    error InvalidPublicKeyHash();
    error InvalidValidityPeriod();
    error InvalidMerkleProof();
    error UnauthorizedCAManager();
}