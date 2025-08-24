// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ITrustedCAs {
    struct CaInfo {
        bytes32 publicKeyHash;
        bytes32 nameHash;
        uint256 validFrom;
        uint256 validUntil;
        bool isActive;
    }

    event CAAdded(
        bytes32 indexed caHash,
        bytes32 publicKeyHash,
        bytes32 nameHash,
        uint256 validFrom,
        uint256 validUntil
    );

    event CARevoked(
        bytes32 indexed caHash,
        uint256 revokedAt
    );

    event CAUpdated(
        bytes32 indexed caHash,
        uint256 newValidUntil
    );

    function addCa(
        bytes32 caHash,
        bytes32 publicKeyHash,
        bytes32 nameHash,
        uint256 validFrom,
        uint256 validUntil
    ) external;

    function revokeCa(bytes32 caHash) external;

    function updateCaValidity(bytes32 caHash, uint256 newValidUntil) external;

    function isValidCaRoot(bytes32 caHash) external view returns (bool);

    function getCaInfo(bytes32 caHash) external view returns (CaInfo memory);

    function getCaMerkleRoot() external view returns (bytes32);

    function verifyCaInclusion(
        bytes32 caHash,
        bytes32[] calldata merkleProof
    ) external view returns (bool);
}