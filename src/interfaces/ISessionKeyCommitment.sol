// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ISessionKeyCommitment {
    struct KeyDerivationData {
        bytes32 masterSecretCommitment;
        bytes32 clientRandomCommitment;
        bytes32 serverRandomCommitment;
        bytes32 sessionKeyCommitment;
        uint256 keyDerivationFunction;
        uint256 cipherSuite;
    }

    struct HKDFParameters {
        bytes32 salt;
        bytes32 info;
        uint256 length;
        uint256 hashFunction;
    }

    event KeyCommitmentVerified(
        bytes32 indexed sessionId,
        bytes32 masterSecretCommitment,
        bytes32 sessionKeyCommitment,
        uint256 keyDerivationFunction
    );

    function verifyKeyDerivation(
        bytes32 sessionId,
        KeyDerivationData calldata keyData,
        HKDFParameters calldata hkdfParams,
        uint256[8] calldata proof
    ) external returns (bool);

    function getKeyCommitment(bytes32 sessionId) external view returns (bytes32);
    
    function getMasterSecretCommitment(bytes32 sessionId) external view returns (bytes32);
    
    function isValidKeyDerivationFunction(uint256 kdf) external view returns (bool);
    
    function getKeyDerivationData(bytes32 sessionId) external view returns (KeyDerivationData memory);
}