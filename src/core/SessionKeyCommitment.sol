// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ISessionKeyCommitment} from "../interfaces/ISessionKeyCommitment.sol";
import {SessionKeyCommitmentErrors} from "../errors/SessionKeyCommitmentErrors.sol";

contract SessionKeyCommitment is ISessionKeyCommitment, AccessControl {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant KDF_MANAGER_ROLE = keccak256("KDF_MANAGER_ROLE");

    mapping(bytes32 => KeyDerivationData) private _keyDerivationData;
    mapping(bytes32 => bool) private _verifiedSessions;
    mapping(uint256 => bool) private _supportedKdfs;
    mapping(uint256 => bool) private _supportedHashFunctions;

    uint256 private constant KDF_HKDF_SHA256 = 1;
    uint256 private constant KDF_HKDF_SHA384 = 2;
    uint256 private constant KDF_TLS12_PRF = 3;
    uint256 private constant KDF_TLS13_HKDF = 4;

    uint256 private constant HASH_SHA256 = 1;
    uint256 private constant HASH_SHA384 = 2;
    uint256 private constant HASH_SHA512 = 3;

    uint256 private constant MIN_KEY_LENGTH = 16;
    uint256 private constant MAX_KEY_LENGTH = 64;

    modifier onlyValidSession(bytes32 sessionId) {
        if (sessionId == bytes32(0)) revert SessionKeyCommitmentErrors.InvalidKeyDerivationData();
        _;
    }

    modifier onlyUnverifiedSession(bytes32 sessionId) {
        if (_verifiedSessions[sessionId]) {
            revert SessionKeyCommitmentErrors.KeyDerivationAlreadyVerified();
        }
        _;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(KDF_MANAGER_ROLE, msg.sender);

        _initializeSupportedKdfs();
        _initializeSupportedHashFunctions();
    }

    function verifyKeyDerivation(
        bytes32 sessionId,
        KeyDerivationData calldata keyData,
        HKDFParameters calldata hkdfParams,
        uint256[8] calldata proof
    ) external onlyRole(VERIFIER_ROLE) onlyValidSession(sessionId) 
      onlyUnverifiedSession(sessionId) returns (bool) {
        
        _validateKeyDerivationData(keyData);
        _validateHKDFParameters(hkdfParams);

        bool isProofValid = _verifyKeyDerivationProof(sessionId, keyData, hkdfParams, proof);
        
        if (!isProofValid) {
            revert SessionKeyCommitmentErrors.InvalidProofForKeyDerivation();
        }

        _keyDerivationData[sessionId] = keyData;
        _verifiedSessions[sessionId] = true;

        emit KeyCommitmentVerified(
            sessionId,
            keyData.masterSecretCommitment,
            keyData.sessionKeyCommitment,
            keyData.keyDerivationFunction
        );

        return true;
    }

    function getKeyCommitment(bytes32 sessionId) external view returns (bytes32) {
        return _keyDerivationData[sessionId].sessionKeyCommitment;
    }

    function getMasterSecretCommitment(bytes32 sessionId) external view returns (bytes32) {
        return _keyDerivationData[sessionId].masterSecretCommitment;
    }

    function isValidKeyDerivationFunction(uint256 kdf) external view returns (bool) {
        return _supportedKdfs[kdf];
    }

    function getKeyDerivationData(bytes32 sessionId) external view returns (KeyDerivationData memory) {
        return _keyDerivationData[sessionId];
    }

    function addSupportedKdf(uint256 kdf) external onlyRole(KDF_MANAGER_ROLE) {
        _supportedKdfs[kdf] = true;
    }

    function removeSupportedKdf(uint256 kdf) external onlyRole(KDF_MANAGER_ROLE) {
        _supportedKdfs[kdf] = false;
    }

    function addSupportedHashFunction(uint256 hashFunc) external onlyRole(KDF_MANAGER_ROLE) {
        _supportedHashFunctions[hashFunc] = true;
    }

    function removeSupportedHashFunction(uint256 hashFunc) external onlyRole(KDF_MANAGER_ROLE) {
        _supportedHashFunctions[hashFunc] = false;
    }

    function _validateKeyDerivationData(KeyDerivationData calldata keyData) private view {
        if (keyData.masterSecretCommitment == bytes32(0)) {
            revert SessionKeyCommitmentErrors.InvalidMasterSecretCommitment();
        }
        
        if (keyData.clientRandomCommitment == bytes32(0) || 
            keyData.serverRandomCommitment == bytes32(0)) {
            revert SessionKeyCommitmentErrors.InvalidRandomCommitment();
        }
        
        if (keyData.sessionKeyCommitment == bytes32(0)) {
            revert SessionKeyCommitmentErrors.InvalidSessionKeyCommitment();
        }
        
        if (!_supportedKdfs[keyData.keyDerivationFunction]) {
            revert SessionKeyCommitmentErrors.UnsupportedKeyDerivationFunction();
        }
    }

    function _validateHKDFParameters(HKDFParameters calldata hkdfParams) private view {
        if (hkdfParams.length < MIN_KEY_LENGTH || hkdfParams.length > MAX_KEY_LENGTH) {
            revert SessionKeyCommitmentErrors.InvalidKeyLength();
        }
        
        if (!_supportedHashFunctions[hkdfParams.hashFunction]) {
            revert SessionKeyCommitmentErrors.InvalidHashFunction();
        }
    }

    function _verifyKeyDerivationProof(
        bytes32 sessionId,
        KeyDerivationData calldata keyData,
        HKDFParameters calldata hkdfParams,
        uint256[8] calldata proof
    ) private pure returns (bool) {
        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            sessionId,
            keyData.masterSecretCommitment,
            keyData.clientRandomCommitment,
            keyData.serverRandomCommitment,
            keyData.sessionKeyCommitment,
            hkdfParams.salt,
            hkdfParams.info
        ));

        uint256 expectedPublicInput = uint256(publicInputsHash) >> 8;
        
        return proof[0] == expectedPublicInput;
    }

    function _initializeSupportedKdfs() private {
        _supportedKdfs[KDF_HKDF_SHA256] = true;
        _supportedKdfs[KDF_HKDF_SHA384] = true;
        _supportedKdfs[KDF_TLS12_PRF] = true;
        _supportedKdfs[KDF_TLS13_HKDF] = true;
    }

    function _initializeSupportedHashFunctions() private {
        _supportedHashFunctions[HASH_SHA256] = true;
        _supportedHashFunctions[HASH_SHA384] = true;
        _supportedHashFunctions[HASH_SHA512] = true;
    }
}