// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ITrustedCAs} from "../interfaces/ITrustedCAs.sol";
import {TrustedCAsErrors} from "../errors/TrustedCAsErrors.sol";
import {MerkleProof} from "../utils/MerkleProof.sol";

contract TrustedCAs is ITrustedCAs, AccessControl {
    bytes32 public constant CA_MANAGER_ROLE = keccak256("CA_MANAGER_ROLE");
    bytes32 public constant CA_UPDATER_ROLE = keccak256("CA_UPDATER_ROLE");

    mapping(bytes32 => CaInfo) private _caInfos;
    mapping(bytes32 => bool) private _caExists;
    bytes32[] private _caHashes;
    bytes32 private _merkleRoot;

    uint256 private constant MAX_VALIDITY_PERIOD = 365 days * 10;
    uint256 private constant MIN_VALIDITY_PERIOD = 30 days;

    modifier onlyExistingCa(bytes32 caHash) {
        if (!_caExists[caHash]) revert TrustedCAsErrors.CADoesNotExist();
        _;
    }

    modifier onlyNonExistingCa(bytes32 caHash) {
        if (_caExists[caHash]) revert TrustedCAsErrors.CAAlreadyExists();
        _;
    }

    modifier onlyValidHash(bytes32 hash) {
        if (hash == bytes32(0)) revert TrustedCAsErrors.InvalidCAHash();
        _;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CA_MANAGER_ROLE, msg.sender);
        _grantRole(CA_UPDATER_ROLE, msg.sender);
        
        _initializeWellKnownCAs();
    }

    function addCa(
        bytes32 caHash,
        bytes32 publicKeyHash,
        bytes32 nameHash,
        uint256 validFrom,
        uint256 validUntil
    ) external onlyRole(CA_MANAGER_ROLE) onlyValidHash(caHash) 
      onlyNonExistingCa(caHash) {
        
        _validateCaParameters(publicKeyHash, validFrom, validUntil);

        _caInfos[caHash] = CaInfo({
            publicKeyHash: publicKeyHash,
            nameHash: nameHash,
            validFrom: validFrom,
            validUntil: validUntil,
            isActive: true
        });

        _caExists[caHash] = true;
        _caHashes.push(caHash);
        _updateMerkleRoot();

        emit CAAdded(caHash, publicKeyHash, nameHash, validFrom, validUntil);
    }

    function revokeCa(
        bytes32 caHash
    ) external onlyRole(CA_MANAGER_ROLE) onlyExistingCa(caHash) {
        
        _caInfos[caHash].isActive = false;
        _updateMerkleRoot();

        emit CARevoked(caHash, block.timestamp);
    }

    function updateCaValidity(
        bytes32 caHash,
        uint256 newValidUntil
    ) external onlyRole(CA_UPDATER_ROLE) onlyExistingCa(caHash) {
        
        CaInfo storage caInfo = _caInfos[caHash];
        
        if (!caInfo.isActive) revert TrustedCAsErrors.CARevoked();
        if (newValidUntil <= block.timestamp) revert TrustedCAsErrors.InvalidValidityPeriod();
        if (newValidUntil > block.timestamp + MAX_VALIDITY_PERIOD) {
            revert TrustedCAsErrors.InvalidValidityPeriod();
        }

        caInfo.validUntil = newValidUntil;
        _updateMerkleRoot();

        emit CAUpdated(caHash, newValidUntil);
    }

    function isValidCaRoot(bytes32 caHash) external view returns (bool) {
        if (!_caExists[caHash]) return false;
        
        CaInfo memory caInfo = _caInfos[caHash];
        
        return caInfo.isActive &&
               block.timestamp >= caInfo.validFrom &&
               block.timestamp <= caInfo.validUntil;
    }

    function getCaInfo(bytes32 caHash) external view returns (CaInfo memory) {
        return _caInfos[caHash];
    }

    function getCaMerkleRoot() external view returns (bytes32) {
        return _merkleRoot;
    }

    function verifyCaInclusion(
        bytes32 caHash,
        bytes32[] calldata merkleProof
    ) external view returns (bool) {
        return MerkleProof.verifyCalldata(merkleProof, _merkleRoot, caHash);
    }

    function getActiveCasCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < _caHashes.length; i++) {
            CaInfo memory caInfo = _caInfos[_caHashes[i]];
            if (caInfo.isActive &&
                block.timestamp >= caInfo.validFrom &&
                block.timestamp <= caInfo.validUntil) {
                count++;
            }
        }
        return count;
    }

    function _validateCaParameters(
        bytes32 publicKeyHash,
        uint256 validFrom,
        uint256 validUntil
    ) private view {
        if (publicKeyHash == bytes32(0)) revert TrustedCAsErrors.InvalidPublicKeyHash();
        if (validFrom >= validUntil) revert TrustedCAsErrors.InvalidValidityPeriod();
        if (validUntil <= block.timestamp) revert TrustedCAsErrors.InvalidValidityPeriod();
        if (validUntil > block.timestamp + MAX_VALIDITY_PERIOD) {
            revert TrustedCAsErrors.InvalidValidityPeriod();
        }
        if ((validUntil - validFrom) < MIN_VALIDITY_PERIOD) {
            revert TrustedCAsErrors.InvalidValidityPeriod();
        }
    }

    function _updateMerkleRoot() private {
        bytes32[] memory activeHashes = new bytes32[](_getActiveCaCount());
        uint256 index = 0;
        
        for (uint256 i = 0; i < _caHashes.length; i++) {
            bytes32 caHash = _caHashes[i];
            CaInfo memory caInfo = _caInfos[caHash];
            
            if (caInfo.isActive &&
                block.timestamp >= caInfo.validFrom &&
                block.timestamp <= caInfo.validUntil) {
                activeHashes[index] = caHash;
                index++;
            }
        }

        _merkleRoot = _computeMerkleRoot(activeHashes);
    }

    function _getActiveCaCount() private view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < _caHashes.length; i++) {
            CaInfo memory caInfo = _caInfos[_caHashes[i]];
            if (caInfo.isActive &&
                block.timestamp >= caInfo.validFrom &&
                block.timestamp <= caInfo.validUntil) {
                count++;
            }
        }
        return count;
    }

    function _computeMerkleRoot(bytes32[] memory leaves) private pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        while (leaves.length > 1) {
            uint256 newLength = (leaves.length + 1) / 2;
            bytes32[] memory newLeaves = new bytes32[](newLength);
            
            for (uint256 i = 0; i < newLength; i++) {
                if (i * 2 + 1 < leaves.length) {
                    newLeaves[i] = keccak256(abi.encodePacked(
                        leaves[i * 2] < leaves[i * 2 + 1] ? leaves[i * 2] : leaves[i * 2 + 1],
                        leaves[i * 2] < leaves[i * 2 + 1] ? leaves[i * 2 + 1] : leaves[i * 2]
                    ));
                } else {
                    newLeaves[i] = leaves[i * 2];
                }
            }
            leaves = newLeaves;
        }
        
        return leaves[0];
    }

    function _initializeWellKnownCAs() private {
        bytes32 letsEncryptHash = keccak256("Let's Encrypt Authority X3");
        _caInfos[letsEncryptHash] = CaInfo({
            publicKeyHash: keccak256("LetsEncryptX3PublicKey"),
            nameHash: keccak256("Let's Encrypt Authority X3"),
            validFrom: block.timestamp,
            validUntil: block.timestamp + 365 days * 5,
            isActive: true
        });
        _caExists[letsEncryptHash] = true;
        _caHashes.push(letsEncryptHash);

        bytes32 digicertHash = keccak256("DigiCert Global Root CA");
        _caInfos[digicertHash] = CaInfo({
            publicKeyHash: keccak256("DigiCertGlobalRootPublicKey"),
            nameHash: keccak256("DigiCert Global Root CA"),
            validFrom: block.timestamp,
            validUntil: block.timestamp + 365 days * 5,
            isActive: true
        });
        _caExists[digicertHash] = true;
        _caHashes.push(digicertHash);

        _updateMerkleRoot();
    }
}