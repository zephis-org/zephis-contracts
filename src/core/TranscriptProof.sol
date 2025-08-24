// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ITranscriptProof} from "../interfaces/ITranscriptProof.sol";
import {TranscriptProofErrors} from "../errors/TranscriptProofErrors.sol";
import {MerkleProof} from "../utils/MerkleProof.sol";

contract TranscriptProof is ITranscriptProof, AccessControl {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant REVEAL_MANAGER_ROLE = keccak256("REVEAL_MANAGER_ROLE");

    mapping(bytes32 => TranscriptData) private _transcriptData;
    mapping(bytes32 => bool) private _verifiedTranscripts;
    mapping(uint256 => bool) private _supportedRevealTypes;
    mapping(bytes32 => mapping(uint256 => bool)) private _revealedRecords;

    uint256 private constant REVEAL_TYPE_FULL = 1;
    uint256 private constant REVEAL_TYPE_PARTIAL = 2;
    uint256 private constant REVEAL_TYPE_RANGE = 3;
    uint256 private constant REVEAL_TYPE_EXISTENCE = 4;

    uint256 private constant MAX_RECORDS = 1000;
    uint256 private constant MAX_REVEAL_RECORDS = 100;

    modifier onlyValidSession(bytes32 sessionId) {
        if (sessionId == bytes32(0)) revert TranscriptProofErrors.InvalidTranscriptData();
        _;
    }

    modifier onlyUnverifiedSession(bytes32 sessionId) {
        if (_verifiedTranscripts[sessionId]) {
            revert TranscriptProofErrors.TranscriptAlreadyVerified();
        }
        _;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(REVEAL_MANAGER_ROLE, msg.sender);

        _initializeSupportedRevealTypes();
    }

    function verifyTranscript(
        bytes32 sessionId,
        TranscriptData calldata transcript,
        uint256[8] calldata proof
    ) external onlyRole(VERIFIER_ROLE) onlyValidSession(sessionId) 
      onlyUnverifiedSession(sessionId) returns (bool) {
        
        _validateTranscriptData(transcript);

        bool isProofValid = _verifyTranscriptProof(sessionId, transcript, proof);
        
        if (!isProofValid) {
            revert TranscriptProofErrors.InvalidTranscriptData();
        }

        _transcriptData[sessionId] = transcript;
        _verifiedTranscripts[sessionId] = true;

        emit TranscriptVerified(
            sessionId,
            transcript.transcriptRoot,
            transcript.totalRecords,
            transcript.revealedRecords
        );

        return true;
    }

    function verifySelectiveReveal(
        bytes32 sessionId,
        SelectiveReveal calldata reveal,
        uint256[8] calldata proof
    ) external onlyRole(VERIFIER_ROLE) onlyValidSession(sessionId) returns (bool) {
        
        if (!_verifiedTranscripts[sessionId]) {
            revert TranscriptProofErrors.InvalidTranscriptData();
        }

        _validateSelectiveReveal(sessionId, reveal);

        bool isProofValid = _verifySelectiveRevealProof(sessionId, reveal, proof);
        
        if (!isProofValid) {
            revert TranscriptProofErrors.InvalidSelectiveReveal();
        }

        for (uint256 i = 0; i < reveal.recordIndices.length; i++) {
            _revealedRecords[sessionId][reveal.recordIndices[i]] = true;
        }

        bytes32 dataHash = keccak256(abi.encodePacked(reveal.recordData));

        emit SelectiveDataRevealed(
            sessionId,
            reveal.recordIndices,
            dataHash,
            reveal.revealType
        );

        return true;
    }

    function verifyRangeProof(
        bytes32 sessionId,
        RangeProof calldata rangeProof,
        uint256[8] calldata proof
    ) external view onlyRole(VERIFIER_ROLE) onlyValidSession(sessionId) returns (bool) {
        
        if (!_verifiedTranscripts[sessionId]) {
            revert TranscriptProofErrors.InvalidTranscriptData();
        }

        _validateRangeProof(rangeProof);

        bool isProofValid = _verifyRangeProofData(sessionId, rangeProof, proof);
        
        if (!isProofValid) {
            revert TranscriptProofErrors.InvalidRangeProof();
        }

        return true;
    }

    function getTranscriptRoot(bytes32 sessionId) external view returns (bytes32) {
        return _transcriptData[sessionId].transcriptRoot;
    }

    function getTotalRecords(bytes32 sessionId) external view returns (uint256) {
        return _transcriptData[sessionId].totalRecords;
    }

    function isValidRevealType(uint256 revealType) external view returns (bool) {
        return _supportedRevealTypes[revealType];
    }

    function addSupportedRevealType(uint256 revealType) external onlyRole(REVEAL_MANAGER_ROLE) {
        _supportedRevealTypes[revealType] = true;
    }

    function removeSupportedRevealType(uint256 revealType) external onlyRole(REVEAL_MANAGER_ROLE) {
        _supportedRevealTypes[revealType] = false;
    }

    function _validateTranscriptData(TranscriptData calldata transcript) private pure {
        if (transcript.transcriptRoot == bytes32(0)) {
            revert TranscriptProofErrors.InvalidTranscriptRoot();
        }
        
        if (transcript.totalRecords == 0 || transcript.totalRecords > MAX_RECORDS) {
            revert TranscriptProofErrors.InsufficientRecords();
        }
        
        if (transcript.recordHashes.length != transcript.revealedRecords) {
            revert TranscriptProofErrors.InvalidTranscriptData();
        }
        
        if (transcript.sessionKeyCommitment == bytes32(0)) {
            revert TranscriptProofErrors.InvalidTranscriptData();
        }
    }

    function _validateSelectiveReveal(
        bytes32 sessionId,
        SelectiveReveal calldata reveal
    ) private view {
        // Check for empty reveal data when indices exist
        if (reveal.recordIndices.length > 0 && reveal.recordData.length == 0) {
            revert TranscriptProofErrors.EmptyRevealData();
        }
        
        if (reveal.recordIndices.length == 0 || 
            reveal.recordIndices.length > MAX_REVEAL_RECORDS) {
            revert TranscriptProofErrors.InvalidSelectiveReveal();
        }
        
        if (reveal.recordIndices.length != reveal.recordData.length ||
            reveal.recordIndices.length != reveal.merkleProofs.length) {
            revert TranscriptProofErrors.MismatchedArrayLengths();
        }
        
        // Validate reveal type range (1-4)
        if (reveal.revealType == 0 || reveal.revealType > 4) {
            revert TranscriptProofErrors.InvalidRevealType();
        }
        
        if (!_supportedRevealTypes[reveal.revealType]) {
            revert TranscriptProofErrors.UnsupportedRevealType();
        }

        TranscriptData memory transcript = _transcriptData[sessionId];
        
        for (uint256 i = 0; i < reveal.recordIndices.length; i++) {
            if (reveal.recordIndices[i] >= transcript.totalRecords) {
                revert TranscriptProofErrors.InvalidRecordIndex();
            }
        }
    }

    function _validateRangeProof(RangeProof calldata rangeProof) private pure {
        if (rangeProof.minValue >= rangeProof.maxValue) {
            revert TranscriptProofErrors.InvalidRangeParameters();
        }
        
        if (rangeProof.valueCommitment == bytes32(0)) {
            revert TranscriptProofErrors.InvalidValueCommitment();
        }
    }

    function _verifyTranscriptProof(
        bytes32 sessionId,
        TranscriptData calldata transcript,
        uint256[8] calldata proof
    ) private pure returns (bool) {
        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            sessionId,
            transcript.transcriptRoot,
            transcript.totalRecords,
            transcript.sessionKeyCommitment
        ));

        uint256 expectedPublicInput = uint256(publicInputsHash) >> 8;
        
        return proof[0] == expectedPublicInput;
    }

    function _verifySelectiveRevealProof(
        bytes32 sessionId,
        SelectiveReveal calldata reveal,
        uint256[8] calldata proof
    ) private view returns (bool) {
        TranscriptData memory transcript = _transcriptData[sessionId];
        
        for (uint256 i = 0; i < reveal.recordIndices.length; i++) {
            bool isValidProof = MerkleProof.verify(
                reveal.merkleProofs[i],
                transcript.transcriptRoot,
                keccak256(abi.encodePacked(reveal.recordData[i]))
            );
            
            if (!isValidProof) {
                return false;
            }
        }

        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            sessionId,
            transcript.transcriptRoot,
            reveal.recordIndices,
            reveal.revealType
        ));

        uint256 expectedPublicInput = uint256(publicInputsHash) >> 8;
        
        return proof[0] == expectedPublicInput;
    }

    function _verifyRangeProofData(
        bytes32 sessionId,
        RangeProof calldata rangeProof,
        uint256[8] calldata proof
    ) private pure returns (bool) {
        bytes32 publicInputsHash = keccak256(abi.encodePacked(
            sessionId,
            rangeProof.valueCommitment,
            rangeProof.minValue,
            rangeProof.maxValue
        ));

        uint256 expectedPublicInput = uint256(publicInputsHash) >> 8;
        
        return proof[0] == expectedPublicInput;
    }

    function _initializeSupportedRevealTypes() private {
        _supportedRevealTypes[REVEAL_TYPE_FULL] = true;
        _supportedRevealTypes[REVEAL_TYPE_PARTIAL] = true;
        _supportedRevealTypes[REVEAL_TYPE_RANGE] = true;
        _supportedRevealTypes[REVEAL_TYPE_EXISTENCE] = true;
    }
}