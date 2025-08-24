// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IZKTLSVerifier} from "../interfaces/IZKTLSVerifier.sol";
import {ZKTLSVerifierErrors} from "../errors/ZKTLSVerifierErrors.sol";

contract ZKTLSVerifier is IZKTLSVerifier, AccessControl, ReentrancyGuard {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant CIRCUIT_MANAGER_ROLE = keccak256("CIRCUIT_MANAGER_ROLE");

    mapping(bytes32 => VerificationResult) private _verificationResults;
    mapping(bytes32 => bool) private _validSessions;
    mapping(uint256 => address) private _circuitVerifiers;

    uint256 private constant PROOF_VALIDITY_PERIOD = 3600;
    uint256 private constant MAX_PUBLIC_INPUTS = 16;

    modifier onlyValidProof(TLSProof calldata proof) {
        if (proof.sessionId == bytes32(0)) revert ZKTLSVerifierErrors.InvalidSessionId();
        if (proof.handshakeCommitment == bytes32(0)) revert ZKTLSVerifierErrors.InvalidCommitment();
        if (proof.keyCommitment == bytes32(0)) revert ZKTLSVerifierErrors.InvalidCommitment();
        if (proof.transcriptRoot == bytes32(0)) revert ZKTLSVerifierErrors.InvalidMerkleRoot();
        _;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(CIRCUIT_MANAGER_ROLE, msg.sender);
    }

    function verifyTLSProof(
        TLSProof calldata proof
    ) external nonReentrant onlyValidProof(proof) returns (bool) {
        if (_validSessions[proof.sessionId]) {
            revert ZKTLSVerifierErrors.SessionAlreadyExists();
        }

        uint256 circuitId = proof.publicInputs[0];
        address verifierContract = _circuitVerifiers[circuitId];
        
        if (verifierContract == address(0)) {
            revert ZKTLSVerifierErrors.InvalidCircuitId();
        }

        bool isValid = _verifyGroth16Proof(verifierContract, proof);
        
        if (isValid) {
            bytes32 dataHash = keccak256(abi.encodePacked(
                proof.handshakeCommitment,
                proof.keyCommitment,
                proof.transcriptRoot
            ));

            _verificationResults[proof.sessionId] = VerificationResult({
                isValid: true,
                sessionId: proof.sessionId,
                verifier: msg.sender,
                timestamp: block.timestamp,
                dataHash: dataHash
            });

            _validSessions[proof.sessionId] = true;

            emit ProofVerified(proof.sessionId, msg.sender, dataHash, block.timestamp);
        } else {
            emit ProofFailed(proof.sessionId, msg.sender, "Groth16 verification failed");
            revert ZKTLSVerifierErrors.ProofVerificationFailed();
        }

        return isValid;
    }

    function getVerificationResult(
        bytes32 sessionId
    ) external view returns (VerificationResult memory) {
        return _verificationResults[sessionId];
    }

    function isValidSession(bytes32 sessionId) external view returns (bool) {
        return _validSessions[sessionId] && 
               (block.timestamp - _verificationResults[sessionId].timestamp) <= PROOF_VALIDITY_PERIOD;
    }

    function getSessionVerifier(bytes32 sessionId) external view returns (address) {
        return _verificationResults[sessionId].verifier;
    }

    function setCircuitVerifier(
        uint256 circuitId,
        address verifierContract
    ) external onlyRole(CIRCUIT_MANAGER_ROLE) {
        _circuitVerifiers[circuitId] = verifierContract;
    }

    function getCircuitVerifier(uint256 circuitId) external view returns (address) {
        return _circuitVerifiers[circuitId];
    }

    function _verifyGroth16Proof(
        address verifierContract,
        TLSProof calldata proof
    ) private view returns (bool) {
        (bool success, bytes memory result) = verifierContract.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
                [proof.groth16Proof[0], proof.groth16Proof[1]],
                [[proof.groth16Proof[2], proof.groth16Proof[3]], 
                 [proof.groth16Proof[4], proof.groth16Proof[5]]],
                [proof.groth16Proof[6], proof.groth16Proof[7]],
                proof.publicInputs
            )
        );

        return success && abi.decode(result, (bool));
    }
}