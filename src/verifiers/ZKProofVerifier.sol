// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IZKProofVerifier.sol";

/**
 * @title ZKProofVerifier
 * @dev Base implementation for zero-knowledge proof verification in ZEPHIS Protocol
 * 
 * This contract handles the submission, verification, and challenging of ZK-TLS proofs
 * with support for multiple proof systems and governance mechanisms.
 */
contract ZKProofVerifier is IZKProofVerifier, AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // Challenge period duration (7 days)
    uint256 public constant CHALLENGE_PERIOD = 7 days;
    
    // Maximum proof data size (1MB)
    uint256 public constant MAX_PROOF_SIZE = 1024 * 1024;

    // Storage mappings
    mapping(bytes32 => ProofData) private _proofs;
    mapping(bytes32 => VerificationResult) private _verificationResults;
    mapping(bytes32 => bool) private _challengedProofs;
    mapping(address => bytes32[]) private _proofsBySubmitter;
    mapping(ProofType => bool) private _supportedProofTypes;

    // State variables
    uint256 private _totalProofs;
    uint256 private _successfulVerifications;
    uint256 private _challengedCount;

    // Events for additional functionality
    event ProofTypeUpdated(ProofType indexed proofType, bool supported);
    event ChallengePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event ProofSizeUpdated(uint256 oldSize, uint256 newSize);

    /**
     * @dev Constructor sets up roles and initial supported proof types
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        
        // Enable supported proof types
        _supportedProofTypes[ProofType.TLSN] = true;
        _supportedProofTypes[ProofType.MPCTLS] = true;
        _supportedProofTypes[ProofType.CUSTOM] = false; // Disabled by default
    }

    /**
     * @dev Submit a ZK proof for verification
     */
    function submitProof(ProofData calldata proofData) 
        external 
        override 
        nonReentrant 
        whenNotPaused 
        returns (bytes32 proofId) 
    {
        require(proofData.proof.length > 0, "ZKProofVerifier: Empty proof data");
        require(proofData.proof.length <= MAX_PROOF_SIZE, "ZKProofVerifier: Proof too large");
        require(_supportedProofTypes[proofData.proofType], "ZKProofVerifier: Unsupported proof type");
        require(proofData.publicInputs.length > 0, "ZKProofVerifier: No public inputs");
        require(bytes(proofData.circuitId).length > 0, "ZKProofVerifier: Empty circuit ID");

        // Generate unique proof ID
        proofId = keccak256(abi.encodePacked(
            proofData.sessionId,
            proofData.proof,
            proofData.commitment,
            block.timestamp,
            msg.sender
        ));

        require(_proofs[proofId].submitter == address(0), "ZKProofVerifier: Proof already exists");

        // Store proof data
        ProofData storage proof = _proofs[proofId];
        proof.proofId = proofId;
        proof.sessionId = proofData.sessionId;
        proof.proofType = proofData.proofType;
        proof.proof = proofData.proof;
        proof.publicInputs = proofData.publicInputs;
        proof.commitment = proofData.commitment;
        proof.circuitId = proofData.circuitId;
        proof.timestamp = block.timestamp;
        proof.submitter = msg.sender;

        // Update tracking
        _proofsBySubmitter[msg.sender].push(proofId);
        _totalProofs++;

        emit ProofSubmitted(
            proofId,
            proofData.sessionId,
            proofData.proofType,
            msg.sender,
            proofData.commitment
        );

        return proofId;
    }

    /**
     * @dev Verify a submitted ZK proof
     */
    function verifyProof(bytes32 proofId) 
        external 
        override 
        onlyRole(VERIFIER_ROLE) 
        nonReentrant 
        whenNotPaused 
        returns (VerificationResult memory result) 
    {
        require(_proofs[proofId].submitter != address(0), "ZKProofVerifier: Proof not found");
        require(_verificationResults[proofId].verifier == address(0), "ZKProofVerifier: Already verified");

        ProofData storage proof = _proofs[proofId];
        
        // Perform verification based on proof type
        bool isValid = _performVerification(proof);
        
        // Generate proof hash for integrity
        bytes32 proofHash = keccak256(abi.encodePacked(
            proof.proof,
            proof.publicInputs,
            proof.commitment
        ));

        // Store verification result
        result = VerificationResult({
            isValid: isValid,
            proofHash: proofHash,
            verifiedAt: block.timestamp,
            verifier: msg.sender,
            reason: isValid ? "Valid proof" : "Invalid proof"
        });

        _verificationResults[proofId] = result;
        
        if (isValid) {
            _successfulVerifications++;
        }

        emit ProofVerified(proofId, isValid, msg.sender, proofHash, result.reason);
        
        return result;
    }

    /**
     * @dev Batch verify multiple proofs
     */
    function batchVerifyProofs(bytes32[] calldata proofIds) 
        external 
        override 
        onlyRole(VERIFIER_ROLE) 
        nonReentrant 
        whenNotPaused 
        returns (VerificationResult[] memory results) 
    {
        require(proofIds.length > 0, "ZKProofVerifier: Empty proof list");
        require(proofIds.length <= 50, "ZKProofVerifier: Batch too large");

        results = new VerificationResult[](proofIds.length);
        uint256 successCount = 0; // Track successes locally to avoid costly storage operations
        
        // Avoid external calls in loop by using internal verification logic
        for (uint256 i = 0; i < proofIds.length; i++) {
            bytes32 proofId = proofIds[i];
            
            // Check if proof exists and not already verified
            require(_proofs[proofId].submitter != address(0), "ZKProofVerifier: Proof not found");
            require(_verificationResults[proofId].verifier == address(0), "ZKProofVerifier: Already verified");
            
            // Perform verification directly (internal logic)
            bool isValid = _performVerification(_proofs[proofId]);
            
            // Store result
            VerificationResult memory result = VerificationResult({
                isValid: isValid,
                proofHash: keccak256(abi.encodePacked(_proofs[proofId].proof, _proofs[proofId].publicInputs, _proofs[proofId].commitment)),
                verifiedAt: block.timestamp,
                verifier: msg.sender,
                reason: isValid ? "" : "Verification failed"
            });
            
            _verificationResults[proofId] = result;
            results[i] = result;
            
            if (isValid) {
                unchecked { ++successCount; } // Use unchecked increment for gas optimization
            }
            
            emit ProofVerified(proofId, isValid, msg.sender, result.proofHash, result.reason);
        }
        
        // Update global counter once after loop
        _successfulVerifications += successCount;
        
        return results;
    }

    /**
     * @dev Challenge a verified proof
     */
    function challengeProof(bytes32 proofId, string calldata reason) 
        external 
        override 
        onlyRole(CHALLENGER_ROLE) 
        nonReentrant 
        whenNotPaused 
    {
        require(_proofs[proofId].submitter != address(0), "ZKProofVerifier: Proof not found");
        require(_verificationResults[proofId].verifier != address(0), "ZKProofVerifier: Proof not verified");
        require(_verificationResults[proofId].isValid, "ZKProofVerifier: Cannot challenge invalid proof");
        require(!_challengedProofs[proofId], "ZKProofVerifier: Already challenged");
        require(bytes(reason).length > 0, "ZKProofVerifier: Empty challenge reason");
        
        // Check challenge period
        uint256 challengeDeadline = _verificationResults[proofId].verifiedAt + CHALLENGE_PERIOD;
        require(block.timestamp <= challengeDeadline, "ZKProofVerifier: Challenge period expired");

        _challengedProofs[proofId] = true;
        _challengedCount++;

        emit ProofChallenged(proofId, msg.sender, reason, challengeDeadline);
    }

    /**
     * @dev Get verification result for a proof
     */
    function getVerificationResult(bytes32 proofId) 
        external 
        view 
        override 
        returns (VerificationResult memory result) 
    {
        require(_proofs[proofId].submitter != address(0), "ZKProofVerifier: Proof not found");
        return _verificationResults[proofId];
    }

    /**
     * @dev Get proof data by ID
     */
    function getProofData(bytes32 proofId) 
        external 
        view 
        override 
        returns (ProofData memory proofData) 
    {
        require(_proofs[proofId].submitter != address(0), "ZKProofVerifier: Proof not found");
        return _proofs[proofId];
    }

    /**
     * @dev Check if proof type is supported
     */
    function isProofTypeSupported(ProofType proofType) 
        external 
        view 
        override 
        returns (bool supported) 
    {
        return _supportedProofTypes[proofType];
    }

    /**
     * @dev Get challenge period
     */
    function getChallengePeriod() external pure override returns (uint256 challengePeriod) {
        return CHALLENGE_PERIOD;
    }

    /**
     * @dev Get total number of proofs
     */
    function getTotalProofs() external view override returns (uint256 totalProofs) {
        return _totalProofs;
    }

    /**
     * @dev Get proofs by submitter with pagination
     */
    function getProofsBySubmitter(
        address submitter,
        uint256 offset,
        uint256 limit
    ) external view override returns (bytes32[] memory proofIds) {
        require(limit > 0 && limit <= 100, "ZKProofVerifier: Invalid limit");
        
        bytes32[] storage userProofs = _proofsBySubmitter[submitter];
        require(offset < userProofs.length, "ZKProofVerifier: Offset out of bounds");
        
        uint256 end = offset + limit;
        if (end > userProofs.length) {
            end = userProofs.length;
        }
        
        proofIds = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            proofIds[i - offset] = userProofs[i];
        }
        
        return proofIds;
    }

    /**
     * @dev Update supported proof type (admin only)
     */
    function updateProofTypeSupport(ProofType proofType, bool supported) 
        external 
        onlyRole(ADMIN_ROLE) 
    {
        _supportedProofTypes[proofType] = supported;
        emit ProofTypeUpdated(proofType, supported);
    }

    /**
     * @dev Get verification statistics
     */
    function getVerificationStats() external view returns (
        uint256 totalProofs,
        uint256 successfulVerifications,
        uint256 challengedCount,
        uint256 successRate
    ) {
        totalProofs = _totalProofs;
        successfulVerifications = _successfulVerifications;
        challengedCount = _challengedCount;
        
        if (_totalProofs > 0) {
            successRate = (_successfulVerifications * 100) / _totalProofs;
        } else {
            successRate = 0;
        }
    }

    /**
     * @dev Check if proof is challenged
     */
    function isProofChallenged(bytes32 proofId) external view returns (bool) {
        return _challengedProofs[proofId];
    }

    /**
     * @dev Pause contract (admin only)
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @dev Unpause contract (admin only)
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @dev Internal proof submission to avoid reentrancy in child contracts
     */
    function _submitProofInternal(ProofData calldata proofData, bytes32 proofId) 
        internal 
        returns (bytes32) 
    {
        require(proofData.proof.length > 0, "ZKProofVerifier: Empty proof data");
        require(proofData.proof.length <= MAX_PROOF_SIZE, "ZKProofVerifier: Proof too large");
        require(_supportedProofTypes[proofData.proofType], "ZKProofVerifier: Unsupported proof type");
        require(proofData.publicInputs.length > 0, "ZKProofVerifier: No public inputs");
        require(bytes(proofData.circuitId).length > 0, "ZKProofVerifier: Empty circuit ID");
        require(_proofs[proofId].submitter == address(0), "ZKProofVerifier: Proof already exists");

        // Store proof data
        ProofData storage proof = _proofs[proofId];
        proof.proofId = proofId;
        proof.sessionId = proofData.sessionId;
        proof.proofType = proofData.proofType;
        proof.proof = proofData.proof;
        proof.publicInputs = proofData.publicInputs;
        proof.commitment = proofData.commitment;
        proof.circuitId = proofData.circuitId;
        proof.timestamp = block.timestamp;
        proof.submitter = msg.sender;

        // Update tracking
        _proofsBySubmitter[msg.sender].push(proofId);
        _totalProofs++;

        emit ProofSubmitted(
            proofId,
            proofData.sessionId,
            proofData.proofType,
            msg.sender,
            proofData.commitment
        );

        return proofId;
    }

    /**
     * @dev Internal function to perform actual proof verification
     * This is where different proof systems would be integrated
     */
    function _performVerification(ProofData memory proof) internal view virtual returns (bool) {
        // Placeholder verification logic
        // In a real implementation, this would call appropriate verifier libraries
        
        if (proof.proofType == ProofType.TLSN) {
            return _verifyTLSNProof(proof);
        } else if (proof.proofType == ProofType.MPCTLS) {
            return _verifyMPCTLSProof(proof);
        } else if (proof.proofType == ProofType.CUSTOM) {
            return _verifyCustomProof(proof);
        }
        
        return false;
    }

    /**
     * @dev Verify TLSN proof
     */
    function _verifyTLSNProof(ProofData memory proof) internal pure returns (bool) {
        // Placeholder - would integrate with TLSN verifier library
        return proof.proof.length > 0 && proof.publicInputs.length > 0;
    }

    /**
     * @dev Verify MPCTLS proof
     */
    function _verifyMPCTLSProof(ProofData memory proof) internal pure returns (bool) {
        // Placeholder - would integrate with MPCTLS verifier library  
        return proof.proof.length > 0 && proof.publicInputs.length > 0;
    }

    /**
     * @dev Verify custom proof
     */
    function _verifyCustomProof(ProofData memory proof) internal pure returns (bool) {
        // Placeholder - would allow custom verification logic
        return proof.proof.length > 0 && proof.publicInputs.length > 0;
    }

    /**
     * @dev Override supportsInterface for AccessControl
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}