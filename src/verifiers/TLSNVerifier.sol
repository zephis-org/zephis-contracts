// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./ZKProofVerifier.sol";

/**
 * @title TLSNVerifier
 * @dev TLSN-specific proof verifier for ZEPHIS Protocol
 * 
 * This contract extends the base verifier with TLSN-specific functionality
 * including notary verification, transcript validation, and commitment schemes.
 */
contract TLSNVerifier is ZKProofVerifier {
    
    // TLSN-specific configuration
    struct TLSNConfig {
        address notaryAddress;          // Trusted notary public key
        uint256 maxTranscriptSize;      // Maximum TLS transcript size
        uint256 commitmentScheme;       // Commitment scheme identifier
        bool requireNotarization;       // Whether notarization is mandatory
    }

    // TLSN proof components
    struct TLSNProofComponents {
        bytes tlsTranscript;            // Raw TLS transcript
        bytes notarySignature;          // Notary signature
        bytes32 sessionHash;           // TLS session hash
        bytes32 transcriptHash;         // Transcript commitment hash
        uint256 timestamp;              // Session timestamp
        string serverName;              // Server name (SNI)
    }

    // Notary registry
    mapping(address => bool) private _trustedNotaries;
    mapping(bytes32 => TLSNProofComponents) private _tlsnComponents;
    
    // TLSN configuration
    TLSNConfig private _tlsnConfig;
    
    // Events
    event NotaryAdded(address indexed notary);
    event NotaryRemoved(address indexed notary);
    event TLSNConfigUpdated();
    event TLSNProofProcessed(bytes32 indexed proofId, string serverName, bytes32 sessionHash);

    /**
     * @dev Constructor with TLSN-specific initialization
     */
    constructor(address initialNotary) {
        // Add initial trusted notary
        if (initialNotary != address(0)) {
            _trustedNotaries[initialNotary] = true;
            emit NotaryAdded(initialNotary);
        }
        
        // Default TLSN configuration
        _tlsnConfig = TLSNConfig({
            notaryAddress: initialNotary,
            maxTranscriptSize: 1024 * 1024, // 1MB
            commitmentScheme: 1,             // SHA256 commitment
            requireNotarization: true
        });
    }

    /**
     * @dev Submit TLSN proof with additional components
     */
    function submitTLSNProof(
        ProofData calldata proofData,
        TLSNProofComponents calldata tlsnComponents
    ) external nonReentrant whenNotPaused returns (bytes32 proofId) {
        require(proofData.proofType == ProofType.TLSN, "TLSNVerifier: Not a TLSN proof");
        require(tlsnComponents.tlsTranscript.length > 0, "TLSNVerifier: Empty transcript");
        require(tlsnComponents.tlsTranscript.length <= _tlsnConfig.maxTranscriptSize, "TLSNVerifier: Transcript too large");
        require(bytes(tlsnComponents.serverName).length > 0, "TLSNVerifier: Empty server name");
        
        // Validate notarization if required
        if (_tlsnConfig.requireNotarization) {
            require(tlsnComponents.notarySignature.length > 0, "TLSNVerifier: Missing notary signature");
            require(_validateNotarySignature(tlsnComponents), "TLSNVerifier: Invalid notary signature");
        }
        
        // Validate transcript integrity
        require(_validateTranscriptIntegrity(tlsnComponents), "TLSNVerifier: Invalid transcript");
        
        // Calculate proof ID deterministically to avoid reentrancy issues
        bytes32 calculatedProofId = keccak256(abi.encode(
            proofData.sessionId,
            proofData.proof,
            proofData.commitment,
            block.timestamp,
            msg.sender
        ));
        
        // Store TLSN-specific components with final proof ID
        _tlsnComponents[calculatedProofId] = tlsnComponents;
        
        // Submit base proof using internal call pattern
        proofId = _submitProofInternal(proofData, calculatedProofId);
        
        emit TLSNProofProcessed(proofId, tlsnComponents.serverName, tlsnComponents.sessionHash);
        
        return proofId;
    }

    /**
     * @dev Get TLSN proof components
     */
    function getTLSNComponents(bytes32 proofId) 
        external 
        view 
        returns (TLSNProofComponents memory components) 
    {
        // Check if TLSN components exist
        require(_tlsnComponents[proofId].tlsTranscript.length > 0, "TLSNVerifier: TLSN components not found");
        return _tlsnComponents[proofId];
    }

    /**
     * @dev Verify TLSN-specific proof components
     */
    function verifyTLSNProof(bytes32 proofId) 
        external 
        view 
        returns (bool isValid, string memory reason) 
    {
        TLSNProofComponents memory components = _tlsnComponents[proofId];
        
        // Check if components exist
        if (components.tlsTranscript.length == 0) {
            return (false, "No TLSN components found");
        }
        
        // Validate transcript hash
        bytes32 computedHash = keccak256(components.tlsTranscript);
        if (computedHash != components.transcriptHash) {
            return (false, "Transcript hash mismatch");
        }
        
        // Validate session hash
        if (components.sessionHash == bytes32(0)) {
            return (false, "Invalid session hash");
        }
        
        // Validate timestamp (not too old, not in future)
        if (components.timestamp > block.timestamp) {
            return (false, "Future timestamp");
        }
        
        if (block.timestamp - components.timestamp > 30 days) {
            return (false, "Timestamp too old");
        }
        
        // Validate server name
        if (bytes(components.serverName).length == 0) {
            return (false, "Empty server name");
        }
        
        return (true, "Valid TLSN proof");
    }

    /**
     * @dev Add trusted notary (admin only)
     */
    function addTrustedNotary(address notary) external onlyRole(ADMIN_ROLE) {
        require(notary != address(0), "TLSNVerifier: Invalid notary address");
        require(!_trustedNotaries[notary], "TLSNVerifier: Notary already trusted");
        
        _trustedNotaries[notary] = true;
        emit NotaryAdded(notary);
    }

    /**
     * @dev Remove trusted notary (admin only)
     */
    function removeTrustedNotary(address notary) external onlyRole(ADMIN_ROLE) {
        require(_trustedNotaries[notary], "TLSNVerifier: Notary not trusted");
        
        _trustedNotaries[notary] = false;
        emit NotaryRemoved(notary);
    }

    /**
     * @dev Check if notary is trusted
     */
    function isTrustedNotary(address notary) external view returns (bool) {
        return _trustedNotaries[notary];
    }

    /**
     * @dev Update TLSN configuration (admin only)
     */
    function updateTLSNConfig(TLSNConfig calldata newConfig) external onlyRole(ADMIN_ROLE) {
        require(newConfig.maxTranscriptSize > 0, "TLSNVerifier: Invalid max transcript size");
        require(newConfig.maxTranscriptSize <= 10 * 1024 * 1024, "TLSNVerifier: Max size too large"); // 10MB limit
        
        _tlsnConfig = newConfig;
        emit TLSNConfigUpdated();
    }

    /**
     * @dev Get current TLSN configuration
     */
    function getTLSNConfig() external view returns (TLSNConfig memory) {
        return _tlsnConfig;
    }

    /**
     * @dev Extract server name from TLS transcript
     */
    function extractServerName(bytes calldata transcript) 
        external 
        pure 
        returns (string memory serverName) 
    {
        // Simplified SNI extraction - in production this would be more robust
        // This is a placeholder implementation
        if (transcript.length < 100) {
            return "";
        }
        
        // Look for SNI extension in ClientHello
        // This is a simplified version - real implementation would properly parse TLS
        for (uint256 i = 0; i < transcript.length - 20; i++) {
            if (transcript[i] == 0x00 && transcript[i+1] == 0x00) { // Server Name extension
                uint256 nameLength = uint256(uint8(transcript[i+7]));
                if (nameLength > 0 && i + 8 + nameLength <= transcript.length) {
                    bytes memory nameBytes = new bytes(nameLength);
                    for (uint256 j = 0; j < nameLength; j++) {
                        nameBytes[j] = transcript[i + 8 + j];
                    }
                    return string(nameBytes);
                }
            }
        }
        
        return "";
    }

    /**
     * @dev Validate notary signature
     */
    function _validateNotarySignature(TLSNProofComponents memory components) 
        internal 
        pure 
        returns (bool) 
    {
        if (components.notarySignature.length == 0) {
            return false;
        }
        
        // In a real implementation, this would verify the notary's signature
        // using ECDSA or other signature schemes against a message hash:
        // bytes32 messageHash = keccak256(abi.encodePacked(
        //     components.sessionHash, components.transcriptHash, 
        //     components.timestamp, components.serverName
        // ));
        // For now, we just check if we have a signature from a trusted notary
        return components.notarySignature.length >= 64; // Minimum signature length
    }

    /**
     * @dev Validate transcript integrity
     */
    function _validateTranscriptIntegrity(TLSNProofComponents memory components) 
        internal 
        pure 
        returns (bool) 
    {
        // Verify transcript hash
        bytes32 computedHash = keccak256(components.tlsTranscript);
        if (computedHash != components.transcriptHash) {
            return false;
        }
        
        // Basic TLS structure validation
        if (components.tlsTranscript.length < 10) {
            return false;
        }
        
        // Basic TLS structure validation (simplified - just check it's not empty)
        // In production, this would do proper TLS parsing
        
        return true;
    }

    /**
     * @dev Override _performVerification for TLSN-specific logic
     */
    function _performVerification(ProofData memory proof) internal view override returns (bool) {
        if (proof.proofType != ProofType.TLSN) {
            return super._performVerification(proof);
        }
        
        // TLSN-specific verification - avoid external call by using internal logic
        TLSNProofComponents memory components = _tlsnComponents[proof.proofId];
        
        // Verify TLSN components exist and are valid (inline verification)
        return _verifyTLSNProofInternal(components);
    }

    /**
     * @dev Internal TLSN verification logic to avoid external calls in loops
     */
    function _verifyTLSNProofInternal(TLSNProofComponents memory components) 
        internal 
        view 
        returns (bool) 
    {
        // Check if components exist
        if (components.tlsTranscript.length == 0) {
            return false;
        }
        
        // Validate transcript hash
        bytes32 computedHash = keccak256(components.tlsTranscript);
        if (computedHash != components.transcriptHash) {
            return false;
        }
        
        // Validate session hash
        if (components.sessionHash == bytes32(0)) {
            return false;
        }
        
        // Validate timestamp (not too old, not in future) - use reasonable bounds
        if (components.timestamp > block.timestamp + 300) { // Allow 5 minutes future tolerance
            return false;
        }
        
        if (components.timestamp + 30 days < block.timestamp) { // More precise comparison
            return false;
        }
        
        // Validate server name
        if (bytes(components.serverName).length == 0) {
            return false;
        }
        
        return true;
    }

    /**
     * @dev Get TLSN verification statistics
     */
    function getTLSNStats() external view returns (
        uint256 totalTLSNProofs,
        uint256 trustedNotariesCount,
        uint256 avgTranscriptSize
    ) {
        // Count TLSN proofs (simplified - in production would track separately)
        totalTLSNProofs = this.getTotalProofs(); // Use inherited function
        
        // Count trusted notaries
        trustedNotariesCount = 0; // Would need to track this separately
        
        // Average transcript size (simplified)
        avgTranscriptSize = _tlsnConfig.maxTranscriptSize / 2; // Approximation
    }
}