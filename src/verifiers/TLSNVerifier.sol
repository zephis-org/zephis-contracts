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
        bytes notaryPubKey;             // Notary public key
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
        if (transcript.length < 43) { // Minimum TLS ClientHello size
            return "";
        }
        
        // Parse TLS Record Layer: type(1) + version(2) + length(2) = 5 bytes
        if (transcript[0] != 0x16) { // Must be Handshake type
            return "";
        }
        
        uint256 recordLength = (uint256(uint8(transcript[3])) << 8) | uint256(uint8(transcript[4]));
        if (recordLength + 5 > transcript.length) {
            return "";
        }
        
        // Parse Handshake Header: type(1) + length(3) = 4 bytes
        if (transcript[5] != 0x01) { // Must be ClientHello
            return "";
        }
        
        // Skip handshake length, version, random (32 bytes), session ID
        uint256 pos = 5 + 4 + 2 + 32; // Start after version and random
        
        if (pos >= transcript.length) return "";
        
        // Skip Session ID
        uint256 sessionIdLen = uint256(uint8(transcript[pos]));
        pos += 1 + sessionIdLen;
        
        if (pos + 2 >= transcript.length) return "";
        
        // Skip Cipher Suites
        uint256 cipherSuitesLen = (uint256(uint8(transcript[pos])) << 8) | uint256(uint8(transcript[pos + 1]));
        pos += 2 + cipherSuitesLen;
        
        if (pos + 1 >= transcript.length) return "";
        
        // Skip Compression Methods
        uint256 compressionMethodsLen = uint256(uint8(transcript[pos]));
        pos += 1 + compressionMethodsLen;
        
        if (pos + 2 >= transcript.length) return "";
        
        // Parse Extensions
        uint256 extensionsLen = (uint256(uint8(transcript[pos])) << 8) | uint256(uint8(transcript[pos + 1]));
        pos += 2;
        
        uint256 extensionsEnd = pos + extensionsLen;
        
        while (pos + 4 <= extensionsEnd && pos + 4 <= transcript.length) {
            uint256 extType = (uint256(uint8(transcript[pos])) << 8) | uint256(uint8(transcript[pos + 1]));
            uint256 extLen = (uint256(uint8(transcript[pos + 2])) << 8) | uint256(uint8(transcript[pos + 3]));
            pos += 4;
            
            if (extType == 0x0000) { // Server Name Indication extension
                if (pos + extLen > transcript.length) return "";
                
                // Parse SNI extension
                if (extLen < 5) return "";
                
                uint256 serverNameListLen = (uint256(uint8(transcript[pos])) << 8) | uint256(uint8(transcript[pos + 1]));
                pos += 2;
                
                if (serverNameListLen + 2 > extLen) return "";
                
                // Parse first server name entry
                if (pos + 3 >= transcript.length) return "";
                if (uint8(transcript[pos]) != 0x00) return ""; // Must be hostname
                
                // Get name length (big endian)
                pos += 3;
                uint256 nameLen = (uint256(uint8(transcript[pos - 2])) << 8) | uint256(uint8(transcript[pos - 1]));
                
                if (nameLen == 0 || pos + nameLen > transcript.length) return "";
                
                // Simple hostname extraction
                bytes memory result = new bytes(nameLen);
                for (uint256 i = 0; i < nameLen;) {
                    result[i] = transcript[pos + i];
                    unchecked { ++i; }
                }
                return string(result);
            }
            
            pos += extLen;
        }
        
        return "";
    }

    /**
     * @dev Validate notary signature
     */
    function _validateNotarySignature(TLSNProofComponents memory components) 
        internal 
        view 
        returns (bool) 
    {
        if (components.notarySignature.length != 65) { // Standard ECDSA signature length
            return false;
        }
        
        // Construct message hash from critical components
        bytes32 messageHash = keccak256(abi.encodePacked(
            components.sessionHash,
            components.transcriptHash,
            components.timestamp,
            components.serverName,
            components.notaryPubKey
        ));
        
        // Add Ethereum signed message prefix
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));
        
        // Extract signature components
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        bytes memory notarySignature = components.notarySignature;
        assembly {
            let sig := add(notarySignature, 0x20)
            r := mload(sig)
            s := mload(add(sig, 0x20))
            v := byte(0, mload(add(sig, 0x40)))
        }
        
        // Adjust v if necessary (some libraries use 0/1 instead of 27/28)
        if (v < 27) {
            v += 27;
        }
        
        // Recover signer address
        address recovered = ecrecover(ethSignedMessageHash, v, r, s);
        if (recovered == address(0)) {
            return false;
        }
        
        // Check if recovered address matches the notary public key
        bytes memory notaryPubKey = components.notaryPubKey;
        address expectedNotary = address(uint160(uint256(keccak256(notaryPubKey))));
        if (recovered != expectedNotary) {
            // Try alternative: check if recovered address is directly the notary
            bytes20 notaryAddr;
            if (notaryPubKey.length >= 20) {
                assembly {
                    notaryAddr := mload(add(notaryPubKey, 0x20))
                }
                if (recovered == address(notaryAddr)) {
                    return _trustedNotaries[recovered];
                }
            }
            return false;
        }
        
        // Verify this notary is trusted
        return _trustedNotaries[expectedNotary];
    }

    /**
     * @dev Validate transcript integrity
     */
    function _validateTranscriptIntegrity(TLSNProofComponents memory components) 
        internal 
        pure 
        returns (bool) 
    {
        // Verify transcript hash matches
        bytes32 computedHash = keccak256(components.tlsTranscript);
        if (computedHash != components.transcriptHash) {
            return false;
        }
        
        // Validate minimum TLS record structure
        if (components.tlsTranscript.length < 5) {
            return false;
        }
        
        // Validate TLS record structure
        bytes memory transcript = components.tlsTranscript;
        uint256 pos = 0;
        
        while (pos + 5 <= transcript.length) {
            // TLS Record Header: Type(1) + Version(2) + Length(2)
            uint8 recordType = uint8(transcript[pos]);
            uint16 version = (uint16(uint8(transcript[pos + 1])) << 8) | uint16(uint8(transcript[pos + 2]));
            uint16 recordLength = (uint16(uint8(transcript[pos + 3])) << 8) | uint16(uint8(transcript[pos + 4]));
            
            // Validate record type (must be valid TLS record type)
            if (recordType < 20 || recordType > 24) {
                return false;
            }
            
            // Validate TLS version (1.0, 1.1, 1.2, 1.3)
            if (version != 0x0301 && version != 0x0302 && 
                version != 0x0303 && version != 0x0304) {
                return false;
            }
            
            // Validate record length
            if (recordLength == 0 || recordLength > 16384) { // Max TLS record size
                return false;
            }
            
            // Check if we have enough data for this record
            if (pos + 5 + recordLength > transcript.length) {
                return false;
            }
            
            // Move to next record
            pos += 5 + recordLength;
        }
        
        // Should have consumed the entire transcript
        return pos == transcript.length;
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