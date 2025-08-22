// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./TestTLSNVerifierInternal.sol";
import "../src/verifiers/TLSNVerifier.sol";

contract TLSNVerifierInternalTest is Test {
    TestTLSNVerifierInternal public verifier;
    
    function setUp() public {
        address initialNotary = makeAddr("initialNotary"); 
        verifier = new TestTLSNVerifierInternal(initialNotary);
    }
    
    function testVerifyTLSNProofInternalHashMismatch() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            notarySignature: abi.encode("notary_signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256("wrong_hash"), // Intentional mismatch
            timestamp: block.timestamp,
            serverName: "api.example.com"
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to hash mismatch
    }
    
    function testVerifyTLSNProofInternalInvalidSessionHash() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            notarySignature: abi.encode("notary_signature"),
            sessionHash: bytes32(0), // Invalid session hash
            transcriptHash: keccak256(abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")),
            timestamp: block.timestamp,
            serverName: "api.example.com"
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to invalid session hash
    }
    
    function testVerifyTLSNProofInternalFutureTimestamp() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            notarySignature: abi.encode("notary_signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256(abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")),
            timestamp: block.timestamp + 1000, // Future timestamp > 5 min tolerance
            serverName: "api.example.com"
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to future timestamp
    }
    
    function testVerifyTLSNProofInternalOldTimestamp() public {
        // Move time forward to test old timestamp
        vm.warp(block.timestamp + 31 days);
        
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            notarySignature: abi.encode("notary_signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256(abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")),
            timestamp: block.timestamp - 31 days, // Old timestamp
            serverName: "api.example.com"
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to old timestamp
    }
    
    function testVerifyTLSNProofInternalEmptyServerName() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            notarySignature: abi.encode("notary_signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256(abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")),
            timestamp: block.timestamp,
            serverName: "" // Empty server name
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to empty server name
    }
    
    function testValidateNotarySignatureEmpty() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("test"),
            notarySignature: "", // Empty signature
            sessionHash: keccak256("session"),
            transcriptHash: keccak256("hash"),
            timestamp: block.timestamp,
            serverName: "test.com"
        });
        
        bool result = verifier.testValidateNotarySignature(components);
        assertFalse(result); // Should fail due to empty signature
    }
    
    function testValidateTranscriptIntegrityHashMismatch() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("test_transcript"),
            notarySignature: abi.encode("signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256("wrong_hash"), // Hash mismatch
            timestamp: block.timestamp,
            serverName: "test.com"
        });
        
        bool result = verifier.testValidateTranscriptIntegrity(components);
        assertFalse(result); // Should fail due to hash mismatch
    }
    
    function testValidateTranscriptIntegrityTooShort() public view {
        bytes memory shortTranscript = new bytes(5); // Less than 10 bytes
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: shortTranscript,
            notarySignature: abi.encode("signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256(shortTranscript),
            timestamp: block.timestamp,
            serverName: "test.com"
        });
        
        bool result = verifier.testValidateTranscriptIntegrity(components);
        assertFalse(result); // Should fail due to short transcript
    }
    
    function testVerifyTLSNProofInternalNoTranscript() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: "", // Empty transcript  
            notarySignature: abi.encode("notary_signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256(abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")),
            timestamp: block.timestamp,
            serverName: "api.example.com"
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to empty transcript (line 312)
    }
    
    function testVerifyTLSNProofInternalEmptyServerNameForLine156() public view {
        TLSNVerifier.TLSNProofComponents memory components = TLSNVerifier.TLSNProofComponents({
            tlsTranscript: abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            notarySignature: abi.encode("notary_signature"),
            sessionHash: keccak256("session"),
            transcriptHash: keccak256(abi.encode("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")),
            timestamp: block.timestamp,
            serverName: "" // Empty server name to hit line 156
        });
        
        bool result = verifier.testVerifyTLSNProofInternal(components);
        assertFalse(result); // Should fail due to empty server name 
    }
}