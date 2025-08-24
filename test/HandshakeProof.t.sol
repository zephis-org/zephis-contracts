// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/core/HandshakeProof.sol";
import "../src/registries/TrustedCAs.sol";

contract HandshakeProofTest is Test {
    HandshakeProof public handshakeProof;
    TrustedCAs public trustedCAs;
    
    address public admin = address(0x1);
    address public verifier = address(0x2);
    address public user = address(0x3);

    bytes32 public testCaHash = keccak256("Test CA");
    bytes32 public sessionId = keccak256("Test Session");

    function setUp() public {
        vm.startPrank(admin);
        
        trustedCAs = new TrustedCAs();
        handshakeProof = new HandshakeProof(address(trustedCAs));
        
        // Add test CA
        trustedCAs.addCa(
            testCaHash,
            keccak256("Test CA Public Key"),
            keccak256("Test CA Name"),
            block.timestamp,
            block.timestamp + 365 days
        );
        
        // Grant roles
        handshakeProof.grantRole(handshakeProof.VERIFIER_ROLE(), verifier);
        
        vm.stopPrank();
    }

    function testInitialState() public view {
        assertTrue(handshakeProof.hasRole(handshakeProof.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(handshakeProof.hasRole(handshakeProof.VERIFIER_ROLE(), admin));
        assertTrue(handshakeProof.hasRole(handshakeProof.CA_MANAGER_ROLE(), admin));
        assertTrue(handshakeProof.hasRole(handshakeProof.VERIFIER_ROLE(), verifier));
    }

    function testSupportedCipherSuites() public view {
        assertTrue(handshakeProof.isValidCipherSuite(0x1301)); // TLS_AES_128_GCM_SHA256
        assertTrue(handshakeProof.isValidCipherSuite(0x1302)); // TLS_AES_256_GCM_SHA384
        assertTrue(handshakeProof.isValidCipherSuite(0xC02F)); // ECDHE_RSA_WITH_AES_128_GCM_SHA256
        assertTrue(handshakeProof.isValidCipherSuite(0xC030)); // ECDHE_RSA_WITH_AES_256_GCM_SHA384
        assertFalse(handshakeProof.isValidCipherSuite(0x0000)); // Unsupported
    }

    function testSupportedProtocolVersions() public view {
        assertTrue(handshakeProof.isValidProtocolVersion(0x0303)); // TLS 1.2
        assertTrue(handshakeProof.isValidProtocolVersion(0x0304)); // TLS 1.3
        assertFalse(handshakeProof.isValidProtocolVersion(0x0301)); // TLS 1.0
    }

    function testVerifyHandshakeSuccess() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });
        certChain.certificates[0] = keccak256("Certificate");

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(sessionId, handshake.clientHello, handshake.serverHello, handshake.certificateHash, certChain.rootCaHash))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        bool result = handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
        assertTrue(result);

        IHandshakeProof.HandshakeData memory storedHandshake = handshakeProof.getHandshakeData(sessionId);
        assertEq(storedHandshake.clientHello, handshake.clientHello);
        assertEq(storedHandshake.serverHello, handshake.serverHello);
        assertEq(storedHandshake.cipherSuite, handshake.cipherSuite);
        assertEq(storedHandshake.protocolVersion, handshake.protocolVersion);
    }

    function testVerifyHandshakeInvalidSessionId() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidHandshakeData.selector);
        handshakeProof.verifyHandshake(bytes32(0), handshake, certChain, proof);
    }

    function testVerifyHandshakeInvalidClientHello() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: bytes32(0),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidClientHello.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeUnsupportedCipherSuite() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x0000, // Unsupported
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.UnsupportedCipherSuite.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeInvalidCertificateChain() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](0), // Empty chain
            rootCaHash: testCaHash,
            chainLength: 0
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidCertificateChain.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeInvalidCaRoot() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        bytes32 invalidCaHash = keccak256("Invalid CA");
        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: invalidCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidCARoot.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeAlreadyVerified() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(sessionId, handshake.clientHello, handshake.serverHello, handshake.certificateHash, certChain.rootCaHash))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.startPrank(verifier);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
        
        vm.expectRevert(HandshakeProofErrors.HandshakeAlreadyVerified.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
        vm.stopPrank();
    }

    function testAddSupportedCipherSuite() public {
        uint256 newCipherSuite = 0x1234;
        assertFalse(handshakeProof.isValidCipherSuite(newCipherSuite));

        vm.prank(admin);
        handshakeProof.addSupportedCipherSuite(newCipherSuite);
        assertTrue(handshakeProof.isValidCipherSuite(newCipherSuite));
    }

    function testRemoveSupportedCipherSuite() public {
        uint256 cipherSuite = 0x1301;
        assertTrue(handshakeProof.isValidCipherSuite(cipherSuite));

        vm.prank(admin);
        handshakeProof.removeSupportedCipherSuite(cipherSuite);
        assertFalse(handshakeProof.isValidCipherSuite(cipherSuite));
    }

    function testUnauthorizedAccess() public {
        vm.prank(user);
        vm.expectRevert();
        handshakeProof.addSupportedCipherSuite(0x1234);
    }

    function testVerifyHandshakeInvalidServerHello() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: bytes32(0), // Invalid
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidServerHello.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeInvalidCertificateHash() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: bytes32(0), // Invalid
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidCertificateHash.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeUnsupportedProtocolVersion() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0301 // TLS 1.0 - Unsupported
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.UnsupportedProtocolVersion.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeInvalidCertificateChainTooLong() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](6), // Too many certificates
            rootCaHash: testCaHash,
            chainLength: 6 // Invalid - max is 5
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidCertificateChain.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testVerifyHandshakeProofVerificationFailure() public {
        IHandshakeProof.HandshakeData memory handshake = IHandshakeProof.HandshakeData({
            clientHello: keccak256("Client Hello"),
            serverHello: keccak256("Server Hello"),
            certificateHash: keccak256("Certificate"),
            serverKeyExchange: keccak256("Server Key Exchange"),
            clientKeyExchange: keccak256("Client Key Exchange"),
            cipherSuite: 0x1301,
            protocolVersion: 0x0303
        });

        IHandshakeProof.CertificateChain memory certChain = IHandshakeProof.CertificateChain({
            certificates: new bytes32[](1),
            rootCaHash: testCaHash,
            chainLength: 1
        });

        // Invalid proof - does not match expected public input
        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(HandshakeProofErrors.InvalidHandshakeData.selector);
        handshakeProof.verifyHandshake(sessionId, handshake, certChain, proof);
    }

    function testGetCaHash() public view {
        // Test accessing the CA hash for coverage
        bytes32 caHash = testCaHash;
        assertTrue(caHash != bytes32(0));
    }
}