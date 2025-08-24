// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/core/SessionKeyCommitment.sol";

contract SessionKeyCommitmentTest is Test {
    SessionKeyCommitment public sessionKeyCommitment;
    
    address public admin = address(0x1);
    address public verifier = address(0x2);
    address public user = address(0x3);

    bytes32 public sessionId = keccak256("Test Session");

    function setUp() public {
        vm.startPrank(admin);
        
        sessionKeyCommitment = new SessionKeyCommitment();
        sessionKeyCommitment.grantRole(sessionKeyCommitment.VERIFIER_ROLE(), verifier);
        
        vm.stopPrank();
    }

    function testInitialState() public view {
        assertTrue(sessionKeyCommitment.hasRole(sessionKeyCommitment.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(sessionKeyCommitment.hasRole(sessionKeyCommitment.VERIFIER_ROLE(), admin));
        assertTrue(sessionKeyCommitment.hasRole(sessionKeyCommitment.KDF_MANAGER_ROLE(), admin));
        assertTrue(sessionKeyCommitment.hasRole(sessionKeyCommitment.VERIFIER_ROLE(), verifier));
    }

    function testSupportedKdfs() public view {
        assertTrue(sessionKeyCommitment.isValidKeyDerivationFunction(1)); // KDF_HKDF_SHA256
        assertTrue(sessionKeyCommitment.isValidKeyDerivationFunction(2)); // KDF_HKDF_SHA384
        assertTrue(sessionKeyCommitment.isValidKeyDerivationFunction(3)); // KDF_TLS12_PRF
        assertTrue(sessionKeyCommitment.isValidKeyDerivationFunction(4)); // KDF_TLS13_HKDF
        assertFalse(sessionKeyCommitment.isValidKeyDerivationFunction(99)); // Unsupported
    }

    function testVerifyKeyDerivationSuccess() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1, // KDF_HKDF_SHA256
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1 // HASH_SHA256
        });

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                keyData.masterSecretCommitment,
                keyData.clientRandomCommitment,
                keyData.serverRandomCommitment,
                keyData.sessionKeyCommitment,
                hkdfParams.salt,
                hkdfParams.info
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.prank(verifier);
        bool result = sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
        assertTrue(result);

        assertEq(sessionKeyCommitment.getKeyCommitment(sessionId), keyData.sessionKeyCommitment);
        assertEq(sessionKeyCommitment.getMasterSecretCommitment(sessionId), keyData.masterSecretCommitment);

        ISessionKeyCommitment.KeyDerivationData memory storedData = sessionKeyCommitment.getKeyDerivationData(sessionId);
        assertEq(storedData.masterSecretCommitment, keyData.masterSecretCommitment);
        assertEq(storedData.sessionKeyCommitment, keyData.sessionKeyCommitment);
        assertEq(storedData.keyDerivationFunction, keyData.keyDerivationFunction);
    }

    function testVerifyKeyDerivationInvalidSessionId() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidKeyDerivationData.selector);
        sessionKeyCommitment.verifyKeyDerivation(bytes32(0), keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationInvalidMasterSecret() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: bytes32(0), // Invalid
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidMasterSecretCommitment.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationInvalidRandomCommitments() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: bytes32(0), // Invalid
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidRandomCommitment.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationUnsupportedKdf() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 99, // Unsupported
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.UnsupportedKeyDerivationFunction.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationInvalidKeyLength() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 8, // Too short (< 16)
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidKeyLength.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationInvalidHashFunction() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 99 // Unsupported
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidHashFunction.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationAlreadyVerified() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [
            uint256(keccak256(abi.encodePacked(
                sessionId,
                keyData.masterSecretCommitment,
                keyData.clientRandomCommitment,
                keyData.serverRandomCommitment,
                keyData.sessionKeyCommitment,
                hkdfParams.salt,
                hkdfParams.info
            ))) >> 8,
            uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)
        ];

        vm.startPrank(verifier);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
        
        vm.expectRevert(SessionKeyCommitmentErrors.KeyDerivationAlreadyVerified.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
        vm.stopPrank();
    }

    function testAddSupportedKdf() public {
        uint256 newKdf = 5;
        assertFalse(sessionKeyCommitment.isValidKeyDerivationFunction(newKdf));

        vm.prank(admin);
        sessionKeyCommitment.addSupportedKdf(newKdf);
        assertTrue(sessionKeyCommitment.isValidKeyDerivationFunction(newKdf));
    }

    function testRemoveSupportedKdf() public {
        uint256 kdf = 1; // KDF_HKDF_SHA256
        assertTrue(sessionKeyCommitment.isValidKeyDerivationFunction(kdf));

        vm.prank(admin);
        sessionKeyCommitment.removeSupportedKdf(kdf);
        assertFalse(sessionKeyCommitment.isValidKeyDerivationFunction(kdf));
    }

    function testAddSupportedHashFunction() public {
        uint256 newHashFunc = 4;
        
        vm.prank(admin);
        sessionKeyCommitment.addSupportedHashFunction(newHashFunc);
        // Note: We can't directly test this as there's no public getter, 
        // but we can verify it doesn't revert in validation
    }

    function testRemoveSupportedHashFunction() public {
        vm.prank(admin);
        sessionKeyCommitment.removeSupportedHashFunction(1); // Remove SHA256
        
        // Test that validation now fails with removed hash function
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1 // Removed SHA256
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidHashFunction.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testUnauthorizedAccess() public {
        vm.prank(user);
        vm.expectRevert();
        sessionKeyCommitment.addSupportedKdf(5);
    }

    function testGetEmptyCommitments() public view {
        bytes32 nonExistentSession = keccak256("Non Existent");
        assertEq(sessionKeyCommitment.getKeyCommitment(nonExistentSession), bytes32(0));
        assertEq(sessionKeyCommitment.getMasterSecretCommitment(nonExistentSession), bytes32(0));
    }

    function testVerifyKeyDerivationInvalidSessionKeyCommitment() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: bytes32(0), // Invalid
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidSessionKeyCommitment.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationInvalidClientRandomCommitment() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: bytes32(0), // Invalid
            serverRandomCommitment: keccak256("Server Random"),
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidRandomCommitment.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }

    function testVerifyKeyDerivationInvalidServerRandomCommitment() public {
        ISessionKeyCommitment.KeyDerivationData memory keyData = ISessionKeyCommitment.KeyDerivationData({
            masterSecretCommitment: keccak256("Master Secret"),
            clientRandomCommitment: keccak256("Client Random"),
            serverRandomCommitment: bytes32(0), // Invalid
            sessionKeyCommitment: keccak256("Session Key"),
            keyDerivationFunction: 1,
            cipherSuite: 0x1301
        });

        ISessionKeyCommitment.HKDFParameters memory hkdfParams = ISessionKeyCommitment.HKDFParameters({
            salt: keccak256("Salt"),
            info: keccak256("Info"),
            length: 32,
            hashFunction: 1
        });

        uint256[8] memory proof = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5), uint256(6), uint256(7), uint256(8)];

        vm.prank(verifier);
        vm.expectRevert(SessionKeyCommitmentErrors.InvalidRandomCommitment.selector);
        sessionKeyCommitment.verifyKeyDerivation(sessionId, keyData, hkdfParams, proof);
    }
}